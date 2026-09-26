// Print the resolved model for the loaded database.
//
// This is the artefact for the live demo and for the walkthrough: it shows the engine's answers
// and their provenance without a UI in the way, so a claim about what the console will render can
// be checked against the server that will render it.
//
//   node scripts/inspect.js                       # the documented fixture
//   CANDIDATE_NONCE=whatever node scripts/inspect.js
//
// Read-only. It opens the same app.db the server does and writes nothing.

import { readFileSync } from 'node:fs';
import { openDatabase } from '../server/db.js';
import { createResolver } from '../server/permissions.js';
import { readNonce, buildOverlay } from './personalise.js';

const db = openDatabase();
const q = (sql, ...args) => db.prepare(sql).all(...args);
const one = (sql, ...args) => db.prepare(sql).get(...args);

const BOLD = '\x1b[1m', DIM = '\x1b[2m', OFF = '\x1b[0m';
const GREEN = '\x1b[32m', RED = '\x1b[31m', CYAN = '\x1b[36m', YELLOW = '\x1b[33m';

// pad to a visible width, ignoring the ANSI colour codes, or every column drifts right
const pad = (s0, n) => s0 + ' '.repeat(Math.max(0, n - stripAnsi(s0).length));
const stripAnsi = (s0) => s0.replace(/\x1b\[[0-9;]*m/g, '');
const show = (v) => (v.effect === 'allow' ? `${GREEN}allow${OFF}` : `${RED}deny ${OFF}`);
const prov = (v) =>
  v.source === null ? `${DIM}source=null reason=${v.reason}${OFF}` : `${DIM}source=${v.source} reason=${v.reason}${OFF}`;

console.log(`\n${BOLD}REFERENCE DATA AS LOADED${OFF}  (read from tables, not from any document)`);
console.log(`  roles        ${q('SELECT key FROM roles ORDER BY rank DESC').map((r) => r.key).join(', ')}`);
console.log(`  permissions  ${one('SELECT count(*) AS n FROM permissions').n} rows`);
const undocumented = one(
  `SELECT count(*) AS n FROM permissions WHERE key NOT IN (
     'device:list','device:view','device:control','device:terminal','device:file_transfer',
     'device:provision','device:update','session:start','session:view','session:terminate',
     'grant:create','grant:revoke','user:read','user:invite','user:role:update','user:remove',
     'audit:read','org:update','org:delete')`
).n;
if (undocumented) {
  const extra = q(
    `SELECT key FROM permissions WHERE key NOT IN (
       'device:list','device:view','device:control','device:terminal','device:file_transfer',
       'device:provision','device:update','session:start','session:view','session:terminate',
       'grant:create','grant:revoke','user:read','user:invite','user:role:update','user:remove',
       'audit:read','org:update','org:delete')`
  ).map((r) => r.key);
  console.log(`  ${YELLOW}-> ${undocumented} of them appear in NO document: ${extra.join(', ')}${OFF}`);
}
console.log(`  orgs         ${q('SELECT id, name, theme FROM organizations ORDER BY name').map((r) => `${r.name} (${r.id}, ${r.theme})`).join('  ')}`);

const interesting = ['device:list', 'device:view', 'device:control', 'device:terminal', 'session:start', 'session:view', 'session:terminate', 'grant:create', 'user:read', 'user:invite', 'audit:read', 'org:update', 'org:delete'];

/** Print one person's resolved set for one org, org-level and per device. */
function report(userId, orgId, label) {
  const r = createResolver(db, { userId, orgId });
  const user = one('SELECT email, name FROM users WHERE id = ?', userId);
  const org = one('SELECT name, theme FROM organizations WHERE id = ?', orgId);
  const devices = q('SELECT id, name FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name', orgId);

  console.log(`\n${BOLD}${label}${OFF}`);
  console.log(`  ${user.name} <${user.email}>  in  ${BOLD}${org.name}${OFF}  as  ${CYAN}${r.role}${OFF}`);

  const orgLevel = r.permissionsFor(null);
  const granted = interesting.filter((p) => orgLevel[p]?.effect === 'allow');
  console.log(`\n  ${DIM}org-level (the union across every device in the org)${OFF}`);
  console.log(`    ${granted.length ? granted.map((p) => `${GREEN}${p}${OFF}`).join('  ') : `${DIM}nothing${OFF}`}`);
  const denied = interesting.filter((p) => orgLevel[p]?.effect === 'deny');
  const explicit = denied.filter((p) => orgLevel[p].reason === 'explicit_deny');
  if (explicit.length) {
    console.log(`    ${YELLOW}explicitly denied org-wide:${OFF} ${explicit.map((p) => `${RED}${p}${OFF} ${DIM}(${orgLevel[p].source})${OFF}`).join('  ')}`);
  }

  console.log(`\n  ${DIM}per device, the rows the console renders${OFF}`);
  const header = ['device', 'device:view', 'device:control', 'device:terminal', 'session:start'];
  const w = [22, 13, 16, 16, 14];
  console.log(`    ${DIM}${header.map((h, i) => pad(h, w[i])).join('')}${OFF}`);
  for (const d of devices) {
    const p = r.permissionsFor(d.id);
    const cells = [
      d.name,
      show(p['device:view']),
      show(p['device:control']),
      show(p['device:terminal']),
      show(p['session:start']),
    ];
    console.log(`    ${cells.map((c, i) => pad(String(c), w[i])).join('')}`);
    const odd = interesting.filter((k) => p[k]?.reason === 'explicit_deny');
    if (odd.length) {
      console.log(`    ${' '.repeat(w[0])}${DIM}denied here by ${[...new Set(odd.map((k) => p[k].source))].join(', ')}${OFF}`);
    }
    if (p['device:view']?.effect === 'deny') {
      console.log(`    ${' '.repeat(w[0])}${DIM}device:view denied -> this row is NOT listed at all, not redacted${OFF}`);
    }
  }
}

console.log(`\n${BOLD}${'='.repeat(78)}${OFF}`);
console.log(`${BOLD}THE FIXTURE STORY${OFF}`);
console.log(`${BOLD}${'='.repeat(78)}${OFF}`);

report('usr_sam', 'org_acme', '1. Sam in Acme, operator, with an ORG-WIDE deny on device:terminal');
report('usr_sam', 'org_globex', '2. Sam in Globex, auditor. Same person, the two locked items swap (D2)');
report('usr_dana', 'org_globex', '3. Dana in Globex, viewer, plus a grant on exactly ONE device (D6)');
report('usr_acme_viewer', 'org_acme', '4. Acme viewer, a grant, a deny, and a row that disappears');

// ---------------------------------------------------------------------------
const overlay = buildOverlay(readNonce());
if (overlay) {
  console.log(`\n${BOLD}${'='.repeat(78)}${OFF}`);
  console.log(`${BOLD}THE PERSONALISED ORGANISATION${OFF}  ${DIM}fingerprint ${overlay.fingerprint}${OFF}`);
  console.log(`${BOLD}${'='.repeat(78)}${OFF}`);
  report(overlay.user.id, overlay.org.id, `5. ${overlay.org.name}, role "${overlay.role.key}", which no document mentions`);
  report(overlay.bystander.id, overlay.org.id, `6. A plain viewer in the same brand-new org`);

  const r = createResolver(db, { userId: overlay.user.id, orgId: overlay.org.id });
  const [a, b] = overlay.grants;
  console.log(`\n  ${YELLOW}the three distinguishable answers for "${overlay.permission.key}"${OFF}`);
  for (const [label, deviceId] of [['granted device', a.deviceId], ['denied device', b.deviceId], ['org-level   ', null]]) {
    const v = r.permissionsFor(deviceId)[overlay.permission.key];
    console.log(`    ${label}  ${show(v)}  ${prov(v)}`);
  }
}

db.close();
console.log();
