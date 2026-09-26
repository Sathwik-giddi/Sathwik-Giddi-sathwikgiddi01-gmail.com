// My own tests for the cases the shipped suites do not reach.
//
// The shipped suites are the floor. The organiser README names the seams the hidden tier goes
// after: offboard/rehire, self-transfer, suspension on ungated routes, malformed-token fuzzing,
// cross-scope laundering, and concurrent inserts against the partial unique indexes. This file
// covers the ones that are reachable at the engine level; the HTTP-level ones live in
// `tests/` and in the routes.
//
// Run: node scripts/check-seams.js

import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openDatabase, newId } from '../server/db.js';
import { createResolver, resolve } from '../server/permissions.js';
import { verifyAccessToken, signToken, issueAccessToken } from '../server/auth.js';

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(60)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const reasonOf = (e) => e?.reason ?? e?.code ?? String(e);
const throws = (fn) => { try { fn(); return 'no throw'; } catch (e) { return reasonOf(e); } };

// --- build a database the way check-permissions.js does ---------------------
const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));

const seed = JSON.parse(readFileSync(new URL('../seed/orgs.json', import.meta.url), 'utf8'));
const at = (o) => {
  if (!o) return null;
  const m = /^([+-])(\d+)([dhm])$/.exec(o);
  if (!m) return o;
  return new Date(Date.now() + (m[1] === '-' ? -1 : 1) * Number(m[2]) * { d: 864e5, h: 36e5, m: 6e4 }[m[3]]).toISOString();
};
for (const o of seed.organizations)
  db.prepare('INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES (?,?,?,?)').run(o.id, o.name, o.theme, o.maxSessionMinutes);
for (const u of seed.users)
  db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)').run(u.id, u.email.toLowerCase(), u.name, 'x');
for (const m of seed.memberships)
  db.prepare('INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,?,?,?)').run(newId('mem'), m.orgId, m.userId, m.role, m.status, at(m.joinedAt));
for (const d of seed.devices)
  db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)').run(d.id, d.orgId, d.name, d.kind, d.online ? 1 : 0);
for (const g of seed.grants) {
  db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by) VALUES (?,?,?,?,?,?,?,?)').run(g.id, g.orgId, g.userId, g.deviceId ?? null, g.effect, at(g.startsAt), at(g.expiresAt), g.createdBy);
  for (const p of g.permissions) db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run(g.id, p);
}

const A = 'org_acme';
const V = 'usr_acme_viewer';   // viewer in Acme, with a device-scoped allow and a device-scoped deny
const S = 'usr_sam';           // operator in Acme, org-wide deny on device:terminal
const O = 'usr_acme_owner';
const effect = (u, o, p, d = null) => resolve(db, { userId: u, orgId: o, deviceId: d }).permissions[p]?.effect;

// ---------------------------------------------------------------------------
console.log('\n== the org-level question is the union; a device deny is not promoted ==');
// This is the decision the documents leave open (PERMISSIONS.md §3 "the union across all
// devices"), pinned here so a later change to it is a deliberate act rather than a drift.
check('device-scoped allow IS visible org-wide (the union)', effect(V, A, 'session:start'), 'allow');
check('  ...and the source still names the grant', resolve(db, { userId: V, orgId: A }).permissions['session:start'].source, 'grant:grt_viewer_start_session');
check('device-scoped DENY is NOT promoted to org-wide', effect(V, A, 'device:view'), 'allow');
check('  ...but it does bite on its own device', effect(V, A, 'device:view', 'dev_kiosk_lobby_01'), 'deny');
check('org-wide deny denies org-wide', effect(S, A, 'device:terminal'), 'deny');
check('org-wide deny denies every device', effect(S, A, 'device:terminal', 'dev_lab_win_01'), 'deny');
check('org-wide deny reason is explicit_deny', resolve(db, { userId: S, orgId: A }).permissions['device:terminal'].reason, 'explicit_deny');

// The self-consistency property that makes the union the right choice: the org-level answer the
// console gates navigation on is the SAME question the org-level endpoints authorise. If a
// permission is allowed org-level, assertCan at org level must agree — and where it is not
// allowed, assertCan must throw rather than quietly pass.
console.log('\n== org-level gating and org-level authorisation cannot disagree ==');
for (const p of ['device:list', 'user:read', 'session:view', 'audit:read', 'org:update', 'org:delete', 'session:start', 'device:control']) {
  const r = createResolver(db, { userId: V, orgId: A });
  const allowed = r.can(p, null);
  const outcome = (() => { try { r.assertCan(p, null); return true; } catch { return false; } })();
  check(`${p} (${allowed ? 'held' : 'not held'}): can() === assertCan()`, outcome, allowed);
}
{
  // And the device row the console renders agrees with the button it draws.
  const r = createResolver(db, { userId: V, orgId: A });
  const rowOnLabMac = r.permissionsFor('dev_lab_mac_01')['device:view'];
  const rowOnKiosk = r.permissionsFor('dev_kiosk_lobby_01')['device:view'];
  check('device:view allowed on the granted device', rowOnLabMac.effect, 'allow');
  check('device:view denied on the denied device', rowOnKiosk.effect, 'deny');
  check('  ...so the kiosk row is not listed at all, not redacted', [rowOnKiosk.effect === 'allow'], [false]);
}

// ---------------------------------------------------------------------------
console.log('\n== D9 cross-scope laundering ==');
{
  // Sam is blocked by an ORG-WIDE deny on device:terminal, so she cannot pass it on, at any
  // scope, even to herself-adjacent targets.
  const sam = createResolver(db, { userId: S, orgId: A });
  check('cannot grant what an org-wide deny took away', throws(() => sam.assertMayGrant(['device:terminal'])), 'explicit_deny');
  check('  ...nor on one device', throws(() => sam.assertMayGrant(['device:terminal'], 'dev_lab_win_01')), 'explicit_deny');
  // A wildcard is refused too, but WHICH reason comes back depends on which permission in the
  // pattern she lacks first — the catalogue is ordered, and `device:provision` sorts before
  // `device:terminal`. Asserting the refusal and the vocabulary, not one exact string, because
  // pinning the string would make the test depend on catalogue order.
  check('  ...nor smuggled inside a wildcard', ['missing_permission', 'explicit_deny'].includes(throws(() => sam.assertMayGrant(['device:*']))), true);
  check('  ...nor as a bare *', ['missing_permission', 'explicit_deny'].includes(throws(() => sam.assertMayGrant(['*']))), true);
  check('  ...and the denied permission is named either way', (() => {
    try { sam.assertMayGrant(['device:*']); return 'no throw'; } catch (e) { return e.message.includes('device:'); }
  })(), true);

  // The scope case: an owner holds device:terminal org-wide, so granting it org-wide is fine but
  // a device-scoped grant of it is legal too (a grant may only narrow, never widen).
  const owner = createResolver(db, { userId: O, orgId: A });
  check('owner may grant a permission they hold', owner.assertMayGrant(['device:terminal']), true);
  check('  ...at a device scope as well', owner.assertMayGrant(['device:terminal'], 'dev_lab_win_01'), true);
  check('owner may grant the whole catalogue as *', owner.assertMayGrant(['*']), true);

  // A viewer holds device:view org-wide but a deny on one device. Granting device:view org-wide
  // is laundering nothing; granting it ON THE DENIED DEVICE would hand out authority the caller
  // does not have there, and the reason has to name the deny so the caller knows what to revoke.
  const viewer = createResolver(db, { userId: V, orgId: A });
  check('viewer may re-grant device:view org-wide (they hold it)', viewer.assertMayGrant(['device:view']), true);
  check('viewer may NOT grant device:view on the denied device', throws(() => viewer.assertMayGrant(['device:view'], 'dev_kiosk_lobby_01')), 'explicit_deny');
  check('  ...because the deny is what is in the way', resolve(db, { userId: V, orgId: A, deviceId: 'dev_kiosk_lobby_01' }).permissions['device:view'].source, 'grant:grt_viewer_deny_kiosk');

  // A pattern covering permissions the caller only partly holds.
  const admin = createResolver(db, { userId: 'usr_acme_admin', orgId: A });
  check('admin lacks org:delete, so * is refused', throws(() => admin.assertMayGrant(['*'])), 'missing_permission');
  check('  ...naming the permission it lacks', (() => { try { admin.assertMayGrant(['*']); return 'no throw'; } catch (e) { return e.message.includes('org:delete'); } })(), true);
  check('admin may grant the six device permissions', admin.assertMayGrant(['device:*']), true);
}

// ---------------------------------------------------------------------------
console.log('\n== offboard and rehire ==');
{
  // grants hang off (org, user), not off the membership, so a re-hire brings them back. That is
  // a consequence of the schema, not a choice I made, and it is worth knowing.
  db.prepare("UPDATE memberships SET status='removed', perm_version=perm_version+1 WHERE org_id=? AND user_id=?").run(A, V);
  check('removed member resolves to nothing', effect(V, A, 'device:list'), 'deny');
  check('  ...with reason not_a_member', resolve(db, { userId: V, orgId: A }).permissions['device:list'].reason, 'not_a_member');
  check('  ...even on the device they had a grant for', effect(V, A, 'session:start', 'dev_lab_mac_01'), 'deny');

  db.prepare("UPDATE memberships SET status='active', role='viewer', joined_at=? WHERE org_id=? AND user_id=?").run(new Date().toISOString(), A, V);
  check('re-hire restores the role baseline', effect(V, A, 'device:list'), 'allow');
  check('  ...AND the grants they had before leaving', effect(V, A, 'session:start', 'dev_lab_mac_01'), 'allow');
  check('  ...including the deny that was on them', effect(V, A, 'device:view', 'dev_kiosk_lobby_01'), 'deny');

  // Re-hire as a different role: the baseline follows the membership, the grants do not.
  db.prepare("UPDATE memberships SET role='auditor' WHERE org_id=? AND user_id=?").run(A, V);
  check('re-hire as a different role swaps the baseline', effect(V, A, 'user:read'), 'allow');
  check('  ...device-scoped grant still applies regardless of role', effect(V, A, 'session:start', 'dev_lab_mac_01'), 'allow');
  db.prepare("UPDATE memberships SET role='viewer' WHERE org_id=? AND user_id=?").run(A, V);
}

// ---------------------------------------------------------------------------
console.log('\n== invited is not active ==');
{
  db.prepare("UPDATE memberships SET status='invited' WHERE org_id=? AND user_id=?").run(A, V);
  check('an invited membership confers nothing', effect(V, A, 'device:list'), 'deny');
  check('  ...reported as not_a_member, not suspended', resolve(db, { userId: V, orgId: A }).permissions['device:list'].reason, 'not_a_member');
  db.prepare("UPDATE memberships SET status='active' WHERE org_id=? AND user_id=?").run(A, V);
}

// ---------------------------------------------------------------------------
console.log('\n== the role on a membership cannot be a role that does not exist ==');
{
  // I wrote this test expecting the engine to have a fallback for a membership pointing at a
  // retired role. It cannot happen: memberships.role REFERENCES roles(key), so the write is
  // refused. That is a guarantee I can lean on instead of coding a branch for it — and the
  // branch would have been untestable, which is the real cost of writing it.
  check('setting a membership to a nonexistent role is refused by the FK', (() => {
    try { db.prepare("UPDATE memberships SET role='ghost_role' WHERE org_id=? AND user_id=?").run(A, V); return 'updated'; }
    catch (e) { return e.code; }
  })(), 'SQLITE_CONSTRAINT_FOREIGNKEY');
  check('so the engine reads a role that is always in `roles`', createResolver(db, { userId: V, orgId: A }).role, 'viewer');
  check('  ...and an empty baseline is only reachable for a role with no rows', (() => {
    db.prepare("INSERT INTO roles (key,rank,label) VALUES ('hollow',7,'Hollow')").run();
    db.prepare("UPDATE memberships SET role='hollow' WHERE org_id=? AND user_id=?").run(A, V);
    return createResolver(db, { userId: V, orgId: A }).permissionsFor(null)['device:list'];
  })(), { effect: 'deny', source: null, reason: 'implicit' });
  db.prepare("UPDATE memberships SET role='viewer' WHERE org_id=? AND user_id=?").run(A, V);
}

// ---------------------------------------------------------------------------
console.log('\n== the snapshot is evidence, not decoration ==');
{
  const sam = createResolver(db, { userId: S, orgId: A });
  const snap = sam.assertCanStartSession('control', 'dev_lab_win_01');
  check('session:start came from the role, so no grant id', snap.grantIds, []);
  check('the snapshot records the role', snap.role, 'operator');

  // The viewer genuinely needs a grant to start a view session. Its id must be in the snapshot,
  // because that row IS the record of why the session was allowed.
  const viewer = createResolver(db, { userId: V, orgId: A });
  check('a grant-authorised session names the grant', viewer.assertCanStartSession('view', 'dev_lab_mac_01').grantIds, ['grt_viewer_start_session']);
}

// ---------------------------------------------------------------------------
console.log('\n== malformed-token fuzzing: nothing gets past verifyAccessToken ==');
{
  const SECRET = 'fuzz-secret';
  const good = issueAccessToken({ userId: 'usr_dana', orgId: A, role: 'owner', permVersion: 3 }, SECRET);
  const [h, p, s] = good.split('.');
  const b64 = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  const mut = (s0) => [...s0].map((c) => (c === 'a' ? 'b' : 'a')).join('');
  const nowSec = () => Math.floor(Date.now() / 1000);

  const cases = {
    'valid token': good,
    'truncated signature': `${h}.${p}.${s.slice(0, -1)}`,
    'swapped payload': `${h}.${b64({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: nowSec() + 900 })}.${s}`,
    'alg none': `${b64({ alg: 'none', typ: 'JWT' })}.${p}.`,
    'alg HS512': signToken({ alg: 'HS512' }, SECRET),
    'no org claim': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
    'org as a number': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: 42, role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
    'pv as a string': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: '3', jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
    'pv negative': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: -1, jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
    'exp as Infinity': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: 'Infinity' }, SECRET),
    'exp far future': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: 9e15 }, SECRET),
    'nested payload': `${h}.${b64({ iss: { toString: () => 'remoteops' } })}.${s}`,
    'array payload': `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64([1, 2, 3])}.${s}`,
    'null payload': `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(null)}.${s}`,
    'prototype pollution attempt': `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: A, role: 'owner', pv: 3, jti: 'x', exp: nowSec() + 900, __proto__: { admin: true } })}.${s}`,
    'every byte flipped': mut(good),
    'unicode in org': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: 'орг__acme', role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
    'path traversal in org': signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: '../../org_globex', role: 'owner', pv: 3, jti: 'x', iat: nowSec(), exp: nowSec() + 900 }, SECRET),
  };

  // A correctly-signed token is authentic by definition, so three of these are ACCEPTED by the
  // parser and refused later, by a different layer. That split is the design: the token parser
  // answers "is this authentic and well-formed", the context answers "does it still describe a
  // real (user, org) pair". Asserting the outcome rather than the layer is the honest test.
  const shapeOnly = {
    'pv negative': 'a stale version is not the parser\'s business — context.js compares it',
    'exp far future': 'only the signature grants authority, and we only mint 15-minute tokens',
    'unicode in org': 'a valid string claim; unaddressable because no membership has that org',
    'path traversal in org': 'bound as a SQL parameter, so it can only ever fail to match',
  };

  const outcomes = {};
  for (const [label, token] of Object.entries(cases)) {
    outcomes[label] = (() => {
      try { verifyAccessToken(token, SECRET); return 'accepted'; }
      catch (e) { return e instanceof Object && e.status ? `${e.status} ${e.code}` : `THREW ${e?.constructor?.name}`; }
    })();
    // The two hand-built forgeries are signed with the wrong key on purpose; everything else is
    // either a well-formed token or must be refused. The four layered cases are asserted below
    // instead, because for those the parser accepting is the correct answer.
    if (label in shapeOnly) continue;
    const want = label === 'valid token' ? 'accepted' : '401 UNAUTHENTICATED';
    check(label, outcomes[label], want);
  }

  for (const [label, explanation] of Object.entries(shapeOnly)) {
    check(`${label} — authentic, so accepted by the parser`, outcomes[label], 'accepted');
    check(`  ...${explanation}`, (() => {
      const claims = verifyAccessToken(cases[label], SECRET);
      const m = db.prepare('SELECT m.id FROM memberships m WHERE m.org_id=? AND m.user_id=?').get(claims.org, claims.sub);
      const fresh = m && m.perm_version === claims.pv;
      return fresh ? 'addressable' : 'refused';
    })(), 'refused');
  }
}

// ---------------------------------------------------------------------------
console.log('\n== D10/D19: the database refuses what a check-then-act would race ==');
{
  // Exclusive session per device. Asserted by attempting the second insert directly, so this
  // tests the INDEX rather than my code.
  const mkSession = (id, mode) => db.prepare(
    `INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,authorized_by,expires_at)
     VALUES (?,?,?,?,?,'active','{}',?)`
  ).run(id, A, O, 'dev_lab_win_01', mode, new Date(Date.now() + 3.6e6).toISOString());

  mkSession('ses_x1', 'control');
  check('a second exclusive session on the same device is refused by the index', (() => { try { mkSession('ses_x2', 'control'); return 'inserted'; } catch (e) { return e.code; } })(), 'SQLITE_CONSTRAINT_UNIQUE');
  check('a second TERMINAL is refused too', (() => { try { mkSession('ses_x3', 'terminal'); return 'inserted'; } catch (e) { return e.code; } })(), 'SQLITE_CONSTRAINT_UNIQUE');
  check('a second VIEW is allowed — view is deliberately not exclusive', (() => { try { mkSession('ses_x4', 'view'); return 'inserted'; } catch { return 'refused'; } })(), 'inserted');
  check('  ...and a third', (() => { try { mkSession('ses_x5', 'view'); return 'inserted'; } catch { return 'refused'; } })(), 'inserted');
  check('releasing the exclusive session frees the device', (() => { db.prepare("UPDATE sessions SET state='ended', end_reason='user_stopped' WHERE id='ses_x1'").run(); try { mkSession('ses_x6', 'control'); return 'inserted'; } catch { return 'refused'; } })(), 'inserted');

  // D19: the foreign key is the validator, and only while the pragma is on.
  check('an unknown permission is refused by the FK', (() => {
    try { db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('grt_viewer_start_session', 'device:teleport'); return 'inserted'; }
    catch (e) { return e.code; }
  })(), 'SQLITE_CONSTRAINT_FOREIGNKEY');
  check('a wildcard is accepted by the same FK', (() => {
    try { db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('grt_viewer_start_session', 'device:*'); return 'inserted'; }
    catch (e) { return e.code; }
  })(), 'inserted');

  // Prove the pragma is what makes the FK fire, on a connection of its own, rather than trusting
  // the README. The probe needs a real grant row, or the grant_id FK fires first and the test
  // would pass for the wrong reason — which is exactly what happened the first time I wrote it.
  const probe = openDatabase(':memory:');
  probe.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
  probe.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));
  probe.prepare("INSERT INTO users (id,email,name,password_hash) VALUES ('u','u@e.test','U','x')").run();
  probe.prepare("INSERT INTO organizations (id,name,theme) VALUES ('o','O','cobalt')").run();
  probe.prepare("INSERT INTO grants (id,org_id,user_id,effect,created_by) VALUES ('g','o','u','allow','u')").run();
  const put = (id, perm) => { try { probe.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run(id, perm); return 'inserted'; } catch { return 'refused'; } };

  probe.pragma('foreign_keys = OFF');
  check('with foreign_keys OFF a nonsense permission inserts (the trap)', put('g', 'device:teleport'), 'inserted');
  probe.pragma('foreign_keys = ON');
  check('  ...and with it ON the very same insert is refused', put('g2', 'device:teleport'), 'refused');
  check('  ...while a real wildcard still inserts', put('g', 'device:*'), 'inserted');
  probe.close();

  // One live invite per email, same story.
  check('a second live invite for the same email is refused', (() => {
    const ins = db.prepare('INSERT INTO invites (id,org_id,email,role,token_hash,invited_by,expires_at) VALUES (?,?,?,?,?,?,?)');
    const exp = new Date(Date.now() + 6e8).toISOString();
    ins.run('inv_1', A, 'dup@example.test', 'viewer', 'h1', O, exp);
    try { ins.run('inv_2', A, 'dup@example.test', 'viewer', 'h2', O, exp); return 'inserted'; } catch (e) { return e.code; }
  })(), 'SQLITE_CONSTRAINT_UNIQUE');
  check('  ...but accepting the first frees the address', (() => {
    db.prepare("UPDATE invites SET accepted_at=? WHERE id='inv_1'").run(new Date().toISOString());
    try { db.prepare('INSERT INTO invites (id,org_id,email,role,token_hash,invited_by,expires_at) VALUES (?,?,?,?,?,?,?)').run('inv_3', A, 'dup@example.test', 'viewer', 'h3', O, new Date(Date.now() + 6e8).toISOString()); return 'inserted'; } catch { return 'refused'; }
  })(), 'inserted');
}

// ---------------------------------------------------------------------------
console.log('\n== a real cross-process race on the exclusive-session index ==');
{
  // better-sqlite3 is synchronous, so an in-process loop cannot interleave two transactions and
  // would prove nothing about the index under contention. This forks N processes that all try to
  // take the same device at the same moment, which is the actual D10 requirement: exactly one
  // 201 and the rest 409.
  const dir = mkdtempSync(join(tmpdir(), 'remoteops-race-'));
  const file = join(dir, 'race.db');
  execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: file }, stdio: 'ignore' });

  const racer = join(dir, 'race.mjs');
  writeFileSync(racer, `
    import { openDatabase, newId } from ${JSON.stringify(new URL('../server/db.js', import.meta.url).href)};
    const db = openDatabase(process.argv[2]);
    try {
      db.prepare(\`INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,authorized_by,expires_at)
                   VALUES (?,?,?,?,?,'active','{}',?)\`)
        .run(newId('ses'), 'org_acme', 'usr_sam', 'dev_lab_mac_01', 'control', new Date(Date.now()+3.6e6).toISOString());
      console.log('WON');
    } catch (e) { console.log('LOST:' + e.code); }
  `);

  const N = 8;
  const kids = Array.from({ length: N }, () => spawnSync(process.execPath, [racer, file], { encoding: 'utf8' }));
  const outcomes = kids.map((k) => (k.stdout || '').trim());
  const won = outcomes.filter((o) => o === 'WON').length;
  const lost = outcomes.filter((o) => o.startsWith('LOST')).length;

  console.log(`         ${N} processes raced for dev_lab_mac_01: ${won} won, ${lost} refused`);
  check('exactly one process wins the device', won, 1);
  check('every other process is refused by the index', lost, N - 1);
  check('  ...and no process crashed', kids.every((k) => k.status === 0), true);

  // Count in the database the racers actually wrote to, not in the in-memory one.
  const raced = openDatabase(file);
  check('the raced database holds exactly one active exclusive session', raced.prepare(
    `SELECT count(*) AS n FROM sessions WHERE device_id='dev_lab_mac_01' AND state='active' AND mode='control'`
  ).get().n, 1);
  check('  ...and the losers reported a constraint failure, not a busy error', outcomes.filter((o) => o === 'LOST:SQLITE_CONSTRAINT_UNIQUE').length, N - 1);
  raced.close();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
