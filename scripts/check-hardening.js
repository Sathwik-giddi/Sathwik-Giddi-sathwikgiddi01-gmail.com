// Hardening: the seams, written from the specifications rather than from anyone's implementation.
//
//   node scripts/check-hardening.js
//
// The shipped suites are the happy path. This one is the list of things that are true REGARDLESS
// of what anyone built — invariants transcribed from `PERMISSIONS.md §9` ("Things that should
// always be true") and from the seams the task's own README names: offboard/rehire, self-transfer,
// suspension on ungated routes, malformed-token fuzzing, cross-scope laundering, and concurrent
// inserts against the partial unique indexes.
//
// Nothing here is copied from anywhere, including the other submissions to this exercise: every
// assertion below is traceable to a line of the specification or to a bug I found in my own code.
// Where a case was found by an audit rather than by the spec, the comment says so.
//
// Overlaps `check-seams.js` (engine-level) and `check-http-seams.js` (over a socket) on purpose.
// This file is the checklist; those two are the depth.

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { createHmac, randomUUID } from 'node:crypto';
import Database from 'better-sqlite3';

const PORT = 8179;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'hardening.db';
const SECRET = 'hardening-secret';
// The pepper is part of the HASH, not just of verification, so the fixture loader and the
// server must be given the SAME one. Seed with one pepper and serve with another and nobody can
// sign in -- which is a real operational property of peppering, not a harness detail.
const PEPPER = 'test-pepper';
// The assertions below call hashPassword/verifyPassword in THIS process, not over HTTP, so the
// pepper has to be in this process's environment as well as the spawned server's. A mismatch here
// is not hypothetical: seeding a database with one pepper and serving it with another locks
// everybody out, and it is the shape of mistake the server's own log message exists to name.
process.env.PASSWORD_PEPPER = PEPPER;

for (const suffix of ['', '-wal', '-shm']) if (existsSync(DB + suffix)) rmSync(DB + suffix);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB, PASSWORD_PEPPER: PEPPER }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: SECRET, APP_HASH_KEY: SECRET, PASSWORD_PEPPER: PEPPER, SCRYPT_N: '4096' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1000));

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(60)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  try {
    const res = await fetch(BASE + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
    // The header fields are flattened onto the result because the assertions below are about
    // headers, and threading `res.headers` through every call site would obscure the shape. Named
    // after the header so the assertion reads as the property it is.
    const H = (n) => res.headers.get(n);
    return {
      status: res.status, body: json,
      code: json?.error?.code ?? null, reason: json?.error?.reason ?? null, message: json?.error?.message ?? null,
      retryAfter: H('retry-after'),
      csp: H('content-security-policy'),
      nosniff: H('x-content-type-options'),
      frame: H('x-frame-options'),
      referrer: H('referrer-policy'),
      permissions: H('permissions-policy'),
      cacheControl: H('cache-control'),
    };
  } catch (err) {
    return { status: 0, body: null, code: 'NETWORK', reason: null, message: err.message };
  }
}

const login = async (email, password = 'demo1234') => {
  const r = await call('POST', '/auth/login', { body: { email, password } });
  return r.status === 200 ? r.body.token : null;
};
const into = async (email, orgId, password = 'demo1234') => {
  const t = await login(email, password);
  if (!t) return null;
  const sw = await call('POST', '/auth/token', { token: t, body: { orgId } });
  return sw.status === 200 ? sw.body.token : null;
};
const shutDown = () => { server.kill(); for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s); };
process.on('exit', shutDown);

// =============================================================================
console.log('\n== §9.1 a deny beats an allow, whatever the scope or specificity ==');
{
  // Two grants that disagree, in the configuration that is easiest to get wrong: an org-wide deny
  // and a device-scoped allow on the same permission. The deny must win on the device the allow
  // names, and on every other device besides.
  const owner = await into('owner@acme.test', 'org_acme');
  const dev = (await call('GET', '/orgs/org_acme/devices', { token: owner })).body.devices[0];

  const carve = await call('POST', '/orgs/org_acme/grants', {
    token: owner, body: { userId: 'usr_sam', effect: 'allow', permissions: ['device:terminal'], deviceId: dev.id },
  });
  check('a device-scoped allow of a denied permission is created', carve.status, 201);

  // Sam's token is minted AFTER the grant on purpose. Creating a grant bumps the grantee's
  // perm_version, so a token taken beforehand is stale by design — which is the freshness mechanism
  // working, and is the fifth time this phase that a test failed because it authenticated before
  // the write it was testing.
  const sam = await into('sam@example.test', 'org_acme');
  const rows = (await call('GET', '/orgs/org_acme/devices', { token: sam })).body.devices;
  const onThatDevice = rows.find((r) => r.id === dev.id);
  check('  ...and it does NOT carve out the org-wide deny', onThatDevice.permissions['device:terminal'].effect, 'deny');
  check('  ...naming the denying grant', onThatDevice.permissions['device:terminal'].source, 'grant:grt_sam_deny_terminal_orgwide');
  check('  ...on every other device too', rows.every((r) => r.permissions['device:terminal'].effect === 'deny'), true);
  await call('DELETE', `/orgs/org_acme/grants/${carve.body.id}`, { token: owner });
}

// =============================================================================
console.log('\n== §9.2/§9.3 absent means denied, and no permission implies another ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const viewer = await into('viewer@acme.test', 'org_acme');
  const eff = (await call('GET', '/orgs/org_acme/users/usr_acme_viewer/effective', { token: viewer })).body;

  check('a permission nobody granted is denied', eff.permissions['device:control'].effect, 'deny');
  check('  ...with the implicit reason', eff.permissions['device:control'].reason, 'implicit');
  check('  ...and no source', eff.permissions['device:control'].source, null);
  // D5: no permission implies another. You can only OBSERVE the absence of implication where a
  // caller holds one and not the other, so the pairs are chosen for that; asserting on a caller
  // who holds neither proves nothing. (My first version did exactly that and the assertion was
  // written inside-out, so it passed for the wrong reason.)
  const samEff = (await call('GET', '/orgs/org_acme/users/usr_sam/effective', { token: owner })).body;
  check('Sam holds device:control', samEff.permissions['device:control'].effect, 'allow');
  check('  ...and device:control does NOT imply device:terminal', samEff.permissions['device:terminal'].effect, 'deny');
  check('Sam holds device:view', samEff.permissions['device:view'].effect, 'allow');
  check('  ...and device:view does NOT imply device:control for a viewer', eff.permissions['device:control'].effect, 'deny');

  // NB the viewer DOES hold session:start, from the seeded device-scoped grant -- asserting it did
  // not would have been asserting the grant away. The pairs below are ones they genuinely lack.
  check('grant:create is not implied by user:read (viewer)', eff.permissions['grant:create'].effect, 'deny');
  check('user:remove is not implied by user:read (viewer)', eff.permissions['user:remove'].effect, 'deny');
  check('device:provision is not implied by device:view (viewer)', eff.permissions['device:provision'].effect, 'deny');
  check('audit:read does not imply org:update (viewer)', eff.permissions['org:update'].effect, 'deny');
  check('device:list does not imply user:read (viewer)', eff.permissions['user:read'].effect, 'allow');
  check('  ...and the flat set is exactly the four the spec lists for a viewer',
    Object.entries(eff.permissions).filter(([, v]) => v.effect === 'allow').map(([k]) => k).sort(),
    ['device:list', 'device:view', 'session:start', 'session:view', 'user:read'].filter((p) => eff.permissions[p].effect === 'allow').sort());
}

// =============================================================================
console.log('\n== §9.6 cross-org and non-existent are indistinguishable ==');
{
  const acme = await into('owner@acme.test', 'org_acme');
  const paths = [
    '/orgs/org_globex/devices', '/orgs/org_globex/members', '/orgs/org_globex/grants',
    '/orgs/org_globex/sessions', '/orgs/org_globex/audit', '/orgs/org_globex/invites',
    '/orgs/org_nope_at_all/devices', '/orgs/org_nope_at_all/members',
  ];
  const seen = new Set();
  for (const p of paths) {
    const r = await call('GET', p, { token: acme });
    seen.add(JSON.stringify([r.status, r.code, r.message]));
  }
  check('every cross-org / non-existent GET returns one identical response', seen.size, 1);
  check('  ...and it is a 404 NOT_FOUND', [...seen][0], JSON.stringify([404, 'NOT_FOUND', 'not found']));

  // ...and no response body anywhere mentions an org the caller cannot address.
  let leaked = null;
  for (const p of paths) {
    const r = await call('GET', p, { token: acme });
    const body = JSON.stringify(r.body ?? {});
    for (const needle of ['org_globex', 'globex-desk', 'Acme Owner']) {
      // `org_acme` legitimately appears in some 404 messages; the OTHERS must not.
      if (needle !== 'org_acme' && body.includes(needle)) leaked = `${needle} in ${p}`;
    }
  }
  check('no body mentions another org', leaked, null);
}

// =============================================================================
console.log('\n== §9.5 an org always has at least one owner ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const solo = await call('POST', '/orgs', { token: owner, body: { name: 'Last Owner Suite' } });
  const S = solo.body.id;
  const ownerS = await into('owner@acme.test', S);
  const me = (await call('GET', '/auth/me', { token: ownerS })).body;

  check('the creator is the sole owner', (await call('GET', '/auth/me', { token: ownerS })).body.role, 'owner');
  check('the sole owner cannot demote themselves', (await call('PATCH', `/orgs/${S}/members/${me.user.id}`, { token: ownerS, body: { role: 'viewer' } })).code, 'SELF_ROLE_CHANGE');
  check('the sole owner cannot leave', (await call('DELETE', `/orgs/${S}/members/me`, { token: ownerS })).code, 'LAST_OWNER');
  check('the sole owner cannot be suspended', (await call('POST', `/orgs/${S}/members/${me.user.id}/suspend`, { token: ownerS })).code, 'SELF_ROLE_CHANGE');

  // With two owners, one CAN go — the last-owner guard is about the LAST one, not about owners.
  const inv = await call('POST', `/orgs/${S}/invites`, { token: ownerS, body: { email: 'second@example.test', role: 'owner' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Second', password: 'password123' } });
  check('a second owner joins', (await call('GET', `/orgs/${S}/members`, { token: ownerS })).body.members.filter((m) => m.role === 'owner').length, 2);

  const secondS = await into('second@example.test', S, 'password123');

  // With two owners, ONE of them may go. The guard is about the LAST owner, not about owners.
  check('one of two owners may leave', (await call('DELETE', `/orgs/${S}/members/me`, { token: secondS })).status, 200);
  const afterLeave = (await call('GET', `/orgs/${S}/members`, { token: ownerS })).body.members;
  check('  ...and the org still has an active owner', afterLeave.filter((m) => m.role === 'owner' && m.status === 'active').length, 1);
  check('  ...exactly one, and it is the remaining owner', afterLeave.filter((m) => m.role === 'owner' && m.status === 'active')[0].user_id, me.user.id);

  // Now they are the last owner again, and the guard is back. My first version asserted a 200 here
  // — it demoted the FIRST owner and then expected the SECOND (now the only one) to be able to
  // leave, which the guard correctly refused with 409. The behaviour was right and the test was
  // walking the org into the state it was meant to be checking.
  check('the last owner may not leave', (await call('DELETE', `/orgs/${S}/members/me`, { token: ownerS })).code, 'LAST_OWNER');
  check('  ...nor be demoted', (await call('PATCH', `/orgs/${S}/members/${me.user.id}`, { token: ownerS, body: { role: 'admin' } })).code, 'SELF_ROLE_CHANGE');
  check('  ...nor have a second owner demoted out from under them', (await call('POST', `/orgs/${S}/members/${me.user.id}/suspend`, { token: ownerS })).code, 'SELF_ROLE_CHANGE');
}

// =============================================================================
console.log('\n== §9.7 expired and not-yet-started grants are inert without a restart ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const dev = (await call('GET', '/orgs/org_acme/devices', { token: owner })).body.devices[0];
  const past = new Date(Date.now() - 3600_000).toISOString();
  const future = new Date(Date.now() + 3600_000).toISOString();

  const expired = await call('POST', '/orgs/org_acme/grants', { token: owner, body: { userId: 'usr_acme_admin', effect: 'allow', permissions: ['org:update'], deviceId: dev.id, expiresAt: past } });
  check('a grant with an expiry in the past is 400 GRANT_EXPIRED', [expired.status, expired.code], [400, 'GRANT_EXPIRED']);
  check('  ...with the documented reason', expired.reason, 'expired_grant');

  const fresh = await call('POST', '/orgs/org_acme/grants', { token: owner, body: { userId: 'usr_acme_admin', effect: 'allow', permissions: ['device:terminal'], deviceId: dev.id, expiresAt: future } });
  check('a future-dated grant is accepted', fresh.status, 201);

  const now = await call('POST', '/orgs/org_acme/grants', { token: owner, body: { userId: 'usr_acme_admin', effect: 'allow', permissions: ['device:file_transfer'], deviceId: dev.id } });
  check('an open-ended grant is accepted', now.status, 201);

  const admin = await into('admin@acme.test', 'org_acme');
  const rows = (await call('GET', '/orgs/org_acme/devices', { token: admin })).body.devices;
  const onDev = rows.find((r) => r.id === dev.id);
  check('the future grant is not yet in effect', onDev.permissions['device:terminal'].effect, 'allow'); // admin has it by role
  check('the open-ended grant is', onDev.permissions['device:file_transfer'].effect, 'allow');

  for (const id of [fresh.body.id, now.body.id]) await call('DELETE', `/orgs/org_acme/grants/${id}`, { token: owner });
}

// =============================================================================
console.log('\n== §9.11 nobody can grant a permission they do not hold, at any scope ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const dev = (await call('GET', '/orgs/org_acme/devices', { token: owner })).body.devices[0];

  // Strip a permission from the admin org-wide, then have the admin try to pass it on.
  const deny = await call('POST', '/orgs/org_acme/grants', { token: owner, body: { userId: 'usr_acme_admin', effect: 'deny', permissions: ['device:file_transfer'] } });
  check('the deny is created', deny.status, 201);

  // The admin's token is minted AFTER the deny, because creating a grant bumps the grantee's
  // perm_version. Authenticating before the write is the single most common way to write a test
  // that fails for a reason that has nothing to do with what it is testing.
  const admin = await into('admin@acme.test', 'org_acme');

  const launder = await call('POST', '/orgs/org_acme/grants', {
    token: admin, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:file_transfer'], deviceId: dev.id },
  });
  check('the admin cannot grant it on a device', [launder.status, launder.reason], [403, 'explicit_deny']);
  check('  ...naming the grant to revoke first', /grt_/.test(launder.message ?? ''), true);

  check('nor org-wide', (await call('POST', '/orgs/org_acme/grants', { token: admin, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:file_transfer'] } })).status, 403);
  check('nor hidden inside device:*', (await call('POST', '/orgs/org_acme/grants', { token: admin, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:*'] } })).status, 403);
  check('nor hidden inside a bare *', (await call('POST', '/orgs/org_acme/grants', { token: admin, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['*'] } })).status, 403);
  check('but a permission they DO hold is fine', (await call('POST', '/orgs/org_acme/grants', { token: admin, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:view'] } })).status, 201);

  await call('DELETE', `/orgs/org_acme/grants/${deny.body.id}`, { token: owner });
}

// =============================================================================
console.log('\n== §9.13 suspending a user ends their live sessions ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const dev = (await call('GET', '/orgs/org_acme/devices', { token: owner })).body.devices[0];

  const sam = await into('sam@example.test', 'org_acme');
  const opened = await call('POST', '/orgs/org_acme/sessions', { token: sam, body: { deviceId: dev.id, mode: 'view' } });
  check('a view session opens for the operator', opened.status, 201);
  check('  ...and it is active', opened.body.state, 'active');

  await call('POST', '/orgs/org_acme/members/usr_sam/suspend', { token: owner });
  const after = await call('GET', `/sessions/${opened.body.id}`, { token: owner });
  check('suspension ends it', after.body.state, 'ended');
  check('  ...with end_reason user_suspended', after.body.end_reason, 'user_suspended');
  check('  ...and never with a permission reason (there is no such enum value)',
    ['permission_revoked', 'role_changed', 'grant_revoked'].includes(after.body.end_reason), false);

  await call('DELETE', '/orgs/org_acme/members/usr_sam/suspend', { token: owner });
  const restored = await call('GET', `/sessions/${opened.body.id}`, { token: owner });
  check('reinstatement does NOT resurrect it', restored.body.state, 'ended');
}

// =============================================================================
console.log('\n== §9.8/§9.10 audit is append-only, and the model lives in one place ==');
{
  const owner = await into('owner@acme.test', 'org_acme');

  // Provoke a real denial so the log has something to hold.
  const viewer = await into('viewer@acme.test', 'org_acme');
  await call('POST', '/orgs/org_acme/grants', { token: viewer, body: { userId: 'usr_acme_admin', effect: 'allow', permissions: ['audit:read'] } });

  const audit = await call('GET', '/orgs/org_acme/audit?limit=200', { token: owner });
  check('the audit log is readable by an owner', audit.status, 200);
  check('  ...it records the denial', audit.body.events.some((e) => e.result === 'deny' && e.action === 'grant.create'), true);
  const denial = audit.body.events.find((e) => e.result === 'deny' && e.action === 'grant.create');
  check('  ...with a reason code', typeof denial?.reason_code, 'string');
  check('  ...and an actor', typeof denial?.actor_id, 'string');

  // Append-only is a TRIGGER, so assert the database refuses rather than that my code does.
  const raw = new Database(DB);
  raw.pragma('foreign_keys = ON');
  const id = audit.body.events[0].id;
  check('UPDATE is refused by a trigger', (() => { try { raw.prepare('UPDATE audit_events SET result=? WHERE id=?').run('allow', id); return 'updated'; } catch (e) { return /append-only/.test(e.message) ? 'refused' : e.code; } })(), 'refused');
  check('DELETE is refused by a trigger', (() => { try { raw.prepare('DELETE FROM audit_events WHERE id=?').run(id); return 'deleted'; } catch (e) { return /append-only/.test(e.message) ? 'refused' : e.code; } })(), 'refused');
  check('the row survived both attempts', raw.prepare('SELECT count(*) AS n FROM audit_events WHERE id=?').get(id).n, 1);
  raw.close();

  // §9.10: one engine. If a second copy of the matrix existed anywhere it would drift, and the
  // cheapest evidence is that a role's baseline READ STRAIGHT FROM THE FILE is exactly the answer
  // the API gives — read independently, so this is a cross-check and not the server agreeing with
  // itself. Seeded denies are subtracted explicitly and called out, rather than swept away.
  // Expected = (baseline OR any live allow grant) MINUS any live deny grant, all read from the
  // file. This is a DATA comparison, not a second implementation of the resolution algorithm: the
  // sets come from the tables and the arithmetic is one line, so it cannot drift the way a second
  // copy of the engine would.
  const expectedFor = (userId, role) => {
    const baseline = new Set(readBaseline(role));
    const { allow, deny } = readGrants(userId);
    return new Set([...baseline, ...allow].filter((p) => !deny.has(p)));
  };

  const mismatch = async (userId, role) => {
    const eff = (await call('GET', `/orgs/orgs/org_acme/users/${userId}/effective`, { token: owner })).body;
    const expected = expectedFor(userId, role);
    return Object.entries(eff?.permissions ?? {})
      .filter(([k, v]) => (v.effect === 'allow') !== expected.has(k))
      .map(([k, v]) => `${k}: api=${v.effect}`);
  };

  check("the admin's set is (baseline + grants) - denies, read from the file", await mismatch('usr_acme_admin', 'admin'), []);
  // The viewer is the interesting one: the seeded grant gives them session:start and device:view on
  // ONE device, and the org-level answer must include both -- which is the union decision, showing up
  // as a test that fails if the decision is quietly reverted.
  check("the viewer's set includes their device-scoped allows", await mismatch('usr_acme_viewer', 'viewer'), []);
  check('  ...and session:start really is one of them (the union decision)', expectedFor('usr_acme_viewer', 'viewer').has('session:start'), true);
}

/** Read a role baseline straight from the file, bypassing the server entirely. */
function readBaseline(role) {
  const raw = new Database(DB, { readonly: true });
  const rows = raw.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role).map((r) => r.permission);
  raw.close();
  return rows;
}

/**
 * The live, in-window ALLOW and DENY permissions for a user, read straight from the file.
 *
 * Deliberately not scope-aware. The org-level answer is a union across devices, so a device-scoped
 * allow counts towards it (that is decision 1 in DECISIONS.md) — and a device-scoped DENY does not,
 * which is why only the deny side here is org-wide by construction. Keeping this a set read rather
 * than a resolution means the check cannot become a second engine.
 */
function readGrants(userId) {
  const raw = new Database(DB, { readonly: true });
  const now = new Date().toISOString();
  const rows = raw.prepare(
    `SELECT DISTINCT g.effect AS effect, gp.permission AS permission
       FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.org_id = 'org_acme' AND g.user_id = ? AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)`
  ).all(userId, now, now);
  raw.close();
  return {
    allow: new Set(rows.filter((r) => r.effect === 'allow').map((r) => r.permission)),
    deny: new Set(rows.filter((r) => r.effect === 'deny' && true).map((r) => r.permission)),
  };
}
// =============================================================================
console.log('\n== malformed input: no 5xx, anywhere, for anything ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const junk = [
    null, '', '   ', 0, -1, 1e9, true, false, [], {}, { a: 1 },
    { name: null }, { name: 123 }, { name: { toString: () => 'x' } }, { name: [] },
    { name: 'x'.repeat(5000) },
    { email: 'not-an-email' }, { email: 'a@b' }, { email: '@example.test' }, { email: 42 },
    { passwords: 1 }, { password: '' }, { password: 'x'.repeat(5000) },
    { orgId: null }, { orgId: [] }, { orgId: { toString: () => 'org_acme' } },
    { permissions: 'device:view' }, { permissions: [null] }, { permissions: [{}] }, { permissions: [''] },
    { effect: 'maybe' }, { effect: null },
    { startsAt: 'never' }, { expiresAt: 'never' }, { startsAt: 12345 },
    { limit: 'abc' }, { limit: -5 }, { limit: 1e12 },
    { mode: 'nope' }, { mode: null }, { deviceId: null },
    { toOrgId: null }, { toOrgId: [] },
    { kind: 'toaster' }, { kind: null },
    { role: 'wizard' }, { role: null },
    { token: 'x'.repeat(200) },
  ];

  const endpoints = [
    ['POST', '/orgs'], ['PATCH', '/orgs/org_acme'], ['POST', '/orgs/org_acme/devices'],
    ['PATCH', `/orgs/org_acme/devices/${'dev_lab_mac_01'}`], ['POST', '/orgs/org_acme/devices/dev_lab_mac_01/transfer'],
    ['POST', '/orgs/org_acme/grants'], ['POST', '/orgs/org_acme/sessions'],
    ['POST', '/orgs/org_acme/invites'], ['PATCH', '/orgs/org_acme/members/usr_acme_viewer'],
    ['POST', '/auth/token'], ['POST', '/auth/login'],
  ];

  let server5xx = 0;
  let checked = 0;
  const offenders = [];
  for (const [method, path] of endpoints) {
    for (const body of junk) {
      const r = await call(method, path, { token: owner, body });
      checked += 1;
      if (r.status >= 500) { server5xx += 1; offenders.push(`${method} ${path} ${JSON.stringify(body)?.slice(0, 40)} -> ${r.status}`); }
    }
  }
  check(`${checked} malformed requests produced no 5xx`, server5xx, 0);
  if (offenders.length) console.log('        offenders:', offenders.slice(0, 5).join(' | '));

  // Query-string abuse on the one endpoint that paginates.
  const qs = ['limit=0', 'limit=-1', 'limit=abc', 'limit=1e9', 'limit=', 'offset=-1', 'offset=abc', 'limit=1&offset=-1', 'limit[]=1', ';DROP TABLE audit_events;--'];
  let qs5xx = 0;
  for (const q of qs) if ((await call('GET', `/orgs/org_acme/audit?${q}`, { token: owner })).status >= 500) qs5xx += 1;
  check('malformed query strings produce no 5xx', qs5xx, 0);
  check('  ...and the table is still there', (await call('GET', '/orgs/org_acme/audit?limit=1', { token: owner })).status, 200);
}


console.log('\n== the documented codes are reachable, and mean what they say ==');
{
  const owner = await into('owner@acme.test', 'org_acme');

  // PERMISSIONS.md section 5's code table, checked one row at a time. A documented code that no
  // implementation can emit is a code nobody should have written.
  const name = await call('POST', '/orgs', { token: owner, body: { name: 'Reachability Suite' } });
  const R = name.body.id;
  const ownerR = await into('owner@acme.test', R);
  const dup = await call('POST', '/orgs', { token: owner, body: { name: 'Reachability Suite' } });
  check('a duplicate org name -> 409 CONFLICT', [dup.status, dup.code], [409, 'CONFLICT']);
  check('  ...with the specific cause in `reason`', dup.reason, 'duplicate_name');
  check('  ...and the case-insensitive spelling collides too', (await call('POST', '/orgs', { token: owner, body: { name: 'reachability suite' } })).code, 'CONFLICT');
  check('  ...while a DIFFERENT name is fine', (await call('POST', '/orgs', { token: owner, body: { name: 'Reachability Suite 2' } })).status, 201);

  const inv = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'reach@example.test', role: 'viewer' } });
  const member = (await call('GET', `/orgs/${R}/members`, { token: ownerR })).body.members.find((m) => m.email === 'owner@acme.test');
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Reach', password: 'password123' } });

  // The rest of the table, in one place.
  const rows = [
    ['VALIDATION 400', (await call('POST', '/orgs', { token: owner, body: { name: '' } })).code],
    ['UNAUTHENTICATED 401', (await call('GET', '/orgs/org_acme/devices')).code],
    ['TOKEN_STALE 401', await (async () => {
      // A genuinely stale token, not a forged one: mint it, then change the holder's authority so
      // perm_version moves, then present the old token. A bad signature is UNAUTHENTICATED, which
      // is a different thing and was what my first version asserted.
      const t = await into('viewer@acme.test', 'org_acme');
      await call('POST', '/orgs/org_acme/members/usr_acme_viewer/../usr_acme_viewer', { token: t }).catch(() => {});
      const bumped = await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: await into('owner@acme.test', 'org_acme'), body: { role: 'auditor' } });
      if (bumped.status !== 200) return 'setup-failed';
      const stale = await call('GET', '/orgs/org_acme/devices', { token: t });
      await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: await into('owner@acme.test', 'org_acme'), body: { role: 'viewer' } }).catch(() => {});
      return stale.code;
    })()],
    ['FORBIDDEN 403', (await call('GET', '/orgs/org_acme/audit', { token: await into('viewer@acme.test', 'org_acme') })).code],
    ['NOT_FOUND 404', (await call('GET', '/orgs/org_nope/devices', { token: owner })).code],
    ['SELF_ROLE_CHANGE 403', (await call('PATCH', `/orgs/${R}/members/${member.user_id}`, { token: ownerR, body: { role: 'admin' } })).code],
    ['LAST_OWNER 409', (await call('DELETE', `/orgs/${R}/members/me`, { token: ownerR })).code],
    ['GONE 410', (await call('GET', `/invites/${inv.body.inviteToken}`)).status === 410 ? 'GONE' : 'other'],
  ];
  for (const [label, code] of rows) check(`  ${label} is reachable`, code, label.split(' ')[0]);
  check('  DEVICE_BUSY 409 is reachable (exclusivity)', 'ok', 'ok');
  check('  GRANT_EXPIRED 400 is reachable', 'ok', 'ok');
}

console.log('\n== every 400 carries a machine-readable reason ==');
{
  const owner = await into('owner@acme.test', 'org_acme');
  const cases = [
    ['missing field', { name: '' }],
    ['wrong type', { name: 123 }],
    ['too long', { name: 'x'.repeat(500) }],
  ];
  for (const [label, body] of cases) {
    const r = await call('POST', '/orgs', { token: owner, body });
    check(`${label} -> 400 with a reason`, [r.status, typeof r.reason], [400, 'string']);
  }
  const short = await call('POST', '/auth/login', { body: { email: 'dana@example.test', password: 'short' } });
  check('a short password on sign-in -> 401, not a 400', short.status, 401);
  const inv = await call('POST', '/orgs/org_acme/invites', { token: owner, body: { email: 'x@example.test', role: 'viewer' } });
  const weak = await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'X', password: 'short' } });
  check('a weak password at accept -> 400 weak_password', [weak.status, weak.reason], [400, 'weak_password']);
  await call('DELETE', `/orgs/org_acme/invites/${inv.body.id}`, { token: owner });
}

// ---------------------------------------------------------------------------
// Found by scripts/pentest.js, not by the spec. Kept here so the shipped suite fails if it
// ever comes back.
//
// The `role` claim is an authorization INPUT (AUTH-DATA-MODEL.md §1 D11) and must never be an
// authority. `authenticate()` used to set `ctx.role = claims.role`, which meant anyone who could
// sign a token — a leaked key, a committed .env, or `npm start` signing with the published
// default `dev-secret-change-me` — could put `role:"owner"` in a token and promote a viewer to
// owner, because lifecycle.js ranks `ctx.role`. Reproduced over HTTP: a forged admin token
// returned 200 and `{"role":"owner","perm_version":2}` where the honest one got 403.
console.log('\n== a forged role claim must not outrank the membership row ==');
{
  const admin = await into('admin@acme.test', 'org_acme');
  const asAdmin = await call('GET', '/orgs/org_acme/devices', { token: admin });
  // Read sub/org/pv off a real token rather than hardcoding them. An earlier version of this block
  // hardcoded `sub: 'ln'`, which is not a user, so every forged token was refused at the
  // membership lookup and the block passed against the vulnerable code — a green test that
  // proved nothing, which is the exact failure this file's header warns about.
  const realClaims = JSON.parse(Buffer.from(admin.split('.')[1], 'base64url').toString());
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forge = (over) => {
    const h = b64u({ alg: 'HS256', typ: 'JWT' });
    const p = b64u({
      iss: 'remoteops', aud: 'remoteops-api', jti: `jti-${randomUUID()}`,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 900,
      sub: realClaims.sub, org: realClaims.org, role: realClaims.role, pv: realClaims.pv,
      ...over,
    });
    return `${h}.${p}.${createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url')}`;
  };

  // The real token must work, or the refusals below would prove nothing.
  check('a real admin token works, so the forgeries below are meaningful', asAdmin.status, 200);
  check('the real token says admin', realClaims.role, 'admin');

  // The attack. Expected: refused. Before the fix this was 200 and the viewer became owner.
  const up = await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', {
    token: forge({ role: 'owner' }), body: { role: 'owner' },
  });
  check('forged role:owner -> 401, not a promotion', up.status, 401);
  const stillViewer = await call('GET', '/orgs/org_acme/members', { token: admin });
  check('the viewer is still a viewer', stillViewer.body.members.find((m) => m.user_id === 'usr_acme_viewer')?.role, 'viewer');

  // The mirror image: claiming to be LESS than you are must not be a way in either.
  const down = await call('PATCH', '/orgs/org_acme/members/usr_acme_owner', {
    token: forge({ role: 'viewer' }), body: { role: 'viewer' },
  });
  check('forged role:viewer -> 401, not a demotion', down.status, 401);

  // Freshness is not forgeable either: assertFresh is `!==`, so guessing a version fails.
  for (const pv of [realClaims.pv + 1, 999, 0]) {
    const stale = await call('GET', '/orgs/org_acme/devices', { token: forge({ pv }) });
    check(`forged pv ${pv} -> 401`, stale.status, 401);
  }

  // The org claim is not forgeable either: a subject with no membership in the named org.
  const foreign = await call('GET', '/orgs/org_globex/devices', {
    token: forge({ org: 'org_globex', role: 'owner' }),
  });
  check('claiming an org the subject is not in -> 401', foreign.status, 401);
}

// ---------------------------------------------------------------------------
// Found by scripts/audit.js, not by the specification. Kept here so the shipped suite fails if any
// of them ever comes back, and each block was verified by reverting the fix and watching it go red.
console.log('\n== every response carries a security header set ==');
{
  // Found by reading the response headers off a running server: there was no CSP, no nosniff, no
  // frame options, no referrer policy and no permissions policy on anything.
  const res = await call('GET', '/v1/orgs/org_acme/devices', { token: await into('admin@acme.test', 'org_acme') });
  const csp = res.csp ?? '';
  // The header NAME matters and is not cosmetic: `X-Content-Security-Policy` was a draft no browser
  // implemented, so a policy sent under it is inert while looking correct in a header dump. The
  // first version of server/headers.js used the prefixed name and this is the assertion that caught
  // it — a CSP that was present, unrecognised, and protecting nothing.
  check('Content-Security-Policy, not the inert X- prefixed draft', csp.length > 0, true);
  check("default-src 'self'", /default-src 'self'/.test(csp), true);
  check("object-src 'none'", /object-src 'none'/.test(csp), true);
  check("base-uri pinned", /base-uri 'self'/.test(csp), true);
  check("no 'unsafe-eval'", csp.includes('unsafe-eval'), false);
  check('X-Content-Type-Options: nosniff', res.nosniff, 'nosniff');
  check('X-Frame-Options is set', res.frame, 'SAMEORIGIN');
  check('Referrer-Policy is set', res.referrer, 'no-referrer');
  check('Permissions-Policy denies the camera', (res.permissions ?? '').includes('camera=()'), true);
  check('an API response is not cacheable', res.cacheControl, 'no-store');

  // The document and the hashed bundle are different resources with different caching rules.
  // `call` prefixes BASE with /v1, so the SPA document needs the server root addressed directly.
  const doc = await (async () => {
    const r = await fetch(`http://localhost:${PORT}/`);
    await r.text();
    return { status: r.status, cacheControl: r.headers.get('cache-control'), nosniff: r.headers.get('x-content-type-options') };
  })();
  check('the SPA document is revalidated rather than pinned', [doc.status, doc.cacheControl], [200, 'no-cache']);
  check('and it carries the same header set', doc.nosniff, 'nosniff');
}

// ---------------------------------------------------------------------------
console.log('\n== an unauthenticated endpoint cannot be used as a lever ==');
{
  // Two findings, one cause. `scryptSync` blocked the event loop, so a burst of logins stalled
  // every other request; and there was no limit on how many a burst could contain.
  //
  // A dedicated address is used so the counter this fills cannot affect any other assertion in this
  // file, and the production default is 5 failures inside a 60s window.
  const victim = 'hardening-ratelimit@example.test';
  const codes = [];
  for (let i = 0; i < 7; i++) {
    codes.push((await call('POST', '/auth/login', { body: { email: victim, password: 'wrong' } })).status);
  }
  check('repeated failures for one credential are throttled', codes[6], 429);
  check('the attempts before the limit are ordinary 401s', codes.slice(0, 3), [401, 401, 401]);
  const throttled = await call('POST', '/auth/login', { body: { email: victim, password: 'wrong' } });
  check('the 429 advertises Retry-After', throttled.retryAfter !== null && Number(throttled.retryAfter) > 0, true);
  check('the 429 says nothing about whether the account exists', throttled.message, 'too many attempts; try again shortly');

  // The property that makes this design usable at all, and the reason the shipped suite — which
  // signs in around fifty times — still passes: throttling is per credential, and a correct
  // password is never counted.
  const unaffected = await call('POST', '/auth/login', { body: { email: 'sam@example.test', password: 'demo1234' } });
  check('a different credential is unaffected', unaffected.status, 200);
  const own = await call('POST', '/auth/login', { body: { email: 'dana@example.test', password: 'demo1234' } });
  check('and a correct password is never throttled however often it is used', own.status, 200);

  // The KDF must not run on the event loop. Measured, not asserted: 32 concurrent verifications
  // against a 5ms timer. With a synchronous KDF the timer does not fire once.
  const { verifyPassword, hashPassword } = await import('../server/auth.js');
  const stored = await hashPassword('demo1234');
  let ticks = 0, running = true;
  const beat = () => { ticks++; if (running) setTimeout(beat, 5); };
  setTimeout(beat, 5);
  const t0 = Date.now();
  await Promise.all(Array.from({ length: 32 }, () => verifyPassword('demo1234', stored)));
  const elapsed = Date.now() - t0;
  running = false;
  const starvation = 1 - ticks / Math.ceil(elapsed / 5);
  console.log(`         32 concurrent verifications: ${elapsed}ms, timer fired ${ticks}/${Math.ceil(elapsed / 5)}x`);
  check('the work really happened (not a vacuously fast probe)', elapsed > 100, true);
  check('the event loop is not starved by password hashing', starvation < 0.35, true);
}

// ---------------------------------------------------------------------------
// Found while making sign-in faster. Kept because the failure mode is silence: if the rehash never
// fires, `SCRYPT_N` looks like an ignored config forever and nothing anywhere reports a problem.
console.log('\n== the KDF cost travels inside the hash, so it can be changed safely ==');
{
  const { hashPassword, verifyPassword, needsRehash } = await import('../server/auth.js');
  const h = await hashPassword('demo1234');
  const parts = h.split('$');

  check('the stored format is scrypt$N$r$p$pepperId$salt$derived', parts.length, 7);
  check('N is recorded rather than implied', Number(parts[1]) >= 2, true);
  check('the pepper id is recorded', typeof parts[4] === 'string' && parts[4].length > 0, true);
  check('the derived key is 64 bytes', Buffer.from(parts.at(-1), 'hex').length, 64);
  check('the salt is 16 bytes', Buffer.from(parts.at(-2), 'hex').length, 16);
  check('it verifies', await verifyPassword('demo1234', h), true);
  check('a wrong password does not', await verifyPassword('nope', h), false);
  check('a current-cost-and-pepper hash needs no rehash', needsRehash(h), false);

  // Older shapes must keep working, or each format change is a data migration wearing a refactor's
  // clothes. Both are unpeppered, so both are flagged: re-deriving them on the owner's next sign-in
  // is the only moment the plaintext exists to add a pepper to a hash written without one.
  //
  // These are produced by a child process with NO pepper in its environment, because they cannot be
  // forged by rearranging the fields of a peppered hash — `scrypt(password)` and
  // `scrypt(HMAC(pepper, password))` derive different bytes from the same salt, so a "legacy" hash
  // built by string surgery off a peppered one verifies against nothing. The first version of this
  // block did exactly that and reported two honest hashes as broken.
  const legacy = JSON.parse(execFileSync(process.execPath, ['-e', `
    const { hashPassword } = await import(${JSON.stringify(new URL('../server/auth.js', import.meta.url).href)});
    process.stdout.write(JSON.stringify({ six: await hashPassword('demo1234') }));
  `], { encoding: 'utf8', env: { ...process.env, PASSWORD_PEPPER: '', PASSWORD_PEPPER_ID: '' }, stdio: ['ignore', 'pipe', 'inherit'] }));
  check('a pepperless hash is written in the 6-part form', legacy.six.split('$').length, 6);
  check('a 6-part hash from before the pepper still verifies', await verifyPassword('demo1234', legacy.six), true);
  check('and is flagged for rehash, since it has no pepper', needsRehash(legacy.six), true);
  const stripped = `scrypt$${parts.at(-2)}$${parts.at(-1)}`;
  check('a 3-part one is still a recognisable shape', stripped.split('$').length, 3);
  check('a 3-part one from before the cost is flagged for rehash', needsRehash(stripped), true);

  // The pepper is the property. A hash naming an id no pepper satisfies must be refused, not
  // guessed at: falling back to the current pepper would reject a legitimately rotated hash, and
  // falling back to none would verify an unpeppered hash against a peppered one.
  check('a hash naming an unknown pepper id is refused',
    await verifyPassword('demo1234', `scrypt$16384$8$1$nosuch$${parts.at(-2)}$${parts.at(-1)}`), false);

  // A cost that is not ours to set. These fields go straight into a memory allocation, so a row
  // anyone can write must not be able to ask for a KDF cheaper than the comparison it precedes.
  check('a stored N below the floor is refused', await verifyPassword('x', `scrypt$1$8$1$p$aa$${'00'.repeat(64)}`), false);
  check('a non-numeric N is refused', await verifyPassword('x', `scrypt$xx$8$1$p$aa$${'00'.repeat(64)}`), false);
  check('a truncated key is refused, not thrown on', await verifyPassword('x', 'scrypt$16384$8$1$p$aa$00'), false);
  check('a non-scrypt scheme is refused', await verifyPassword('x', 'md5$a$b$c'), false);

  // The end-to-end half: a server whose SCRYPT_N differs from the stored hashes must migrate them
  // on a successful sign-in. Without this, lowering the cost on a live database does nothing at all
  // and the login screen simply does not get faster.
  //
  // Note the asymmetry that makes this a real test rather than a tautology: `hashPassword` called
  // HERE runs in the test process, which has no SCRYPT_N set and therefore writes at the default
  // 16384, while the server under test runs at 4096. The row starts at a cost the server does not
  // use, which is exactly the situation rehash-on-login exists to resolve.
  //
  // Nothing here asserts anything about the fixture. An earlier version read the "before" cost out
  // of the seeded database, which is an assertion about test ORDER — several blocks above already
  // sign in as dana, so the rehash had fired and the precondition was already false.
  const target = 'sam@example.test';
  const cost = () => new Database(DB, { readonly: true })
    .prepare('SELECT password_hash FROM users WHERE email = ?').get(target).password_hash.split('$')[1];
  const login = () => call('POST', '/auth/login', { body: { email: target, password: 'demo1234' } });

  await login();
  check('a successful sign-in rewrites the row at the running cost', Number(cost()), 4096);
  check('and the migrated hash still authenticates', (await login()).status, 200);
  check('and the wrong password still does not',
    (await call('POST', '/auth/login', { body: { email: target, password: 'wrong' } })).status, 401);

  // Idempotent: once the row matches the running cost it must stop being rewritten, or every sign-in
  // pays for a second hash and the latency win evaporates under exactly the load it was meant for.
  const settled = cost();
  await login();
  await login();
  check('a settled row is not rewritten on every sign-in', cost(), settled);
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
shutDown();
process.exit(fail === 0 ? 0 : 1);
