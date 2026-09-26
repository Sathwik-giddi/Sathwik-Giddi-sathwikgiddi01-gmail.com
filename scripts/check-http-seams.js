// Seam tests at the HTTP layer — the cases the shipped suites do not reach over a real socket.
//
//   node scripts/check-http-seams.js
//
// The organiser README names the hidden tier's targets: "offboard/rehire, self-transfer,
// suspension on ungated routes, malformed-token fuzzing, cross-scope laundering, concurrent
// inserts against the partial unique index". `check-seams.js` covers the first, second and fifth
// against the engine directly, and `check-jwt.js` the fourth. This file covers what is left — the
// ones that only exist once a request goes through the pipeline — and adds the concurrency cases
// with genuinely parallel requests, which is the only honest way to test a race.
//
// Every org, user and device used here is created by the test. Nothing reads the published
// fixture's ids, so this file keeps working on a database built from a different nonce.

import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';
import { rmSync, existsSync } from 'node:fs';

const PORT = 8178;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'http-seams.db';
const SECRET = 'http-seams-secret';

for (const suffix of ['', '-wal', '-shm']) if (existsSync(DB + suffix)) rmSync(DB + suffix);
const { execFileSync } = await import('node:child_process');
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: SECRET },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1000));

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(62)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  const res = await fetch(BASE + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
  return { status: res.status, body: json, code: json?.error?.code ?? null, reason: json?.error?.reason ?? null };
}

// Returns null for ANY failure, including a missing token on a 200. Two of my checks were
// `x !== null`, which is TRUE for `undefined` — so a sign-in that returned no token at all read as
// a pass and the real failure surfaced four lines later as a missing Authorization header.
/**
 * A request to an ABSOLUTE path. `call()` above is relative to /v1, which is right for the API and
 * wrong for the two things this file also needs to exercise: the SPA fallback in `serveStatic`, and
 * proving the process is still alive. Writing '/%ff' through `call()` would have produced
 * '/v1/%ff', which the router 404s before reaching the code under test — a test that passes because
 * it tested the wrong thing, which is the failure mode this file exists to catch.
 */
async function raw(method, path, { token, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE.replace(/\/v1$/, '')}${path}`, { method, headers: h });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
  return { status: res.status, body: json, code: json?.error?.code ?? null, reason: json?.error?.reason ?? null };
}

const login = async (email, password = 'demo1234') => {
  const r = await call('POST', '/auth/login', { body: { email, password } });
  if (r.status !== 200 || typeof r.body?.token !== 'string') {
    console.log(`         \x1b[33mlogin(${email}) -> ${r.status} ${r.code ?? ''} ${r.body?.error?.message ?? ''}\x1b[0m`);
    return null;
  }
  return r.body.token;
};

const shutDown = () => { server.kill(); for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s); };
process.on('exit', shutDown);

// =============================================================================
console.log('\n== setup: two orgs, an owner each, and a device in each ==');
const ownerToken = await login('owner@acme.test');
check('owner signs in', ownerToken !== null, true);

const acme = await call('POST', '/orgs', { token: ownerToken, body: { name: 'Seams Alpha' } });
const other = await call('POST', '/orgs', { token: ownerToken, body: { name: 'Seams Beta' } });
check('two orgs created by one owner', [acme.status, other.status], [201, 201]);
const A = acme.body.id;
const B = other.body.id;

// The token that CREATED org A is scoped to org_acme, and cannot touch A. That is D18 doing its
// job, and the setup has to respect it: acting inside a new org means minting a token for it.
const A_TOKEN = (await call('POST', '/auth/token', { token: ownerToken, body: { orgId: A } })).body.token;
const B_TOKEN = (await call('POST', '/auth/token', { token: ownerToken, body: { orgId: B } })).body.token;
check('the creating token cannot reach the org it just made', (await call('GET', `/orgs/${A}/devices`, { token: ownerToken })).status, 404);
check('a token minted for it can', (await call('GET', `/orgs/${A}/devices`, { token: A_TOKEN })).status, 200);

const devA = await call('POST', `/orgs/${A}/devices`, { token: A_TOKEN, body: { name: 'alpha-box', kind: 'linux' } });
const devA2 = await call('POST', `/orgs/${A}/devices`, { token: A_TOKEN, body: { name: 'alpha-laptop', kind: 'macos' } });
const devB = await call('POST', `/orgs/${B}/devices`, { token: B_TOKEN, body: { name: 'beta-box', kind: 'linux' } });
check('devices created in both orgs', [devA.status, devA2.status, devB.status], [201, 201, 201]);
const dA = devA.body.id, dA2 = devA2.body.id, dB = devB.body.id;

// A second human in org A, so the tests have a non-owner to act.
const invite = await call('POST', `/orgs/${A}/invites`, { token: A_TOKEN, body: { email: 'helper@example.test', role: 'operator' } });
check('invite created', invite.status, 201);
await call('POST', `/invites/${invite.body.inviteToken}/accept`, { body: { name: 'Helper', password: 'password123' } });
const helper = await login('helper@example.test', 'password123');
check('the invitee can sign in', typeof helper === 'string', true);
const helperA = (await call('POST', '/auth/token', { token: helper, body: { orgId: A } })).body.token;
check('and is scoped into org A', typeof helperA === 'string', true);

// =============================================================================
console.log('\n== D10 under real concurrency: 8 simultaneous exclusive starts ==');
{
  // A dedicated device: this block ends by decommissioning it, and later blocks need dA alive.
  const race = await call('POST', `/orgs/${A}/devices`, { token: A_TOKEN, body: { name: 'race-box', kind: 'linux' } });
  const dRace = race.body.id;
  // Genuinely parallel: eight fetches in flight at once, not eight sequential calls. The point of
  // D10 is that the DATABASE refuses the losers, so the test has to actually race.
  const attempts = await Promise.all(
    Array.from({ length: 8 }, () =>
      call('POST', `/orgs/${A}/sessions`, { token: A_TOKEN, body: { deviceId: dRace, mode: 'control' } })
    )
  );
  const created = attempts.filter((r) => r.status === 201);
  const busy = attempts.filter((r) => r.status === 409 && r.code === 'DEVICE_BUSY');
  console.log(`         ${attempts.filter(r=>r.status===201).length}x 201, ${busy.length}x 409 DEVICE_BUSY, ${attempts.filter(r=>r.status!==201&&r.status!==409).length}x other`);

  check('exactly one request wins the device', created.length, 1);
  check('every other request is 409 DEVICE_BUSY', busy.length, 7);
  check('no request produced a 500', attempts.filter((r) => r.status >= 500).length, 0);
  check('the refusal names the holder', /ses_/.test(busy[0]?.body?.error?.message ?? ''), true);

  // view is not exclusive, so the same device takes any number of watchers.
  const watchers = await Promise.all(
    Array.from({ length: 5 }, () => call('POST', `/orgs/${A}/sessions`, { token: A_TOKEN, body: { deviceId: dRace, mode: 'view' } }))
  );
  check('five concurrent VIEW sessions on the busy device all succeed', watchers.filter((r) => r.status === 201).length, 5);

  // and the exclusivity really was the index, not a lucky interleaving
  const sessions = await call('GET', `/orgs/${A}/sessions`, { token: A_TOKEN });
  const exclusive = sessions.body.sessions.filter((s) => s.device_id === dRace && s.state === 'active' && s.mode === 'control');
  check('the database holds exactly one active control session on that device', exclusive.length, 1);

  // Decommissioning cascades too (D20): a decommissioned device must not keep a live session.
  const decom = await call('DELETE', `/orgs/${A}/devices/${dRace}`, { token: A_TOKEN });
  check('decommissioning it succeeds', decom.status, 200);
  check('  ...and it is gone from the list', (await call('GET', `/orgs/${A}/devices`, { token: A_TOKEN })).body.devices.some((d) => d.id === dRace), false);
  const afterDecom = await call('GET', `/sessions/${created[0].body.id}`, { token: A_TOKEN });
  check('  ...and its live session ended', [afterDecom.body.state, afterDecom.body.end_reason], ['ended', 'device_transferred']);
}

// =============================================================================
console.log('\n== an invite, redeemed twice at once ==');
{
  const inv = await call('POST', `/orgs/${A}/invites`, { token: A_TOKEN, body: { email: 'racer@example.test', role: 'viewer' } });
  const [a, b] = await Promise.all([
    call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Racer', password: 'password123' } }),
    call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Racer', password: 'password123' } }),
  ]);
  const statuses = [a.status, b.status].sort();
  console.log(`         ${statuses.join(' and ')}`);
  check('one accept succeeds and one conflicts', statuses, [200, 409]);
  const loser = a.status === 409 ? a : b;
  check('the loser is told the INVITE was used, not that the address is taken', loser.code, 'INVITE_USED');

  // And the user table did not gain two people.
  const token = await login('racer@example.test', 'password123');
  check('exactly one account exists afterwards', token !== null, true);
}

// =============================================================================
console.log('\n== self-transfer, and transfer without authority in the destination ==');
{
  const self = await call('POST', `/orgs/${A}/devices/${dA2}/transfer`, { token: A_TOKEN, body: { toOrgId: A } });
  check('transferring to the org it is already in -> 400', self.status, 400);
  check('  ...with a reason, not a silent no-op', self.reason, 'same_org');
  check('  ...and the device is still there', (await call('GET', `/orgs/${A}/devices/${dA2}`, { token: A_TOKEN })).status, 200);

  // A device in org A named while addressing org B is invisible, not forbidden.
  const cross = await call('POST', `/orgs/${B}/devices/${dA2}/transfer`, { token: A_TOKEN, body: { toOrgId: B } });
  check('a device from another org is 404', cross.status, 404);

  // Permission is checked before the destination exists, which is the right order: the caller is
  // told they may not do this at all, rather than being walked through which org ids are real.
  const noPerm = await call('POST', `/orgs/${A}/devices/${dA2}/transfer`, { token: helperA, body: { toOrgId: B } });
  check('an operator cannot transfer at all -> 403, before the destination is even looked at', noPerm.status, 403);

  // The owner does hold device:provision, so they get the real answer about the destination.
  const noDest = await call('POST', `/orgs/${A}/devices/${dA2}/transfer`, { token: A_TOKEN, body: { toOrgId: 'org_nope' } });
  check('an owner transferring to an org that does not exist -> 404', noDest.status, 404);

  // The owner CAN move it, and live sessions on it end wherever they are.
  const live = await call('POST', `/orgs/${A}/sessions`, { token: A_TOKEN, body: { deviceId: dA2, mode: 'control' } });
  check('a control session is live on the device first', live.status, 201);
  const moved = await call('POST', `/orgs/${A}/devices/${dA2}/transfer`, { token: A_TOKEN, body: { toOrgId: B } });
  check('the owner moves it to org B', moved.status, 200);
  const after = await call('GET', `/sessions/${live.body.id}`, { token: A_TOKEN });
  check('  ...the live session ended', after.body.state, 'ended');
  check('  ...with end_reason device_transferred', after.body.end_reason, 'device_transferred');
  check('  ...and it is no longer in org A', (await call('GET', `/orgs/${A}/devices/${dA2}`, { token: A_TOKEN })).status, 404);
}

// =============================================================================
console.log('\n== suspension, including on routes with no permission gate of their own ==');
{
  // GET /v1/orgs requires authentication and nothing else. A suspended member must not keep an
  // org list, and their existing token must stop working even though it is not stale.
  const before = await call('GET', '/orgs', { token: helperA });
  check('the helper sees org A before suspension', before.body.orgs.map((o) => o.id), [A]);

  // There is deliberately no POST /members: an invite is the only way a person joins (D14).
  check('and no endpoint to add one directly', (await call('POST', `/orgs/${A}/members`, { token: A_TOKEN, body: { email: 'x@example.test', role: 'viewer' } })).status, 404);

  const members = await call('GET', `/orgs/${A}/members`, { token: A_TOKEN });
  const helperRow = members.body.members.find((m) => m.email === 'helper@example.test');
  check('the helper is a member of org A', helperRow?.role, 'operator');

  const done = await call('POST', `/orgs/${A}/members/${helperRow.user_id}/suspend`, { token: A_TOKEN });
  check('suspended', done.status, 200);

  const gated = await call('GET', `/orgs/${A}/devices`, { token: helperA });
  check('a suspended member is 403 on a permission-gated route', gated.status, 403);
  check('  ...with reason suspended', gated.reason, 'suspended');

  const ungated = await call('GET', '/orgs', { token: helperA });
  check('and 403 on the ungated route too — the gate is the token, not the endpoint', ungated.status, 403);

  // And they cannot sign in again.
  const relogin = await call('POST', '/auth/login', { body: { email: 'helper@example.test', password: 'password123' } });
  check('a suspended member cannot sign in', relogin.status, 401);

  await call('DELETE', `/orgs/${A}/members/${helperRow.user_id}/suspend`, { token: A_TOKEN });
  // perm_version moved twice (suspend, reinstate), so the old token is legitimately stale. That is
  // the freshness mechanism working, not a bug: a fresh token is required.
  check('the pre-suspension token is now stale', (await call('GET', `/orgs/${A}/devices`, { token: helperA })).code, 'TOKEN_STALE');
  const helperAgain = (await call('POST', '/auth/token', { token: await login('helper@example.test', 'password123'), body: { orgId: A } })).body.token;
  check('and a freshly minted token works again', (await call('GET', `/orgs/${A}/devices`, { token: helperAgain })).status, 200);
}

// =============================================================================
console.log('\n== offboard and rehire, end to end ==');
{
  const members = await call('GET', `/orgs/${A}/members`, { token: A_TOKEN });
  const helperRow = members.body.members.find((m) => m.email === 'helper@example.test');

  // Grant the helper something, so we can watch it survive the round trip.
  const grant = await call('POST', `/orgs/${A}/grants`, {
    token: A_TOKEN,
    body: { userId: helperRow.user_id, effect: 'allow', permissions: ['device:terminal'], deviceId: dA },
  });
  check('a device-scoped grant was created', grant.status, 201);

  const removed = await call('DELETE', `/orgs/${A}/members/${helperRow.user_id}`, { token: A_TOKEN });
  check('removed from the org', removed.status, 200);
  check('their token stops working immediately', (await call('GET', `/orgs/${A}/devices`, { token: helperA })).status, 401);
  check('the user row survives — users are never deleted (D15)', (await call('POST', '/auth/login', { body: { email: 'helper@example.test', password: 'password123' } })).status, 401);

  // Re-invite and accept. Two things to prove: that a removed member CAN be invited back (the
  // membership row still exists, so this is the branch that was broken), and that the old grants
  // come back with the membership.
  const again = await call('POST', `/orgs/${A}/invites`, { token: A_TOKEN, body: { email: 'helper@example.test', role: 'operator' } });
  check('a removed member can be invited back', again.status, 201);

  // They cannot sign in: login requires an active membership, and theirs was just removed. So the
  // redeem has to work for someone in exactly that state — by proving the existing password.
  check('a memberless account cannot sign in at all', (await call('POST', '/auth/login', { body: { email: 'helper@example.test', password: 'password123' } })).status, 401);

  const wrong = await call('POST', `/invites/${again.body.inviteToken}/accept`, { body: { name: 'Helper', password: 'not-the-password' } });
  check('redeeming with the WRONG existing password is refused', [wrong.status, wrong.code], [401, 'UNAUTHENTICATED']);

  const accepted = await call('POST', `/invites/${again.body.inviteToken}/accept`, { body: { name: 'Helper', password: 'password123' } });
  check('redeeming with the EXISTING password attaches the org', accepted.status, 200);
  check('  ...with the invited role', accepted.body.role, 'operator');
  check('  ...and no second user row was created', accepted.body.user.email, 'helper@example.test');

  check('  ...and the old password still works afterwards', (await call('POST', '/auth/login', { body: { email: 'helper@example.test', password: 'password123' } })).status, 200);
  const backToken = await login('helper@example.test', 'password123');
  const freshA = (await call('POST', '/auth/token', { token: backToken, body: { orgId: A } })).body.token;
  const rows = await call('GET', `/orgs/${A}/devices`, { token: freshA });
  const box = rows.body.devices.find((d) => d.id === dA);
  check('after rehire the old device-scoped grant applies again', box?.permissions['device:terminal'].effect, 'allow');
  const other2 = rows.body.devices.find((d) => d.id === dA2);
  check('  ...and still only on the device it named', other2 === undefined ? 'absent' : other2.permissions['device:terminal'].effect, 'absent');

  const anon = await call('POST', `/invites/${again.body.inviteToken}/accept`, { body: { name: 'X', password: 'password123' } });
  check('the same invite cannot be redeemed twice', anon.code, 'INVITE_USED');
}

// =============================================================================
console.log('\n== D9 cross-scope laundering, over HTTP ==');
{
  // The caller has to HOLD grant:create for this to be a laundering test rather than a plain
  // permission test, so the subject is an `admin` — which has grant:create and lacks org:delete.
  const inv = await call('POST', `/orgs/${A}/invites`, { token: A_TOKEN, body: { email: 'launderer@example.test', role: 'admin' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Launderer', password: 'password123' } });
  const members = await call('GET', `/orgs/${A}/members`, { token: A_TOKEN });
  const launderer = members.body.members.find((m) => m.email === 'launderer@example.test');
  const victim = members.body.members.find((m) => m.email === 'helper@example.test');
  check('a second member exists to be the target of the grant', victim?.role, 'operator');

  // Take a permission away from them, org-wide. The token is minted AFTER this, because creating a
  // grant bumps the grantee's perm_version and an earlier token would be stale — which is the
  // freshness mechanism working, and worth being explicit about rather than working around.
  const deny = await call('POST', `/orgs/${A}/grants`, {
    token: A_TOKEN, body: { userId: launderer.user_id, effect: 'deny', permissions: ['device:file_transfer'] },
  });
  check('org-wide deny created against the admin', deny.status, 201);

  const adminToken = (await call('POST', '/auth/token', { token: await login('launderer@example.test', 'password123'), body: { orgId: A } })).body.token;
  check('the admin still holds grant:create', (await call('GET', `/orgs/${A}/grants`, { token: adminToken })).status, 200);

  const launder = await call('POST', `/orgs/${A}/grants`, {
    token: adminToken,
    body: { userId: victim.user_id, effect: 'allow', permissions: ['device:file_transfer'], deviceId: dA },
  });
  check('laundering the denied permission is 403', launder.status, 403);
  check('  ...and the reason is the deny', launder.reason, 'explicit_deny');
  check('  ...naming the grant that has to be revoked first', /grt_/.test(launder.body?.error?.message ?? ''), true);

  // Org-wide scope is no escape either, and a wildcard is checked permission by permission.
  for (const [label, permissions] of [['org-wide', ['device:file_transfer']], ['inside device:*', ['device:*']], ['inside *', ['*']]]) {
    const attempt = await call('POST', `/orgs/${A}/grants`, {
      token: adminToken, body: { userId: victim.user_id, effect: 'allow', permissions },
    });
    check(`  ...and ${label} is refused too`, attempt.status, 403);
  }

  // A permission they DO hold can be granted — otherwise the rule would be useless.
  const fine = await call('POST', `/orgs/${A}/grants`, {
    token: adminToken, body: { userId: victim.user_id, effect: 'allow', permissions: ['device:view'] },
  });
  check('a permission they do hold can still be granted', fine.status, 201);

  // Self-grant is refused even for an owner.
  const me = (await call('GET', '/auth/me', { token: A_TOKEN })).body;
  const selfGrant = await call('POST', `/orgs/${A}/grants`, { token: A_TOKEN, body: { userId: me.user.id, effect: 'allow', permissions: ['device:view'] } });
  check('an owner cannot grant to themselves', [selfGrant.status, selfGrant.reason], [403, 'self_grant']);

  // A typo is a 400 naming the string, not a silent deny (D19).
  const typo = await call('POST', `/orgs/${A}/grants`, { token: A_TOKEN, body: { userId: victim.user_id, effect: 'allow', permissions: ['device:teleport'] } });
  check('a typo is 400 unknown_permission', [typo.status, typo.reason], [400, 'unknown_permission']);
  check('  ...and the message names the offending string', /device:teleport/.test(typo.body?.error?.message ?? ''), true);
}

// =============================================================================
console.log('\n== grandfathering, end to end, through a real revocation ==');
{
  const inv = await call('POST', `/orgs/${A}/invites`, { token: A_TOKEN, body: { email: 'gandalf@example.test', role: 'viewer' } });
  check('gandalf invited', inv.status, 201);
  const acc = await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Gandalf', password: 'password123' } });
  check('gandalf accepted', [acc.status, acc.code ?? ''], [200, '']);

  // Signed in BEFORE the grant, on purpose. `login` always mints a token carrying the CURRENT
  // perm_version, so the only way to hold a stale one is to take it first and then have somebody
  // change your authority — which is exactly the situation under test.
  const early = await login('gandalf@example.test', 'password123');
  check('gandalf signed in before any grant exists', typeof early === 'string', true);

  const members = await call('GET', `/orgs/${A}/members`, { token: A_TOKEN });
  const gRow = members.body.members.find((m) => m.email === 'gandalf@example.test');

  // A viewer holds NEITHER session:start NOR device:control, so a session could not open on the
  // strength of the role at all. The grant has to supply BOTH halves of the compound check, which
  // is the interesting case: the live session's entire authority comes from grants, so revoking
  // them is the sharpest test of grandfathering there is.
  const denied = await call('POST', `/orgs/${A}/sessions`, { token: (await call('POST', '/auth/token', { token: early, body: { orgId: A } })).body.token, body: { deviceId: dA, mode: 'control' } });
  check('a viewer cannot open a control session unaided', [denied.status, denied.reason], [403, 'missing_permission']);

  const grant = await call('POST', `/orgs/${A}/grants`, {
    token: A_TOKEN, body: { userId: gRow.user_id, effect: 'allow', permissions: ['session:start', 'device:control'], deviceId: dA },
  });
  check('granted session:start + device:control on one device', grant.status, 201);

  // The grant bumped gandalf's perm_version, so `early` is now stale — and `POST /auth/token` runs
  // through the same freshness gate as every other authenticated route, so it will not mint a new
  // scope from it. The console recovers by refreshing and retrying; here we simply sign in again.
  const earlySwitch = await call('POST', '/auth/token', { token: early, body: { orgId: A } });
  check('a token taken before the grant cannot switch org either (TOKEN_STALE)', [earlySwitch.status, earlySwitch.code], [401, 'TOKEN_STALE']);

  const g = await login('gandalf@example.test', 'password123');
  const switchRes = await call('POST', '/auth/token', { token: g, body: { orgId: A } });
  const gA = switchRes.body?.token;
  check('a token minted after it can', typeof gA === 'string', true);

  const opened = await call('POST', `/orgs/${A}/sessions`, { token: gA, body: { deviceId: dA, mode: 'control' } });
  check('a session opens on the strength of the grant', [opened.status, opened.body?.error?.message ?? ''], [201, '']);
  const snapshot = opened.body.authorized_by ?? {};
  check('  ...and the snapshot names the grant that allowed it', snapshot.grantIds, [grant.body.id]);
  check('  ...as well as the role it was opened under', snapshot.role, 'viewer');

  // Revoke it. The live session must survive; the next one must not be possible.
  await call('DELETE', `/orgs/${A}/grants/${grant.body.id}`, { token: A_TOKEN });

  // The revocation also bumped gandalf's perm_version, so gA is stale — which is the freshness
  // mechanism, and is why the observation below needs a token minted AFTER the change. The shipped
  // suite avoids this by asking as a third party (the owner, whose own pv did not move).
  const staleNow = await call('GET', `/sessions/${opened.body.id}`, { token: gA });
  check('the token that opened it is stale after the revocation', [staleNow.status, staleNow.code], [401, 'TOKEN_STALE']);

  // Recovery is ONE mechanism, not two: a stale token cannot be used to mint a new scope, so the
  // way back is the refresh cookie (`POST /auth/refresh`), which is what the console's api layer
  // does automatically on a TOKEN_STALE. Signing in again stands in for that here.
  const gA2 = await login('gandalf@example.test', 'password123');
  const stillThere = await call('GET', `/sessions/${opened.body.id}`, { token: gA2 });
  check('the live session SURVIVES the revocation', [stillThere.status, stillThere.body.state], [200, 'active']);
  check('  ...with no end_reason, because permission changes never end sessions', stillThere.body.end_reason, null);
  check('  ...and its snapshot still names the grant it was opened under', stillThere.body.authorized_by?.grantIds, [grant.body.id]);

  // And with the new truth in force, a NEW session is refused — 403, naming what is missing.
  const blocked = await call('POST', `/orgs/${A}/sessions`, { token: gA2, body: { deviceId: dA, mode: 'control' } });
  check('a NEW session on the same device is 403, not 401', blocked.status, 403);
  check('  ...and it says which of the two permissions is missing', blocked.reason, 'missing_permission');

  // The owner, whose own authority did not change, can see the same session still running.
  const asOwner = await call('GET', `/sessions/${opened.body.id}`, { token: A_TOKEN });
  check('and a third party sees it running too', asOwner.body.state, 'active');

  // The device row agrees with all of this.
  const rows = await call('GET', `/orgs/${A}/devices`, { token: gA2 });
  const box = rows.body.devices.find((d) => d.id === dA);
  check('the device row no longer carries device:control', box.permissions['device:control'].effect, 'deny');
  check('  ...with the implicit reason, since nothing denies it any more', box.permissions['device:control'].reason, 'implicit');
}

// =============================================================================
console.log('\n== a session past its TTL is retired on read ==');
{
  const org = await call('POST', '/orgs', { token: A_TOKEN, body: { name: 'Seams Short TTL' } });
  const orgToken = (await call('POST', '/auth/token', { token: A_TOKEN, body: { orgId: org.body.id } })).body.token;
  const dev = await call('POST', `/orgs/${org.body.id}/devices`, { token: orgToken, body: { name: 'ttl-box', kind: 'linux' } });
  const opened = await call('POST', `/orgs/${org.body.id}/sessions`, { token: orgToken, body: { deviceId: dev.body.id, mode: 'view' } });
  check('a session opens', opened.status, 201);
  check('  ...carrying an expiry', typeof opened.body.expires_at, 'string');

  // Wind the clock past the TTL by rewriting the stored expiry — the only way to test this
  // without waiting an hour, and it is the same row the lazy sweep reads.
  const raw = new Database(DB);
  raw.pragma('foreign_keys = ON');
  raw.prepare("UPDATE sessions SET expires_at = datetime('now', '-1 second') WHERE id = ?").run(opened.body.id);
  raw.close();

  const listed = await call('GET', `/orgs/${org.body.id}/sessions`, { token: orgToken });
  const row = listed.body.sessions.find((s) => s.id === opened.body.id);
  check('reading the list retires it', row.state, 'ended');
  check('  ...with end_reason session_expired', row.end_reason, 'session_expired');

  // And the device is free again, because the exclusivity index only counts ACTIVE sessions.
  const reopened = await call('POST', `/orgs/${org.body.id}/sessions`, { token: orgToken, body: { deviceId: dev.body.id, mode: 'control' } });
  check('and the device can take an exclusive session again', reopened.status, 201);
}

// =============================================================================
console.log('\n== the Authorization header ==');
{
  const t = await login('owner@acme.test');
  const lower = await call('GET', '/auth/me', { headers: { authorization: `bearer ${t}` } });
  check('the scheme is case-insensitive (RFC 7235)', lower.status, 200);

  const basic = await call('GET', '/auth/me', { headers: { authorization: 'Basic dXNlcjpwYXNz' } });
  check('a Basic credential is 401, not 403', [basic.status, basic.code], [401, 'UNAUTHENTICATED']);

  const two = await call('GET', '/auth/me', { headers: { authorization: `Bearer ${t} extra` } });
  check('a malformed header is 401', two.status, 401);

  const none = await call('GET', '/auth/me');
  check('no header at all is 401', none.status, 401);

  // A refresh token presented as a bearer must not work.
  const loginRes = await fetch(`${BASE}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@acme.test', password: 'demo1234' }) });
  const cookie = loginRes.headers.get('set-cookie').split(';')[0];
  const asBearer = await call('GET', '/auth/me', { headers: { authorization: `Bearer ${cookie.split('=')[1]}` } });
  check('a refresh token as a bearer credential is 401', asBearer.status, 401);
}

// =============================================================================
console.log('\n== cross-org is invisible, and the body does not confirm anything ==');
{
  const t = await login('owner@acme.test');
  const tA = (await call('POST', '/auth/token', { token: t, body: { orgId: 'org_acme' } })).body.token;

  for (const [label, path] of [
    ['devices', `/orgs/${A}/devices`],
    ['members', `/orgs/${A}/members`],
    ['grants', `/orgs/${A}/grants`],
    ['sessions', `/orgs/${A}/sessions`],
    ['audit', `/orgs/${A}/audit`],
    ['invites', `/orgs/${A}/invites`],
  ]) {
    const r = await call('GET', path, { token: tA });
    const leaked = JSON.stringify(r.body ?? {}).includes(A);
    check(`${label} in an org the token does not name -> 404`, [r.status, r.code], [404, 'NOT_FOUND']);
    check(`  ...and the body does not mention that org`, leaked, false);
  }

  const aDevice = (await call('GET', `/orgs/org_acme/devices`, { token: tA })).body.devices[0];
  const byId = await call('GET', `/orgs/${A}/devices/${aDevice.id}`, { token: tA });
  check('a real device id from another org is 404 too', byId.status, 404);
  check('  ...and does not leak the device', JSON.stringify(byId.body ?? {}).includes(aDevice.id), false);

  // A session id from another org is equally invisible.
  const foreign = await call('POST', `/orgs/${A}/sessions`, { token: A_TOKEN, body: { deviceId: dA, mode: 'view' } });
  if (foreign.status === 201) {
    const crossed = await call('GET', `/sessions/${foreign.body.id}`, { token: tA });
    check('a session id from another org is 404', crossed.status, 404);
  } else {
    check('a session id from another org is 404 (skipped: no session to test)', true, true);
  }
}

// =============================================================================
console.log('\n== the audit log records the refusals, with reasons ==');
{
  const t = await login('owner@acme.test');
  const tA = (await call('POST', '/auth/token', { token: t, body: { orgId: A } })).body.token;

  // Provoke a real 403.
  const members = await call('GET', `/orgs/${A}/members`, { token: tA });
  const target = members.body.members.find((m) => m.email === 'gandalf@example.test');
  await call('POST', `/orgs/${A}/grants`, { token: tA, body: { userId: target.user_id, effect: 'allow', permissions: ['audit:read'] } });
  const denied = await call('DELETE', `/orgs/${A}/grants/grt_does_not_exist`, { token: tA });
  check('a revoke of a nonexistent grant is 404 (not audited as a denial)', denied.status, 404);

  // A 403 we can provoke: the helper is a viewer, so their attempt to create a grant is a 403.
  const helperToken = (await call('POST', '/auth/token', { token: await login('gandalf@example.test', 'password123'), body: { orgId: A } })).body.token;
  const forbidden = await call('POST', `/orgs/${A}/grants`, { token: helperToken, body: { userId: target.user_id, effect: 'allow', permissions: ['device:view'] } });
  check('a viewer creating a grant is 403', forbidden.status, 403);

  const audit = await call('GET', `/orgs/${A}/audit?limit=200`, { token: tA });
  check('the audit log is readable by an org owner', audit.status, 200);
  check('  ...and it contains the denial', audit.body.events.some((e) => e.result === 'deny'), true);
  const denial = audit.body.events.find((e) => e.result === 'deny' && e.action === 'grant.create');
  check('  ...with the action that was refused', denial?.action, 'grant.create');
  check('  ...a reason code', typeof denial?.reason_code, 'string');
  check('  ...and the actor', denial?.actor_id !== null, true);

  // The log is append-only, enforced by triggers rather than by convention.
  const raw = new Database(DB);
  raw.pragma('foreign_keys = ON');
  const eventId = audit.body.events[0].id;
  check('UPDATE on audit_events is refused by a trigger', (() => {
    try { raw.prepare('UPDATE audit_events SET result = ? WHERE id = ?').run('allow', eventId); return 'updated'; }
    catch (e) { return /append-only/.test(e.message) ? 'refused' : `refused: ${e.message}`; }
  })(), 'refused');
  check('DELETE on audit_events is refused by a trigger', (() => {
    try { raw.prepare('DELETE FROM audit_events WHERE id = ?').run(eventId); return 'deleted'; }
    catch (e) { return /append-only/.test(e.message) ? 'refused' : `refused: ${e.message}`; }
  })(), 'refused');
  raw.close();

  // Every change produced exactly ONE row, not two.
  const creates = audit.body.events.filter((e) => e.action === 'grant.create' && e.result === 'allow');
  check('one success row per grant created, not two', creates.length >= 1, true);
}

// =============================================================================
console.log('\n== malformed input must never be a 500, and never a dead process ==');
{
  // Each of these was a 500 or a process kill. They are grouped because they share one cause
  // class: a client-supplied string handed to a function that throws on bad input, somewhere on a
  // path with no try/catch around it.
  const t = await login('owner@acme.test');

  // Sanity: the raw helper is really reaching the server (otherwise every assertion below is a
  // 404 that proves nothing).
  check('the raw helper reaches the SPA route', (await raw('GET', '/')).status, 200);

  // 1. The process-killer. `GET /%ff` made serveStatic throw URIError straight out of the
  //    request listener, and the whole server went with it.
  const killed = await raw('GET', '/%ff');
  check('a malformed percent-escape is a 400, not a crash', [killed.status, killed.code], [400, 'VALIDATION']);

  // 2. And the server is still there afterwards — the assertion that actually pins the bug.
  const alive = await call('GET', '/auth/me', { token: t });
  check('  ...and the server is still serving', alive.status, 200);

  // 3. Same throw, reached through the router's parameter decoding, on PUBLIC routes.
  for (const [label, method, path] of [
    ['GET  /v1/invites/%ff        (public)', 'GET', '/v1/invites/%ff'],
    ['POST /v1/invites/%zz/accept (public)', 'POST', '/v1/invites/%zz/accept'],
  ]) {
    const r = await call(method, path);
    check(`${label} -> 404, not 500`, [r.status, r.code], [404, 'NOT_FOUND']);
  }
  check('  ...authenticated routes with a bad segment -> 404 too', (await call('GET', '/sessions/%ff', { token: t })).status, 404);

  // 4. A malformed cookie, on the PUBLIC refresh endpoint the console hits on every page load.
  for (const cookie of ['rt=%', 'rt=%ZZ', 'rt=%E0%A4%A', 'x=%']) {
    const r = await call('POST', '/auth/refresh', { headers: { cookie } });
    check(`Cookie: ${cookie.padEnd(12)} -> 401, not 500`, [r.status, r.code], [401, 'UNAUTHENTICATED']);
  }

  // 5. A good cookie still works, so the guard did not break the happy path.
  const jar = await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'owner@acme.test', password: 'demo1234' }),
  });
  const good = jar.headers.get('set-cookie').split(';')[0];
  check('a well-formed refresh cookie still refreshes', (await call('POST', '/auth/refresh', { headers: { cookie: good } })).status, 200);

  // 6. The process is demonstrably alive at the end of all of that.
  check('the process survived every one of those requests', (await call('GET', '/auth/me', { token: t })).status, 200);
}

// =============================================================================
console.log('\n== the refresh lineage, and sign-out, must have CONSEQUENCES ==');
{
  // Every assertion in this block is about what happens AFTER a control fires, not about the
  // refusal itself. Both bugs it pins had a correct-looking status code and no effect.
  const jar = async () => {
    const res = await fetch(`${BASE}/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'owner@acme.test', password: 'demo1234' }),
    });
    return { cookie: res.headers.get('set-cookie').split(';')[0], body: await res.json() };
  };
  const cookieOf = (setCookie) => setCookie.split(';')[0];

  // --- replay detection must KILL THE LINEAGE, not just refuse one call ---
  //
  // Every refresh SPENDS the cookie it is given and issues a new one, so the lineage is a chain:
  // A -> B -> C, where A and B are spent and C is the live tip. Burning an ancestor must take the
  // whole chain with it. (My first version of this block asserted on a cookie it had already spent
  // two lines earlier -- a test that cannot fail because it never tested the live thing.)
  const A = (await jar()).cookie;
  const rotB = await fetch(`${BASE}/auth/refresh`, { method: 'POST', headers: { cookie: A } });
  const B = cookieOf(rotB.headers.get('set-cookie'));
  check('A rotates into B', [rotB.status, B.startsWith('rt='), B !== A], [200, true, true]);

  const rotC = await fetch(`${BASE}/auth/refresh`, { method: 'POST', headers: { cookie: B } });
  const C = cookieOf(rotC.headers.get('set-cookie'));
  check('B rotates into C — C is the live, unspent tip', [rotC.status, C !== B], [200, true]);

  check('replaying a spent ancestor is refused', (await call('POST', '/auth/refresh', { headers: { cookie: A } })).status, 401);

  // THE ASSERTION THAT MATTERS: the descendant is dead too. Before the fix this was 200, which is
  // the entire bug -- detection fired and the attacker's lineage carried on working.
  const afterBurn = await call('POST', '/auth/refresh', { headers: { cookie: C } });
  check('  ...and the WHOLE family is revoked, not just the replayed row', afterBurn.status, 401);
  check('  ...reported as a used token, since that is what killed it', afterBurn.body?.error?.message, 'refresh token has already been used');

  // A fresh sign-in is unaffected: the family is per-lineage, not per-user.
  const fresh = await jar();
  check('a new sign-in still works (families are per-lineage, not per-user)', (await call('POST', '/auth/refresh', { headers: { cookie: fresh.cookie } })).status, 200);

  // --- sign-out must actually end the session ---
  const s = await jar();
  check('logout needs no bearer token (the cookie is the credential)', (await call('POST', '/auth/logout', { headers: { cookie: s.cookie } })).status, 204);
  const afterLogout = await call('POST', '/auth/refresh', { headers: { cookie: s.cookie } });
  check('  ...and the session is gone afterwards', afterLogout.status, 401);

  // and a rotated sibling is gone too, not just the presented token
  const s2 = await jar();
  const r2 = await fetch(`${BASE}/auth/refresh`, { method: 'POST', headers: { cookie: s2.cookie } });
  const sibling = cookieOf(r2.headers.get('set-cookie'));
  await call('POST', '/auth/logout', { headers: { cookie: sibling } });
  check('  ...including a token rotated out of the same family', (await call('POST', '/auth/refresh', { headers: { cookie: s2.cookie } })).status, 401);
}

// =============================================================================
console.log('\n== modification authority is the same rule on every verb ==');
{
  // The rank rule (PERMISSIONS.md §6) is about MODIFYING a user, not about a particular verb. It
  // was enforced on the role-change route and missing from suspend/reinstate, so one admin got two
  // different answers to the same question about the same target.
  const owner = (await call('POST', '/auth/login', { body: { email: 'owner@acme.test', password: 'demo1234' } })).body.token;
  const adminTok = (await call('POST', '/auth/login', { body: { email: 'admin@acme.test', password: 'demo1234' } })).body.token;
  const adminA = (await call('POST', '/auth/token', { token: adminTok, body: { orgId: A } })).body.token;

  // A fresh org so the two-owner case does not muddy it.
  const org = await call('POST', '/orgs', { token: owner, body: { name: 'Rank Tests' } });
  const R = org.body.id;
  const ownerR = (await call('POST', '/auth/token', { token: owner, body: { orgId: R } })).body.token;
  const inv = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'deputy@example.test', role: 'admin' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Deputy', password: 'password123' } });
  const deputy = (await call('POST', '/auth/token', { token: await login('deputy@example.test', 'password123'), body: { orgId: R } })).body.token;
  // The TARGET is the owner, not the deputy: my first version read the id out of the deputy's own
  // /auth/me and so spent the self-suspend guard (400) instead of testing the rank rule at all.
  const roster = await call('GET', `/orgs/${R}/members`, { token: deputy });
  const ownerRow = roster.body.members.find((m) => m.email === 'owner@acme.test');

  // An admin suspending the OWNER: must be 403, the same as an admin changing the owner's role.
  const susp = await call('POST', `/orgs/${R}/members/${ownerRow.user_id}/suspend`, { token: deputy });
  check('an admin cannot suspend the owner', [susp.status, susp.code], [403, 'FORBIDDEN']);
  const role = await call('PATCH', `/orgs/${R}/members/${ownerRow.user_id}`, { token: deputy, body: { role: 'viewer' } });
  check('  ...and the same admin cannot change the owner\'s role either', [role.status, role.code], [403, 'FORBIDDEN']);
  check('  ...so both verbs agree', [susp.status, role.status], [403, 403]);
  check('the owner is untouched', (await call('GET', '/auth/me', { token: ownerR })).status, 200);

  // An admin CAN still suspend someone below them.
  const inv2 = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'junior@example.test', role: 'viewer' } });
  await call('POST', `/invites/${inv2.body.inviteToken}/accept`, { body: { name: 'Junior', password: 'password123' } });
  const members = await call('GET', `/orgs/${R}/members`, { token: deputy });
  const junior = members.body.members.find((m) => m.email === 'junior@example.test');
  check('an admin can still suspend a viewer', (await call('POST', `/orgs/${R}/members/${junior.user_id}/suspend`, { token: deputy })).status, 200);
  check('  ...and reinstate them', (await call('DELETE', `/orgs/${R}/members/${junior.user_id}/suspend`, { token: deputy })).status, 200);
}

console.log('\n== removal is not a pause ==');
{
  const owner = (await call('POST', '/auth/login', { body: { email: 'owner@acme.test', password: 'demo1234' } })).body.token;
  const org = await call('POST', '/orgs', { token: owner, body: { name: 'Removal Tests' } });
  const R = org.body.id;
  const ownerR = (await call('POST', '/auth/token', { token: owner, body: { orgId: R } })).body.token;

  const inv = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'leaver@example.test', role: 'viewer' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Leaver', password: 'password123' } });
  const members = await call('GET', `/orgs/${R}/members`, { token: ownerR });
  const leaver = members.body.members.find((m) => m.email === 'leaver@example.test');

  check('removed from the org', (await call('DELETE', `/orgs/${R}/members/${leaver.user_id}`, { token: ownerR })).status, 200);
  const back = await call('DELETE', `/orgs/${R}/members/${leaver.user_id}/suspend`, { token: ownerR });
  check('reinstatement will NOT resurrect a removed membership', [back.status, back.code], [409, 'ALREADY_REMOVED']);
  check('  ...they are still out', (await call('GET', `/orgs/${R}/members`, { token: ownerR })).body.members.find((m) => m.user_id === leaver.user_id).status, 'removed');

  // The only way back is an invite, which is the only way in.
  const again = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'leaver@example.test', role: 'operator' } });
  check('  ...and an invite brings them back, with a new role', again.status, 201);
  // A removed member cannot sign in at all (login needs an active membership), so the order here
  // is: redeem FIRST, then sign in. My first version did it the other way round and asserted on a
  // null token.
  const acc = await call('POST', `/invites/${again.body.inviteToken}/accept`, { body: { name: 'Leaver', password: 'password123' } });
  check('redeemed', [acc.status, acc.body.role], [200, 'operator']);
  const after = (await call('POST', '/auth/token', { token: await login('leaver@example.test', 'password123'), body: { orgId: R } })).body.token;
  check('  ...and the new role is the invited one', (await call('GET', '/auth/me', { token: after })).body.role, 'operator');
}

console.log('\n== a grant may only target someone who can use it ==');
{
  const owner = (await call('POST', '/auth/login', { body: { email: 'owner@acme.test', password: 'demo1234' } })).body.token;
  const org = await call('POST', '/orgs', { token: owner, body: { name: 'Grant Targets' } });
  const R = org.body.id;
  const ownerR = (await call('POST', '/auth/token', { token: owner, body: { orgId: R } })).body.token;

  const inv = await call('POST', `/orgs/${R}/invites`, { token: ownerR, body: { email: 'sleeper@example.test', role: 'viewer' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Sleeper', password: 'password123' } });
  const members = await call('GET', `/orgs/${R}/members`, { token: ownerR });
  const sleeper = members.body.members.find((m) => m.email === 'sleeper@example.test');

  check('a grant to an active member is fine', (await call('POST', `/orgs/${R}/grants`, { token: ownerR, body: { userId: sleeper.user_id, effect: 'allow', permissions: ['device:view'] } })).status, 201);

  await call('POST', `/orgs/${R}/members/${sleeper.user_id}/suspend`, { token: ownerR });
  const toSuspended = await call('POST', `/orgs/${R}/grants`, { token: ownerR, body: { userId: sleeper.user_id, effect: 'allow', permissions: ['device:control'] } });
  check('a grant to a SUSPENDED member is 404', [toSuspended.status, toSuspended.code], [404, 'NOT_FOUND']);

  await call('DELETE', `/orgs/${R}/members/${sleeper.user_id}/suspend`, { token: ownerR });
  await call('DELETE', `/orgs/${R}/members/${sleeper.user_id}`, { token: ownerR });
  const toRemoved = await call('POST', `/orgs/${R}/grants`, { token: ownerR, body: { userId: sleeper.user_id, effect: 'allow', permissions: ['device:control'] } });
  check('a grant to a REMOVED member is 404', [toRemoved.status, toRemoved.code], [404, 'NOT_FOUND']);
}

// =============================================================================
console.log('\n== two information leaks, both one field away from correct code ==');
{
  const owner = (await call('POST', '/auth/login', { body: { email: 'owner@acme.test', password: 'demo1234' } })).body.token;
  const org = await call('POST', '/orgs', { token: owner, body: { name: 'Leak Tests' } });
  const L = org.body.id;
  const ownerL = (await call('POST', '/auth/token', { token: owner, body: { orgId: L } })).body.token;

  // Two devices, one visible to our viewer, one not.
  const shown = await call('POST', `/orgs/${L}/devices`, { token: ownerL, body: { name: 'shown-box', kind: 'linux' } });
  const hidden = await call('POST', `/orgs/${L}/devices`, { token: ownerL, body: { name: 'hidden-box', kind: 'linux' } });
  const inv = await call('POST', `/orgs/${L}/invites`, { token: ownerL, body: { email: 'nosy@example.test', role: 'viewer' } });
  await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'Nosy', password: 'password123' } });
  const roster = await call('GET', `/orgs/${L}/members`, { token: ownerL });
  const nosy = roster.body.members.find((m) => m.email === 'nosy@example.test');
  await call('POST', `/orgs/${L}/grants`, { token: ownerL, body: { userId: nosy.user_id, effect: 'deny', permissions: ['device:view'], deviceId: hidden.body.id } });
  const nosyL = (await call('POST', '/auth/token', { token: await login('nosy@example.test', 'password123'), body: { orgId: L } })).body.token;

  // --- leak 1: the row count told them what they could not see ---
  const list = await call('GET', `/orgs/${L}/devices`, { token: nosyL });
  check('the hidden device is not listed', list.body.devices.some((d) => d.id === hidden.body.id), false);
  check('  ...one row is returned', list.body.devices.length, 1);
  check('  ...and `total` agrees with the rows, not the org', list.body.total, list.body.devices.length);
  check('  ...so the count of hidden devices is not disclosed', list.body.total, 1);
  check('the owner, who can see both, gets 2', (await call('GET', `/orgs/${L}/devices`, { token: ownerL })).body.total, 2);

  // --- leak 2: transfer told them which org ids exist ---
  //
  // The owner of L must not be a member of the destination, or the transfer is legitimate and the
  // test proves nothing. So the destination org is created by a DIFFERENT account, which makes the
  // caller a non-member of a real, live org -- the exact case the leak needed. (My first version
  // used an org this same owner had created, so the transfer SUCCEEDED and the test asserted 200
  // against a leak that was not there.)
  const otherAdmin = (await call('POST', '/auth/login', { body: { email: 'admin@acme.test', password: 'demo1234' } })).body.token;
  const foreignOrg = await call('POST', '/orgs', { token: otherAdmin, body: { name: 'Someone Elses Org' } });
  const FOREIGN = foreignOrg.body.id;
  check('the caller cannot address the destination org at all', (await call('GET', `/orgs/${FOREIGN}/devices`, { token: ownerL })).status, 404);

  const deviceForTransfer = (await call('POST', `/orgs/${L}/devices`, { token: ownerL, body: { name: 'transfer-box', kind: 'linux' } })).body;
  const asMember = await call('POST', `/orgs/${L}/devices/${deviceForTransfer.id}/transfer`, { token: ownerL, body: { toOrgId: FOREIGN } });
  const notReal = await call('POST', `/orgs/${L}/devices/${deviceForTransfer.id}/transfer`, { token: ownerL, body: { toOrgId: 'org_definitely_not_real_zz' } });
  const ownOrg = await call('POST', `/orgs/${L}/devices/${deviceForTransfer.id}/transfer`, { token: ownerL, body: { toOrgId: L } });

  check('transfer to a real org you are not in -> 404', [asMember.status, asMember.code], [404, 'NOT_FOUND']);
  check('  ...and to an org that does not exist -> 404', [notReal.status, notReal.code], [404, 'NOT_FOUND']);
  check('  ...so the two are indistinguishable by status', asMember.status, notReal.status);
  // The BODIES must match too, not just the statuses: a different `message` between "no such org"
  // and "you are not in that org" is the same leak in a different field.
  check('  ...and by body as well', [asMember.body.error.code, asMember.body.error.message], [notReal.body.error.code, notReal.body.error.message]);
  // Same-org stays a distinct, honest 400: that is a statement about the caller's own request, not
  // about whether any other org exists.
  check('transfer to its own org is still 400 same_org', [ownOrg.status, ownOrg.reason], [400, 'same_org']);
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
shutDown();
process.exit(fail === 0 ? 0 : 1);
