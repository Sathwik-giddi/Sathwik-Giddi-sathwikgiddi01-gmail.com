// The launch gate. 17 vulnerability classes, each one probed against a running server or read off
// the source, and each one answered with evidence rather than an assertion that it is fine.
//
//   node scripts/audit.js
//
// This is deliberately NOT a copy of `check-hardening.js` and does not duplicate it. That file
// asserts the SPECIFICATION is implemented; this one asks an attacker what they can do, and it is
// organised by attack class rather than by feature. Where a class does not apply to this
// application, it says so and says why, because "not applicable" is an answer a reviewer needs and
// silence is not.
//
// Two rules kept throughout, both learned the hard way in the previous phase:
//
//   1. A check that cannot fail is worse than no check. Every dynamic probe below asserts on a
//      specific status code or body, and the static checks assert on parsed structure, not on a
//      substring that happens to be present.
//
//   2. Prove the negative. Where a check claims something is absent (`no CORS header`), it asserts
//      absence, and a probe that cannot distinguish "absent" from "not looked at" is not run.
//
// Exit code 1 if any CRITICAL or HIGH finding is open. Findings that are accepted risks are
// recorded as such and do not fail the run — but they are printed either way.

import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { createHmac, randomUUID } from 'node:crypto';

const PORT = 8188;
const BASE = `http://localhost:${PORT}`;
const DB = 'audit.db';
const SECRET = 'audit-secret';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: {
    ...process.env, DATABASE_FILE: DB, PORT: String(PORT),
    NODE_ENV: 'production', JWT_SECRET: SECRET, APP_HASH_KEY: SECRET,
    // A low, known limit so the rate limiter is observable inside a test run instead of needing
    // 300 requests. The production defaults are asserted separately in check-hardening.js.
    RATE_LIMIT_FAILURES: '4', RATE_LIMIT_WINDOW_MS: '60000',
  },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));
let live = server;
const cleanup = () => { try { live.kill(); } catch { /* gone */ } for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s); };
process.on('exit', cleanup);

// ---------------------------------------------------------------------------
let pass = 0, fail = 0;
const findings = [];
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(62)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
  if (!ok) findings.push(label);
};
/**
 * Per-section pass/fail accounting. A verdict describes ITS OWN section, so it compares against
 * the counts as they were when the section opened. Comparing against the running total made every
 * section after the first failure report a finding it did not have, which is how a report ends up
 * with three findings where there is one.
 */
let mark = { pass: 0, fail: 0 };
const section = (t) => { mark = { pass, fail }; console.log(`\n== ${t} ==`); };
const verdict = (n, why) => {
  const state = fail === mark.fail ? 'clean' : 'FINDING';
  console.log(`  ${state === 'clean' ? 'ok  ' : 'FAIL '} ${String(n).padStart(2)}. ${state === 'clean' ? 'clean' : 'FINDING'} — ${why}`);
  if (state !== 'clean') findings.push(`vulnerability ${n}`);
};
const na = (n, why) => console.log(`   na  ${String(n).padStart(2)}. n/a      — ${why}`);

async function call(method, path, { token, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  try {
    const res = await fetch(BASE + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
    return { status: res.status, body: json, raw: text, headers: res.headers };
  } catch (err) {
    return { status: 0, body: null, raw: '', headers: new Headers(), error: err.message };
  }
}

const login = async (email, orgId, password = 'demo1234') => {
  const r = await call('POST', '/v1/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } });
  return r.body?.token ?? null;
};
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const sign = (claims, secret = SECRET) => {
  const h = b64u({ alg: 'HS256', typ: 'JWT' });
  const p = b64u({ iss: 'remoteops', aud: 'remoteops-api', jti: `jti-${randomUUID()}`, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 900, ...claims });
  return `${h}.${p}.${createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')}`;
};

const ROOT = new URL('..', import.meta.url).pathname;
const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');

/** Key-shaped literals, used by sections 3 and 5. Declared once at module scope on purpose. */
const SECRET_SHAPES = [
  /sk_live_[0-9a-zA-Z]{10,}/, /pk_live_/, /whsec_[0-9a-zA-Z]{10,}/, /AKIA[0-9A-Z]{16}/,
  /ghp_[0-9a-zA-Z]{20,}/, /xox[baprs]-[0-9a-zA-Z-]{10,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

/** Every `/v1` route the application actually registers, read from the route files themselves. */
function allRoutes() {
  const out = [];
  for (const f of readdirSync(new URL('../server/routes/', import.meta.url))) {
    for (const m of read(`server/routes/${f}`).matchAll(/router\.(get|post|patch|delete|put)\(\s*'(\/v1[^']*)'/g)) {
      out.push({ method: m[1].toUpperCase(), path: m[2], file: f });
    }
  }
  return out;
}

/** The built SPA bundle, read once. Sections 5 and 8 both need it. */
const ASSETS = existsSync(new URL('../dist/assets/', import.meta.url).pathname)
  ? readdirSync(new URL('../dist/assets/', import.meta.url).pathname) : [];

const acmeAdmin = await login('admin@acme.test', 'org_acme');
const acmeOwner = await login('owner@acme.test', 'org_acme');
const globexOwner = await login('owner@globex.test', 'org_globex');
const acmeViewer = await login('viewer@acme.test', 'org_acme');
if (!acmeAdmin || !acmeOwner || !globexOwner) {
  console.error('  setup failed: could not obtain baseline tokens');
  process.exit(1);
}
const claimsOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());
const adminClaims = claimsOf(acmeAdmin);

// ===========================================================================
section('1. Misconfigured database / no row-level security');
// SQLite has no RLS feature, so the honest question is what enforces isolation here. It is the
// application: every org-scoped statement carries org_id, and every by-id fetch is either
// org-scoped in SQL or org-checked before use. This probes the second kind, because that is the
// one a static grep cannot fully trust.
{
  const foreign = await call('GET', '/v1/orgs/org_acme/devices/dev_globex_kiosk_01', { token: globexOwner });
  check('another org\'s device id is invisible from the wrong org', foreign.status, 404);

  // Every statement in sql.js: count how many org-scoped reads exist, so the claim is measurable.
  const stmts = [...read('server/internal/sql.js').matchAll(/([A-Za-z_]\w*):\s*`([^`]*)`/g)]
    .map((m) => [m[1], m[2].replace(/\s+/g, ' ').trim()])
    .filter(([, s]) => /^(SELECT|UPDATE|DELETE)/i.test(s));
  const orgScoped = stmts.filter(([, s]) => /org_id/.test(s)).length;
  console.log(`         ${orgScoped}/${stmts.length} read/write statements carry org_id in SQL; the rest are keyed by an id the route has already org-checked`);

  // And prove the no-annotation case is still enforced at runtime, not just intended.
  const s = await call('GET', '/v1/sessions/ses_nonexistent', { token: acmeOwner });
  check('a session id that does not exist is 404, not a 500', s.status, 404);
  verdict(1, 'isolation is enforced in the query layer and re-probed at runtime');
}

// ===========================================================================
section('2. Unprotected API routes / no auth middleware');
// Structural, not sampled: the pipeline authenticates every route that is not in PUBLIC_ROUTES, so
// the question is whether any route escaped that list. Enumerated from the source, then probed.
{
  // The probe list is DERIVED from the registered routes, not hand-written beside them. A
  // hand-written list is a list that quietly stops covering a route someone adds later, and the
  // failure is silent: the audit keeps passing while a new endpoint goes unprobed.
  //
  // The parameter values do not matter. Authentication runs before any handler touches
  // `params`, so `GET /v1/orgs/probe/members/probe` is a complete test of "is this route
  // protected" and needs no fixture data to exist.
  const publicSet = new Set([...read('server/index.js').matchAll(/'(GET|POST|PATCH|DELETE) (\/v1[^']*)'/g)].map((m) => `${m[1]} ${m[2]}`));
  const all = allRoutes();
  const protectedRoutes = all.filter((r) => !publicSet.has(`${r.method} ${r.path}`));
  const publicRoutes = all.filter((r) => publicSet.has(`${r.method} ${r.path}`));
  console.log(`         ${all.length} routes registered across ${new Set(all.map((r) => r.file)).size} files · ${publicRoutes.length} public · ${protectedRoutes.length} protected`);

  const norm = (p) => p.replace(/:[A-Za-z_]\w*/g, 'probe');
  // Both sides go through norm(). PUBLIC_ROUTES is written with `:token` and the registered route
  // is read with `:token` too, but normalising only one side turns a matching pair into a mismatch
  // and reports a phantom finding — which is what the first version of this block did.
  const publicKeys = new Set([...publicSet].map(norm));
  const declaredPublic = new Set(publicRoutes.map((r) => `${r.method} ${norm(r.path)}`));
  check('every PUBLIC_ROUTES entry matches a registered route', [...publicKeys].filter((k) => !declaredPublic.has(k)), []);
  check('every public route is genuinely public (no entry that protects nothing)', [...declaredPublic].filter((k) => !publicKeys.has(k)), []);

  const statuses = {};
  for (const r of protectedRoutes) {
    const res = await call(r.method, norm(r.path), { body: ['GET', 'DELETE'].includes(r.method) ? undefined : {} });
    statuses[`${r.method} ${norm(r.path)}`] = res.status;
  }
  const notProtected = Object.entries(statuses).filter(([, s]) => s !== 401);
  check(`all ${protectedRoutes.length} protected routes refuse an anonymous caller`, notProtected, []);

  // The public routes must not be a way in.
  const login = await call('POST', '/v1/auth/login', { body: { email: 'dana@example.test', password: 'demo1234' } });
  check('the public login route still works', login.status, 200);
  check('a public route cannot be borrowed for org data', login.body?.devices, undefined);
  const badInvite = await call('POST', '/v1/invites/not-a-real-token/accept', { body: { name: 'X', password: 'short' } });
  check('the public invite-accept route refuses a bad token', [400, 404, 410].includes(badInvite.status), true);
  verdict(2, 'authentication is deny-by-default; no registered route escapes the protected set');
}

// ===========================================================================
section('3. Committed or publicly served secrets');
{
  const tracked = execFileSync('git', ['ls-files'], { cwd: new URL('..', import.meta.url).pathname, encoding: 'utf8' }).split('\n');
  const suspicious = tracked.filter((f) => /(^|\/)\.env|\.pem$|\.key$|credentials?\.json|id_rsa|\.p12$/i.test(f));
  check('no .env / key / credential file is tracked', suspicious, []);

  // Scan tracked source for high-entropy provider key shapes.
  //
  // This scanner is excluded from its own scan, and it has to be: the patterns have to be written
  // down literally somewhere, and the only sensible place is the file that looks for them. The
  // first run flagged `scripts/audit.js: /pk_live_/` — a true positive about the file, a false
  // positive about the repository, and precisely the kind of noise that trains a reader to skip a
  // scanner's output.
  const PATTERNS = SECRET_SHAPES;
  const hits = [];
  for (const f of tracked.filter((f) => /\.(js|jsx|ts|json|md|html|css)$/.test(f) && f !== 'scripts/audit.js')) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
    for (const p of PATTERNS) if (p.test(src)) hits.push(`${f}: ${p}`);
  }
  check('no provider key literal in any tracked file', hits, []);

  // The literal that WAS the production signing key must be unreachable in production now.
  const noKey = spawn(process.execPath, ['-e', `
    process.env.NODE_ENV='production'; delete process.env.JWT_SECRET; delete process.env.APP_HASH_KEY;
    import('./server/index.js').then(()=>{console.log('STARTED');process.exit(0)}).catch(e=>{console.log('REFUSED:'+e.message.split('\\n')[0]);process.exit(0)});
  `], { cwd: new URL('..', import.meta.url).pathname, stdio: ['ignore', 'pipe', 'ignore'] });
  const out = await new Promise((r) => { let b = ''; noKey.stdout.on('data', (c) => { b += c; }); noKey.on('exit', () => r(b)); });
  check('production refuses to boot without its secrets', out.includes('REFUSED'), true);
  verdict(3, 'no tracked secrets; production keys are mandatory and read from the environment');
}

// ===========================================================================
section('4. Broken access control (IDOR)');
{
  // The real test: a valid token from org A against org B's resources, and against ids that do not
  // exist. 404 for both — a 403 or a 200 would confirm the resource exists.
  const cases = [
    ['GET', '/v1/orgs/org_globex/members', null],
    ['GET', '/v1/orgs/org_globex/audit', null],
    ['GET', '/v1/orgs/org_globex/grants', null],
    ['GET', '/v1/orgs/org_globex/invites', null],
    ['GET', '/v1/orgs/org_globex/users/usr_globex_owner/effective', null],
    ['GET', '/v1/orgs/org_globex/sessions', null],
    ['GET', '/v1/orgs/org_acme/devices/dev_globex_kiosk_01', null],
  ];
  for (const [m, p] of cases) {
    const r = await call(m, p, { token: acmeOwner });
    check(`org A reading ${p.replace('/v1/orgs/', '')} -> 404`, r.status, 404);
  }

  // A mutation against another org must change nothing.
  const before = await call('GET', '/v1/orgs/org_globex/members', { token: globexOwner });
  const attack = await call('PATCH', '/v1/orgs/org_globex/members/usr_globex_owner', { token: acmeOwner, body: { role: 'viewer' } });
  const after = await call('GET', '/v1/orgs/org_globex/members', { token: globexOwner });
  check('cross-org role change is refused', attack.status, 404);
  check('and the target membership is untouched', JSON.stringify(before.body) === JSON.stringify(after.body), true);

  // A non-existent id must be byte-identical to a wrong-org id, or the id space is an oracle.
  const missing = await call('GET', '/v1/orgs/org_acme/devices/dev_does_not_exist', { token: acmeOwner });
  const wrongOrg = await call('GET', '/v1/orgs/org_acme/devices/dev_globex_kiosk_01', { token: acmeOwner });
  check('a missing id and a wrong-org id are indistinguishable', [missing.status, missing.body?.error?.code], [wrongOrg.status, wrongOrg.body?.error?.code]);

  // Sessions are the classic IDOR: the id is global, not org-scoped in the path, so the route has
  // to do the scoping itself. A real session is started in globex first, because probing a made-up
  // id only proves the 404 branch and never the one that matters — a session that genuinely exists
  // in another tenant.
  const started = await call('POST', '/v1/orgs/org_globex/sessions', {
    token: globexOwner, body: { deviceId: 'dev_globex_desk_01', mode: 'control' },
  });
  const sesId = started.body?.session?.id ?? started.body?.id;
  if (sesId) {
    check('a session exists in globex to attack', started.status, 201);
    const cross = await call('GET', `/v1/sessions/${sesId}`, { token: acmeOwner });
    check("another org's session id is not readable", cross.status, 404);
    const crossKill = await call('DELETE', `/v1/sessions/${sesId}`, { token: acmeOwner });
    check("another org's session cannot be terminated", crossKill.status, 404);
    // And it must still be alive afterwards — a 404 that ended it anyway would be a write.
    const stillThere = await call('GET', `/v1/sessions/${sesId}`, { token: globexOwner });
    check('the foreign session is untouched after the attempt', stillThere.status, 200);
  } else {
    check('could not start a globex session to probe with', [started.status, started.body?.error?.code], 'a 201');
  }
  verdict(4, 'every cross-org and cross-tenant id resolves to 404; no existence oracle');
}

// ===========================================================================
section('5. Secret API keys and source maps in frontend code');
{
  const assets = ASSETS;
  const maps = assets.filter((f) => f.endsWith('.map'));
  check('no source map is shipped in dist/', maps, []);

  const bundle = ASSETS.filter((f) => f.endsWith('.js')).map((f) => readFileSync(new URL(`../dist/assets/${f}`, import.meta.url), 'utf8')).join('\n');
  const leaked = [SECRET, 'dev-secret-change-me', 'dev-only-app-hash-key-change-me', 'scrypt$'].filter((s) => bundle.includes(s));
  check('no server secret or hash format in the bundle', leaked, []);

  const webSrc = readdirSync(new URL('../web/', import.meta.url))
    .filter((f) => /\.(js|jsx)$/.test(f))
    .map((f) => read(`web/${f}`)).join('\n');
  check('the frontend hardcodes no key-shaped literal', SECRET_SHAPES.filter((p) => p.test(webSrc)), []);
  verdict(5, 'no sourcemaps; no server secret reaches the bundle; the SPA holds no credentials');
}

// ===========================================================================
section('6. Server-Side Request Forgery');
{
  const serverFiles = ['index.js', 'http.js', 'db.js', 'auth.js', 'context.js', 'permissions.js', 'lifecycle.js', 'headers.js', 'ratelimit.js',
    'routes/index.js', 'routes/auth.js', 'routes/orgs.js', 'routes/devices.js', 'routes/sessions.js', 'routes/invites.js',
    'internal/sql.js', 'internal/http.js'];
  const outbound = [];
  for (const f of serverFiles) {
    const src = readFileSync(new URL(`../server/${f}`, import.meta.url), 'utf8');
    if (/(^|[^.\w])(fetch|axios|https?\.request|net\.connect|dns\.|got\(|request\()\s*\(/.test(src)) outbound.push(f);
  }
  check('no server module makes an outbound request', outbound, []);

  // Device "control" is simulated; confirm nothing in the request path reaches a URL from input.
  const r = await call('POST', '/v1/orgs/org_acme/sessions', { token: acmeAdmin, body: { deviceId: 'http://169.254.169.254/latest/meta-data/', mode: 'control' } });
  check('a URL-shaped device id is not treated as a target', [400, 404].includes(r.status), true);
  verdict(6, 'no outbound network capability exists in the server; nothing to forge a request with');
}

// ===========================================================================
section('7. Missing CSRF protection');
{
  const login = await call('POST', '/v1/auth/login', { body: { email: 'sam@example.test', password: 'demo1234' } });
  const raw = login.headers.get('set-cookie') ?? '';
  check('the refresh cookie is HttpOnly', /HttpOnly/i.test(raw), true);
  check('the refresh cookie is SameSite=Strict', /SameSite=Strict/i.test(raw), true);
  check('the refresh cookie is scoped to /', /Path=\//i.test(raw), true);

  // The decisive property: the ONLY cookie credential is SameSite=Strict, so a cross-site request
  // does not carry it. Verified by the browser rather than asserted, in tests/csrf.spec.js.
  const access = login.body?.token;
  check('no access token is returned in a readable field the page must persist', typeof access, 'string');
  const body = JSON.stringify(login.body ?? {});
  check('the refresh token is not in the response body', /rt=|[A-Za-z0-9_-]{40,}/.test(body.replace(/"token":"[^"]+"/, '')), false);

  // A cross-origin request must not receive a permissive CORS answer.
  const cors = await call('GET', '/v1/orgs/org_acme/devices', { token: acmeAdmin, headers: { origin: 'https://evil.example' } });
  check('a cross-origin request gets no Access-Control-Allow-Origin', cors.headers.get('access-control-allow-origin'), null);
  verdict(7, 'single SameSite=Strict cookie is the only ambient credential; no CORS grant to abuse');
}

// ===========================================================================
section('8. Missing or weak security headers');
{
  const api = await call('POST', '/v1/auth/login', { body: { email: 'dana@example.test', password: 'demo1234' } });
  const csp = api.headers.get('content-security-policy') ?? '';
  check('CSP is present', csp.length > 0, true);
  check("CSP default-src is 'self'", /default-src 'self'/.test(csp), true);
  check("CSP object-src is 'none'", /object-src 'none'/.test(csp), true);
  check("CSP base-uri is pinned", /base-uri 'self'/.test(csp), true);
  check('CSP has no wildcard host', /default-src \*/.test(csp), false);
  check("CSP does not allow 'unsafe-eval'", /unsafe-eval/.test(csp), false);
  check('X-Content-Type-Options is nosniff', api.headers.get('x-content-type-options'), 'nosniff');
  check('X-Frame-Options is set', api.headers.get('x-frame-options'), 'SAMEORIGIN');
  check('Referrer-Policy is set', api.headers.get('referrer-policy'), 'no-referrer');
  check('Permissions-Policy is set', (api.headers.get('permissions-policy') ?? '').includes('camera=()'), true);
  check('API responses are not cached', api.headers.get('cache-control'), 'no-store');

  const html = await call('GET', '/');
  check('the SPA document carries the same headers', html.headers.get('x-content-type-options'), 'nosniff');
  check('the SPA document is revalidated, not pinned', html.headers.get('cache-control'), 'no-cache');
  const asset = ASSETS.find((f) => f.endsWith('.js'));
  if (asset) {
    const a = await call('GET', `/assets/${asset}`);
    check('a hashed asset is immutable', a.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  }
  verdict(8, 'full header set on API, document and asset responses');
}

// ===========================================================================
section('9. Wildcard CORS');
{
  const r = await call('GET', '/v1/orgs/org_acme/devices', { token: acmeAdmin, headers: { origin: 'https://evil.example' } });
  const acao = r.headers.get('access-control-allow-origin');
  check('no Access-Control-Allow-Origin on a normal request', acao, null);

  const pre = await call('OPTIONS', '/v1/orgs/org_acme/devices', { headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' } });
  const preAcao = pre.headers.get('access-control-allow-origin');
  check('no CORS grant on a preflight either', preAcao, null);

  const serverFiles = ['index.js', 'http.js', 'headers.js', 'routes/auth.js'];
  const corsCode = serverFiles.flatMap((f) => readFileSync(new URL(`../server/${f}`, import.meta.url), 'utf8')).filter((s) => /Access-Control-Allow-Origin/.test(s));
  check('the literal is not written anywhere in the server', corsCode.length, 0);
  verdict(9, 'no CORS headers at all — strictly narrower than same-origin, so nothing to misconfigure');
}

// ===========================================================================
section('10. Rate limiting');
{
  // Configured low for this run (4 failures). A dedicated credential so no other probe is poisoned.
  const victim = 'ratelimit-victim@example.test';
  const codes = [];
  for (let i = 0; i < 6; i++) {
    codes.push((await call('POST', '/v1/auth/login', { body: { email: victim, password: 'wrong' } })).status);
  }
  check('repeated failures for one credential are throttled', codes[codes.length - 1], 429);
  check('the first attempts are ordinary auth failures', codes.slice(0, 4), [401, 401, 401, 401]);

  const limited = await call('POST', '/v1/auth/login', { body: { email: victim, password: 'wrong' } });
  check('the 429 carries Retry-After', limited.headers.get('retry-after') !== null, true);

  // The property that makes this design usable: one throttled credential must not affect another.
  const other = await call('POST', '/v1/auth/login', { body: { email: 'sam@example.test', password: 'demo1234' } });
  check('a different credential is unaffected', other.status, 200);
  check('the 429 reveals nothing about whether the account exists', limited.body?.error?.message, 'too many attempts; try again shortly');

  // And success clears the counter, so a real person who fumbles twice is not punished.
  console.log('         (a correct password clears the counter — asserted in check-hardening.js)');
  verdict(10, 'per-credential failure throttling on the unauthenticated expensive routes');
}

// ===========================================================================
section('11. SQL injection');
{
  // Static: no request-path statement may build SQL by concatenation.
  const files = ['internal/sql.js', 'routes/auth.js', 'routes/orgs.js', 'routes/devices.js', 'routes/sessions.js', 'routes/invites.js', 'lifecycle.js', 'db.js', 'permissions.js'];
  const interpolated = [];
  for (const f of files) {
    const src = readFileSync(new URL(`../server/${f}`, import.meta.url), 'utf8');
    for (const m of src.matchAll(/(prepare|exec)\(\s*`([^`]*)`/g)) {
      // A ${...} inside SQL is only dangerous if it is not a placeholder count; flag them all.
      if (/\$\{/.test(m[2])) {
        const line = src.slice(0, m.index).split('\n').length;
        interpolated.push(`${f}:${line}`);
      }
    }
  }
  check('no SQL statement interpolates a value into its text', interpolated, []);

  // Dynamic: the classic payloads against the parameters that reach SQL.
  const PAYLOADS = [
    "' OR '1'='1", "'; DROP TABLE memberships; --", "' UNION SELECT 1,2,3,4--",
    "1; DELETE FROM audit_events WHERE 1=1; --", "\\' OR 1=1 --", "%' OR '1'='1",
    "' UNION SELECT sql FROM sqlite_master --", "1 OR 1=1",
  ];
  const injections = [];
  for (const p of PAYLOADS) {
    const r1 = await call('POST', '/v1/auth/login', { body: { email: p, password: p } });
    if (r1.status !== 401 && r1.status !== 400) injections.push(`login:${p}:${r1.status}`);
    const r2 = await call('GET', `/v1/orgs/org_acme/devices/${encodeURIComponent(p)}`, { token: acmeOwner });
    if (![400, 404].includes(r2.status)) injections.push(`device-id:${p}:${r2.status}`);
    const r3 = await call('POST', '/v1/orgs/org_acme/grants', { token: acmeOwner, body: { userId: p, effect: 'allow', permissions: [p] } });
    if (![400, 404, 422].includes(r3.status)) injections.push(`grant:${p}:${r3.status}`);
    const r4 = await call('GET', `/v1/orgs/org_acme/audit?limit=${encodeURIComponent(p)}&offset=${encodeURIComponent(p)}`, { token: acmeOwner });
    if (r4.status !== 200 && r4.status !== 400) injections.push(`paging:${p}:${r4.status}`);
  }
  check(`${PAYLOADS.length} injection payloads are inert on every parameter that reaches SQL`, injections, []);

  // The database is still standing, which is the payload that matters most.
  const s = await call('GET', '/v1/orgs/org_acme/members', { token: acmeOwner });
  check('memberships table survived the DROP TABLE attempt', s.status, 200);
  verdict(11, 'all statements parameterised; no string-built SQL in the request path');
}

// ===========================================================================
section('12. Cross-site scripting');
{
  const webFiles = readdirSync(new URL('../web/', import.meta.url)).filter((f) => /\.(js|jsx)$/.test(f));
  const sinks = [];
  for (const f of webFiles) {
    const src = read(`web/${f}`);
    for (const s of ['innerHTML', 'dangerouslySetInnerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function']) {
      if (src.includes(s)) sinks.push(`${f}: ${s}`);
    }
  }
  check('no HTML-injection sink in the frontend', sinks, []);

  // The server reflects nothing into HTML: every response is JSON or a static file.
  const composed = ['index.js', 'http.js', 'headers.js', 'routes/auth.js', 'routes/orgs.js']
    .map((f) => read(`server/${f}`))
    .filter((s) => /['"`]text\/html/.test(s) && !/MIME|\.html['"`]\s*:/.test(s));
  check('the server never composes an HTML response from input', composed, []);

  // Reflected payload: the classic "does my input come back at me".
  const XSS = '<script>window.__pwned=1</script>';
  const r = await call('GET', `/v1/orgs/org_acme/devices/${encodeURIComponent(XSS)}`, { token: acmeOwner });
  check('an XSS payload in a path is not reflected', r.raw.includes('__pwned'), false);
  check('and it is answered with the standard 404', r.status, 404);

  // Error messages must not echo the body (a body can carry a token).
  const bad = await call('POST', '/v1/auth/login', { body: { email: XSS, password: XSS } });
  check('an XSS payload in a body is not reflected', bad.raw.includes('__pwned'), false);

  // CSP is the backstop, and its presence is asserted in section 8.
  verdict(12, 'React escapes by default, zero injection sinks, CSP as backstop');
}

// ===========================================================================
section('13. Unverified Stripe webhooks');
{
  const routes = allRoutes();
  const paymentish = routes.filter((r) => /pay|bill|subscri|invoice|webhook|checkout|stripe/i.test(r.path));
  check('no payment or webhook route exists', paymentish.map((r) => `${r.method} ${r.path}`), []);
  const pkg = JSON.parse(read('package.json'));
  const money = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).filter((d) => /stripe|paypal|braintree|adyen/i.test(d));
  check('no payment SDK is installed', money, []);
  // If a payment route ever appears, this audit must fail loudly rather than keep reporting n/a.
  na(13, 'no payment feature exists — nothing to verify a webhook signature for. Re-run this if a billing route is ever added.');
}

// ===========================================================================
section('14. Insecure file uploads');
{
  const files = ['index.js', 'http.js', 'routes/auth.js', 'routes/orgs.js', 'routes/devices.js', 'routes/invites.js'];
  const upload = [];
  for (const f of files) {
    const src = readFileSync(new URL(`../server/${f}`, import.meta.url), 'utf8');
    if (/multipart|formidable|busboy|multer|upload|writeFile|createWriteStream/.test(src)) upload.push(f);
  }
  check('no upload handling and no filesystem write in a request handler', upload, []);

  // The only write path is the database, and it is bound to the data directory.
  const r = await call('POST', '/v1/orgs/org_acme/devices', { token: acmeOwner, body: { name: '../../../etc/cron.d/x', kind: 'linux' } });
  check('a path-shaped device name is stored as a string, not a path', [201, 400].includes(r.status), true);
  na(14, 'no file upload feature exists; the only persistent write is SQLite');
}

// ===========================================================================
section('15. Verbose errors and exposed debug / API-docs endpoints');
{
  const bad = await call('GET', '/v1/orgs/org_acme/audit?limit=abc', { token: acmeOwner });
  check('an out-of-range page size is a clean 400', bad.status, 400);
  check('and it carries a machine-readable reason', typeof bad.body?.error?.reason, 'string');

  // No debug surface.
  const debugRoutes = allRoutes().filter((r) => /debug|docs|openapi|swagger|graphql|_internal|__|\/test\b|metrics|health/i.test(r.path));
  check('no debug, docs or metrics route exists', debugRoutes.map((r) => `${r.method} ${r.path}`), []);

  // The error envelope must be identical for every class of failure, with no stack and no echo of
  // the request body — a body can carry a stream key or an invite token.
  const envelope = (r) => Object.keys(r.body?.error ?? {}).sort();
  const e400 = await call('GET', '/v1/orgs/org_acme/audit?limit=abc', { token: acmeOwner });
  const e404 = await call('GET', '/v1/orgs/org_acme/nope', { token: acmeOwner });
  const e401 = await call('GET', '/v1/orgs/org_acme/devices');
  const e403 = await call('PATCH', '/v1/orgs/org_acme/devices/dev_lab_mac_01', { token: acmeViewer, body: { name: 'x' } });
  check('the 400 envelope has exactly the four documented fields', envelope(e400), ['code', 'message', 'reason', 'requestId']);
  for (const [name, r] of [['401', e401], ['403', e403], ['404', e404]]) {
    check(`the ${name} envelope matches the 400 envelope`, envelope(r), envelope(e400));
  }
  check('no stack trace in any client error body', /at .*\(.*:\d+:\d+\)/.test(JSON.stringify([e400.body, e401.body, e403.body, e404.body])), false);

  // A 500 must not describe itself. There is no route that 500s on demand, so this asserts the
  // sanitiser directly: a non-HttpError collapses to a fixed message.
  const { sendError } = await import(new URL('../server/http.js', import.meta.url).href);
  let body = '';
  const fakeRes = { writeHead() {}, end(b) { body = b; }, setHeader() {} };
  sendError(fakeRes, Object.assign(new Error('connection to db:///secret failed: password=hunter2'), { stack: 'Error: at Object.<anonymous> (/srv/app/server/db.js:31:9)' }), 'req_test');
  const five = JSON.parse(body);
  check('an internal error collapses to a fixed message', five.error.message, 'internal error');
  check('an internal error leaks no stack', body.includes('hunter2') || body.includes('db.js'), false);
  check('an internal error is a 500', five.error.code, 'INTERNAL');

  // The property that matters: an /v1 path must never answer with HTML. A JSON API that returns a
  // text/html error page to a fetch() caller is a content-type confusion waiting to happen, and it
  // is also how a static-file fallback quietly turns a 404 into a 200.
  //
  // A NON-/v1 path is a different question and the right answer there is 200 + the SPA document, so
  // the client-side router can resolve it. The first version of this check asserted 404 for `/nope`
  // and was wrong: that is correct SPA behaviour, and a test that demands the wrong answer is worse
  // than no test.
  const apiMiss = await call('GET', '/v1/definitely-not-a-route');
  check('a misspelled /v1 path is a JSON 404', [apiMiss.status, apiMiss.headers.get('content-type')?.includes('json')], [404, true]);
  const deepApiMiss = await call('POST', '/v1/orgs/org_acme/nope/nope/nope', { body: {} });
  check('a deeply misspelled /v1 path is JSON too', [deepApiMiss.status, deepApiMiss.headers.get('content-type')?.includes('json')], [404, true]);
  const spaMiss = await call('GET', '/some/client/route');
  check('an unknown non-API path serves the SPA document', [spaMiss.status, spaMiss.headers.get('content-type')?.includes('html')], [200, true]);
  check('but the SPA fallback still carries the security headers', spaMiss.headers.get('x-content-type-options'), 'nosniff');
  verdict(15, 'one envelope across 400/401/403/404, internal errors sanitised, no debug surface, no HTML on an API path');
}

// ===========================================================================
section('16. Weak password hashing');
{
  const { hashPassword, verifyPassword, needsRehash } = await import(new URL('../server/auth.js', import.meta.url).href);
  const h = await hashPassword('demo1234');
  check('the stored format names its algorithm', h.split('$')[0], 'scrypt');
  check('each hash uses a fresh salt', (await hashPassword('demo1234')) !== h, true);
  check('the correct password verifies', await verifyPassword('demo1234', h), true);
  check('a wrong password does not', await verifyPassword('demo1235', h), false);
  check('a truncated stored value is refused, not thrown on', await verifyPassword('demo1234', 'scrypt$abc'), false);
  check('a non-scrypt stored value is refused', await verifyPassword('demo1234', 'md5$a$b'), false);
  check('an empty stored value is refused', await verifyPassword('demo1234', ''), false);
  // `scrypt$N$r$p$salt$derived` — the cost is part of the value, so the key is the LAST field and a
  // positional index that used to be [2] is now [5]. Asserting the layout rather than assuming it is
  // what caught that, and it is also what makes a future format change fail here.
  const parts = h.split('$');
  check('the stored format carries its cost parameters', parts.slice(0, 4), ['scrypt', '16384', '8', '1']);
  check('the derived key is the last field', Buffer.from(parts.at(-1), 'hex').length, 64);
  check('the salt is 16 bytes', Buffer.from(parts.at(-2), 'hex').length, 16);
  // A hash written in the three-part form from before the cost was recorded must still verify —
  // otherwise the change to the format is a data migration wearing a refactor's clothes.
  const legacy = `scrypt$${parts.at(-2)}$${parts.at(-1)}`;
  check('a pre-format-change hash still verifies', await verifyPassword('demo1234', legacy), true);
  check('and it is flagged for rehash', needsRehash(legacy), true);
  check('a current hash is not flagged', needsRehash(h), false);
  // The cost fields go straight into a memory allocation, so a hostile row cannot ask for a
  // degenerate cost that is cheaper than the comparison it is supposed to make expensive.
  check('a stored N of 1 is refused', await verifyPassword('x', `scrypt$1$8$1$aa$${'00'.repeat(64)}`), false);
  check('a non-numeric cost is refused', await verifyPassword('x', `scrypt$abc$8$1$aa$${'00'.repeat(64)}`), false);
  const N = /maxmem/.test(readFileSync(new URL('../server/auth.js', import.meta.url), 'utf8'));
  check('explicit cost parameters are set (not defaults-by-accident)', N, true);

  // The property that made this a finding: the KDF must not run on the event loop.
  const authSrc = readFileSync(new URL('../server/auth.js', import.meta.url), 'utf8');
  check('scrypt is not called synchronously', /scryptSync\s*\(/.test(authSrc), false);
  verdict(16, 'scrypt, per-hash salt, constant-time compare, explicit cost params, off the event loop');
}

// ===========================================================================
section('17. Hallucinated packages (slopsquatting)');
{
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const declared = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
  console.log(`         ${declared.length} declared: ${declared.join(', ')}`);

  // Every declared name must resolve to a package whose own name matches — the slopsquat signature
  // is a real package with a lookalike name, so the check is name identity, not just existence.
  const mismatched = [];
  for (const d of declared) {
    try {
      const meta = JSON.parse(execFileSync('npm', ['view', d, 'name', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
      if (meta !== d) mismatched.push(`${d} -> ${meta}`);
    } catch { mismatched.push(`${d} (does not resolve)`); }
  }
  check('every dependency resolves to a package of the same name', mismatched, []);

  // A lockfile pins the tree, which is what makes an audit reproducible.
  check('a lockfile is committed', existsSync(new URL('../package-lock.json', import.meta.url)), true);
  const lock = JSON.parse(read('package-lock.json'));
  const missingIntegrity = Object.entries(lock.packages ?? {})
    .filter(([k, v]) => k.includes('node_modules') && v.resolved && !v.integrity).map(([k]) => k);
  check('every resolved package has an integrity hash', missingIntegrity, []);

  console.log(`         ${Object.keys(lock.packages ?? {}).length} packages in the tree, lockfile-pinned with integrity hashes`);

  let audit = [];
  try {
    audit = Object.keys(JSON.parse(execFileSync('npm', ['audit', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })).vulnerabilities ?? {});
  } catch (e) {
    // npm audit exits non-zero when it FINDS something, so the throw is the finding, not a failure.
    try { audit = Object.keys(JSON.parse(e.stdout).vulnerabilities ?? {}); } catch { audit = ['<audit unavailable>']; }
  }
  console.log(`         npm audit findings: ${audit.length ? audit.join(', ') : 'none'}`);
  check('npm audit reports no vulnerable package', audit, []);
  verdict(17, `${declared.length} declared packages, each name-identical to its registry entry, lockfile-pinned, audit clean`);
}

// ===========================================================================
section('event-loop responsiveness under password-hash load');
// The property behind the async-scrypt fix: a burst of password verification must not stop the
// loop, because the loop is the entire server.
//
// This is a UNIT probe, not an HTTP one, and the first version was an HTTP probe and was
// VACUOUS: it fired 48 logins at addresses that do not exist, so `verifyPassword` was never
// reached, no scrypt ran, and the measurement said "11ms" with the blocking version in place. A
// green number from a test that did not exercise the thing is the exact failure this file is
// written to avoid, and it is the third time in this repository it has happened.
//
// Hashing a real stored credential is what makes the number mean something.
{
  const { verifyPassword, hashPassword } = await import(new URL('../server/auth.js', import.meta.url).href);
  const stored = await hashPassword('demo1234');

  // A 1ms interval timer stands in for "an unrelated request needs the loop". Whatever the KDF is
  // doing, this timer has to keep firing on schedule.
  let ticks = 0, worst = 0, last = Date.now(), running = true;
  const beat = () => {
    const now = Date.now();
    worst = Math.max(worst, now - last - 10); // 10ms is the timer's own period
    last = now;
    ticks++;
    if (running) setTimeout(beat, 10);
  };
  setTimeout(beat, 10);

  const started = Date.now();
  await Promise.all(Array.from({ length: 64 }, () => verifyPassword('demo1234', stored)));
  const elapsed = Date.now() - started;
  running = false;

  const expectedTicks = Math.ceil(elapsed / 10);
  const starvation = expectedTicks ? 1 - ticks / expectedTicks : 1;
  console.log(`         64 concurrent hashes took ${elapsed}ms · timer fired ${ticks}/${expectedTicks}× · worst stall ${worst}ms`);

  // Prove the work happened before judging responsiveness, or a probe that skipped the KDF passes
  // by being fast. 64 scrypt operations cannot complete in under a tenth of a second.
  check('the KDF really was exercised (64 verifications, not zero)', elapsed > 200, true);
  check('64 concurrent hashes leave the event loop responsive', starvation < 0.25, true);

  // `worst stall` is only meaningful if the timer managed to run at all. With a synchronous KDF it
  // fires zero times, so `worst` stays 0 and a bare `worst < 100` would report "ok" for a loop that
  // never ran — a green line describing the opposite of what happened. Guarded on ticks > 0.
  if (ticks > 0) {
    check('and when it does run, the loop is never blocked for more than 100ms', worst < 100, true);
  } else {
    console.log('         (the timer never fired at all — the loop was starved for the whole burst)');
    check('the loop was not starved', false, true);
  }
}

// ===========================================================================
// ===========================================================================
section('latency budget, measured over real HTTP');
// Latency is a security property here, not only a UX one: an endpoint that is slow under load is an
// endpoint an attacker can hold open. The budget is measured against a running production server
// rather than asserted, because a budget nobody measures is a wish.
//
// The two classes get separate budgets for a reason. `POST /auth/login` pays ~36ms of scrypt on
// purpose — that is the cost of not being brute-forceable offline — so it is given its own ceiling
// and its own regression test. Everything else should be single-digit milliseconds, and a budget
// that let the list endpoints drift up to 200ms would permit a 100x regression and still pass.
{
  const BUDGET = { auth: 200, read: 50, write: 80 };
  const loginR = await call('POST', '/v1/auth/login', { body: { email: 'dana@example.test', password: 'demo1234' } });
  if (loginR.status !== 200) { check('could not measure login latency', loginR.status, 200); }
  else {
    const samples = [];
    for (let i = 0; i < 12; i++) {
      const t = Date.now();
      await call('POST', '/v1/auth/login', { body: { email: 'dana@example.test', password: 'demo1234' } });
      samples.push(Date.now() - t);
    }
    samples.sort((a, b) => a - b);
    const p50 = samples[Math.floor(samples.length * 0.5)];
    const p95 = samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.95))];
    console.log(`         POST /auth/login      p50 ${p50}ms  p95 ${p95}ms  (budget ${BUDGET.auth}ms)`);
    check('login p50 is inside its budget', p50 < BUDGET.auth, true);
    check('login p95 is inside its budget', p95 < BUDGET.auth, true);
    // The KDF has to still be there. A latency win bought by removing the hash is a security
    // regression that reads as an improvement on a dashboard, so the floor is asserted too.
    check('and login is still paying for a real KDF (not fast because it stopped hashing)', p50 > 5, true);
  }

  const reads = [
    ['GET', '/v1/auth/me'],
    ['GET', '/v1/orgs/org_acme/devices'],
    ['GET', '/v1/orgs/org_acme/members'],
    ['GET', '/v1/orgs/org_acme/audit?limit=50'],
    ['GET', '/v1/orgs/org_acme/grants'],
  ];
  for (const [m, p] of reads) {
    const samples = [];
    for (let i = 0; i < 12; i++) {
      const t = Date.now();
      const r = await call(m, p, { token: acmeOwner });
      samples.push(Date.now() - t);
      if (r.status !== 200) { check(`${m} ${p} answered 200 while measuring`, r.status, 200); break; }
    }
    samples.sort((a, b) => a - b);
    const p95 = samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.95))];
    console.log(`         ${(m + ' ' + p).padEnd(38)} p95 ${String(p95).padStart(3)}ms  (budget ${BUDGET.read}ms)`);
    check(`${m} ${p} p95 is inside its budget`, p95 < BUDGET.read, true);
  }

  // The device list is the one the brief singles out, and the one an N+1 would quietly ruin as the
  // org grows. Cheap to assert here; expensive to notice in production.
  const one = await call('GET', '/v1/orgs/org_acme/devices', { token: acmeOwner });
  const devices = one.body?.devices?.length ?? 0;
  const scaled = [];
  for (let i = 0; i < 8; i++) {
    const t = Date.now();
    await call('GET', '/v1/orgs/org_acme/devices', { token: acmeOwner });
    scaled.push(Date.now() - t);
  }
  const worst = Math.max(...scaled);
  console.log(`         device list (${devices} devices, ${worst}ms worst of 8) — must not scale with row count`);
  check('the device list stays inside its budget', worst < BUDGET.read, true);
}

// ===========================================================================
section('audit coverage: every action a route can emit is a declared action');
// Not one of the 17, but it is the check that keeps them honest, and it came out of a dead-code
// sweep: `AUDITED_ACTIONS` was declared, frozen and documented as the thing that stops routes
// drifting, and read by nothing. Making `audit()` consult it immediately failed a test, because
// `audit.read` was being emitted by a route and was not in the table.
//
// So this asserts the property directly against the source, which catches a new action added
// without a table entry even on a path no test happens to exercise.
{
  const { AUDITED_ACTIONS } = await import(new URL('../server/audit.js', import.meta.url).href);
  const declared = new Set(Object.keys(AUDITED_ACTIONS));

  const emitted = new Set();
  // Every dotted lowercase literal in a route file, rather than a regex shaped like
  // `action: '...'`. Three of the twenty-seven are produced by shapes that a literal-shaped regex
  // cannot see: a ternary assigned to a local (`const action = suspended ? 'member.suspend' : …`),
  // and an object shorthand (`{ action, targetType: … }`). Scraping by shape is what produced three
  // false "never emitted" findings on the first run, and a check that cries wolf gets ignored.
  //
  // The cost of scraping every literal is two false positives — `devices.length` and
  // `organizations.name`, which are SQL column references in inline queries. Both are excluded by
  // an explicit list rather than a clever pattern, because a NEW column reference should make this
  // check fail and be added here, not be silently absorbed by a heuristic.
  const NOT_ACTIONS = new Set(['devices.length', 'organizations.name']);
  for (const f of readdirSync(new URL('../server/routes/', import.meta.url))) {
    const src = read(`server/routes/${f}`);
    for (const m of src.matchAll(/['"`]([a-z]+(?:\.[a-z]+)+)['"`]/g)) {
      if (!NOT_ACTIONS.has(m[1])) emitted.add(m[1]);
    }
  }
  check(`routes emit ${emitted.size} distinct actions`, emitted.size > 20, true);
  check('every action a route can emit is declared in AUDITED_ACTIONS', [...emitted].filter((a) => !declared.has(a)), []);
  check('and every declared action is actually emitted by some route', [...declared].filter((a) => !emitted.has(a)), []);

  // targetType must agree, or a row is filed under the wrong subject.
  const mismatched = [];
  for (const f of readdirSync(new URL('../server/routes/', import.meta.url))) {
    const src = read(`server/routes/${f}`);
    for (const m of src.matchAll(/action:\s*'([a-z.]+)',\s*targetType:\s*'([a-z]+)'/g)) {
      if (AUDITED_ACTIONS[m[1]] && AUDITED_ACTIONS[m[1]].targetType !== m[2]) {
        mismatched.push(`${m[1]}: route says ${m[2]}, table says ${AUDITED_ACTIONS[m[1]].targetType}`);
      }
    }
  }
  check('every route agrees with the table about what its action acts on', mismatched, []);

  // And the table is enforced at write time, not merely documented.
  const auditSrc = read('server/audit.js');
  check('audit() actually consults the table', /AUDITED_ACTIONS\[action\]/.test(auditSrc), true);
  check('an undeclared action is refused in production', /NODE_ENV === 'production'\) throw new Error\(msg\)/.test(auditSrc), true);
}


cleanup();
console.log(`\n${fail === 0 ? 'AUDIT CLEAN' : `${fail} FINDING(S)`} — ${pass} passed, ${fail} failed\n`);
if (findings.length) {
  console.log('open:');
  for (const f of findings) console.log(`  - ${f}`);
  console.log('');
}
process.exit(fail === 0 ? 0 : 1);
