// Measure what the brief asks to be able to defend: query counts per request, and latency.
//
//   node scripts/measure.js
//
// Two separate things, measured two separate ways, because one number cannot stand in for the
// other:
//
//   QUERIES  counted in-process, by wrapping better-sqlite3's Statement methods BEFORE the server
//            modules are imported, then invoking the real route handlers with fake req/res. This
//            counts EXECUTED statements, not prepared ones — the statement registry compiles each
//            query once per connection, so counting `prepare` would undercount every endpoint by
//            the number of distinct queries it uses.
//
//   LATENCY  measured over real HTTP against a real server, because a handler invoked in-process
//            skips serialisation, the socket and JSON encoding, which is most of what a person
//            waiting at a screen actually waits for.
//
// Both are printed as raw numbers on purpose. The point of the exercise is that these are
// measurements, not adjectives.

import { performance } from 'node:perf_hooks';
import { EventEmitter } from 'node:events';
import Database from 'better-sqlite3';
import { readFileSync, rmSync, existsSync } from 'node:fs';

// --- count executed statements ----------------------------------------------
const counts = new Map();
let counting = false;
let current = null;

const bump = (sql) => {
  if (!counting) return;
  const key = `${current}  ${sql.replace(/\s+/g, ' ').trim().slice(0, 68)}`;
  counts.set(key, (counts.get(key) ?? 0) + 1);
};

// Wrapped before anything imports the server, so every statement the server prepares is wrapped.
const originalPrepare = Database.prototype.prepare;
Database.prototype.prepare = function (sql) {
  const statement = originalPrepare.call(this, sql);
  for (const method of ['run', 'get', 'all']) {
    const original = statement[method].bind(statement);
    statement[method] = (...args) => { bump(sql); return original(...args); };
  }
  return statement;
};
const originalExec = Database.prototype.exec;
Database.prototype.exec = function (sql) { bump(`exec: ${String(sql).slice(0, 40)}`); return originalExec.call(this, sql); };

// --- build a real database ---------------------------------------------------
const DB_FILE = 'measure.db';
for (const suffix of ['', '-wal', '-shm']) if (existsSync(DB_FILE + suffix)) rmSync(DB_FILE + suffix);

const { execFileSync } = await import('node:child_process');
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB_FILE }, stdio: 'ignore' });

const { openDatabase } = await import('../server/db.js');
const { createRouter } = await import('../server/router.js');
const { registerRoutes } = await import('../server/routes/index.js');
const { issueAccessToken } = await import('../server/auth.js');

const SECRET = 'measure-secret';
const db = openDatabase(DB_FILE);
const router = createRouter();
registerRoutes(router, { db, secret: SECRET });

// --- fake req / res ----------------------------------------------------------
function fakeRes() {
  return {
    statusCode: 0, payload: null, headers: {},
    writeHead(status, headers) { this.statusCode = status; this.headers = headers ?? {}; return this; },
    end(body) { this.payload = body; return this; },
    setHeader(k, v) { this.headers[k] = v; return this; },
    getHeader(k) { return this.headers[k]; },
  };
}

function fakeReq(method, body, token) {
  const req = new EventEmitter();
  req.method = method;
  req.headers = token ? { authorization: `Bearer ${token}` } : {};
  process.nextTick(() => {
    if (body !== undefined) req.emit('data', Buffer.from(JSON.stringify(body)));
    req.emit('end');
  });
  return req;
}

const tokenFor = (userId, orgId) => {
  const m = db.prepare('SELECT role, perm_version FROM memberships WHERE org_id=? AND user_id=?').get(orgId, userId);
  return issueAccessToken({ userId, orgId, role: m.role, permVersion: m.perm_version }, SECRET);
};

/** Invoke a real route handler through the real pipeline and return { status, body, queries }. */
async function call(method, path, { token, body } = {}) {
  const url = new URL(`http://x${path}`);
  const hit = router.match(method, url.pathname);
  if (!hit) return { status: 404, body: null, queries: 0 };

  counts.clear();
  counting = true;
  current = `${method} ${path}`;

  const ctx = { db, secret: SECRET, requestId: 'req_measure', query: url.searchParams, body: {}, req: fakeReq(method, body, token) };

  const { authenticate } = await import('../server/context.js');
  const PUBLIC = new Set(['POST /v1/auth/login', 'POST /v1/auth/refresh', 'GET /v1/invites/:token', 'POST /v1/invites/:token/accept']);
  try {
    if (!PUBLIC.has(`${method} ${hit.pattern}`)) Object.assign(ctx, authenticate(db, SECRET)(ctx.req, hit.params));
    if (method !== 'GET' && method !== 'DELETE') ctx.body = await import('../server/http.js').then((m) => m.readJson(ctx.req));
    const res = fakeRes();
    await hit.handler(ctx, hit.params, res);
    counting = false;
    const snapshot = new Map(counts);
    return { status: res.statusCode, body: res.payload ? JSON.parse(res.payload) : null, queries: [...snapshot.values()].reduce((a, b) => a + b, 0), detail: snapshot };
  } catch (err) {
    counting = false;
    return { status: err.status ?? 500, body: { error: { code: err.code, message: err.message, reason: err.reason } }, queries: [...counts.values()].reduce((a, b) => a + b, 0) };
  }
}

const danaAcme = tokenFor('usr_dana', 'org_acme');
const danaGlobex = tokenFor('usr_dana', 'org_globex');
const viewerAcme = tokenFor('usr_acme_viewer', 'org_acme');

// =============================================================================
console.log('\n\x1b[1mQUERIES PER REQUEST\x1b[0m   (executed statements, not prepared ones)\n');

const scenarios = [
  ['GET  /auth/me                    (boot)', () => call('GET', '/v1/auth/me', { token: danaAcme })],
  ['GET  /orgs/:o/devices            (5 devices, per-row perms)', () => call('GET', '/v1/orgs/org_acme/devices', { token: danaAcme })],
  ['GET  /orgs/:o/devices            (viewer: 4 visible of 5)', () => call('GET', '/v1/orgs/org_acme/devices', { token: viewerAcme })],
  ['GET  /orgs/:o/grants             (+ members, devices)', () => call('GET', '/v1/orgs/org_acme/grants', { token: danaAcme })],
  ['GET  /orgs/:o/sessions', () => call('GET', '/v1/orgs/org_acme/sessions', { token: danaAcme })],
  ['GET  /orgs/:o/audit?limit=50', () => call('GET', '/v1/orgs/org_acme/audit?limit=50', { token: danaAcme })],
  ['GET  /orgs/:o/members', () => call('GET', '/v1/orgs/org_acme/members', { token: danaAcme })],
  ['GET  /orgs/:o/users/:u/effective', () => call('GET', '/v1/orgs/org_acme/users/usr_sam/effective', { token: danaAcme })],
  ['GET  /reference', () => call('GET', '/v1/reference', { token: danaAcme })],
  ['POST /orgs/:o/sessions           (start)', () => call('POST', '/v1/orgs/org_globex/sessions', { token: danaGlobex, body: { deviceId: 'dev_globex_kiosk_02', mode: 'view' } })],
  ['GET  cross-org device list       (404 path)', () => call('GET', '/v1/orgs/org_globex/devices', { token: danaAcme })],
];

const results = [];
for (const [label, run] of scenarios) {
  const r = await run();
  results.push([label, r]);
  const flag = r.status >= 400 ? '\x1b[33m' : '\x1b[32m';
  console.log(`  ${flag}${String(r.queries).padStart(3)}\x1b[0m  ${String(r.status).padStart(3)}  ${label}`);
}

console.log('\n\x1b[1mWHERE THE QUERIES GO\x1b[0m — the device list, which is the one the brief singles out\n');
{
  const detail = results[1][1].detail;
  for (const [sql, n] of [...detail].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(n).padStart(3)}x  ${sql.replace(/^\S+\s{2}/, '')}`);
  }
  const total = [...detail].reduce((a, [, n]) => a + n, 0);
  console.log(`\n  \x1b[2m5 devices, 5 per-row permission maps, ${total} statements total.\x1b[0m`);
  console.log(`  \x1b[2mA per-device query loop would be 3 + 5 = 8, and would grow with the org.\x1b[0m`);
}

// =============================================================================
// Latency, over real HTTP.
console.log('\n\x1b[1mLATENCY OVER REAL HTTP\x1b[0m   (production server, fresh process each run)\n');

const { spawn } = await import('node:child_process');
const PORT = 8177;
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB_FILE, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: SECRET, APP_HASH_KEY: SECRET },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 900));

async function timed(label, fn, runs = 40) {
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await fn();
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const p50 = samples[Math.floor(runs * 0.5)];
  const p95 = samples[Math.floor(runs * 0.95)];
  console.log(`  \x1b[32m${p50.toFixed(1).padStart(6)} ms\x1b[0m p50   ${p95.toFixed(1).padStart(6)} ms p95   ${label}`);
  return p50;
}

const base = `http://localhost:${PORT}/v1`;
const json = { 'content-type': 'application/json' };

// Sign in once to get a token for the latency runs.
const loginRes = await fetch(`${base}/auth/login`, { method: 'POST', headers: json, body: JSON.stringify({ email: 'dana@example.test', password: 'demo1234' }) });
const { token } = await loginRes.json();
const auth = { authorization: `Bearer ${token}`, ...json };

await timed('POST /auth/login            (scrypt password verify)', async () => {
  await fetch(`${base}/auth/login`, { method: 'POST', headers: json, body: JSON.stringify({ email: 'dana@example.test', password: 'demo1234' }) });
}, 20);

await timed('GET  /auth/me               (console boot)', () => fetch(`${base}/auth/me`, { headers: auth }));
await timed('GET  /orgs/:o/devices       (the first screen)', () => fetch(`${base}/orgs/org_acme/devices`, { headers: auth }));
await timed('GET  /orgs/:o/audit?limit=50', () => fetch(`${base}/orgs/org_acme/audit?limit=50`, { headers: auth }));
await timed('GET  /auth/me  with a STALE token (pv mismatch)', () => {
  const stale = token.slice(0, token.lastIndexOf('.') + 1) + 'x'.repeat(43);
  return fetch(`${base}/auth/me`, { headers: { authorization: `Bearer ${stale}` } });
}, 20);

server.kill();
db.close();
for (const suffix of ['', '-wal', '-shm']) if (existsSync(DB_FILE + suffix)) rmSync(DB_FILE + suffix);
console.log();
