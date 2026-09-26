// The whole application: one process, one port.
//
//   /v1/*  -> the API (routes registered in server/routes/)
//   else   -> the SPA (Vite middleware in dev for HMR, static dist/ in production)
//
// Run:  npm run dev     (one command, both halves, hot reload)
//       npm run build && npm start

import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

import { createRouter } from './router.js';
import { openDatabase } from './db.js';
import { send, sendError, readJson, notFound } from './http.js';
import { authenticate } from './context.js';
import { headersFor } from './headers.js';
import { registerRoutes } from './routes/index.js';

const DEV = process.env.NODE_ENV !== 'production';
const PORT = Number(process.env.PORT ?? 8080);
const DIST = new URL('../dist/', import.meta.url).pathname;

/**
 * A required secret, or a refusal to start.
 *
 * This used to be `process.env.JWT_SECRET ?? 'dev-secret-change-me'`, and that fallback was
 * reachable in production: `npm start` sets NODE_ENV=production and does not set JWT_SECRET, so
 * the documented way to run the app signed every token with a literal that is published in the
 * source. scripts/pentest.js mints a token with it and reads the org's devices.
 *
 * A dev default is still useful — `npm run dev` should work with no setup — so the fallback
 * survives, but ONLY off the production path. In production a missing key is fatal at boot
 * rather than a warning, because a server that starts with a known signing key is worse than a
 * server that does not start: the first one looks healthy and fails open.
 */
function requireSecret(name, devFallback) {
  const value = process.env[name];
  if (typeof value === 'string' && value.length > 0) return value;
  if (DEV) return devFallback;
  const gen = `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`;
  throw new Error(
    `${name} must be set when NODE_ENV=production.\n` +
      `  Generate one:  ${gen}\n` +
      `  Then:          ${name}=<that value> npm start`,
  );
}

const SECRET = requireSecret('JWT_SECRET', 'dev-secret-change-me');

// The same mistake one line away, and it was worth fixing while here. auth.js HMACs refresh and
// invite tokens with APP_HASH_KEY before storing them, and its own comment says the key "is an
// application secret, not a hardcoded literal" — while defaulting to exactly that. A known key
// does not make a 256-bit random token guessable, but it does make the stored hash reproducible
// by anyone holding the database, which is the whole reason for storing a hash. Exported rather
// than kept local because auth.js reads it back off process.env at module load.
process.env.APP_HASH_KEY = requireSecret('APP_HASH_KEY', 'dev-only-app-hash-key-change-me');

const db = openDatabase();
const router = createRouter();
registerRoutes(router, { db, secret: SECRET });

// Routes reachable without a token. Everything else requires a valid JWT.
const PUBLIC_ROUTES = new Set([
  'POST /v1/auth/login',
  'POST /v1/auth/refresh',
  'GET /v1/invites/:token',
  'POST /v1/invites/:token/accept',
  // The refresh cookie is the credential for signing out, so this must work with no bearer token.
  // It was missing from this list while `web/api.js` called it with `{ auth: false }` — the route
  // 401'd, the console swallowed it in a bare `catch {}`, and a reload silently signed the person
  // back in. The control existed, was called, and did nothing.
  'POST /v1/auth/logout',
]);

// ---------------------------------------------------------------------------
// The request pipeline. Read this top to bottom and you know how the app works.
// ---------------------------------------------------------------------------
async function handleApi(req, res, url) {
  const requestId = `req_${crypto.randomUUID().slice(0, 8)}`;

  try {
    const hit = router.match(req.method, url.pathname);
    if (!hit) throw notFound();

    const ctx = { db, secret: SECRET, requestId, query: url.searchParams, body: {}, req };

    const key = `${req.method} ${hit.pattern}`;
    if (!PUBLIC_ROUTES.has(key)) {
      Object.assign(ctx, authenticate(db, SECRET)(req, hit.params));
    }

    if (req.method !== 'GET' && req.method !== 'DELETE') {
      ctx.body = await readJson(req);
    }

    await hit.handler(ctx, hit.params, res);
  } catch (err) {
    sendError(res, err, requestId);
  }
}

// ---------------------------------------------------------------------------
// Production static files. ~25 lines, no dependency, no surprises.
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

async function serveStatic(req, res, url) {
  // normalize() collapses '..' so a crafted path cannot escape dist/.
  //
  // The decode is guarded because `decodeURIComponent` THROWS `URIError` on a malformed
  // percent-escape — `GET /%ff` is enough — and this function is called straight from the request
  // listener with nothing in between. Unguarded, that throw was an uncaught exception and it took
  // the whole process down: one unauthenticated request, no valid route needed, and `npm start`
  // has no supervisor to bring it back. Verified before the fix: after a single `GET /%ff` the
  // listener count on the port went to zero and every subsequent request was connection-refused.
  let rel;
  try {
    rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  } catch {
    return send(res, 400, { error: { code: 'VALIDATION', message: 'malformed request path', reason: 'malformed_path', requestId: null } });
  }

  let file = join(DIST, rel);

  try {
    const info = await stat(file);
    if (info.isDirectory()) file = join(file, 'index.html');
  } catch {
    file = join(DIST, 'index.html'); // SPA fallback: let the client router handle it
  }

  try {
    const body = await readFile(file);
    res.writeHead(200, {
      'content-type': MIME[extname(file)] ?? 'application/octet-stream',
      'content-length': body.length,
      ...headersFor(url.pathname),
    });
    res.end(body);
  } catch {
    send(res, 404, { error: { code: 'NOT_FOUND', message: 'not found', reason: null, requestId: null } });
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
let vite = null;
if (DEV) {
  const { createServer } = await import('vite');
  vite = await createServer({ server: { middlewareMode: true }, appType: 'spa' });
  console.log('vite middleware attached (HMR enabled)');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/v1' || url.pathname.startsWith('/v1/')) {
    return handleApi(req, res, url);
  }

  if (vite) return vite.middlewares(req, res, () => send(res, 404, { error: { code: 'NOT_FOUND' } }));
  return serveStatic(req, res, url);
});

server.listen(PORT, () => {
  console.log(`RemoteOps on http://localhost:${PORT}  (${DEV ? 'development' : 'production'})`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}

// ---------------------------------------------------------------------------
// Last-resort net.
//
// Everything above this line is inside a try/catch, and that is where a failure belongs: a request
// gets a response and the process carries on. This handler exists for the class of bug where
// something throws on a path nobody guarded — the `decodeURIComponent` one above was found by
// sending `GET /%ff` and watching the process disappear.
//
// It logs loudly and keeps serving, deliberately. The alternative — an uncaught exception
// terminating the process — means one malformed request takes down a server whose whole job is
// answering requests, and `npm start` has no supervisor. Nothing here mutates state: SQLite is
// synchronous, so a throw inside a handler cannot leave a transaction half-applied.
// ---------------------------------------------------------------------------
process.on('uncaughtException', (err) => {
  console.error('[uncaught] continuing after:', err);
});

process.on('unhandledRejection', (reason) => {
  console.error('[unhandled rejection] continuing after:', reason);
});
