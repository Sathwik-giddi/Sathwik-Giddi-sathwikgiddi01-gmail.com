// Response security headers, applied to every response the process emits.
//
// Why this is its own file and not three `setHeader` calls in `index.js`: the headers have to be on
// the JSON path, the static-file path AND the dev/Vite path, and the failure mode is silent. A
// header added to one of three paths looks correct in a test that exercises that path and is absent
// everywhere else. One list, applied once, at the single point where a response is created.
//
// What was actually missing, found by reading the response headers off a running server rather than
// by reading this repository: nothing. There was no CSP, no `X-Content-Type-Options`, no
// `X-Frame-Options`, no `Referrer-Policy` and no `Permissions-Policy` on any response.
//
// The CSP is the one that matters most, and getting it right took two attempts and one browser test:
//
//   1. The first version sent it as `X-Content-Security-Policy`. That was an abandoned draft no
//      browser implements, so the policy was inert — present in a header dump, enforcing nothing.
//      `tests/csp.spec.js` is what caught it, because a header-presence assertion cannot.
//
//   2. The second version was `script-src 'self' 'unsafe-inline'`, added for Vite's dev client.
//      `'unsafe-inline'` permits inline script, which is the single thing a CSP exists to stop — a
//      browser test that injects an inline script and checks whether it ran proved the policy was
//      doing nothing. The 34 UI tests all passed, because "does not break the app" and "blocks
//      attacks" are different questions and only one of them was being asked.
//
// So the policy is environment-dependent, because the requirement genuinely is. The production
// bundle is two external hashed files and no inline script or style at all — verified by reading
// dist/index.html — so production gets the strict form. Only the Vite dev client needs the
// permissive one, and dev is not what ships.

const DEV = process.env.NODE_ENV !== 'production';

/**
 * `script-src` and `style-src` differ per environment, and ONLY these two directives.
 *
 * Production is `'self'`: no inline script, no eval, no external origin. That is the directive
 * that turns a stored-XSS foothold into a non-event, and permitting `'unsafe-inline'` for
 * convenience gives it away while still looking like a policy in review.
 *
 * Dev adds `'unsafe-inline'` because Vite injects an inline module preamble and the HMR client,
 * and refuses to boot without it. It also needs `ws:` in `connect-src` for the HMR socket.
 */
const SCRIPT_STYLE = DEV
  ? { 'script-src': "'self' 'unsafe-inline'", 'style-src': "'self' 'unsafe-inline'" }
  : { 'script-src': "'self'", 'style-src': "'self'" };

const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'self'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  // The directive NAME is part of the value. Building these as bare source expressions produced a
  // policy reading `… font-src 'self'; 'self'; 'self'; connect-src 'self'` — two nameless
  // directives that Chrome discards. Blocking still worked, because `default-src 'self'` was
  // acting as the fallback, so every test that checked behaviour passed while the policy said
  // something other than what it was written to say.
  `script-src ${SCRIPT_STYLE['script-src']}`,
  `style-src ${SCRIPT_STYLE['style-src']}`,
  DEV ? "connect-src 'self' ws: wss:" : "connect-src 'self'",
  // `frame-ancestors` supersedes X-Frame-Options; both are sent because they fail in different
  // browser versions. `upgrade-insecure-requests` is deliberately absent — the Playwright suite
  // runs a production build over plain http on localhost, where this directive would rewrite the
  // test's own URLs. It belongs at the proxy, with a real certificate.
].join('; ');

/**
 * The header set for an API response. `no-store` is already set by `send()`; repeated here so this
 * function is the whole answer to "what goes on a response".
 */
const BASE = {
  // Tells the browser not to guess a response's type from its bytes. Without it a browser will
  // happily run a JSON or SVG body as script if something upstream lets an attacker control the
  // content type — which is the entire class of bug that `X-Content-Type-Options: nosniff` exists
  // to close. Cheap, and there is no reason for this API to serve sniffed content.
  'x-content-type-options': 'nosniff',

  // Clickjacking. `SAMEORIGIN` rather than `DENY` because the console is a same-origin SPA served
  // by this same process, so there is no legitimate framing case, but SAMEORIGIN is the value that
  // survives someone embedding the app in a review harness on the same origin. This is belt-and-
  // braces alongside the CSP's `frame-ancestors 'self'`, which is the one that actually holds in
  // modern browsers — kept both because the two fail in different browser versions.
  'x-frame-options': 'SAMEORIGIN',

  // The URL of this app carries no path segment worth leaking and no query string at all, so the
  // strictest useful value costs nothing. `strict-origin-when-cross-origin` is the browser default;
  // being explicit means a future default change cannot loosen this silently.
  'referrer-policy': 'no-referrer',

  // The console uses no camera, microphone, geolocation, payment or USB API, so every powerful
  // feature the browser exposes is denied. This is the header that stops a future
  // copy-pasted snippet from quietly asking for a permission the product never intended to request.
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',

  // Turn off the features this app has no use for. `eval` is the important one: it is the single
  // biggest XSS amplifier, and a build with no `unsafe-eval` cannot be walked out of by an injected
  // string even if one gets past React's escaping.
  //
  // The header name is `Content-Security-Policy`, with no `X-` prefix — see the note at the top of
  // this file for why that is not a detail.
  'content-security-policy': CSP,

  // HSTS. Only meaningful over TLS, and only honoured over TLS, so it is deliberately NOT sent over
  // plain http: a browser that saw it on localhost would then refuse to talk to the test server, and
  // a browser that saw it on a real http deployment has been downgraded already. Set this at the
  // proxy, in front of a real certificate, where it belongs.
  // 'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

/**
 * Static assets are content-addressed by Vite (`index-CMc7VP8v.js`), so they can be cached hard and
 * an API response never can. `index.html` is the exception — it names the hashed bundle, so caching
 * it pins a client to an old build — and is served `no-cache`, which revalidates rather than
 * refusing to store.
 */
const STATIC_ASSET = { ...BASE, 'cache-control': 'public, max-age=31536000, immutable' };
const STATIC_HTML = { ...BASE, 'cache-control': 'no-cache' };

/**
 * Long-lived immutable assets only. A hashed file under dist/assets/ is safe to pin for a year; the
 * SPA entry document is not, and gets `no-cache` instead.
 */
export function headersFor(pathname) {
  if (pathname.startsWith('/assets/')) return STATIC_ASSET;
  if (pathname === '/' || pathname.endsWith('.html') || pathname.endsWith('/')) return STATIC_HTML;
  return { ...BASE, 'cache-control': 'no-cache' };
}

/** Headers for any `/v1/*` JSON response. */
export function apiHeaders() {
  return { ...BASE, 'cache-control': 'no-store' };
}
