// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scrypt as scryptCallback, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// The verifying half. `node scripts/check-jwt.js` is the suite.
//
// Design notes, because two of these choices are load-bearing:
//
//  - The header is DATA, never a decision. I compare `header.alg` against my own ALG constant
//    and refuse anything else, rather than switching on what the header asks for. A denylist
//    (`alg !== 'none' && alg !== 'HS256'`) has to be updated every time a new algorithm exists;
//    an allowlist of exactly one value cannot be defeated by a header I have not thought about.
//
//  - Every rejection carries the SAME client-facing message, and puts the specific cause on a
//    non-serialised `detail` property. `sendError` only copies status/code/message/reason, so the
//    cause reaches the server log and never the response. Telling an attacker *which* check
//    failed turns the verifier into an oracle for forging one; keeping it internally is what
//    makes a 401 debuggable without being informative to the caller.
// ---------------------------------------------------------------------------

// base64url, and nothing else. Buffer.from(_, 'base64url') silently DISCARDS characters outside
// the alphabet, so a segment of '!!!not-base64!!!' would decode to a short buffer and only fail
// later on a length comparison. Testing the segment first turns that into an explicit refusal.
const B64URL = /^[A-Za-z0-9_-]+$/;

function reject(detail) {
  const err = unauthenticated('invalid access token');
  err.detail = detail; // server-side only — sendError does not serialise it
  return err;
}

// Returns { ok, value, why }. A segment is only usable if it is base64url, decodes to UTF-8,
// parses as JSON, and is a JSON OBJECT — `null`, an array, a number and a bare string are all
// refused, because every field read below assumes an object.
function decodeSegment(segment) {
  if (!B64URL.test(segment)) return { ok: false, why: `${segment.length}-char segment is not base64url` };

  let text;
  try {
    text = unb64(segment).toString('utf8');
  } catch {
    return { ok: false, why: 'segment does not decode as utf-8' };
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, why: 'segment is not JSON' };
  }

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, why: 'segment is JSON but not an object' };
  }

  return { ok: true, value };
}

const isNonEmptyString = (v) => typeof v === 'string' && v.length > 0;

export function verifyAccessToken(token, secret) {
  // 1. shape. Covers null, undefined, '', an opaque refresh token, and a refresh token that
  //    happens to contain a dot — none of them are three segments.
  if (!isNonEmptyString(token)) throw reject('token is not a non-empty string');
  const parts = token.split('.');
  if (parts.length !== 3) throw reject(`${parts.length} segments, expected 3`);
  const [encodedHeader, encodedPayload, signature] = parts;
  if (!encodedHeader || !encodedPayload || !signature) throw reject('empty segment');

  // 2. header: parse, then pin the algorithm. Nothing below reads `alg` again.
  const header = decodeSegment(encodedHeader);
  if (!header.ok) throw reject(`header ${header.why}`);
  if (header.value.alg !== ALG) throw reject(`alg is ${JSON.stringify(header.value.alg)}, not ${ALG}`);
  if (header.value.typ !== 'JWT') throw reject(`typ is ${JSON.stringify(header.value.typ)}, not JWT`);

  // 3. signature, over the exact bytes that were sent, in constant time. This happens BEFORE
  //    any claim is trusted, so a swapped payload with a replayed signature is refused here and
  //    never reaches claim validation.
  const expected = createHmac('sha256', secret).update(`${encodedHeader}.${encodedPayload}`).digest();
  const actual = unb64(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw reject('signature does not match');
  }

  // 4. now the payload is authentic, so its claims can be believed.
  const decoded = decodeSegment(encodedPayload);
  if (!decoded.ok) throw reject(`payload ${decoded.why}`);
  const claims = decoded.value;

  // Half-open, like a grant window (D7): exp == now is already expired.
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) {
    throw reject(`exp is ${JSON.stringify(claims.exp)}, not a number`);
  }
  if (claims.exp <= now) throw reject(`exp ${claims.exp} <= now ${now}`);

  if (claims.iss !== ISS) throw reject(`iss is ${JSON.stringify(claims.iss)}`);
  if (claims.aud !== AUD) throw reject(`aud is ${JSON.stringify(claims.aud)}`);
  if (!isNonEmptyString(claims.jti)) throw reject('jti missing or empty');

  // The four claims the request pipeline cannot work without. issueAccessToken always sets
  // them, so requiring them costs nothing and stops a hand-rolled token with no `org` from
  // being read as "the empty org", which would be a scoping bug rather than a 401.
  if (!isNonEmptyString(claims.sub)) throw reject('sub missing or empty');
  if (!isNonEmptyString(claims.org)) throw reject('org missing or empty');
  if (!isNonEmptyString(claims.role)) throw reject('role missing or empty');
  if (!Number.isInteger(claims.pv)) throw reject(`pv is ${JSON.stringify(claims.pv)}, not an integer`);

  return claims;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------
//
// ASYNC, and that is a security property rather than a style choice.
//
// These used to be `scryptSync`. On a single-threaded event loop a synchronous KDF does not just
// slow the caller down — it stops the entire server, because nothing else can run until it returns.
// Measured on this codebase: 1 concurrent sign-in stalled the loop ~41ms, and 64 stalled it for
// 2641ms, because every hash after the first queued behind the one in progress. The work is
// deliberately expensive, so "make it slower" is exactly the wrong response to a slow login: the
// cost lands on every other request in the meantime, turning an unauthenticated endpoint into a
// lever for stalling authenticated ones.
//
// `crypto.scrypt` off the sync binding runs on the libuv threadpool instead, so the loop stays
// responsive and the concurrency is bounded by the pool (UV_THREADPOOL_SIZE, default 4) rather than
// serialised. That bound is also the reason a rate limiter is not optional: four hashes at a time is
// still four, and it is still unauthenticated input driving it.

const SCRYPT = { keylen: 64, N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// crypto.scrypt takes its options object with cost parameters at the top level, not nested under
// `cost`, so the shared object above is spread rather than passed whole.
const SCRYPT_OPTIONS = { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem };

/** `crypto.scrypt` as a promise. The sync version's failure mode is the whole reason this exists. */
const scrypt = promisify(scryptCallback);

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, SCRYPT.keylen, SCRYPT_OPTIONS);
  return `scrypt$${salt}$${derived.toString('hex')}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  // Decoded from hex up front: comparing the raw strings would be a length-dependent comparison,
  // and the stored value is attacker-influenced in the sense that anyone who can write a users row
  // controls it. timingSafeEqual needs equal-length buffers or it throws.
  let b;
  try { b = Buffer.from(expected, 'hex'); } catch { return false; }
  if (b.length !== SCRYPT.keylen) return false;
  const actual = await scrypt(password, salt, SCRYPT.keylen, SCRYPT_OPTIONS);
  return timingSafeEqual(actual, b);
}
