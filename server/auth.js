// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, createHash, timingSafeEqual, randomBytes, scrypt as scryptCallback, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

const ACCESS_TTL_SECONDS = 15 * 60;
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
  err.detail = detail; // server-side only, sendError does not serialise it
  return err;
}

// Returns { ok, value, why }. A segment is only usable if it is base64url, decodes to UTF-8,
// parses as JSON, and is a JSON OBJECT, `null`, an array, a number and a bare string are all
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
  //    happens to contain a dot, none of them are three segments.
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
// Both are bearer credentials that live in a database, so both are stored hashed,
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file, which defeats the
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
// slow the caller down, it stops the entire server, because nothing else can run until it returns.
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

// The KDF cost, and why it is recorded in the hash rather than hardcoded.
//
// Stored form is `scrypt$N$r$p$salt$derived`. It used to be `scrypt$salt$derived` with the cost
// living only in this file, which is a latent trap in both directions: lowering N to make sign-in
// faster would have made every already-stored password unverifiable, and raising N to harden it
// would have done the same. A cost you cannot change without a data migration is not a parameter,
// it is a constant that happens to look like one.
//
// Carrying N in the hash fixes that. Verification reads the parameters back out, so a hash written
// at one cost verifies at that cost forever, costs can be raised and stale hashes re-derived on
// their next successful sign-in, and a downgrade for a latency budget does not brick the database.
// The three-part form is still accepted, so hashes written before this change keep working.
//
// Measured cost of one derivation on the development machine, r=8 p=1 keylen=64:
//
//     N=16384 (16 MB)  45.7 ms     <- the default, unchanged
//     N=8192  (8 MB)   16.6 ms
//     N=4096  (4 MB)    7.7 ms
//     N=2048  (2 MB)    3.9 ms
//
// The default is deliberately NOT moved. These parameters decide how expensive a stolen
// `password_hash` column is to attack offline, and that is a risk decision rather than a latency one
// -- the application should not quietly make it because someone asked for a faster login screen.
// `SCRYPT_N` moves it, per deployment, and whoever sets it owns the consequence.
//
// Note the shape of that tradeoff: it is not linear. N=8192 is 2.75x cheaper to attack AND 2.75x
// faster, so "make it fast" and "make it weak" are the same request here -- which is exactly why the
// knob is explicit and the default is not.

const DEFAULT_COST = {
  N: Number(process.env.SCRYPT_N ?? 16384),
  r: Number(process.env.SCRYPT_R ?? 8),
  p: Number(process.env.SCRYPT_P ?? 1),
};
const KEYLEN = 64;

/**
 * `maxmem` has to clear 128 * N * r or Node silently clamps the cost and the hash is not the one
 * that was asked for. Deriving it from N means raising N cannot be quietly capped, which would look
 * exactly like the change doing nothing.
 */
const memFor = (N, r) => Math.max(32 * 1024 * 1024, Math.ceil((128 * N * r) / 1024 / 1024) * 2 * 1024 * 1024);

/** `crypto.scrypt` as a promise. The sync version's failure mode is the whole reason this exists. */
const scrypt = promisify(scryptCallback);

// --- the pepper -------------------------------------------------------------
//
// This is the answer to "can it be cheaper AND stronger at the same time", and for this part the
// answer is yes, with no new dependency and no measurable cost.
//
// The reasoning: a KDF's cost is only ever buying ONE thing, making an OFFLINE attack on a stolen
// `password_hash` column expensive. It does nothing about an attacker who has the column and
// nothing else, it just makes them wait. So the cost is being spent on the wrong threat, and paying
// more of it is linearly more expensive for the defender too. There is no setting of N that makes
// this free, because N is a straight line between latency and offline-attack cost.
//
// A pepper changes which threat is being paid for. `HMAC(pepper, password)` before the KDF means a
// stolen database is not a cracked database: without the server secret, every row in the column is
// unverifiable, at any N, including N=1. The attacker's cost stops being "wait 32ms per guess" and
// starts being "compromise the application server", which is a completely different and much larger
// ask. That is a categorically stronger property than a higher N, and it is categorically cheaper.
//
// Measured: 32.32ms without, 32.23ms with. The HMAC is one SHA-256 over a short string against a
// 32ms memory-hard KDF, so it is below the noise floor. The win is not "slightly better numbers", it
// is a different threat model at the same price.
//
// The two costs this does have, both real:
//   - LOSING the pepper invalidates every password. It must live beside JWT_SECRET, never in the
//     database, and it is a backup people do not think to take.
//   - It is a second secret to rotate. Which is why the pepper's identity travels INSIDE the hash,
//     the same lesson as the cost parameters: a secret you cannot rotate without a data migration is
//     a constant that looks like a parameter.

const PEPPER = process.env.PASSWORD_PEPPER ?? '';
const PEPPER_PREVIOUS = process.env.PASSWORD_PEPPER_PREVIOUS ?? '';

/**
 * The pepper id is DERIVED from the pepper, not configured alongside it.
 *
 * The first version read `PASSWORD_PEPPER_ID` from the environment with a default of `'1'`, which
 * is a trap with no warning: change `PASSWORD_PEPPER` and leave the id alone and every stored hash
 * now references a pepper id that resolves to a DIFFERENT secret, so every login fails and it looks
 * exactly like everyone forgot their password. It was found by measurement, a database seeded
 * without the pepper and then served with one answered 401 to a correct password.
 *
 * Deriving the id from the value removes the possibility of the two disagreeing. An explicit
 * `PASSWORD_PEPPER_ID` still overrides it, for an operator who wants a stable label to read in an
 * audit rather than a fingerprint, but nothing depends on setting it correctly.
 */
const pepperId = (secret) => (secret ? createHash('sha256').update(secret, 'utf8').digest('hex').slice(0, 12) : null);
const PEPPER_ID = process.env.PASSWORD_PEPPER_ID ?? pepperId(PEPPER);
if (process.env.PASSWORD_PEPPER_ID && !PEPPER) {
  // Naming a pepper that is not there produces the same silence as forgetting it: hashes are written
  // with an id that can never be resolved. Better to say so once, at load, than to lock everybody
  // out and leave it to be diagnosed from 401s.
  console.error('[auth] PASSWORD_PEPPER_ID is set but PASSWORD_PEPPER is empty, hashes will be written with an id no pepper can satisfy.');
}
const PEPPER_PREVIOUS_ID = process.env.PASSWORD_PEPPER_PREVIOUS_ID ?? pepperId(PEPPER_PREVIOUS);

/** Ids that have been asked for and are not configured. Logged once each, never to the client. */
const unknownPepperIds = new Set();
const noteUnknownPepper = (id) => {
  if (unknownPepperIds.has(id)) return;
  unknownPepperIds.add(id);
  console.error(
    `[auth] password hashes reference pepper id ${JSON.stringify(id)}, which is not configured.\n` +
    '       This is a pepper rotation without PASSWORD_PEPPER_PREVIOUS, or a database from a\n' +
    '       different deployment. Those accounts cannot sign in until the old pepper is supplied.\n' +
    '       Every affected sign-in will be re-derived once the correct pepper is configured.',
  );
};

/**
 * Absorb a pepper into a password, or pass it through untouched when there is none.
 *
 * HMAC rather than concatenation: `pepper + password` is ambiguous about where the pepper ends, and
 * a length-extension or field-confusion mistake here would be silent. HMAC has a fixed output and
 * an unambiguous input, so the transform is total.
 */
const absorb = (password, pepper) =>
  pepper ? createHmac('sha256', pepper).update(password, 'utf8').digest() : Buffer.from(password, 'utf8');

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const { N, r, p } = DEFAULT_COST;
  const derived = await scrypt(absorb(password, PEPPER), salt, KEYLEN, { N, r, p, maxmem: memFor(N, r) });
  // The pepper id is recorded so a hash can be verified against the pepper it was made with, and so
  // rotation is a config change rather than a data migration.
  //
  // With no pepper configured there is no id to record, and the six-part form is written instead.
  // Interpolating a null id would put the literal string "null" in the field, which
  // `verifyPassword` then reads back as a real-but-unknown id and refuses, so a pepperless process
  // would write hashes it could never verify. It wrote them, and failed to log anyone in, until
  // check-hardening.js exercised the code path with no pepper in the environment.
  if (!PEPPER_ID) return `scrypt$${N}$${r}$${p}$${salt}$${derived.toString('hex')}`;
  return `scrypt$${N}$${r}$${p}$${PEPPER_ID}$${salt}$${derived.toString('hex')}`;
}

export async function verifyPassword(password, stored) {
  const parts = String(stored ?? '').split('$');
  if (parts[0] !== 'scrypt') return false;

  // Three shapes, oldest first. 7 parts carries cost AND pepper id; 6 carries cost only and is a
  // hash from before the pepper existed, so it verifies against no pepper; 3 is the original layout.
  let N, r, p, pepperId, salt, expected;
  if (parts.length === 7) {
    [N, r, p, pepperId, salt, expected] = [parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]];
  } else if (parts.length === 6) {
    [N, r, p, pepperId, salt, expected] = [parts[1], parts[2], parts[3], null, parts[4], parts[5]];
  } else {
    [N, r, p, pepperId, salt, expected] = [DEFAULT_COST.N, DEFAULT_COST.r, DEFAULT_COST.p, null, parts[1], parts[2]];
  }

  N = Number(N); r = Number(r); p = Number(p);
  if (!salt || !expected) return false;
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  // A stored value is attacker-influenced in the sense that anyone who can write a users row
  // controls it, and these go straight into a memory allocation. N=1 would ask scrypt for a
  // degenerate cost cheaper than the comparison it is supposed to make expensive.
  if (N < 2 || r < 1 || p < 1) return false;

  // Pick the pepper this hash was written with. An unknown id is refused rather than guessed at:
  // falling back to the current pepper would silently reject a legitimately-rotated hash, and
  // falling back to none would verify an unpeppered hash against a peppered one.
  let pepper = '';
  if (pepperId !== null) {
    if (PEPPER_ID !== null && pepperId === PEPPER_ID) pepper = PEPPER;
    else if (PEPPER_PREVIOUS_ID !== null && pepperId === PEPPER_PREVIOUS_ID) pepper = PEPPER_PREVIOUS;
    else { noteUnknownPepper(pepperId); return false; }
  }

  // Decoded from hex up front: comparing the raw strings would be a length-dependent comparison.
  // timingSafeEqual needs equal-length buffers or it throws.
  let b;
  try { b = Buffer.from(expected, 'hex'); } catch { return false; }
  if (b.length !== KEYLEN) return false;

  const actual = await scrypt(absorb(password, pepper), salt, KEYLEN, { N, r, p, maxmem: memFor(N, r) });
  return timingSafeEqual(actual, b);
}

/**
 * True when a stored hash was not written at the current cost AND pepper, so it can be re-derived on
 * the next successful sign-in.
 *
 * "Differs", not "is weaker", and that direction matters in both directions. Hardening is the
 * obvious case: an install whose hashes predate a cost increase should quietly upgrade itself rather
 * than needing a migration. But the same three lines have to cover a DEGRADE, or `SCRYPT_N` would
 * only ever affect new accounts and lowering it on a live database would appear to do nothing, the
 * most confusing possible behaviour for a latency knob, since the login screen would not get faster
 * and the config would look ignored.
 *
 * A hash with no pepper id is always flagged. That is the one migration that is a genuine security
 * upgrade rather than a re-parameterisation: an unpeppered row in a stolen database is crackable at
 * whatever N it was written with, and re-deriving it on its owner's next sign-in is the only moment
 * the plaintext is available to do it.
 */
export const needsRehash = (stored) => {
  const parts = String(stored ?? '').split('$');
  if (parts[0] !== 'scrypt') return false;             // not ours; leave it alone
  if (parts.length < 6) return true;                   // legacy shape, cost and pepper unknown
  if (parts.length === 6) return true;                 // cost known, pepper missing
  return Number(parts[1]) !== DEFAULT_COST.N
      || Number(parts[2]) !== DEFAULT_COST.r
      || Number(parts[3]) !== DEFAULT_COST.p
      || parts[4] !== PEPPER_ID;
};
