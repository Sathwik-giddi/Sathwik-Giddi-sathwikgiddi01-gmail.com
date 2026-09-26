// Small helpers shared by more than one route. Anything that is a RULE lives in permissions.js,
// lifecycle.js or audit.js instead — this file is plumbing only.

import { badRequest, forbidden } from '../http.js';
import { stmt } from './sql.js';
import { nowIso, newId } from '../db.js';

// --- cookies ----------------------------------------------------------------
// Hand-rolled, because the process has exactly one dependency (better-sqlite3) and a cookie
// parser is not worth a package. The refresh cookie is the only one this server sets.

export function parseCookies(req) {
  const header = req.headers?.cookie;
  const out = Object.create(null);
  if (typeof header !== 'string' || header.length === 0) return out;

  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const name = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (name.length === 0) continue;

    // A cookie value is attacker-controlled and `decodeURIComponent` throws on a malformed escape
    // — `Cookie: rt=%` was enough. This parser runs on `POST /v1/auth/refresh`, which is PUBLIC and
    // which the console calls on every single page load, so an unguarded throw there meant one
    // stray percent sign anywhere on the origin bricked the boot path with a 500.
    //
    // A value that will not decode is kept raw rather than dropped: the token is compared by hash,
    // so a mangled value simply fails to match, which is the correct outcome and needs no special
    // case. The one thing that must not happen is throwing.
    let value = raw;
    try {
      value = decodeURIComponent(raw);
    } catch {
      /* keep the raw value; it will not match any token hash */
    }
    out[name] = value;
  }
  return out;
}

export const REFRESH_COOKIE = 'rt';

/**
 * `Secure` is set from the transport, not from NODE_ENV. The Playwright config runs the
 * production server over http://localhost, and a browser drops a `Secure` cookie received over
 * plain http — so keying this off NODE_ENV would silently break "a reload restores the session
 * from the refresh cookie" and nothing would say why. Behind a TLS-terminating proxy the
 * forwarded protocol is the honest signal.
 */
export function setRefreshCookie(res, token, maxAgeSeconds, req) {
  const forwarded = String(req?.headers?.['x-forwarded-proto'] ?? '').split(',')[0].trim();
  const isHttps = req?.socket?.encrypted === true || forwarded === 'https';

  const parts = [
    `${REFRESH_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (isHttps) parts.push('Secure');

  const existing = res.getHeader('set-cookie');
  const list = Array.isArray(existing) ? existing : existing ? [existing] : [];
  res.setHeader('set-cookie', [...list, parts.join('; ')]);
}

export function clearRefreshCookie(res, req) {
  setRefreshCookie(res, '', 0, req);
}

// --- validation -------------------------------------------------------------
//
// Deliberately hand-written rather than a schema library: the rules are few, the messages are
// part of the contract (`login-error` has to read like a person wrote it), and the boundaries
// are asserted in the suites.

export const LIMITS = Object.freeze({
  name: 120,
  email: 254,
  password: 8,        // minimum; long enough to not be a typo, short enough to type
  passwordMax: 200,
  deviceName: 120,
  limit: 1000,        // audit page size ceiling
  limitDefault: 50,
});

export function requireString(value, field, { max = LIMITS.name, min = 1 } = {}) {
  if (typeof value !== 'string') throw badRequest(`${field} is required`);
  const trimmed = value.trim();
  if (trimmed.length < min) throw badRequest(`${field} is required`);
  if (trimmed.length > max) throw badRequest(`${field} must be at most ${max} characters`, 'too_long');
  return trimmed;
}

/**
 * Email: trimmed, lowercased, and shape-checked. The lowercase is not cosmetic — `users.email`
 * and `invites.email` both carry `CHECK (email = lower(email) COLLATE BINARY)`, so an un-lowered
 * insert is a database error rather than a validation message. Normalising here turns a 500 into
 * a 400 and puts the rule in one place.
 */
export function requireEmail(value) {
  const email = requireString(value, 'email', { max: LIMITS.email }).toLowerCase();
  if (!/^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email)) throw badRequest('email is not a valid address', 'invalid_email');
  return email;
}

export function requirePassword(value) {
  if (typeof value !== 'string') throw badRequest('password is required');
  if (value.length < LIMITS.password) throw badRequest(`password must be at least ${LIMITS.password} characters`);
  if (value.length > LIMITS.passwordMax) throw badRequest('password is too long');
  return value;
}

/**
 * A bounded, non-negative integer from the query string. Absent means the default; present but
 * not a usable integer is a 400 rather than a silent clamp, because `limit=0` and `limit=99999`
 * are mistakes a caller wants to hear about (`scripts/check-api.js:189` pins both).
 */
export function boundedInt(params, name, { min, max, fallback }) {
  const raw = params.get(name);
  if (raw === null || raw === '') return fallback;
  if (!/^\d+$/.test(raw)) throw badRequest(`${name} must be a whole number`, 'invalid_pagination');
  const n = Number(raw);
  if (n < min || n > max) throw badRequest(`${name} must be between ${min} and ${max}`, 'invalid_pagination');
  return n;
}

// --- SQLite error translation ----------------------------------------------

/**
 * The database refuses several things that are 400s or 409s to a client, and the routes would
 * otherwise each need their own try/catch. Translated here, once.
 *
 * A LIMITATION worth stating, because I got it wrong first: better-sqlite3 reports a foreign key
 * violation as the bare string `FOREIGN KEY constraint failed`. It does not name the table or the
 * column, so there is no way to tell from the error whether `grant_permissions.permission` (D19 —
 * a typo) or `grant_permissions.grant_id` (a bug in my route) caused it. I initially matched on
 * the message text, which can therefore never match, and every unknown-permission grant came back
 * as a 500. `unknownPermission()` below does the identification properly: the FK has already
 * refused the write, and asking the table which value was unknown is a diagnostic, not a
 * re-implementation of the rule.
 */
export function translateConstraint(err, { onForeignKey, onUnique } = {}) {
  if (!err || typeof err.code !== 'string' || !err.code.startsWith('SQLITE_CONSTRAINT')) return err;

  if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
    return onForeignKey ? onForeignKey(err) : err;
  }

  if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
    return onUnique ? onUnique(err) : err;
  }

  return err;
}

/**
 * Which of `patterns` is not in `permission_patterns` (D19). Called only AFTER the foreign key has
 * already refused the insert, so this explains the refusal rather than pre-empting it.
 */
export function unknownPermission(db, patterns) {
  const known = new Set(stmt(db, 'referencePatterns').all().map((r) => r.pattern));
  return patterns.find((p) => !known.has(p)) ?? null;
}

// --- shared row shapes ------------------------------------------------------

/** The `is`-then-`then` of a device row, with the caller's resolved permissions for THAT device. */
export const deviceRow = (device, permissions) => ({
  id: device.id,
  name: device.name,
  kind: device.kind,
  online: device.online === 1,
  created_at: device.created_at,
  permissions: permissions ?? null,
});

export const grantRow = (grant, { userName, deviceName, permissions }) => ({
  id: grant.id,
  user_id: grant.user_id,
  user_name: userName ?? null,
  device_id: grant.device_id,
  device_name: deviceName ?? null,
  effect: grant.effect,
  starts_at: grant.starts_at,
  expires_at: grant.expires_at,
  revoked_at: grant.revoked_at,
  created_at: grant.created_at,
  permissions: permissions ?? [],
});

export const memberRow = (membership, user) => ({
  user_id: membership.user_id,
  org_id: membership.org_id,
  email: user?.email ?? null,
  name: user?.name ?? null,
  role: membership.role,
  status: membership.status,
  perm_version: membership.perm_version,
  joined_at: membership.joined_at,
});

export { nowIso, newId, forbidden };
