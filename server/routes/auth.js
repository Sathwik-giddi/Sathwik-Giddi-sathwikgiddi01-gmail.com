// auth.js, sign in, refresh, switch org, and "who am I".
//
// The four rules that shape this file:
//
//  1. The ACCESS TOKEN goes in the response body and lives in the client's memory (D13). The
//     REFRESH TOKEN goes in an httpOnly cookie and is never returned, never logged, and never
//     readable by script. Nothing is written to localStorage or sessionStorage.
//  2. `refresh_tokens` has NO org column. So a refresh cannot remember which org the user was
//     looking at, and `POST /auth/refresh` re-issues for the caller's default org. That is a
//     consequence of the given schema, not an oversight, see DECISIONS.md.
//  3. A wrong password and an unknown account produce the same 401 with the same message. The
//     console must not improve on that either (UI-INVENTORY.md §4), and `tests/ui.spec.js:333`
//     asserts the screen does not.
//  4. `POST /auth/token` (switch org) requires an ACTIVE membership in the target org. It is
//     the only way to get a token for another org, which is what makes one-org-per-token (D18)
//     structural rather than a filter.

import { send, unauthenticated, forbidden, notFound, badRequest, tooManyRequests } from '../http.js';
import { attempt, succeed, fail } from '../ratelimit.js';
import { apiHeaders } from '../headers.js';
import { verifyPassword, hashPassword, needsRehash, issueAccessToken, newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS } from '../auth.js';
import { stmt } from '../internal/sql.js';
import { newId, nowIso } from '../db.js';
import { requireEmail, requireString, parseCookies, setRefreshCookie, clearRefreshCookie, REFRESH_COOKIE, LIMITS } from '../internal/http.js';
import { expireStaleSessions } from '../lifecycle.js';

const GENERIC_LOGIN_FAILURE = 'invalid email or password';

/**
 * The org a token is minted for when the caller does not say: the caller's active memberships
 * ordered by org name, first one wins. Alphabetical rather than by created_at so the choice is
 * stable across calls and does not depend on insertion order.
 */
const defaultOrgFor = (db, userId) => stmt(db, 'orgsForUser').all(userId)[0] ?? null;

/** The shape `GET /auth/me` and `POST /auth/login` both return, so the console has one reader. */
function sessionPayload(db, { user, org, role, permissions }) {
  return {
    user: { id: user.id, email: user.email, name: user.name },
    org: { id: org.id, name: org.name, theme: org.theme },
    role,
    orgs: stmt(db, 'orgsForUser').all(user.id).map((o) => ({ id: o.id, name: o.name, theme: o.theme, role: o.role })),
    // Only `me` and `login` include permissions; the switch endpoint omits it and the console
    // asks `/auth/me` for the org it has just switched into.
    ...(permissions ? { permissions } : {}),
  };
}

/**
 * Mint an access token and a refresh token, and set the cookie.
 *
 * `familyId` is the whole point of this function's signature. A family is a ROTATION LINEAGE: one
 * sign-in starts a family, and every subsequent rotation stays inside it. Passing `null` starts a
 * new family; passing the current one continues it.
 *
 * I had this wrong in the most expensive way available. The original read `newId('fam')` here
 * unconditionally, so EVERY issue started a fresh family and a family was a family of exactly one.
 * `revokeFamily` on the replay branch therefore matched the single already-revoked row and changed
 * nothing: replay detection fired, returned 401, and the attacker's rotated token kept working.
 * Verified before this fix, replay the old cookie (401, as designed) and then refresh with the
 * new one, and you get 200. The control was inert and both my write-ups claimed it worked.
 *
 * The lesson is the assertion, not the code: I had a test for "the replay is refused" and none for
 * "the lineage is dead". See BUILD-LOG.md, Phase 9.
 */
function issueFor(db, secret, { user, orgId, role, permVersion, familyId = null }, res, req) {
  const token = issueAccessToken({ userId: user.id, orgId, role, permVersion }, secret);

  const raw = newRefreshToken();
  stmt(db, 'insertRefresh').run(
    newId('rt'),
    user.id,
    hashRefreshToken(raw),
    familyId ?? newId('fam'),
    new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
  );
  setRefreshCookie(res, raw, REFRESH_TTL_SECONDS, req);

  return token;
}

export function register(router) {
  // -------------------------------------------------------------------------
  router.post('/v1/auth/login', async (ctx, _params, res) => {
    const email = requireEmail(ctx.body.email);
    const password = requireString(ctx.body.password, 'password', { max: LIMITS.passwordMax });

    // Throttle on the credential, before the KDF runs. A correct password is never counted, so this
    // costs an honest user nothing and bounds only the guessing. See server/ratelimit.js for why it
    // counts failures rather than requests.
    const gate = attempt(ctx.req, email);
    if (gate.limited) throw tooManyRequests(gate.retryAfter);

    const user = stmt(ctx.db, 'userByEmail').get(email);

    // One message, one status, whether the account exists or the password is wrong. The
    // comparison runs either way so a missing account does not answer measurably faster.
    //
    // It is awaited rather than called synchronously because `verifyPassword` runs scrypt on the
    // threadpool; see the note in server/auth.js. This is also why the gate above matters even
    // after that fix: the KDF is the expensive part, and it is reachable without a credential.
    const ok = user ? await verifyPassword(password, user.password_hash) : false;
    if (!ok) {
      fail(ctx.req, email);
      throw unauthenticated(GENERIC_LOGIN_FAILURE);
    }
    succeed(ctx.req, email);

    // Rehash-on-login, and the reason the KDF cost lives inside the stored value.
    //
    // `SCRYPT_N` only affects hashes written AFTER it is set, because verification deliberately
    // reads the cost back out of the stored hash, that is what stops a cost change from bricking
    // every existing password. The cost of that safety is that lowering N appears to do nothing to
    // a database that already exists, which is a confusing thing to ship.
    //
    // This closes the gap: a successful sign-in re-derives the hash at the current cost, so a
    // deployment migrates its own password column one sign-in at a time. No downtime, no migration
    // script, no locked-out users, and it works in both directions, raising N to harden an
    // existing install is the same three lines.
    //
    // It runs AFTER the credential is proven, on a string the caller already supplied in the clear,
    // and it is not audited: nothing about the caller's authority changed, only the encoding of a
    // secret they already hold. A failure here is swallowed on purpose, a rehash that fails must
    // not turn a correct password into a 500.
    if (user && needsRehash(user.password_hash)) {
      try {
        stmt(ctx.db, 'rehashUser').run(await hashPassword(password), user.id);
      } catch (err) {
        console.error('[auth] rehash-on-login failed for', user.id, err?.message ?? err);
      }
    }

    const requested = ctx.body.orgId;
    let org;
    if (requested !== undefined && requested !== null) {
      if (typeof requested !== 'string') throw badRequest('orgId must be a string');
      const membership = stmt(ctx.db, 'membershipByOrgUser').get(requested, user.id);
      if (!membership || membership.status !== 'active') {
        // 401, not 404: this is a sign-in attempt, and the credential is what is being refused.
        // Answering 404 would confirm which org ids exist.
        throw unauthenticated('not an active member of that organization');
      }
      org = stmt(ctx.db, 'orgById').get(requested);
      if (!org || org.deleted_at !== null) throw unauthenticated('not an active member of that organization');

      const payload = sessionPayload(ctx.db, { user, org, role: membership.role });
      payload.token = issueFor(ctx.db, ctx.secret, { user, orgId: org.id, role: membership.role, permVersion: membership.perm_version }, res, ctx.req);
      return send(res, 200, payload);
    }

    org = defaultOrgFor(ctx.db, user.id);
    if (!org) throw unauthenticated('this account is not an active member of any organization');

    const membership = stmt(ctx.db, 'membershipByOrgUser').get(org.id, user.id);
    const payload = sessionPayload(ctx.db, { user, org, role: membership.role });
    payload.token = issueFor(ctx.db, ctx.secret, { user, orgId: org.id, role: membership.role, permVersion: membership.perm_version }, res, ctx.req);
    return send(res, 200, payload);
  });

  // -------------------------------------------------------------------------
  router.post('/v1/auth/refresh', async (ctx, _params, res) => {
    const raw = parseCookies(ctx.req)[REFRESH_COOKIE];
    if (!raw) {
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('no refresh token');
    }

    const hash = hashRefreshToken(raw);
    const row = stmt(ctx.db, 'refreshByHash').get(hash);

    if (!row) {
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('refresh token is not recognised');
    }

    // Reuse of an already-rotated token means the cookie leaked: kill the whole family, so the
    // attacker and the victim both lose the lineage (AUTH-DATA-MODEL.md §2).
    if (row.revoked_at !== null) {
      stmt(ctx.db, 'revokeFamily').run(nowIso(), row.family_id);
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('refresh token has already been used');
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('refresh token has expired');
    }

    const user = stmt(ctx.db, 'userById').get(row.user_id);
    if (!user) {
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('refresh token is not recognised');
    }

    const org = defaultOrgFor(ctx.db, user.id);
    if (!org) {
      clearRefreshCookie(res, ctx.req);
      throw unauthenticated('this account is not an active member of any organization');
    }
    const membership = stmt(ctx.db, 'membershipByOrgUser').get(org.id, user.id);

    // Rotate INSIDE the family this token belongs to, so a replay can still reach the whole
    // lineage. `busy` if two refreshes race: the loser finds the row already revoked, which is the
    // reuse branch above, and the family dies, which is the correct outcome for two concurrent
    // uses of one refresh token.
    const rotate = ctx.db.transaction(() => {
      stmt(ctx.db, 'revokeRefresh').run(nowIso(), row.id);
      return issueFor(ctx.db, ctx.secret, {
        user, orgId: org.id, role: membership.role, permVersion: membership.perm_version, familyId: row.family_id,
      }, res, ctx.req);
    });

    const payload = sessionPayload(ctx.db, { user, org, role: membership.role });
    payload.token = rotate();
    return send(res, 200, payload);
  });

  // -------------------------------------------------------------------------
  // Switch org. The ONLY way to obtain a token scoped to another org (D18), which is why the
  // console's org switcher is a token mint rather than a client-side filter.
  router.post('/v1/auth/token', async (ctx, _params, res) => {
    const orgId = ctx.body.orgId;
    if (typeof orgId !== 'string' || orgId.length === 0) throw badRequest('orgId is required');

    const membership = stmt(ctx.db, 'membershipByOrgUser').get(orgId, ctx.userId);
    if (!membership || membership.status !== 'active') throw forbidden('not an active member of that organization', 'not_a_member');

    const org = stmt(ctx.db, 'orgById').get(orgId);
    if (!org || org.deleted_at !== null) throw notFound();

    // A switch is not a permission event, but it is the moment a stale token would otherwise
    // silently keep working, so retire anything already past its TTL before handing over.
    expireStaleSessions(ctx.db, { orgId });

    const payload = sessionPayload(ctx.db, { user: ctx.user, org, role: membership.role });
    payload.token = issueFor(ctx.db, ctx.secret, { user: ctx.user, orgId, role: membership.role, permVersion: membership.perm_version }, res, ctx.req);
    return send(res, 200, payload);
  });

  // -------------------------------------------------------------------------
  // What the console boots from. The ORG-LEVEL resolved set is the important part: it is the
  // one answer that gates navigation, and it is produced by the same function that authorises
  // the org-level endpoints, so the two cannot disagree.
  router.get('/v1/auth/me', async (ctx, _params, res) => {
    expireStaleSessions(ctx.db, { orgId: ctx.orgId });

    const user = stmt(ctx.db, 'userById').get(ctx.userId);
    if (!user) throw unauthenticated('not a member of this org');

    const org = stmt(ctx.db, 'orgById').get(ctx.orgId);
    return send(res, 200, sessionPayload(ctx.db, { user, org, role: ctx.role, permissions: ctx.resolver.permissionsFor(null) }));
  });

  // -------------------------------------------------------------------------
  // Sign-out. The refresh cookie IS the credential here, which is why this route is in
  // PUBLIC_ROUTES: requiring a bearer token to sign out would mean the one request that must work
  // without a valid access token is the one that cannot.
  //
  // It revokes the whole FAMILY, not just the presented row. A sign-out that revokes one token out
  // of a rotating lineage leaves the others alive, and "I signed out" has to mean it.
  router.post('/v1/auth/logout', async (_ctx, _params, res) => {
    const raw = parseCookies(_ctx.req)[REFRESH_COOKIE];
    if (raw) {
      const row = stmt(_ctx.db, 'refreshByHash').get(hashRefreshToken(raw));
      if (row) stmt(_ctx.db, 'revokeFamily').run(nowIso(), row.family_id);
    }
    clearRefreshCookie(res, _ctx.req);
    // 204: there is nothing to say. `ok: true` was a body describing an absence.
    res.writeHead(204, apiHeaders());
    res.end();
  });
}
