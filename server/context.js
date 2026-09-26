// Per-request context: turn a bearer token into an authenticated caller.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6, AUTH-DATA-MODEL.md §3):
//   - read the bearer token and verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that names a
//     different org is INVISIBLE, 404, never 403. Isolation is structural: the caller cannot
//     name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version, so a role or grant change takes effect
//     on the NEXT request rather than at token expiry
//   - throw through the one error path in ./http.js
//
// The org is taken from the token and NEVER from the URL. A route that reads `:org` compares it
// against `caller.orgId` and 404s on a mismatch, so the comparison is a filter on an id the
// caller already proved they hold, not the thing that establishes which org they are in.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, forbidden, notFound } from './http.js';
import { createResolver } from './permissions.js';
import { stmt } from './internal/sql.js';

/**
 * The bearer scheme is matched case-insensitively (RFC 7235 says the scheme is
 * case-insensitive) but nothing else about the header is forgiving: exactly one space, then a
 * token with no whitespace in it.
 */
function readBearer(req) {
  const header = req.headers?.authorization;
  if (typeof header !== 'string' || header.length === 0) {
    throw unauthenticated('missing Authorization header');
  }

  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer' || parts[1].length === 0) {
    throw unauthenticated('Authorization header is not a bearer credential');
  }

  return parts[1];
}

/**
 * `authenticate(db, secret)` returns `(req, params) => caller`.
 *
 * The caller carries { userId, orgId, role, membership, claims, resolver }. `resolver` is the
 * per-request permission resolver: one catalogue read, one baseline read, one grant read for the
 * whole request, with every device answered from memory after that. It is created here and dies
 * with the request, which is what makes it safe, see the note on `createResolver`.
 */
export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const claims = verifyAccessToken(readBearer(req), secret);

    // One lookup for the membership AND the org's liveness. A token for a soft-deleted org is
    // refused here rather than producing empty lists further down: `organizations.deleted_at`
    // exists precisely so a deleted org stops being addressable while its rows stay auditable.
    const row = stmt(db, 'membershipWithOrg').get(claims.org, claims.sub);

    if (!row || row.deleted_at !== null) {
      // One message for "no such org", "no such membership" and "the org is gone". Distinguishing
      // them would confirm that an org id exists to someone holding a token for a different one.
      throw unauthenticated('not a member of this org');
    }

    const membership = {
      id: row.membership_id,
      org_id: row.org_id,
      user_id: row.user_id,
      role: row.role,
      status: row.status,
      perm_version: row.perm_version,
    };

    // D16: suspension is reversible, so it is a 403 with an empty permission set rather than a
    // 401, the credential is still good, the account is not usable. `removed` and `invited` are
    // both 401: there is no membership to speak of, active or not.
    if (membership.status === 'suspended') {
      throw forbidden('membership is suspended', 'suspended');
    }
    if (membership.status !== 'active') {
      throw unauthenticated('not an active member of this org');
    }

    // AUTH-DATA-MODEL.md §3: `!==`, not `<`. A token minted with a version from the future is as
    // suspect as a stale one, and this is the one place that notices.
    assertFresh(claims, membership);

    // P11: the token's `role` claim is an INPUT, never an authority. It exists so the client can
    // render without a second round trip; the membership row is what the server decides with.
    //
    // These two values are not supposed to be able to disagree. A role change bumps
    // `perm_version` (server/routes/orgs.js) and `assertFresh` above just proved the token's `pv`
    // still matches, so for any honestly-minted token they are equal by construction. Reaching
    // this line with `claims.role !== membership.role` therefore means one of two things: the
    // signing key leaked, or the token was forged. Both are 401.
    //
    // Before this check, `ctx.role` was `claims.role`, which meant a token saying `role:"owner"`
    // carried owner rank into lifecycle.js's `assertRoleAssignable`/`assertCanModify` and could
    // promote a viewer to owner. Signing is what makes a claim authentic, not the field name.
    if (claims.role !== membership.role) {
      throw unauthenticated('token role does not match the membership');
    }

    const user = stmt(db, 'userById').get(claims.sub);
    if (!user) throw unauthenticated('not a member of this org');

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      user,
      membership,
      claims,
      org: { id: row.org_id, name: row.org_name, theme: row.org_theme, maxSessionMinutes: row.max_session_minutes },
      resolver: createResolver(db, { userId: claims.sub, orgId: claims.org }),
    };
  };
}

/**
 * Best-effort authentication, for the one public route that is nicer when you are signed in.
 *
 * `POST /invites/:token/accept` is public: a stranger redeeming an invite has no token. But an
 * EXISTING user accepting an invite must not be asked for a password, and must not have one
 * reset by a link in their inbox. So the route asks "who is this, if anyone?" and branches:
 * nobody redeems as a new account, somebody redeems as the account they already hold. This
 * returns null for every failure rather than throwing, because "not signed in" is a normal
 * answer here and not an error.
 */
export function optionalCaller(db, secret, req) {
  try {
    return authenticate(db, secret)(req, {});
  } catch {
    return null;
  }
}

/**
 * The structural isolation check. Called by every route that takes an `:org` parameter, and
 * deliberately the FIRST thing any of them do, before any permission question, because "can you
 * see this?" has to be answered before "may you do this?" (PERMISSIONS.md §5).
 *
 * A token scoped to org A asking about org B gets `404`, and the body is byte-identical to the
 * body for an id that does not exist at all. That is the whole point: a 403 would confirm the
 * resource is real.
 */
export function assertSameOrg(caller, orgIdFromPath) {
  if (orgIdFromPath !== caller.orgId) throw notFound();
  return caller.orgId;
}
