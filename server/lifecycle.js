// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// The rules more than one route needs live here, so "what ends a session" and "who may modify
// whom" each have exactly one implementation. Sources: PERMISSIONS.md §6 and §7, D8.
//
// Two traps worth naming, because both are in the code below rather than only in this comment:
//
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can() question.
//     operator and auditor are unordered by permission — `roles.rank` says operator(30) is
//     above auditor(20), and Sam's two orgs prove that number is meaningless for permissions.
//     Nothing in this file is reachable from the resolution engine, and nothing in
//     permissions.js imports this file. That separation is the defence.
//
//   - a permission change does NOT end a session in flight (grandfathering, D20). Suspension,
//     membership removal and device transfer DO. `endActiveSessions` is therefore only ever
//     called for tenancy and account events, and the reason enum it accepts is the reason the
//     caller already had to choose.

import { forbidden, badRequest, lastOwner } from './http.js';
import { stmt } from './internal/sql.js';
import { nowIso } from './db.js';

// The one role key this file needs by name. It is a ROLE, not a permission: last-owner
// protection and owner-may-modify-a-peer are both statements about the owner role specifically,
// and no permission in the catalogue can express them. The rank is still read from the table
// rather than assumed, so an added role participates in the ordering.
const OWNER = 'owner';

/** `{ roleKey: rank }` for every role in the table. Never a hardcoded five. */
export function roleRanks(db) {
  const ranks = Object.create(null);
  for (const row of stmt(db, 'allRoles').all()) ranks[row.key] = row.rank;
  return ranks;
}

const rankOf = (db, role) => {
  const ranks = roleRanks(db);
  const rank = ranks[role];
  if (rank === undefined) throw badRequest(`unknown role ${JSON.stringify(role)}`, 'unknown_role');
  return rank;
};

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || role.length === 0) throw badRequest('role is required', 'unknown_role');
  rankOf(db, role);
  return role;
}

/**
 * D8, modification authority. This is the ONLY place roles are compared, and the comparison is
 * about administration rather than permissions.
 *
 * `PERMISSIONS.md §6` gives the table as "modify a user of strictly lower role → allowed" and
 * "modify a user of equal role (admin → admin) → 403". Taken literally that also makes
 * owner → owner a 403, which `scripts/check-api.js:150` contradicts: it has one owner demote
 * another owner in an org with two of them and expects 200. So the rule that satisfies both is
 * two clauses rather than one:
 *
 *   - strictly lower target: allowed (the normal case)
 *   - equal target, and the caller is an owner: allowed, because an org needs to be able to
 *     demote one of its owners, and owners are peers by definition
 *
 * Everything else — a peer that is not an owner, or anyone above the caller — is 403. Written
 * up in DECISIONS.md, since it is the one place I had to reconcile a table against a test.
 */
export function assertCanModify(db, callerRole, targetRole) {
  const callerRank = rankOf(db, callerRole);
  const targetRank = rankOf(db, targetRole);

  if (targetRank < callerRank) return true;
  if (callerRole === OWNER && targetRole === OWNER) return true;

  throw forbidden(
    `a ${callerRole} cannot modify a ${targetRole}`,
    callerRole === targetRole ? 'equal_role' : 'insufficient_rank'
  );
}

/**
 * The role a caller is allowed to hand out. Derived rather than special-cased: assigning a role
 * above your own is refused, and since `owner` holds the top rank in the table, "assign owner
 * unless you are an owner" (`PERMISSIONS.md §6`) falls out of the same comparison. An admin
 * assigning `admin` is fine; an admin assigning `owner` is 403.
 */
export function assertRoleAssignable(db, callerRole, newRole) {
  assertRoleExists(db, newRole);
  if (rankOf(db, newRole) > rankOf(db, callerRole)) {
    throw forbidden(`you cannot assign the ${newRole} role`, 'insufficient_rank');
  }
  return newRole;
}

/**
 * An org always has at least one owner (invariant 5). Counted over ACTIVE owners, because a
 * suspended owner cannot administer anything and an org whose only owner is suspended has
 * nobody who can fix it.
 */
export function assertNotLastOwner(db, orgId, userId) {
  const owners = stmt(db, 'owners').all(orgId);
  if (owners.length === 0) return true; // nothing to protect; caller is not an owner

  if (owners.length > 1) return true;
  if (owners[0].userId !== userId) return true;

  throw lastOwner();
}

/**
 * The one implementation of "a session ends". Account and tenancy events cascade; permission
 * changes never come through here, because there is deliberately no `permission_revoked` reason
 * in the schema's enum and adding one would be the wrong fix.
 *
 * Every filter is NULL-tolerant, INCLUDING `orgId`, and that is not a stylistic choice. A device
 * transfer calls this with only a `deviceId`, because the sessions to end may be in either org
 * (the device is moving between them). An earlier version guarded `userId` and `deviceId` with
 * `? IS NULL OR col = ?` but wrote `org_id = ?` unguarded — so with no org it compared
 * `org_id = NULL`, which is never true, and the transfer cascade silently updated ZERO rows while
 * the transfer itself returned 200. Found by `scripts/check-http-seams.js`, which asserts that a
 * live session on a transferred device actually ends. A cascade that does nothing is worse than no
 * cascade: it looks like it worked.
 *
 * `exceptSessionId` exists for the case where one session should not end itself.
 */
export function endActiveSessions(db, { orgId = null, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  const at = nowIso();
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE state = 'active'
        AND (? IS NULL OR org_id = ?)
        AND (? IS NULL OR user_id = ?)
        AND (? IS NULL OR device_id = ?)
        AND (? IS NULL OR id <> ?)`
  ).run(reason, at, orgId, orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}

/**
 * TTL expiry, applied lazily. `sessions.expires_at` is NOT NULL and every session carries one,
 * which is what stops "never terminated by a permission change" from becoming "never terminated".
 * Rather than a timer, every read and every write that looks at sessions first retires the ones
 * whose TTL has passed. The alternative — a background sweeper — is a second writer racing the
 * request path for no benefit, since a session past its TTL has no authority left to protect.
 */
export function expireStaleSessions(db, { orgId = null } = {}) {
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE state = 'active' AND expires_at <= ? AND (? IS NULL OR org_id = ?)`
  ).run(nowIso(), nowIso(), orgId, orgId).changes;
}

/**
 * `expires_at` for a session about to start: `started_at + org.max_session_minutes`. Read from
 * the org row, because the bound is the org's and the org's is the only place it is written.
 */
export function sessionExpiry(db, orgId) {
  const minutes = stmt(db, 'maxSessionMinutes').get(orgId)?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

// The mode -> permission map is a property of the mode, not a resolution, which is why it can
// live here without this module depending on permissions.js.
const MODE_TO_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };
