// Append-only audit writes.
//
// `audit_events` has BEFORE UPDATE / BEFORE DELETE triggers, so this module can only ever INSERT.
// Two rules from the spec shape it:
//
//   - DENIED attempts are recorded, not just successes. A log that only holds successes cannot
//     answer "who tried to change what", and the fixture seeds one denial for exactly that
//     reason (`seed/orgs.json` aud_003).
//   - a single action produces a single row. The success row is written INSIDE the transaction
//     that makes the change, by the route that makes it. Nothing here also logs the allow from a
//     wrapper, because a wrapper that logs both cannot tell you which of the two actually
//     committed — and a success row for a rolled-back transaction is worse than no row.
//
// `auditDenials` is the exception, and it only ever writes the *denial*: the allow, if the action
// was permitted, is the route's to write inside its own transaction.

import { HttpError } from './http.js';
import { stmt } from './internal/sql.js';
import { newId, nowIso } from './db.js';

/**
 * Append one event. `orgId` is NOT NULL in the schema, so an event that cannot be attributed to
 * an org — a failed sign-in, a bad token — is not auditable and is not written. That is a real
 * limitation of the given schema rather than a choice, and it is why "someone tried to log in as
 * our admin account" is not answerable from this table.
 */
export function audit(db, { orgId, actorId = null, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  if (!orgId) throw new Error('audit: orgId is required — audit_events.org_id is NOT NULL');
  if (result !== 'allow' && result !== 'deny') throw new Error(`audit: result must be allow|deny, got ${result}`);

  return stmt(db, 'insertAudit').run(
    newId('aud'),
    orgId,
    actorId,          // nullable: an unauthenticated or not-yet-known actor is still an event
    action,
    targetType,
    targetId,
    result,
    reasonCode,
    requestId,
    nowIso()
  );
}

/**
 * Run `fn`; if it refuses, record the denial and rethrow the ORIGINAL error.
 *
 * Only 403 is audited. A 404 is not a denial — it is the deliberate absence of information, and
 * writing "someone probed org_x and got 404" into a log that `audit:read` holders can read would
 * turn the audit trail into a map of what exists. A 401 means the request never established who
 * the caller was, so there is no actor to attribute it to. A 403 is exactly the case the log
 * exists for: a real person, in a real org, asking for something they may not have.
 */
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: meta.orgId ?? ctx?.orgId ?? null,
        actorId: ctx?.userId ?? null,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code,
        requestId: ctx?.requestId ?? null,
      });
    }
    throw err;
  }
}

/**
 * Record the successful half of an action, inside the caller's transaction.
 *
 * `tx` is a better-sqlite3 transaction function the route is already inside, so the audit row
 * and the change it describes commit or roll back together. Writing the row outside the
 * transaction would leave events describing changes that did not happen.
 */
export function auditSuccess(db, ctx, meta) {
  return audit(db, {
    orgId: meta.orgId ?? ctx?.orgId,
    actorId: ctx?.userId ?? null,
    action: meta.action,
    targetType: meta.targetType ?? null,
    targetId: meta.targetId ?? null,
    result: 'allow',
    reasonCode: null,
    requestId: ctx?.requestId ?? null,
  });
}

/**
 * What counts as an auditable event. Stated once, because the alternative is deciding per route
 * and drifting:
 *
 *   - anything that CHANGES authorization state: role, status, membership, grants, devices,
 *     org settings, invites, sessions
 *   - any REFUSAL of one of those (via auditDenials)
 *   - reads are not audited. `audit:read` on a hot list endpoint would make the table grow with
 *     traffic rather than with decisions, and the schema's append-only triggers mean there is no
 *     way to prune it afterwards.
 */
export const AUDITED_ACTIONS = Object.freeze({
  'org.create': { targetType: 'org' },
  'org.update': { targetType: 'org' },
  'org.delete': { targetType: 'org' },
  'member.role.update': { targetType: 'user' },
  'member.suspend': { targetType: 'user' },
  'member.reinstate': { targetType: 'user' },
  'member.remove': { targetType: 'user' },
  'member.leave': { targetType: 'user' },
  'invite.create': { targetType: 'invite' },
  'invite.revoke': { targetType: 'invite' },
  'invite.accept': { targetType: 'invite' },
  'device.create': { targetType: 'device' },
  'device.update': { targetType: 'device' },
  'device.delete': { targetType: 'device' },
  'device.transfer': { targetType: 'device' },
  'grant.create': { targetType: 'grant' },
  'grant.revoke': { targetType: 'grant' },
  'session.start': { targetType: 'device' },
  'session.stop': { targetType: 'session' },
  'session.terminate': { targetType: 'session' },
});
