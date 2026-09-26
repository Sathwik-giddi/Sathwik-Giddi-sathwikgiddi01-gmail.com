// sessions.js — opening, listing, reading and ending remote-access sessions.
//
// A session is a RECORD (BRIEF.md §4: no input injection, no shell, no capture). What this file
// actually decides is who may open one, on which device, in which mode, and when an existing one
// stops being a thing.
//
// The lifecycle rules, which are the part with any subtlety in it:
//
//   OPENING    session:start AND the mode's permission, on the SAME device, and the refusal has to
//              say which of the two was missing. `assertCanStartSession` owns that; this file only
//              chooses the order the two are presented in, which is: session:start first, because
//              "you cannot open sessions at all" and "not on this device" are different problems.
//
//   EXCLUSIVE  control and terminal are exclusive per device (D10). Enforced by the partial unique
//              index `one_exclusive_session_per_device`, NOT by a check-then-insert. Two
//              simultaneous requests therefore produce exactly one 201 and one 409 with no
//              application-level locking at all — see the 8-process race in check-seams.js.
//
//   BOUNDED    every session gets expires_at = now + org.max_session_minutes, and expired sessions
//              are retired lazily on every read and write that touches them.
//
//   GRANDFATHERED  a permission change, a role change, a revoked grant or a lapsed grant window
//              does NOT end a live session. Suspension, membership removal and device transfer DO.
//              There is deliberately no `permission_revoked` reason in the schema's enum, and this
//              file is why that is a fact about the model rather than an omission.

import { send, notFound, badRequest, deviceBusy } from '../http.js';
import { assertSameOrg } from '../context.js';
import { stmt } from '../internal/sql.js';
import { newId } from '../db.js';
import { requireString, translateConstraint } from '../internal/http.js';
import { audit, auditDenials, auditSuccess } from '../audit.js';
import { expireStaleSessions, sessionExpiry } from '../lifecycle.js';
import { MODE_PERMISSION } from '../permissions.js';

const MODES = Object.keys(MODE_PERMISSION);

/** A session in this org, or 404. A session id is not a capability, so it is scoped like a device. */
function sessionInOrg(db, orgId, sessionId) {
  const session = stmt(db, 'sessionById').get(sessionId);
  if (!session || session.org_id !== orgId) throw notFound();
  return session;
}

export function register(router) {
  // =========================================================================
  // Open a session
  // =========================================================================
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'session.start', targetType: 'device' }, () => {
      // Retiring lapsed sessions first means the exclusivity check below cannot be blocked by a
      // session whose authority has already expired.
      expireStaleSessions(ctx.db, { orgId: params.org });

      const deviceId = requireString(ctx.body.deviceId, 'deviceId', { max: 60 });
      const mode = requireString(ctx.body.mode, 'mode', { max: 20 });
      if (!MODES.includes(mode)) throw badRequest(`mode must be one of ${MODES.join(', ')}`, 'invalid_mode');

      // The device has to exist in this org. Whether the caller may SEE it is deliberately not
      // asked here: BRIEF.md §5.1 gives this endpoint exactly two requirements (`session:start` and
      // the mode permission), and `device:view` is a LIST-row gate. A device-scoped allow of
      // `device:control` works even where `device:view` is denied, which is the only reading that
      // does not quietly make a grant unusable. Written up in DECISIONS.md.
      const device = stmt(ctx.db, 'deviceInOrg').get(deviceId, params.org);
      if (!device) throw notFound();

      // The compound check. Throws 403 with `missing_permission` or `missing_device_permission`,
      // and returns the authorized_by snapshot — the grants that actually decided it.
      const authorizedBy = ctx.resolver.assertCanStartSession(mode, device.id);

      const id = newId('ses');
      const start = ctx.db.transaction(() => {
        stmt(ctx.db, 'insertSession').run(
          id,
          params.org,
          ctx.userId,
          device.id,
          mode,
          JSON.stringify(authorizedBy),
          new Date().toISOString(),
          sessionExpiry(ctx.db, params.org)
        );
        auditSuccess(ctx.db, ctx, { action: 'session.start', targetType: 'device', targetId: device.id });
      });

      try {
        start();
      } catch (err) {
        // D10, by the database. The holder's session id is included because "someone else is
        // already in there" is only actionable if you are told who.
        const holder = stmt(ctx.db, 'activeExclusiveOnDevice').get(device.id);
        if (holder) throw deviceBusy(`device already has an exclusive session (${holder.id})`);
        throw translateConstraint(err, { onUnique: () => deviceBusy('device already has an exclusive session') });
      }

      return send(res, 201, sessionView(stmt(ctx.db, 'sessionById').get(id), { user: ctx.user, device }));
    });
  });

  // =========================================================================
  // List this org's sessions
  // =========================================================================
  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'session.read', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('session:view');
      expireStaleSessions(ctx.db, { orgId: params.org });

      const sessions = stmt(ctx.db, 'sessionsForOrg').all(params.org);
      return send(res, 200, {
        sessions: sessions.map((s) => ({
          ...sessionView(s, { user: { id: s.user_id, name: s.user_name, email: s.user_email }, device: { id: s.device_id, name: s.device_name } }),
          // The console needs to know which rows it may act on, and that is a question about the
          // CALLER, so it is answered here from the same resolved set the buttons are drawn from.
          can_stop: s.user_id === ctx.userId || ctx.resolver.can('session:terminate'),
          is_mine: s.user_id === ctx.userId,
        })),
      });
    });
  });

  // =========================================================================
  // One session, by id. Not org-scoped in the path, so the org comes from the token — and the
  // session's own org_id has to match it, or it is a 404.
  // =========================================================================
  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const session = stmt(ctx.db, 'sessionById').get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();
    expireStaleSessions(ctx.db, { orgId: ctx.orgId });

    return auditDenials(ctx.db, ctx, { action: 'session.read.one', targetType: 'session', targetId: session.id }, () => {
      // "participant OR session:view" — you can always watch your own session, whatever your role.
      if (session.user_id !== ctx.userId) ctx.resolver.assertCan('session:view');

      const fresh = stmt(ctx.db, 'sessionById').get(session.id);
      return send(res, 200, sessionView(fresh, { user: { id: session.user_id }, device: { id: session.device_id } }));
    });
  });

  // =========================================================================
  // End a session
  // =========================================================================
  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    const session = stmt(ctx.db, 'sessionById').get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();

    return auditDenials(ctx.db, ctx, { action: 'session.terminate', targetType: 'session', targetId: session.id }, () => {
      const isMine = session.user_id === ctx.userId;

      // Your own session, or `session:terminate`. Note the ORDER: a person who is both ends their
      // own session as `user_stopped`, because that is the more accurate record of what happened.
      if (!isMine) ctx.resolver.assertCan('session:terminate');

      if (session.state !== 'active') {
        // Already ended. Returning the row is more useful than a 409: the caller's intent — "make
        // sure this is not running" — is satisfied, and the reason it stopped is in the response.
        return send(res, 200, sessionView(session, {}));
      }

      const reason = isMine ? 'user_stopped' : 'admin_terminated';
      const stop = ctx.db.transaction(() => {
        stmt(ctx.db, 'endSession').run(reason, new Date().toISOString(), session.id);
        audit(ctx.db, {
          orgId: ctx.orgId,
          actorId: ctx.userId,
          action: isMine ? 'session.stop' : 'session.terminate',
          targetType: 'session',
          targetId: session.id,
          result: 'allow',
          requestId: ctx.requestId,
        });
      });
      stop();

      return send(res, 200, sessionView(stmt(ctx.db, 'sessionById').get(session.id), {}));
    });
  });
}

/**
 * The session row as the API reports it. Deliberately close to the stored row — `state`, `mode`,
 * `device_id` and `end_reason` keep their column names, because `scripts/check-api.js:121-127`
 * reads them and because a session is a record whose fields should match what was written.
 */
function sessionView(session, { user, device } = {}) {
  return {
    id: session.id,
    org_id: session.org_id,
    user_id: session.user_id,
    user_name: user?.name ?? session.user_name ?? null,
    device_id: session.device_id,
    device_name: device?.name ?? session.device_name ?? null,
    mode: session.mode,
    state: session.state,
    end_reason: session.end_reason,
    authorized_by: parseSnapshot(session.authorized_by),
    started_at: session.started_at,
    expires_at: session.expires_at,
    ended_at: session.ended_at,
  };
}

/**
 * `authorized_by` is `json_valid(...)` in the schema, so it is stored as text and could still be
 * anything a caller wrote. Parsed defensively: a session list must not 500 because one row has a
 * malformed snapshot, and a snapshot that will not parse is reported as null rather than guessed
 * at.
 */
function parseSnapshot(raw) {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'object') return raw;
  try {
    const parsed = JSON.parse(raw);
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
