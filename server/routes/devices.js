// devices.js, device CRUD, transfer, and grants.
//
// Two things in here are the reason this file is more than CRUD:
//
//  1. THE DEVICE LIST IS ONE QUERY. `GET /devices` resolves the caller's permissions for every
//     device from the request's single resolver and returns them on each row, so the console
//     never issues a follow-up request per row and never re-derives a permission (BRIEF.md §5.2,
//     §6). Row inclusion is then decided from that same answer: a device whose `device:view` is
//     denied is ABSENT from the list, not present with the metadata stripped.
//
//  2. GRANT CREATION DELEGATES ITS VALIDATION TO THE FOREIGN KEY. The route checks the two things
//     the database cannot know, that the pattern set is non-empty, and that the caller is not
//     laundering, and then lets `grant_permissions.permission REFERENCES
//     permission_patterns(pattern)` reject `device:teleport` (D19). The FK's error is translated
//     into a 400 with `reason: "unknown_permission"` in one place, so it is a validation failure
//     rather than a 500, and a typo is never a silent deny.

import { send, notFound, badRequest, forbidden, normalizeTs, HttpError } from '../http.js';
import { assertSameOrg } from '../context.js';
import { stmt } from '../internal/sql.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { requireString, translateConstraint, unknownPermission, deviceRow, grantRow, LIMITS } from '../internal/http.js';
import { auditDenials, auditSuccess } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';
import { createResolver } from '../permissions.js';

const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];
const EFFECTS = ['allow', 'deny'];

/**
 * A device in this org, or 404. Used by every device-scoped route so that "belongs to another
 * org" and "does not exist" are the same response, from one line of code.
 */
function deviceInOrg(db, orgId, deviceId) {
  const device = stmt(db, 'deviceInOrg').get(deviceId, orgId);
  if (!device) throw notFound();
  return device;
}

export function register(router) {
  // =========================================================================
  // Devices
  // =========================================================================

  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.list', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('device:list');

      const devices = stmt(ctx.db, 'devicesOfOrg').all(params.org);

      // One resolver, already built by context.js, answers every row. Adding devices to the org
      // adds no queries, the thing BRIEF.md §6 warns about is a query per row, not a per-row cost.
      const visible = devices.filter((d) => {
        const verdict = ctx.resolver.verdict('device:view', d.id);
        // If the catalogue ever lacks device:view, list everything rather than nothing: an absent
        // permission key is a schema change, and silently emptying the list would hide it.
        if (verdict === undefined) return true;
        return verdict.effect === 'allow';
      });

      return send(res, 200, {
        devices: visible.map((d) => deviceRow(d, ctx.resolver.permissionsFor(d.id))),
        // `total` is the count of rows RETURNED, not the count of rows in the org. It used to be
        // `devices.length`, the unfiltered count, which undid the filter one field away: a caller
        // denied `device:view` on one machine received 4 rows and was told there were 5, which is
        // both an information leak and a direct contradiction of "absence is not redaction"
        // (UI-INVENTORY.md §1.3). Verified before the fix: 4 rows, total 5.
        total: visible.length,
      });
    });
  });

  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.read', targetType: 'device', targetId: params.id }, () => {
      const device = deviceInOrg(ctx.db, params.org, params.id);
      ctx.resolver.assertCan('device:view', device.id);
      return send(res, 200, deviceRow(device, ctx.resolver.permissionsFor(device.id)));
    });
  });

  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.create', targetType: 'device' }, () => {
      ctx.resolver.assertCan('device:provision');
      const name = requireString(ctx.body.name, 'name', { max: LIMITS.deviceName });
      const kind = requireString(ctx.body.kind, 'kind', { max: 20 });
      if (!DEVICE_KINDS.includes(kind)) throw badRequest(`kind must be one of ${DEVICE_KINDS.join(', ')}`, 'invalid_kind');

      const id = newId('dev');
      const create = ctx.db.transaction(() => {
        stmt(ctx.db, 'insertDevice').run(id, params.org, name, kind, ctx.body.online ? 1 : 0);
        auditSuccess(ctx.db, ctx, { action: 'device.create', targetType: 'device', targetId: id });
      });
      create();

      return send(res, 201, deviceRow(stmt(ctx.db, 'deviceById').get(id), ctx.resolver.permissionsFor(id)));
    });
  });

  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.update', targetType: 'device', targetId: params.id }, () => {
      const device = deviceInOrg(ctx.db, params.org, params.id);
      ctx.resolver.assertCan('device:update', device.id);
      const name = requireString(ctx.body.name, 'name', { max: LIMITS.deviceName });

      const update = ctx.db.transaction(() => {
        stmt(ctx.db, 'updateDevice').run(name, device.id);
        auditSuccess(ctx.db, ctx, { action: 'device.update', targetType: 'device', targetId: device.id });
      });
      update();
      return send(res, 200, deviceRow(stmt(ctx.db, 'deviceById').get(device.id), ctx.resolver.permissionsFor(device.id)));
    });
  });

  // Decommission is a SOFT delete: `devices.deleted_at`. Grants and sessions reference the row, and
  // a hard delete would either cascade away the audit trail or be refused by the foreign keys.
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.delete', targetType: 'device', targetId: params.id }, () => {
      const device = deviceInOrg(ctx.db, params.org, params.id);
      ctx.resolver.assertCan('device:provision', device.id);

      const remove = ctx.db.transaction(() => {
        endActiveSessions(ctx.db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
        stmt(ctx.db, 'softDeleteDevice').run(nowIso(), device.id);
        auditSuccess(ctx.db, ctx, { action: 'device.delete', targetType: 'device', targetId: device.id });
      });
      remove();
      return send(res, 200, { ok: true, id: device.id });
    });
  });

  // --- transfer ------------------------------------------------------------
  // `device:provision` in BOTH orgs. The caller's token only speaks for `:org`, so authority in the
  // destination is resolved directly against that org's membership, there is no token to mint
  // for an org you are not currently addressing, and inventing one would defeat the point.
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'device.transfer', targetType: 'device', targetId: params.id }, () => {
      const device = deviceInOrg(ctx.db, params.org, params.id);
      ctx.resolver.assertCan('device:provision', device.id);

      const toOrgId = requireString(ctx.body.toOrgId, 'toOrgId', { max: 60 });

      // A transfer to the org the device is already in is not a no-op: it would still cascade and
      // end every live session on the device with `device_transferred`, which is a destructive
      // action dressed as a successful one. Refused rather than silently accepted.
      if (toOrgId === params.org) throw badRequest('the device is already in that organization', 'same_org');

      const target = stmt(ctx.db, 'orgById').get(toOrgId);

      // Membership is part of "can you see this?", so it is answered BEFORE the destination's
      // permissions, and a destination you are not a member of is a 404 rather than a 403.
      //
      // I had this the other way round, and the comment I wrote argued FOR it, I said a 404 "would
      // confirm the org exists", which is precisely the reasoning PERMISSIONS.md §5 rejects. The
      // order I actually had was: org exists? -> 404. then assertCan(device:provision) -> 403. So
      // walking the id space gave 403 for every org that exists and is not soft-deleted, and 404
      // for the rest. Verified before the fix, as a caller holding device:provision in exactly one
      // org:
      //
      //     toOrgId=org_globex            -> 403   this org exists and you are not in it
      //     toOrgId=org_nonexistent_zzz   -> 404   no such org
      //
      // That is a complete enumeration of the deployment from one org you legitimately belong to,
      // and it is what §5 calls an information leak. Both branches are now the same 404, so the
      // response says only what the caller already knew: they are not able to address it.
      const destinationMembership = stmt(ctx.db, 'membershipByOrgUser').get(toOrgId, ctx.userId);
      if (!target || target.deleted_at !== null || !destinationMembership || destinationMembership.status !== 'active') {
        throw notFound();
      }

      // Now authority: device:provision in the DESTINATION as well (BRIEF.md §5.1). The caller's
      // token only speaks for the source org, so this is resolved directly against the destination
      // membership, the one deliberate cross-org authorisation in the system, and the reason the
      // membership check above has to come first.
      const destination = createResolver(ctx.db, { userId: ctx.userId, orgId: toOrgId });
      destination.assertCan('device:provision');

      const move = ctx.db.transaction(() => {
        // Tenancy event: live sessions on this device end wherever they are, in either org.
        endActiveSessions(ctx.db, { deviceId: device.id, reason: 'device_transferred' });
        stmt(ctx.db, 'moveDevice').run(toOrgId, device.id);
        auditSuccess(ctx.db, ctx, { action: 'device.transfer', targetType: 'device', targetId: device.id });
      });
      move();

      // Grants in the source org that named this device are left alone deliberately. They are
      // org-scoped by construction, so they are already inert: the device is no longer in that org,
      // so no question in that org can ever name it. If the device is transferred back, they
      // apply again, which is the correct reading of "the org granted this person access to that
      // machine". Written up in DECISIONS.md.
      return send(res, 200, { ok: true, id: device.id, from: params.org, to: toOrgId });
    });
  });

  // =========================================================================
  // Grants
  // =========================================================================

  // Gated on `user:read`, not `grant:create`, there is no `grant:read` permission in the
  // catalogue, and UI-INVENTORY.md §3 says so explicitly. Creating and revoking are separate
  // permissions, so an auditor can read the grants table without being able to change it.
  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'grant.read', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('user:read');

      const grants = stmt(ctx.db, 'grantsForOrg').all(params.org);
      // One extra query for the whole list rather than one per grant.
      const byGrant = new Map();
      for (const row of ctx.db.prepare(
        `SELECT gp.grant_id AS grantId, gp.permission AS permission
           FROM grant_permissions gp
           JOIN grants g ON g.id = gp.grant_id
          WHERE g.org_id = ?
          ORDER BY gp.permission`
      ).all(params.org)) {
        const list = byGrant.get(row.grantId);
        if (list) list.push(row.permission);
        else byGrant.set(row.grantId, [row.permission]);
      }

      return send(res, 200, {
        grants: grants.map((g) => grantRow(g, { userName: g.user_name, deviceName: g.device_name, permissions: byGrant.get(g.id) ?? [] })),
      });
    });
  });

  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'grant.create', targetType: 'grant' }, () => {
      ctx.resolver.assertCan('grant:create');

      const userId = requireString(ctx.body.userId, 'userId', { max: 60 });
      const effect = requireString(ctx.body.effect, 'effect', { max: 10 });
      if (!EFFECTS.includes(effect)) throw badRequest(`effect must be one of ${EFFECTS.join(', ')}`, 'invalid_effect');

      const permissions = ctx.body.permissions;
      if (!Array.isArray(permissions) || permissions.length === 0) {
        throw badRequest('at least one permission is required', 'empty_permissions');
      }
      const patterns = permissions.map((p) => requireString(p, 'permission', { max: 80 }));

      // A grant is org-scoped by construction, so the target has to be a member of THIS org. A user
      // from another org is 404, not 403, the same invisibility rule as a device.
      //
      // `status` is checked, and 'active' is the only acceptable answer: AUTH-DATA-MODEL.md §8
      // says "userId is an ACTIVE member of this org → 404". I had only excluded 'removed', which
      // meant a grant could be attached to a `suspended` or an un-accepted `invited` membership,
      // authority staged for someone who cannot use it, and pre-loaded for the moment they are
      // reinstated.
      const target = stmt(ctx.db, 'membershipByOrgUser').get(params.org, userId);
      if (!target || target.status !== 'active') throw notFound();

      // D9, first half. Self-grants are refused even for an owner: the point is that authority
      // flows downward through a deliberate act by someone else, not that owners are exempt.
      if (userId === ctx.userId) throw forbidden('you cannot create a grant for yourself', 'self_grant');

      // An optional device scope. Cross-org device -> 404, checked before any permission question.
      let deviceId = null;
      if (ctx.body.deviceId !== undefined && ctx.body.deviceId !== null) {
        deviceId = requireString(ctx.body.deviceId, 'deviceId', { max: 60 });
        deviceInOrg(ctx.db, params.org, deviceId);
      }

      // Half-open windows, stored in the canonical form so lexicographic comparison in SQL is
      // chronological comparison (D7). `normalizeTs` also turns '...+00:00' into '...Z', which
      // would otherwise sort before every stored value and read as already expired.
      const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
      const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
      if (expiresAt !== null && new Date(expiresAt).getTime() <= Date.now()) {
        // `GRANT_EXPIRED` appears in BOTH columns of the spec and they want different things.
        //
        //   PERMISSIONS.md §5, code table:  "| `GRANT_EXPIRED` | 400 | creating a grant that is
        //                                        already expired |"
        //   PERMISSIONS.md §5, prose:        "`reason` is the machine-readable cause,
        //                                        `missing_permission`, `explicit_deny`,
        //                                        `suspended`, `expired_grant`, `scope_mismatch`"
        //
        // So the CODE is `GRANT_EXPIRED` and the REASON is `expired_grant`, and I was emitting
        // `invalid_window` for the reason, a word that appears nowhere in the specification, on an
        // error the specification names twice. My own DECISIONS.md even claimed I emitted
        // `expired_grant`. Both are now what the documents say.
        throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is in the past', 'expired_grant');
      }
      if (startsAt !== null && expiresAt !== null && expiresAt <= startsAt) {
        throw badRequest('expiresAt must be after startsAt', 'invalid_window');
      }

      // D9, second half: no laundering. Checked at the scope being granted, and a wildcard is
      // expanded against the catalogue first, so `device:*` is checked against all seven device
      // permissions rather than waved through. A caller carrying an org-wide deny therefore cannot
      // pass that permission on to anyone.
      ctx.resolver.assertMayGrant(patterns, deviceId);

      const id = newId('grt');
      const create = ctx.db.transaction(() => {
        stmt(ctx.db, 'insertGrant').run(id, params.org, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
        for (const pattern of patterns) stmt(ctx.db, 'insertGrantPermission').run(id, pattern);
        // The version bump is what makes the new grant visible on the target's NEXT request. It is
        // not a session event: a live session keeps the authority it was started with.
        bumpPermVersion(ctx.db, { orgId: params.org, userId });
        auditSuccess(ctx.db, ctx, { action: 'grant.create', targetType: 'grant', targetId: id });
      });

      try {
        create();
      } catch (err) {
        // D19. The foreign key is the validator and it has already refused the write. All this does
        // is work out WHICH value it objected to, so the 400 can name it: `device:teleport` is a
        // typo, not a permission nobody holds, and a caller who is told which one is fixed.
        if (err?.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
          const unknown = unknownPermission(ctx.db, patterns);
          if (unknown) throw badRequest(`unknown permission ${JSON.stringify(unknown)}`, 'unknown_permission');
        }
        throw translateConstraint(err, { onForeignKey: () => badRequest('referenced row does not exist', 'invalid_reference') });
      }

      const grant = stmt(ctx.db, 'grantById').get(id);
      return send(res, 201, grantRow(grant, { permissions: patterns }));
    });
  });

  // Revoking an already-revoked grant is a 404: it is no longer visible (AUTH-DATA-MODEL.md §8).
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => {
      ctx.resolver.assertCan('grant:revoke');

      const grant = ctx.db.prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, params.org);
      if (!grant) throw notFound();

      const revoke = ctx.db.transaction(() => {
        stmt(ctx.db, 'revokeGrant').run(nowIso(), grant.id);
        bumpPermVersion(ctx.db, { orgId: params.org, userId: grant.user_id });
        auditSuccess(ctx.db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: grant.id });
      });
      revoke();

      // Like a create, this is a permission event and not a session event.
      return send(res, 200, { ok: true, id: grant.id });
    });
  });

  // =========================================================================
  // Reference data, for the console's forms.
  // =========================================================================
  //
  // The console needs the permission catalogue (to offer checkboxes on the grant form) and the
  // role list (to offer a role on an invite or a role-select). Both are read from the tables and
  // sent over the wire, because the alternative is a copy of the catalogue in `web/`, which is
  // the one thing BRIEF.md §5.3 and UI-INVENTORY.md §1 both forbid in spirit: two copies of the
  // model, which drift. Requires no org-scoped permission: this is the schema's reference data,
  // not anybody's authority.
  router.get('/v1/reference', async (ctx, _params, res) => {
    return send(res, 200, {
      permissions: stmt(ctx.db, 'referencePermissions').all(),
      patterns: stmt(ctx.db, 'referencePatterns').all().map((r) => r.pattern),
      roles: stmt(ctx.db, 'allRoles').all(),
      modes: ['view', 'control', 'terminal'],
    });
  });
}
