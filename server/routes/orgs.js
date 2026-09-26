// orgs.js — organizations, members, effective permissions, and the audit log.
//
// The ordering inside every handler here is the same and it is the whole point of the file:
//
//   1. assertSameOrg(caller, :org)      -> 404. Structural isolation, before anything else.
//   2. look the target up IN THIS ORG   -> 404. Invisible is not forbidden.
//   3. assertCan(permission)            -> 403. Now, and only now, may you do this?
//   4. do the thing, inside a transaction, with the audit row inside it
//   5. bump perm_version                -> every token for that person is stale next request
//
// Steps 1 and 2 produce byte-identical bodies, because a 403 on a resource in another org would
// confirm that resource exists.

import { send, notFound, badRequest, selfRoleChange } from '../http.js';
import { assertSameOrg } from '../context.js';
import { stmt } from '../internal/sql.js';
import { newId, nowIso } from '../db.js';
import { requireString, boundedInt, memberRow, LIMITS } from '../internal/http.js';
import { auditDenials, auditSuccess } from '../audit.js';
import { assertRoleExists, assertCanModify, assertRoleAssignable, assertNotLastOwner, endActiveSessions, expireStaleSessions } from '../lifecycle.js';
import { createResolver } from '../permissions.js';

// The six themes `scripts/personalise.js` draws from, for orgs this app creates. A new org needs a
// theme because `data-org-theme` is a required console attribute; the value only has to be
// distinct enough that the console renders a visibly different org.
const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

const orgRow = (org) => ({ id: org.id, name: org.name, theme: org.theme, max_session_minutes: org.max_session_minutes, created_at: org.created_at });

export function register(router) {
  // =========================================================================
  // Orgs
  // =========================================================================

  router.get('/v1/orgs', async (ctx, _params, res) => {
    const orgs = stmt(ctx.db, 'orgsForUser').all(ctx.userId);
    return send(res, 200, { orgs: orgs.map((o) => ({ id: o.id, name: o.name, theme: o.theme, role: o.role })) });
  });

  // Creating an org needs no org-scoped permission: there is no org yet to hold one. What it does
  // need is a transaction, because an org without an owner membership is an org nobody can
  // administer — and `assertNotLastOwner` would then refuse every future fix.
  router.post('/v1/orgs', async (ctx, _params, res) => {
    const name = requireString(ctx.body.name, 'name', { max: LIMITS.name });
    const requested = typeof ctx.body.theme === 'string' ? ctx.body.theme : null;
    if (requested && !THEMES.includes(requested)) throw badRequest(`theme must be one of ${THEMES.join(', ')}`, 'invalid_theme');

    // Deterministic rather than random: the same name yields the same accent, so a re-created org
    // does not change colour under the user, and two orgs never collide on an accent by accident
    // of the clock.
    const theme = requested ?? THEMES[Math.abs([...name].reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 7)) % THEMES.length];
    const id = newId('org');

    const create = ctx.db.transaction(() => {
      stmt(ctx.db, 'insertOrg').run(id, name, theme, 60);
      stmt(ctx.db, 'insertMembership').run(newId('mem'), id, ctx.userId, 'owner', ctx.userId, nowIso());
      auditSuccess(ctx.db, ctx, { orgId: id, action: 'org.create', targetType: 'org', targetId: id });
      return stmt(ctx.db, 'orgById').get(id);
    });

    return send(res, 201, { ...orgRow(create()), role: 'owner' });
  });

  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'org.update', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('org:update');

      const name = requireString(ctx.body.name, 'name', { max: LIMITS.name });
      const update = ctx.db.transaction(() => {
        stmt(ctx.db, 'renameOrg').run(name, params.org);
        auditSuccess(ctx.db, ctx, { action: 'org.update', targetType: 'org', targetId: params.org });
      });
      update();
      return send(res, 200, orgRow(stmt(ctx.db, 'orgById').get(params.org)));
    });
  });

  // Soft delete. The org row survives so the audit log that references it still resolves, and
  // `organizations.deleted_at` is what stops the org being addressed by a live token — the
  // membership lookup in context.js joins on `deleted_at IS NULL`, so every token for every former
  // member starts failing with a 401 the moment this commits.
  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'org.delete', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('org:delete');

      // There is deliberately no LAST_OWNER guard here: deleting the org is how an org with an
      // unwanted owner stops existing, and `org:delete` is owner-only in the baseline anyway.
      const remove = ctx.db.transaction(() => {
        expireStaleSessions(ctx.db, { orgId: params.org });
        endActiveSessions(ctx.db, { orgId: params.org, reason: 'membership_removed' });
        for (const m of stmt(ctx.db, 'membersOfOrg').all(params.org)) {
          if (m.status !== 'active') continue;
          stmt(ctx.db, 'setMemberStatus').run('removed', m.id);
        }
        stmt(ctx.db, 'softDeleteOrg').run(nowIso(), params.org);
        auditSuccess(ctx.db, ctx, { action: 'org.delete', targetType: 'org', targetId: params.org });
      });
      remove();

      return send(res, 200, { ok: true, id: params.org });
    });
  });

  // =========================================================================
  // Members
  // =========================================================================

  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'member.read', targetType: 'org', targetId: params.org }, () => {
      // The Grants card shares this gate with People, because the API does (UI-INVENTORY.md §3).
      ctx.resolver.assertCan('user:read');
      const members = stmt(ctx.db, 'membersOfOrg').all(params.org);
      return send(res, 200, { members: members.map((m) => memberRow(m, { email: m.email, name: m.name })) });
    });
  });

  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'user.effective.read', targetType: 'user', targetId: params.userId }, () => {
      // "user:read, or self". Self is not a shortcut past the org boundary — assertSameOrg has
      // already run — it is just a person being able to see their own resolved set, which is how
      // the console explains a lock to someone who cannot see the People card at all.
      if (params.userId !== ctx.userId) ctx.resolver.assertCan('user:read');

      const membership = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      if (!membership) throw notFound();

      const answer = createResolver(ctx.db, { userId: params.userId, orgId: params.org });
      return send(res, 200, { role: answer.role, status: membership.status, permissions: answer.permissionsFor(null) });
    });
  });

  // --- role change ---------------------------------------------------------
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'member.role.update', targetType: 'user', targetId: params.userId }, () => {
      ctx.resolver.assertCan('user:role:update');

      // Self before anything else: SELF_ROLE_CHANGE is a more specific answer than FORBIDDEN, and
      // an admin changing their own role is a different mistake from an admin changing a peer.
      if (params.userId === ctx.userId) throw selfRoleChange();

      const target = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      if (!target) throw notFound();

      const newRole = requireString(ctx.body.role, 'role', { max: 40 });
      assertRoleExists(ctx.db, newRole);
      assertRoleAssignable(ctx.db, ctx.role, newRole);
      assertCanModify(ctx.db, ctx.role, target.role);
      if (target.role === 'owner' && newRole !== 'owner') assertNotLastOwner(ctx.db, params.org, params.userId);

      const apply = ctx.db.transaction(() => {
        stmt(ctx.db, 'setMemberRole').run(newRole, target.id);
        auditSuccess(ctx.db, ctx, { action: 'member.role.update', targetType: 'user', targetId: params.userId });
      });
      apply();

      // The bumped perm_version is what makes the change visible on the NEXT request. The session
      // in flight is deliberately untouched — see endActiveSessions, which is not called here.
      const updated = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      return send(res, 200, { user_id: updated.user_id, role: updated.role, perm_version: updated.perm_version });
    });
  });

  // --- suspend / reinstate -------------------------------------------------
  const setSuspended = (suspended) => async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    const action = suspended ? 'member.suspend' : 'member.reinstate';
    return auditDenials(ctx.db, ctx, { action, targetType: 'user', targetId: params.userId }, () => {
      ctx.resolver.assertCan('user:remove');
      if (params.userId === ctx.userId) throw badRequest('you cannot suspend yourself', 'self_suspend');

      const target = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      if (!target) throw notFound();

      if (suspended && target.role === 'owner') assertNotLastOwner(ctx.db, params.org, params.userId);
      if (!suspended && target.role === 'owner') assertNotLastOwner(ctx.db, params.org, params.userId);

      // Suspension CASCADES to live sessions (D16 / D20) — it is an account event, not a
      // permission tweak. Reinstatement does not resurrect them; a session is a record of
      // something that happened, and re-creating it would be a lie.
      const apply = ctx.db.transaction(() => {
        stmt(ctx.db, 'setMemberStatus').run(suspended ? 'suspended' : 'active', target.id);
        if (suspended) endActiveSessions(ctx.db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
        auditSuccess(ctx.db, ctx, { action, targetType: 'user', targetId: params.userId });
      });
      apply();

      const updated = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      return send(res, 200, { user_id: updated.user_id, status: updated.status, perm_version: updated.perm_version });
    });
  };

  router.post('/v1/orgs/:org/members/:userId/suspend', setSuspended(true));
  router.delete('/v1/orgs/:org/members/:userId/suspend', setSuspended(false));

  // --- self-leave ----------------------------------------------------------
  // No permission required: leaving is not something an org can grant or withhold. The only
  // refusal is LAST_OWNER, because an org with no owner cannot be administered or deleted.
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);

    const target = stmt(ctx.db, 'membershipByOrgUser').get(params.org, ctx.userId);
    if (!target) throw notFound();
    if (target.status !== 'active') throw notFound();
    if (target.role === 'owner') assertNotLastOwner(ctx.db, params.org, ctx.userId);

    const apply = ctx.db.transaction(() => {
      stmt(ctx.db, 'setMemberStatus').run('removed', target.id);
      endActiveSessions(ctx.db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
      auditSuccess(ctx.db, ctx, { action: 'member.leave', targetType: 'user', targetId: ctx.userId });
    });
    apply();

    // Their access token is stale from this response onward (perm_version moved), and the console
    // treats the resulting 401 TOKEN_STALE as a sign-out rather than an error.
    return send(res, 200, { ok: true });
  });

  // --- remove --------------------------------------------------------------
  // D15: the user row is NEVER deleted. Removal is a membership status, which is what lets the
  // audit log keep resolving an actor id forever.
  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'member.remove', targetType: 'user', targetId: params.userId }, () => {
      ctx.resolver.assertCan('user:remove');
      if (params.userId === ctx.userId) throw badRequest('use the self-leave endpoint to leave', 'self_remove');

      const target = stmt(ctx.db, 'membershipByOrgUser').get(params.org, params.userId);
      if (!target) throw notFound();
      assertCanModify(ctx.db, ctx.role, target.role);
      if (target.role === 'owner') assertNotLastOwner(ctx.db, params.org, params.userId);

      const apply = ctx.db.transaction(() => {
        stmt(ctx.db, 'setMemberStatus').run('removed', target.id);
        endActiveSessions(ctx.db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
        auditSuccess(ctx.db, ctx, { action: 'member.remove', targetType: 'user', targetId: params.userId });
      });
      apply();

      return send(res, 200, { ok: true, user_id: params.userId });
    });
  });

  // =========================================================================
  // Audit
  // =========================================================================

  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'audit.read', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('audit:read');

      // Boundaries are DEFINED, not clamped (scripts/check-api.js:189): `limit=0`, `limit=-1` and
      // `limit=99999` are all 400, `offset=99999` is a 200 with an empty page. A clamp would hide
      // a caller's bug from them.
      const limit = boundedInt(ctx.query, 'limit', { min: 1, max: LIMITS.limit, fallback: LIMITS.limitDefault });
      const offset = boundedInt(ctx.query, 'offset', { min: 0, max: Number.MAX_SAFE_INTEGER, fallback: 0 });

      const rows = ctx.db.prepare(
        `SELECT e.*, u.name AS actor_name
           FROM audit_events e
           LEFT JOIN users u ON u.id = e.actor_id
          WHERE e.org_id = ?
          ORDER BY e.at DESC, e.id DESC
          LIMIT ? OFFSET ?`
      ).all(params.org, limit, offset);

      const total = ctx.db.prepare('SELECT count(*) AS n FROM audit_events WHERE org_id = ?').get(params.org).n;

      return send(res, 200, { events: rows, limit, offset, total });
    });
  });
}
