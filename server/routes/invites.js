// invites.js — the only way a person joins an organization (D14).
//
// The lifecycle, which is the part worth stating because no document enumerates it:
//
//   created ──accept──> accepted_at set, single use forever
//      │
//      ├──revoke──> revoked_at set, dead
//      │
//      └──7 days pass──> dead by expiry, and no row changes
//
// "Dead" is computed, never stored as a status, because the schema has no status column: an
// invite is live when `accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now`. The
// partial unique index `one_live_invite_per_email` keys off the first two, so an expired invite
// does not block a fresh one for the same address — which is right, and is why I did not add an
// application-level "is there already an invite" check that would have to reproduce that rule.

import { send, notFound, badRequest, conflict, gone, forbidden, unauthenticated, tooManyRequests } from '../http.js';
import { attempt } from '../ratelimit.js';
import { assertSameOrg, optionalCaller } from '../context.js';
import { stmt } from '../internal/sql.js';
import { newId, nowIso } from '../db.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { requireEmail, requireString, requirePassword, translateConstraint, LIMITS } from '../internal/http.js';
import { audit, auditDenials, auditSuccess } from '../audit.js';
import { assertRoleExists, assertRoleAssignable } from '../lifecycle.js';

const INVITE_TTL_DAYS = 7; // D17

const inviteRow = (invite, { orgName, deviceCount } = {}) => ({
  id: invite.id,
  org_id: invite.org_id,
  org_name: orgName ?? null,
  email: invite.email,
  role: invite.role,
  expires_at: invite.expires_at,
  accepted_at: invite.accepted_at,
  revoked_at: invite.revoked_at,
  created_at: invite.created_at,
  device_count: deviceCount ?? null,
});

/** A live invite is one that is neither accepted nor revoked. Expiry is applied by comparison. */
const isLive = (invite) => invite.accepted_at === null && invite.revoked_at === null;
const isExpired = (invite) => new Date(invite.expires_at).getTime() <= Date.now();

/**
 * `GET /invites/:token` is PUBLIC and unauthenticated, which makes it the one endpoint in the
 * system that hands information to a caller we know nothing about. The raw token is a bearer
 * credential, so the response carries the minimum that lets someone decide whether to accept:
 * the org's NAME, the email, and the role. Not the org id, not a device count, not a member list —
 * `scripts/check-api.js:171-172` asserts the body contains neither `lab-mac` nor `org_acme`, and
 * `tests/ui.spec.js:312` asserts the same thing through the rendered page.
 */
function publicInviteView(invite, org) {
  return {
    orgName: org.name,
    email: invite.email,
    role: invite.role,
    expiresAt: invite.expires_at,
  };
}

export function register(router) {
  // =========================================================================
  // Scoped to an org, and permission-gated by user:invite.
  // =========================================================================

  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'invite.create', targetType: 'invite' }, () => {
      ctx.resolver.assertCan('user:invite');

      const email = requireEmail(ctx.body.email);
      const role = requireString(ctx.body.role, 'role', { max: 40 });
      assertRoleExists(ctx.db, role);

      // Handing out a role above your own is the same rule as assigning one (D8), so the invite
      // path cannot be used to sidestep the role-change path.
      //
      // `assertRoleAssignable`, not `assertCanModify`. I had the latter here, which compares the
      // caller's rank against the INVITED role as if it were an existing member — and since an
      // invited role has no membership to be "strictly lower" than, an admin inviting an admin was
      // refused with "a admin cannot modify a admin". Nobody is being modified by an invite.
      assertRoleAssignable(ctx.db, ctx.role, role);

      // Already an ACTIVE member? The `memberships(org_id, user_id)` unique index is the real
      // guarantee, but a 409 here is a far better message than a raw constraint error, and it is
      // not a race because the index still catches the concurrent case below.
      //
      // `status <> 'removed'` matters and I got it wrong first: a removed member still has a row,
      // so without this filter a person who had been removed could never be invited back — the one
      // moment the flow most needs to work. Offboard/rehire is a named seam, and this was it.
      const byEmail = ctx.db.prepare(
        `SELECT m.status FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND u.email = ?`
      ).get(params.org, email);
      if (byEmail && byEmail.status !== 'removed') {
        throw conflict('that person is already a member of this organization', 'ALREADY_MEMBER');
      }

      const raw = newInviteToken();
      const id = newId('inv');
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 86_400_000).toISOString();

      const create = ctx.db.transaction(() => {
        // Hashed at rest (D17). The raw value is returned exactly once, here, and never stored,
        // never logged, and never recoverable — there is no endpoint that can show it again.
        stmt(ctx.db, 'insertInvite').run(id, params.org, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
        auditSuccess(ctx.db, ctx, { action: 'invite.create', targetType: 'invite', targetId: id });
      });

      try {
        create();
      } catch (err) {
        // The partial unique index is the race-safe enforcement; the check above is only there to
        // produce a readable message in the common case.
        throw translateConstraint(err, { onUnique: () => conflict('there is already a live invite for that address', 'INVITE_EXISTS') });
      }

      const invite = stmt(ctx.db, 'inviteByHash').get(hashInviteToken(raw));
      return send(res, 201, { ...inviteRow(invite), inviteToken: raw });
    });
  });

  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'invite.read', targetType: 'org', targetId: params.org }, () => {
      ctx.resolver.assertCan('user:invite');
      const invites = stmt(ctx.db, 'invitesForOrg').all(params.org);
      return send(res, 200, { invites: invites.map((i) => inviteRow(i)) });
    });
  });

  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    assertSameOrg(ctx, params.org);
    return auditDenials(ctx.db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: params.id }, () => {
      ctx.resolver.assertCan('user:invite');
      const invite = ctx.db.prepare('SELECT * FROM invites WHERE id = ? AND org_id = ?').get(params.id, params.org);
      if (!invite) throw notFound();
      if (!isLive(invite)) throw notFound();   // already spent — nothing left to see

      const revoke = ctx.db.transaction(() => {
        stmt(ctx.db, 'revokeInvite').run(nowIso(), invite.id);
        auditSuccess(ctx.db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: invite.id });
      });
      revoke();
      return send(res, 200, { ok: true, id: invite.id });
    });
  });

  // =========================================================================
  // Public. No token, no org in the path — just the invite token.
  // =========================================================================

  // 404 for "no such token" and 410 for "this token existed and is spent". The distinction is
  // safe here because the caller already holds the token, so it tells them something they could
  // not have guessed: whether their link was ever valid.
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const invite = lookupInvite(ctx.db, params.token);
    // A token the caller HOLDS, so telling them it is spent costs nothing they could not already
    // know, and `410 GONE` is the status that means exactly this. The POST below uses 409 for the
    // same state because there the request conflicts with the resource rather than describing it.
    assertUsable(invite, () => gone(inviteDeadReason(invite)));
    const org = stmt(ctx.db, 'orgById').get(invite.org_id);
    if (!org || org.deleted_at !== null) throw notFound();

    return send(res, 200, publicInviteView(invite, org));
  });

  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    // Gated before anything else, and with no credential to key on: an invite token is a bearer
    // credential that has not been spent yet, so there is nothing to count failures against. The
    // address ceiling in server/ratelimit.js is the whole defence here, which is the right shape —
    // this endpoint creates accounts, and creating accounts in a loop is the thing to bound.
    const gate = attempt(ctx.req, null);
    if (gate.limited) throw tooManyRequests(gate.retryAfter);

    const invite = lookupInvite(ctx.db, params.token);
    // Redeeming a spent invite is a CONFLICT with the current state of the resource, not a
    // description of a resource that is gone — which is why this is 409 and the GET above is 410.
    // `scripts/check-api.js:178` pins the 409.
    assertUsable(invite, () => conflict('this invite has already been used', 'INVITE_USED'));
    const org = stmt(ctx.db, 'orgById').get(invite.org_id);
    if (!org || org.deleted_at !== null) throw notFound();

    // Three ways in, and the difference matters:
    //   - signed in, and it is your account   -> attach this org to the account you hold
    //   - signed out, and the address is new  -> create the account with the password given
    //   - signed out, and the address is taken -> PROVE it is you by giving the existing password
    //
    // The third case is not a password reset and must not become one. The link proves the INVITE;
    // the password proves the PERSON. Nothing about the stored credential changes, and a wrong
    // password gets the same generic refusal a sign-in would.
    //
    // It has to exist at all: a person removed from their only organization cannot sign in (login
    // requires an active membership, because a token must be scoped to an org), so without it the
    // one moment they most need to redeem an invite is the one moment they cannot. Found by the
    // offboard/rehire case in `scripts/check-http-seams.js`.
    const caller = optionalCaller(ctx.db, ctx.secret, ctx.req);
    const existingUser = stmt(ctx.db, 'userByEmail').get(invite.email);

    if (caller && existingUser && caller.user.email !== invite.email) {
      throw forbidden('this invite was issued to a different email address', 'invite_email_mismatch');
    }

    const name = requireString(ctx.body.name, 'name', { max: LIMITS.name });
    const password = ctx.body.password === undefined ? null : requirePassword(ctx.body.password);

    let userId;
    if (existingUser) {
      if (caller) {
        userId = existingUser.id;
      } else {
        // Re-authenticate against the EXISTING credential. A wrong password is refused exactly as a
        // sign-in would refuse it, and with the same wording, so this endpoint is not a password
        // oracle for addresses that happen to exist.
        if (password === null || !(await verifyPassword(password, existingUser.password_hash))) {
          throw unauthenticated('that email already has an account — enter its existing password to join');
        }
        userId = existingUser.id;
      }
    } else {
      if (password === null) throw badRequest('password is required');
      // The unique index on users.email is what makes two simultaneous accepts of the same invite
      // resolve to one user and one membership rather than two half-created accounts.
      try {
        userId = newId('usr');
        stmt(ctx.db, 'insertUser').run(userId, invite.email, name, await hashPassword(password));
      } catch (err) {
        // Someone else created this address between the lookup and the insert. Re-read the invite:
        // if it is spent, that is what actually happened, and saying so is more use than reporting
        // a unique-constraint failure on the email.
        const fresh = lookupInvite(ctx.db, params.token);
        if (!isLive(fresh) || isExpired(fresh)) throw conflict('this invite has already been used', 'INVITE_USED');
        throw translateConstraint(err, { onUnique: () => conflict('an account with that email already exists', 'ACCOUNT_EXISTS') });
      }
    }

    // Re-read the invite now that the account question is settled. Two accepts of ONE invite both
    // read it as live at the top of the handler; by the time the loser gets here the winner has
    // committed, so the honest answer is "this invite is spent" — not "you are already a member",
    // which is a true but useless thing to tell someone who clicked a link five seconds ago.
    // `scripts/check-http-seams.js` fires two accepts in parallel and asserts exactly this.
    const current = lookupInvite(ctx.db, params.token);
    assertUsable(current, () => conflict('this invite has already been used', 'INVITE_USED'));

    // Is this org still able to have this person in it? An org can be deleted between the invite
    // being mailed and being opened, and the membership insert would happily create an active
    // membership in a soft-deleted org.
    const already = stmt(ctx.db, 'membershipByOrgUser').get(invite.org_id, userId);
    if (already && already.status === 'active') throw conflict('you are already a member of this organization', 'ALREADY_MEMBER');

    const accept = ctx.db.transaction(() => {
      if (already) {
        // Re-hire: revive the existing membership row rather than inserting a second one, because
        // `memberships` has UNIQUE (org_id, user_id). Its grants were never deleted on removal —
        // see DECISIONS.md, decision 5 — so they come back with the membership.
        ctx.db.prepare(`UPDATE memberships SET status='active', role=?, joined_at=COALESCE(joined_at, ?), perm_version = perm_version + 1 WHERE id = ?`)
          .run(invite.role, nowIso(), already.id);
      } else {
        stmt(ctx.db, 'insertMembership').run(newId('mem'), invite.org_id, userId, invite.role, userId, nowIso());
      }

      // Single use, enforced by the `accepted_at IS NULL` in the WHERE clause rather than by a
      // read-then-write, so two simultaneous accepts produce one membership and one 409.
      const claimed = stmt(ctx.db, 'acceptInvite').run(nowIso(), userId, invite.id);
      if (claimed.changes === 0) throw conflict('this invite has already been used', 'INVITE_USED');

      audit(ctx.db, { orgId: invite.org_id, actorId: userId, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    });

    try {
      accept();
    } catch (err) {
      if (err?.status) throw err;                       // already an HttpError from inside
      throw translateConstraint(err, { onUnique: () => conflict('this invite has already been used', 'INVITE_USED') });
    }

    const user = stmt(ctx.db, 'userById').get(userId);
    const membership = stmt(ctx.db, 'membershipByOrgUser').get(invite.org_id, userId);

    return send(res, 200, {
      org: { id: org.id, name: org.name, theme: org.theme },
      role: membership.role,
      user: { id: user.id, email: user.email, name: user.name },
      // The org to open straight into, so the console does not have to guess which of the caller's
      // orgs this invite just added.
      orgId: org.id,
    });
  });
}

/**
 * Resolve a raw invite token to its row, or 404. Deliberately does NOT check whether the invite is
 * still usable: the two callers disagree about which status a spent invite should be — 410 GONE
 * when describing the token over GET, 409 CONFLICT when trying to redeem it over POST — so the
 * liveness check belongs to the caller.
 */
function lookupInvite(db, raw) {
  // A token is 32 random bytes, so anything shorter was never issued by us. Refusing on length
  // first also means a 4-character string is never hashed, which is a small thing to be able to say.
  if (typeof raw !== 'string' || raw.length < 20) throw notFound();
  const invite = stmt(db, 'inviteByHash').get(hashInviteToken(raw));
  if (!invite) throw notFound();
  return invite;
}

const inviteDeadReason = (invite) =>
  invite.accepted_at !== null ? 'this invite has already been used'
  : invite.revoked_at !== null ? 'this invite was cancelled'
  : isExpired(invite) ? 'this invite has expired'
  : null;

/**
 * Throw the error the caller wants, if the invite is spent.
 *
 * `fail` RETURNS an HttpError rather than throwing it, and this THROWS what it returns. Getting
 * that wrong is the single nastiest bug I hit in this build: the first version called `fail()` and
 * threw away its return value, so neither the 410 nor the 409 path ever fired — a spent invite
 * sailed through as though it were live. It was caught only because `check-api.js:178` asserts
 * the 409 and I happened to also be asserting the CODE, which was coming back as `ALREADY_MEMBER`
 * instead of `INVITE_USED`. The shipped assertion passed the whole time, because both are 409s.
 * A test that passes for the wrong reason is worse than a test that fails.
 */
const assertUsable = (invite, fail) => {
  if (!isLive(invite) || isExpired(invite)) throw fail();
  return invite;
};
