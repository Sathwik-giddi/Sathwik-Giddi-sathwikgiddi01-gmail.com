// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and especially
// under web/ — that is the bug this module exists to prevent. The console renders what this
// returns; it must never re-derive it.
//
// Everything is read from the tables at call time: the catalogue, the role baselines, the
// memberships and the grants. Nothing here knows how many permissions exist or which roles
// there are, because the database this runs against has one role and one permission that no
// document mentions.
//
// THE ALGORITHM, once, in `decide()` below:
//
//   1. no membership, or one that is not active  -> every permission denied, with the reason
//   2. collect the grants that apply to THIS question, right now (half-open windows, D7)
//   3. if any applicable grant denies it          -> deny, naming the grant
//   4. else if the role baseline has it           -> allow, naming the role
//   5. else if an applicable grant allows it      -> allow, naming the grant
//   6. else                                       -> deny, implicitly
//
// Step 3 before step 4 is D1 and is the load-bearing one: an org-wide deny is not carved out by
// a device-scoped allow, so the deny set is collected and tested before the baseline is
// consulted at all.

import { forbidden } from './http.js';
import { stmt } from './internal/sql.js';

/** The permission each session mode needs, beyond `session:start`. */
export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Why a permission is denied. The console explains itself with these, so the difference
// between "nobody granted this" and "someone took this away" has to survive to the response.
const NOT_A_MEMBER = 'not_a_member';
const SUSPENDED = 'suspended';
const EXPLICIT_DENY = 'explicit_deny';
const IMPLICIT = 'implicit';

// --- wildcards ---------------------------------------------------------------

/**
 * Does a grant naming `pattern` speak for the concrete permission `permission`?
 *
 * `permission_patterns` is the catalogue plus the wildcards, so a grant may hold `device:*` or
 * `*`. Matching is on the resource prefix, which is what makes `user:*` cover `user:role:update`
 * — a two-segment action — and not just the single-segment ones.
 */
function patternCovers(pattern, permission) {
  if (pattern === permission) return true;
  if (pattern === '*') return true;
  if (pattern.endsWith(':*')) return permission.startsWith(pattern.slice(0, -1));
  return false;
}

/** The concrete permissions a grant pattern speaks for, given the catalogue. */
function expand(pattern, catalogue) {
  const out = [];
  for (const permission of catalogue) if (patternCovers(pattern, permission)) out.push(permission);
  return out;
}

// --- the resolver ------------------------------------------------------------

/**
 * Build a resolver for ONE (user, org) pair at ONE instant.
 *
 * The catalogue, the baseline and every live grant are read once, here, and the per-device
 * answers are then computed in memory. That is the whole reason a device list is three queries
 * instead of three-per-row (BRIEF.md §6), and it is also the answer to "if you cache, say why it
 * cannot serve stale authority": this object's lifetime is one request. It is created by
 * `authenticate()` per request and dropped when the response is sent, so there is no window in
 * which a time-dependent answer (D7) or a revoked grant (D1) could be served from a previous
 * request's conclusion. `perm_version` staleness is still caught per request by `context.js`.
 */
export function createResolver(db, { userId, orgId, now = new Date() }) {
  const at = now.toISOString();
  const catalogue = stmt(db, 'catalogue').all().map((r) => r.key);

  const membership = stmt(db, 'membershipByOrgUser').get(orgId, userId) ?? null;

  // A membership only confers authority while it is `active`. `suspended` is reversible (D16) and
  // is reported distinctly because the console has to be able to say why. `invited` has not
  // joined yet and `removed` is gone (D15) — for both, the caller is simply not a member, and
  // inventing a third word for it would only give the console something to say that is not true.
  const isActive = membership !== null && membership.status === 'active';
  const role = membership?.role ?? null;
  const emptyReason =
    membership !== null && membership.status === 'suspended' ? SUSPENDED : NOT_A_MEMBER;

  const baseline = isActive
    ? new Set(stmt(db, 'baseline').all(role).map((r) => r.permission))
    : new Set();

  // Index the live grants by what they say rather than re-scanning them per permission.
  //   denyOrgWide[perm]        org-wide denies                       -> deny at any scope
  //   denyByDevice[dev][perm]  a deny scoped to one device           -> deny on that device only
  //   allowOrgWide[perm]       org-wide allows
  //   allowByDevice[dev][perm] device-scoped allows
  //   allowAnywhere[perm]      every allow, any scope                -> the org-level union
  //
  // Two dictionaries rather than one, because the org-level question and the device-level
  // question are answered from different sets. That asymmetry is deliberate and is the one place
  // the documents leave the answer open; see DECISIONS.md.
  const denyOrgWide = new Map();
  const denyByDevice = new Map();
  const allowOrgWide = new Map();
  const allowByDevice = new Map();
  const allowAnywhere = new Map();

  if (isActive) {
    const rows = stmt(db, 'grants').all(orgId, userId, at, at);

    // (grant, pattern) rows -> one entry per grant, holding every permission it covers. A grant
    // may reach the same permission through two patterns (`device:*` and `device:control`), so
    // the covered set is de-duplicated here rather than by a second pass over the rows.
    const byGrant = new Map();
    for (const row of rows) {
      let g = byGrant.get(row.id);
      if (!g) {
        g = { id: row.id, effect: row.effect, deviceId: row.deviceId, covered: new Set() };
        byGrant.set(row.id, g);
      }
      for (const permission of expand(row.pattern, catalogue)) g.covered.add(permission);
    }

    // The query orders by (created_at, id), so the first entry recorded for a permission is a
    // deterministic choice rather than whichever row the planner happened to return.
    const push = (map, key, grantId) => {
      const list = map.get(key);
      if (list) list.push(grantId);
      else map.set(key, [grantId]);
    };

    for (const g of byGrant.values()) {
      for (const permission of g.covered) {
        if (g.effect === 'deny') {
          if (g.deviceId === null) push(denyOrgWide, permission, g.id);
          else {
            let perDevice = denyByDevice.get(g.deviceId);
            if (!perDevice) denyByDevice.set(g.deviceId, (perDevice = new Map()));
            push(perDevice, permission, g.id);
          }
        } else {
          push(allowAnywhere, permission, g.id);
          if (g.deviceId === null) push(allowOrgWide, permission, g.id);
          else {
            let perDevice = allowByDevice.get(g.deviceId);
            if (!perDevice) allowByDevice.set(g.deviceId, (perDevice = new Map()));
            push(perDevice, permission, g.id);
          }
        }
      }
    }
  }

  /**
   * The one decision. `deviceId === null` is the org-level question.
   */
  function decide(deviceId) {
    const permissions = {};

    if (!isActive) {
      for (const key of catalogue) permissions[key] = { effect: 'deny', source: null, reason: emptyReason };
      return permissions;
    }

    const scopedDenies = deviceId === null ? null : denyByDevice.get(deviceId);
    const scopedAllows = deviceId === null ? null : allowByDevice.get(deviceId);

    for (const key of catalogue) {
      // 3. deny wins. Org-wide first, then — device-level only — a deny scoped to this device.
      //    A device-scoped deny is deliberately NOT promoted to the org-level question, because
      //    "not the lobby kiosk" is not a statement about the org. (DECISIONS.md)
      const deniedBy = denyOrgWide.get(key) ?? (scopedDenies ? scopedDenies.get(key) : undefined);
      if (deniedBy) {
        permissions[key] = { effect: 'deny', source: `grant:${deniedBy[0]}`, reason: EXPLICIT_DENY };
        continue;
      }

      // 4. the role baseline. Reported as the source when it applies, even if a grant also
      //    covers the permission: the baseline is the reason it is true, and a grant that
      //    duplicates it is not news.
      if (baseline.has(key)) {
        permissions[key] = { effect: 'allow', source: `role:${role}`, reason: null };
        continue;
      }

      // 5. an applicable allow grant. Org-wide at either scope; device-scoped only for the
      //    device it names, or for the org-level union, which asks "can they do this anywhere".
      const allowedBy =
        (deviceId === null ? allowAnywhere.get(key) : scopedAllows?.get(key) ?? allowOrgWide.get(key));
      if (allowedBy) {
        permissions[key] = { effect: 'allow', source: `grant:${allowedBy[0]}`, reason: null };
        continue;
      }

      // 6. absent means denied.
      permissions[key] = { effect: 'deny', source: null, reason: IMPLICIT };
    }

    return permissions;
  }

  const answerFor = (deviceId) => ({
    userId,
    orgId,
    deviceId: deviceId ?? null,
    role,
    membership,
    permissions: decide(deviceId),
  });

  return {
    userId,
    orgId,
    role,
    membership,
    /** The full answer for one device, or the org-level answer when deviceId is null. */
    resolve: answerFor,
    /** Just the permission map, for the callers that only need that. */
    permissionsFor: decide,
    can: (permission, deviceId = null) => decide(deviceId)[permission]?.effect === 'allow',
    /** The granted verdict for a permission, or null. */
    verdict: (permission, deviceId = null) => decide(deviceId)[permission] ?? null,
    assertCan: (permission, deviceId = null) => assertPermissionHeld(decide(deviceId), permission, deviceId),
    assertMayGrant: (patterns, deviceId = null) => assertMayGrantHeld(decide, patterns, deviceId),
    assertCanStartSession: (mode, deviceId) => assertSessionStartable(decide, mode, role, deviceId),
  };
}

// --- the module-level API the routes and the suites use ----------------------

/**
 * Resolve one user's permission set in one org. deviceId === null means the org-level
 * view; a deviceId means the exact per-device check.
 */
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  return createResolver(db, { userId, orgId, now }).resolve(deviceId);
}

/**
 * Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
 *
 * One catalogue read, one baseline read, one grant read — then every device is answered from
 * memory. Adding devices to an org adds no queries, which is the property BRIEF.md §6 asks for.
 */
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const resolver = createResolver(db, { userId, orgId, now });
  const byDevice = {};
  for (const deviceId of deviceIds) byDevice[deviceId] = resolver.permissionsFor(deviceId);
  return { role: resolver.role, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  return createResolver(db, { userId: ctx.userId, orgId: ctx.orgId }).can(permission, deviceId);
}

/** Throws 403 carrying the reason code, so a refusal is debuggable. */
export function assertCan(db, ctx, permission, deviceId = null) {
  return createResolver(db, { userId: ctx.userId, orgId: ctx.orgId }).assertCan(permission, deviceId);
}

/** No privilege laundering: you may only grant authority you hold at that scope. */
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  return createResolver(db, { userId: ctx.userId, orgId: ctx.orgId }).assertMayGrant(patterns, deviceId);
}

/**
 * The compound check: session:start AND the permission for the requested mode, and a refusal
 * must distinguish WHICH of the two was missing.
 */
export function assertCanStartSession(db, ctx, mode, deviceId) {
  return createResolver(db, { userId: ctx.userId, orgId: ctx.orgId }).assertCanStartSession(mode, deviceId);
}

// --- the refusals ------------------------------------------------------------

// A 403 has to say which of two different problems it is, so the reason code is derived from the
// resolution verdict rather than invented at the call site.
const REFUSAL_REASON = {
  [EXPLICIT_DENY]: EXPLICIT_DENY,
  [SUSPENDED]: SUSPENDED,
  [IMPLICIT]: 'missing_permission',
  [NOT_A_MEMBER]: 'missing_permission',
};

function assertPermissionHeld(permissions, permission, deviceId) {
  const verdict = permissions[permission];
  if (verdict && verdict.effect === 'allow') return verdict;

  const scope = deviceId ? ` on device ${deviceId}` : '';
  const reason = REFUSAL_REASON[verdict?.reason] ?? 'missing_permission';
  const detail = verdict?.reason === EXPLICIT_DENY ? ` (denied by ${verdict.source})` : '';
  throw forbidden(`missing ${permission}${scope}${detail}`, reason);
}

/**
 * D9's second half: you may not grant authority you do not hold, at the scope you are granting
 * it. A caller who is blocked by an org-wide deny therefore cannot pass that permission on —
 * which is the point: the deny cannot be laundered through a second grant.
 *
 * Patterns are expanded against the catalogue, so granting `device:*` is checked against all
 * seven device permissions rather than being waved through as "a wildcard".
 */
function assertMayGrantHeld(decide, patterns, deviceId) {
  const here = decide(deviceId);

  for (const pattern of patterns) {
    for (const permission of expand(pattern, Object.keys(here))) {
      const verdict = here[permission];
      if (verdict?.effect === 'allow') continue;

      // The refusal reason is the resolution verdict's reason, so the caller is told what is in
      // the way. `explicit_deny` is the useful one: it names the grant that has to be revoked
      // first, which is a thing the caller can go and do.
      //
      // I first wrote a `scope_mismatch` branch here, for the case "you hold this org-wide but
      // not on this device". My own test proved it unreachable: an org-wide allow is collected at
      // every device scope (see `decide`), so the ONLY way to hold a permission org-wide and not
      // on a device is a device-scoped deny — which is the explicit_deny case. PERMISSIONS.md §5
      // lists `scope_mismatch` as a reason code; under §3's algorithm it cannot occur. Written
      // up in DECISIONS.md rather than left in as decoration.
      const denied = verdict?.reason === EXPLICIT_DENY;
      const scope = deviceId ? ` on device ${deviceId}` : '';
      throw forbidden(
        denied
          ? `${pattern} covers ${permission}, which you do not hold${scope} (denied by ${verdict.source})`
          : `${pattern} covers ${permission}, which you do not hold${scope}`,
        denied ? EXPLICIT_DENY : 'missing_permission'
      );
    }
  }

  return true;
}

/**
 * session:start AND the mode's permission, on the same device. Order matters: `session:start`
 * is tested first because "you cannot open sessions at all" and "not on this device" are
 * different problems, and the caller has to be able to tell them apart.
 *
 * Returns the `authorized_by` snapshot the session row carries. The grant ids are the ones that
 * actually decided the two permissions, not every grant the user has — otherwise the snapshot
 * would not be evidence of why this session was allowed.
 */
function assertSessionStartable(decide, mode, role, deviceId) {
  const permission = MODE_PERMISSION[mode];
  if (!permission) throw forbidden(`unknown session mode ${JSON.stringify(mode)}`, 'missing_permission');

  const here = decide(deviceId);

  assertPermissionHeld(here, 'session:start', deviceId);

  try {
    assertPermissionHeld(here, permission, deviceId);
  } catch (err) {
    // Same 403, different cause: distinguishing these two is the point of the compound check
    // (BRIEF.md §5.1, AUTH-DATA-MODEL.md §9).
    throw forbidden(err.message, 'missing_device_permission');
  }

  const grantIds = [];
  for (const key of ['session:start', permission]) {
    const source = here[key]?.source;
    if (typeof source === 'string' && source.startsWith('grant:')) {
      const id = source.slice('grant:'.length);
      if (!grantIds.includes(id)) grantIds.push(id);
    }
  }

  return { role, grantIds, snapshotAt: new Date().toISOString() };
}

export const __testing = { patternCovers, expand };
