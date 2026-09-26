// Prepared-statement registry.
//
// better-sqlite3 compiles SQL on prepare(), so a statement that is prepared per call is compiled
// per call. Everything in this server that runs more than once per request goes through here, and
// the compiled statements are cached per connection in a WeakMap — so the test suites, which each
// open their own throwaway database, get their own set and none of them leak into another.
//
// Two reasons this is a module and not a helper sprinkled through the routes:
//   1. the SQL is the interesting part of most of these queries, and it should be readable in one
//      place rather than assembled at each call site;
//   2. it makes the query count of any request countable by reading one file.

const SQL = {
  // --- identity ---
  membershipWithOrg: `
    SELECT m.id AS membership_id, m.org_id, m.user_id, m.role, m.status, m.perm_version,
           o.name AS org_name, o.theme AS org_theme,
           o.max_session_minutes, o.deleted_at
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
     WHERE m.org_id = ? AND m.user_id = ?`,

  userById: `SELECT id, email, name FROM users WHERE id = ?`,
  userByEmail: `SELECT id, email, name, password_hash FROM users WHERE email = ?`,

  // --- permissions ---
  catalogue: `SELECT key FROM permissions ORDER BY key`,
  baseline: `SELECT permission FROM role_permissions WHERE role = ?`,
  membershipByOrgUser: `SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`,
  grants: `
    SELECT g.id AS id, g.effect AS effect, g.device_id AS deviceId, gp.permission AS pattern
      FROM grants g
      JOIN grant_permissions gp ON gp.grant_id = g.id
     WHERE g.org_id = ? AND g.user_id = ? AND g.revoked_at IS NULL
       AND (g.starts_at IS NULL OR g.starts_at <= ?)
       AND (g.expires_at IS NULL OR ? < g.expires_at)
     ORDER BY g.created_at, g.id, gp.permission`,

  activeMembershipsForUser: `
    SELECT o.id AS orgId, o.name AS name, o.theme AS theme, m.role AS role, m.status AS status
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
     WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
     ORDER BY o.name COLLATE NOCASE, o.id`,

  // --- lifecycle / modification authority ---
  allRoles: `SELECT key, rank FROM roles`,
  roleByKey: `SELECT key, rank, label FROM roles WHERE key = ?`,
  owners: `SELECT user_id AS userId FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`,
  maxSessionMinutes: `SELECT max_session_minutes FROM organizations WHERE id = ?`,

  // --- audit ---
  insertAudit: `
    INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`,

  // --- orgs / members ---
  orgById: `SELECT id, name, theme, max_session_minutes, created_at, deleted_at FROM organizations WHERE id = ?`,
  orgsForUser: `
    SELECT o.id AS id, o.name AS name, o.theme AS theme, m.role AS role, m.status AS status
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
     WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
     ORDER BY o.name COLLATE NOCASE, o.id`,
  insertOrg: `INSERT INTO organizations (id, name, theme, max_session_minutes) VALUES (?,?,?,?)`,
  renameOrg: `UPDATE organizations SET name = ? WHERE id = ? AND deleted_at IS NULL`,
  softDeleteOrg: `UPDATE organizations SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`,
  membershipByOrgUser: `SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`,
  membersOfOrg: `
    SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version, m.joined_at, u.email, u.name
      FROM memberships m
      JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ?
     ORDER BY u.name COLLATE NOCASE`,
  setMemberRole: `UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE id = ?`,
  setMemberStatus: `UPDATE memberships SET status = ?, perm_version = perm_version + 1 WHERE id = ?`,

  // --- invites ---
  insertUser: `INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)`,
  insertMembership: `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?,?,?,?,'active',?,?)`,
  insertInvite: `
    INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
    VALUES (?,?,?,?,?,?,?)`,
  inviteByHash: `SELECT * FROM invites WHERE token_hash = ?`,
  liveInviteByEmail: `SELECT id FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL`,
  invitesForOrg: `SELECT * FROM invites WHERE org_id = ? ORDER BY created_at DESC`,
  revokeInvite: `UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND accepted_at IS NULL`,
  acceptInvite: `UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`,

  // --- devices ---
  devicesOfOrg: `SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name COLLATE NOCASE`,
  deviceById: `SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL`,
  deviceInOrg: `SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`,
  insertDevice: `INSERT INTO devices (id, org_id, name, kind, online) VALUES (?,?,?,?,?)`,
  updateDevice: `UPDATE devices SET name = ? WHERE id = ?`,
  softDeleteDevice: `UPDATE devices SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`,
  moveDevice: `UPDATE devices SET org_id = ? WHERE id = ? AND deleted_at IS NULL`,

  // --- grants ---
  grantsForOrg: `
    SELECT g.*, u.name AS user_name, d.name AS device_name
      FROM grants g
      JOIN users u ON u.id = g.user_id
      LEFT JOIN devices d ON d.id = g.device_id
     WHERE g.org_id = ?
     ORDER BY g.created_at DESC, g.id`,
  grantById: `SELECT * FROM grants WHERE id = ? AND revoked_at IS NULL`,
  grantPermissions: `SELECT permission FROM grant_permissions WHERE grant_id = ? ORDER BY permission`,
  insertGrant: `
    INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
    VALUES (?,?,?,?,?,?,?,?)`,
  insertGrantPermission: `INSERT INTO grant_permissions (grant_id, permission) VALUES (?,?)`,
  revokeGrant: `UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,

  // --- sessions ---
  insertSession: `
    INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
    VALUES (?,?,?,?,?,'active',?,?,?)`,
  sessionsForOrg: `
    SELECT s.*, u.name AS user_name, u.email AS user_email, d.name AS device_name
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      JOIN devices d ON d.id = s.device_id
     WHERE s.org_id = ?
     ORDER BY s.started_at DESC`,
  sessionById: `SELECT * FROM sessions WHERE id = ?`,
  endSession: `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state = 'active'`,
  activeExclusiveOnDevice: `
    SELECT id, user_id FROM sessions
     WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`,

  // --- refresh tokens (D12) ---
  insertRefresh: `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)`,
  refreshByHash: `SELECT * FROM refresh_tokens WHERE token_hash = ?`,
  revokeRefresh: `UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
  revokeFamily: `UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`,

  // --- reference data, for the console ---
  referencePermissions: `SELECT key, resource, action, description FROM permissions ORDER BY resource, action`,
  referencePatterns: `SELECT pattern FROM permission_patterns ORDER BY pattern`,
};

const compiled = new WeakMap();

/** The compiled statement `name`, compiled once per connection. */
export function stmt(db, name) {
  let byName = compiled.get(db);
  if (!byName) compiled.set(db, (byName = new Map()));

  let s = byName.get(name);
  if (!s) {
    const sql = SQL[name];
    if (!sql) throw new Error(`server/internal/sql.js: no statement named ${name}`);
    byName.set(name, (s = db.prepare(sql)));
  }
  return s;
}

/** Every statement this server knows about. Used by the query-count test in Phase 8. */
export const statementNames = () => Object.keys(SQL);
