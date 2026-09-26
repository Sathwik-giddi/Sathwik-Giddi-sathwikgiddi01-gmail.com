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
  ownerCount: `SELECT count(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`,
  owners: `SELECT user_id AS userId FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`,
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
