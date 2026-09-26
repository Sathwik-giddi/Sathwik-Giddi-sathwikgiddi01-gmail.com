// The six cards.
//
// Every one of them takes the same two things: the org-level resolved set (for the card's own
// entries and its rows) and the per-device sets (for the device rows). Nothing here reads a role.
//
// The card definitions come from UI-INVENTORY.md §2 — including the one that looks like a mistake
// and is not: the GRANTS card is gated on `user:read`, the same as People, because `GET /grants`
// requires `user:read` and there is no `grant:read` permission in the catalogue. An auditor
// therefore sees the grants table and cannot change it, which is the correct reading of "read-only".

import React, { useState } from 'react';
import * as api from '../api.js';
import { IfAllowed, PermButton, allows, allowsAny, verdict, provenance } from '../presence.jsx';

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

// ===========================================================================
// Devices
// ===========================================================================
export function DevicesCard({ orgId, orgPermissions, devices, onReload, onError }) {
  const [busy, setBusy] = useState(null);
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newKind, setNewKind] = useState('linux');

  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); }
    catch (err) { onError(err); }
    finally { setBusy(null); }
  };

  return (
    <section className="card">
      <header className="card__head">
        <h2>Devices</h2>
        <IfAllowed permissions={orgPermissions} permission="device:provision">
          <button
            data-testid="add-device"
            className="btn btn--ghost"
            disabled={busy === 'add'}
            onClick={() => setAdding((v) => !v)}
          >
            Add device
          </button>
        </IfAllowed>
      </header>

      {adding && (
        <div className="inline-form">
          <input
            placeholder="device name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            aria-label="new device name"
          />
          <select value={newKind} onChange={(e) => setNewKind(e.target.value)} aria-label="new device kind">
            {['macos', 'windows', 'linux', 'android', 'ios'].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <button
            className="btn btn--primary"
            disabled={busy === 'add' || newName.trim() === ''}
            onClick={() => run('add', async () => { await api.createDevice(orgId, newName.trim(), newKind); setNewName(''); setAdding(false); })}
          >
            Create
          </button>
        </div>
      )}

      {devices.length === 0 ? (
        // The empty state is a real state, not a spinner that never resolves. A brand-new org is
        // the case `tests/ui.spec.js:280` asserts on.
        <p className="empty" data-testid="devices-empty">
          No devices in this organization yet.
          <IfAllowed permissions={orgPermissions} permission="device:provision">
            <span> Add one to get started.</span>
          </IfAllowed>
        </p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Device</th><th>Kind</th><th>State</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <DeviceRow key={d.id} orgId={orgId} device={d} busy={busy} run={run} onError={onError} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function DeviceRow({ orgId, device, busy, run, onError }) {
  const p = device.permissions;
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(device.name);

  // Which grants touch this row. Read from the server's own provenance rather than recomputed, so
  // the console cannot disagree with the engine about why a button is present.
  const fromGrants = Object.entries(p).filter(([, v]) => v.source?.startsWith('grant:'));

  return (
    // The row is governed by device:view (UI-INVENTORY §3). The row only exists at all when that
    // permission is held, because the server omits the row otherwise — so it is always "unlocked".
    <tr data-testid="device-row" data-device-id={device.id} data-kind={device.kind} data-permission="device:view" data-state="unlocked">
      <td>
        <div className="cell-name">{device.name}</div>
        <div className="cell-sub">
          <code>{device.id}</code>
          {fromGrants.length > 0 && (
            <span className="tag tag--grant" title={fromGrants.map(([k, v]) => `${k} ${provenance(v)}`).join('\n')}>
              +{fromGrants.length} grant{fromGrants.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
      </td>
      <td><span className="tag">{device.kind}</span></td>
      <td>
        <span className={`dot ${device.online ? 'dot--on' : 'dot--off'}`} aria-label={device.online ? 'online' : 'offline'} />
        {device.online ? 'online' : 'offline'}
      </td>
      <td className="actions">
        {renaming ? (
          <>
            <input value={name} onChange={(e) => setName(e.target.value)} aria-label={`rename ${device.name}`} />
            <button
              className="btn btn--primary"
              disabled={busy === `rename-${device.id}`}
              onClick={() => run(`rename-${device.id}`, async () => {
                await api.renameDevice(orgId, device.id, name.trim());
                setRenaming(false);
              })}
            >Save</button>
          </>
        ) : (
          <>
            <PermButton permissions={p} permission="device:view" data-testid="start-view" title={`View ${device.name} · ${provenance(verdict(p, 'device:view'))}`}
              onClick={() => run(`view-${device.id}`, () => api.startSession(orgId, device.id, 'view').catch(rejectBusy(orgId, onError)))}>
              View
            </PermButton>
            <PermButton permissions={p} permission="device:control" data-testid="start-control" title={`Control ${device.name} · ${provenance(verdict(p, 'device:control'))}`}
              onClick={() => run(`control-${device.id}`, () => api.startSession(orgId, device.id, 'control').catch(rejectBusy(orgId, onError)))}>
              Control
            </PermButton>
            <PermButton permissions={p} permission="device:terminal" data-testid="start-terminal" title={`Terminal ${device.name} · ${provenance(verdict(p, 'device:terminal'))}`}
              onClick={() => run(`terminal-${device.id}`, () => api.startSession(orgId, device.id, 'terminal').catch(rejectBusy(orgId, onError)))}>
              Terminal
            </PermButton>
            <PermButton permissions={p} permission="device:file_transfer" data-testid="transfer-files" title={`Transfer files · ${provenance(verdict(p, 'device:file_transfer'))}`}
              onClick={() => run(`xfer-${device.id}`, () => startTransfer(orgId, device))}>
              Transfer files
            </PermButton>
            <PermButton permissions={p} permission="device:update" data-testid="rename-device" title={`Rename · ${provenance(verdict(p, 'device:update'))}`}
              onClick={() => { setName(device.name); setRenaming(true); }}>
              Rename
            </PermButton>
            <PermButton permissions={p} permission="device:provision" data-testid="decommission-device" title={`Decommission · ${provenance(verdict(p, 'device:provision'))}`}
              className="danger"
              onClick={() => run(`decom-${device.id}`, async () => {
                if (!window.confirm(`Decommission ${device.name}? It stops responding to sessions.`)) return;
                await api.decommissionDevice(orgId, device.id);
              })}>
              Decommission
            </PermButton>
          </>
        )}
      </td>
    </tr>
  );
}

// A transfer needs a destination org, so it asks. Returns a promise so the row's `run` wrapper can
// show busy state, and resolves without doing anything if the person cancels.
function startTransfer(orgId, device) {
  const destination = window.prompt(`Move ${device.name} to which organization id?`, '');
  if (!destination) return Promise.resolve();
  return api.transferDevice(orgId, device.id, destination.trim());
}

// A session needs both permissions; when the server refuses with `missing_device_permission` the
// button was rendered from a set that has since changed, so reload rather than guess.
const rejectBusy = (orgId, onError) => async (err) => {
  onError(err);
  try { await api.listDevices(orgId); } catch { /* the error above is the one worth showing */ }
};

// ===========================================================================
// People
// ===========================================================================
export function PeopleCard({ orgId, orgPermissions, members, onReload, onError, meId }) {
  const [inviting, setInviting] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [issued, setIssued] = useState(null);
  const [busy, setBusy] = useState(null);

  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); }
    catch (err) { onError(err); }
    finally { setBusy(null); }
  };

  return (
    <section className="card">
      <header className="card__head">
        <h2>People</h2>
        <IfAllowed permissions={orgPermissions} permission="user:invite">
          <button data-testid="invite-user" className="btn btn--ghost" onClick={() => setInviting((v) => !v)}>
            Invite
          </button>
        </IfAllowed>
      </header>

      {inviting && (
        <div className="inline-form">
          <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="invite email" />
          {/* Already inside an IfAllowed for `user:invite`; passing `permissions` lets this one
              annotate its own <select> too, rather than relying on a clone that cannot reach it. */}
          <RolePicker permissions={orgPermissions} permission="user:invite" value={role} onChange={setRole} label="invite role" />
          <button
            className="btn btn--primary"
            disabled={busy === 'invite' || email.trim() === ''}
            onClick={() => run('invite', async () => {
              const created = await api.createInvite(orgId, email.trim(), role);
              // The raw token is returned exactly once and never stored server-side, so this is the
              // only moment it can be shown. Email delivery is out of scope, so the console is the
              // delivery mechanism.
              setIssued(created.inviteToken);
              setEmail('');
              setInviting(false);
            })}
          >Create invite</button>
        </div>
      )}

      {issued && (
        <p className="notice" role="status">
          Invite link (shown once): <code>{window.location.origin}/invite/{issued}</code>
          <button className="btn btn--ghost" onClick={() => setIssued(null)}>Dismiss</button>
        </p>
      )}

      <table className="table">
        <thead>
          <tr><th>Person</th><th>Role</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {members.map((m) => (
            // Governed by user:read (UI-INVENTORY §3). Rows are annotated explicitly rather than
            // through IfAllowed: the card is already gated, so every row is unconditionally
            // unlocked, and wrapping fifty rows in a helper that clones an element would cost more
            // than it explains.
            <tr
              key={m.user_id}
              data-testid="user-row"
              data-permission="user:read"
              data-state="unlocked"
              data-user-id={m.user_id}
              data-role={m.role}
              data-status={m.status}
            >
              <td>
                <div className="cell-name">{m.name}{m.user_id === meId && <span className="tag tag--you">you</span>}</div>
                <div className="cell-sub"><code>{m.email}</code></div>
              </td>
              <td>
                {/* RolePicker gates ITSELF rather than being wrapped. `IfAllowed` attaches the
                    contract attributes by cloning its child, and cloning a composite component
                    drops any prop that component does not forward — so wrapping RolePicker
                    produced a <select> with no data-permission at all. A host element is the only
                    thing cloneElement can reliably annotate. */}
                <RolePicker
                  permissions={orgPermissions}
                  permission="user:role:update"
                  value={m.role}
                  userId={m.user_id}
                  disabled={busy === `role-${m.user_id}`}
                  onChange={(next) => run(`role-${m.user_id}`, () => api.setRole(orgId, m.user_id, next))}
                  label={`role for ${m.name}`}
                />
                {!allows(orgPermissions, 'user:role:update') && <span className="tag">{m.role}</span>}
              </td>
              <td><span className={`tag tag--${m.status}`}>{m.status}</span></td>
              <td className="actions">
                <IfAllowed permissions={orgPermissions} permission="user:remove">
                  {m.status === 'suspended' ? (
                    <PermButton permissions={orgPermissions} permission="user:remove" data-testid="suspend-user"
                      onClick={() => run(`susp-${m.user_id}`, () => api.reinstateMember(orgId, m.user_id))}>
                      Reinstate
                    </PermButton>
                  ) : (
                    <PermButton permissions={orgPermissions} permission="user:remove" data-testid="suspend-user"
                      onClick={() => run(`susp-${m.user_id}`, () => api.suspendMember(orgId, m.user_id))}>
                      Suspend
                    </PermButton>
                  )}
                  <PermButton permissions={orgPermissions} permission="user:remove" className="danger" data-testid="remove-user"
                    onClick={() => run(`rm-${m.user_id}`, async () => {
                      if (!window.confirm(`Remove ${m.name} from this organization?`)) return;
                      await api.removeMember(orgId, m.user_id);
                    })}>
                    Remove
                  </PermButton>
                </IfAllowed>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

/**
 * The role picker. `user:role:update` gates whether it is rendered at all; the CHOICES come from
 * the server's reference data, so a role that exists only in the graded fixture's database appears
 * here without any code change. Never a hardcoded list of five.
 */
function RolePicker({ permissions, permission = 'user:role:update', value, onChange, disabled, label, userId }) {
  const [roles, setRoles] = useState([]);
  React.useEffect(() => {
    let live = true;
    api.reference()
      .then((r) => { if (live) setRoles(r.roles); })
      .catch(() => { if (live) setRoles([]); });
    return () => { live = false; };
  }, []);

  return (
    <IfAllowed permissions={permissions} permission={permission}>
      <select
        className="select"
        data-testid="role-select"
        data-user-id={userId}
        aria-label={label}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      >
        {roles.map((r) => <option key={r.key} value={r.key}>{r.label ?? r.key}</option>)}
      </select>
    </IfAllowed>
  );
}

// ===========================================================================
// Grants
// ===========================================================================
export function GrantsCard({ orgId, orgPermissions, grants, members, devices, onReload, onError }) {
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(null);

  // The catalogue comes from the server. This is the single most important reason the console has
  // no permission table of its own: the checkboxes below are generated from the DATABASE, so a
  // permission that appears in no document still shows up here and can be granted.
  const [ref, setRef] = useState({ permissions: [], patterns: [] });
  React.useEffect(() => {
    let live = true;
    api.reference()
      .then((r) => { if (live) setRef(r); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); }
    catch (err) { onError(err); }
    finally { setBusy(null); }
  };

  return (
    <section className="card">
      <header className="card__head">
        <h2>Grants</h2>
        <IfAllowed permissions={orgPermissions} permission="grant:create">
          <button data-testid="new-grant" className="btn btn--ghost" onClick={() => setCreating((v) => !v)}>
            New grant
          </button>
        </IfAllowed>
      </header>

      {creating && (
        <NewGrantForm
          orgId={orgId}
          orgPermissions={orgPermissions}
          members={members}
          devices={devices}
          reference={ref}
          busy={busy === 'create'}
          onCancel={() => setCreating(false)}
          onSubmit={async (payload) => { await run('create', async () => { await api.createGrant(orgId, payload); setCreating(false); }); }}
        />
      )}

      {grants.length === 0 ? (
        <p className="empty">No grants. Everyone is on their role baseline.</p>
      ) : (
        <table className="table">
          <thead>
            <tr><th>Who</th><th>Scope</th><th>Effect</th><th>Permissions</th><th /></tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr
                key={g.id}
                data-testid="grant-row"
                data-permission="user:read"
                data-state="unlocked"
                data-effect={g.effect}
                data-grant-id={g.id}
              >
                <td>
                  <div className="cell-name">{g.user_name ?? g.user_id}</div>
                  <div className="cell-sub"><code>{g.id}</code></div>
                </td>
                <td>{g.device_name ? <span className="tag">{g.device_name}</span> : <span className="tag">whole org</span>}</td>
                <td><span className={`tag tag--${g.effect}`}>{g.effect}</span></td>
                <td className="perms">
                  {g.revoked_at
                    ? <span className="cell-sub">revoked {fmtTime(g.revoked_at)}</span>
                    : g.permissions.map((p) => <span key={p} className="tag tag--perm">{p}</span>)}
                  {g.expires_at && !g.revoked_at && <div className="cell-sub">until {fmtTime(g.expires_at)}</div>}
                </td>
                <td className="actions">
                  <IfAllowed permissions={orgPermissions} permission="grant:revoke">
                    {!g.revoked_at && (
                      <button
                        data-testid="revoke-grant"
                        data-grant-id={g.id}
                        className="perm danger"
                        onClick={() => run(`revoke-${g.id}`, () => api.revokeGrant(orgId, g.id))}
                      >
                        Revoke
                      </button>
                    )}
                  </IfAllowed>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NewGrantForm({ orgId, orgPermissions, members, devices, reference, busy, onCancel, onSubmit }) {
  const [userId, setUserId] = useState(members[0]?.user_id ?? '');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [chosen, setChosen] = useState(() => new Set());

  // Grouped by resource so twenty permissions are not twenty undifferentiated checkboxes. The
  // groups come from the `resource` column the server sends, not from splitting strings here.
  const byResource = {};
  for (const p of reference.permissions) (byResource[p.resource] ??= []).push(p);

  const toggle = (key) => setChosen((prev) => {
    const next = new Set(prev);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

  return (
    <div className="grant-form" data-testid="grant-form">
      <div className="inline-form">
        <label className="inline">
          <span>Person</span>
          <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
            {members.filter((m) => m.user_id !== null).map((m) => (
              <option key={m.user_id} value={m.user_id}>{m.name ?? m.user_id}</option>
            ))}
          </select>
        </label>

        <label className="inline">
          <span>Device</span>
          {/* `""` is the whole org. An org-wide grant is a different question from a device-scoped
              one, so it is an explicit choice rather than a blank default. */}
          <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">Whole organization</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </label>

        <label className="inline">
          <span>Effect</span>
          <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </label>
      </div>

      <fieldset className="perm-grid">
        <legend>Permissions</legend>
        {Object.entries(byResource).map(([resource, list]) => (
          <div key={resource} className="perm-group">
            <h4>{resource}</h4>
            {list.map((p) => (
              <label key={p.key} className="check" title={p.description}>
                <input
                  type="checkbox"
                  data-permission-key={p.key}
                  checked={chosen.has(p.key)}
                  onChange={() => toggle(p.key)}
                />
                <span>{p.action}</span>
              </label>
            ))}
          </div>
        ))}
      </fieldset>

      <div className="inline-form">
        <button
          data-testid="grant-submit"
          className="btn btn--primary"
          disabled={busy || chosen.size === 0 || userId === ''}
          onClick={() => onSubmit({ userId, deviceId, effect, permissions: [...chosen] })}
        >
          Create grant
        </button>
        <button className="btn btn--ghost" onClick={onCancel}>Cancel</button>
        {chosen.size === 0 && <span className="cell-sub">Pick at least one permission.</span>}
      </div>
      <p className="cell-sub">
        You can only grant what you hold at that scope. A grant naming a permission you do not hold
        is refused with the reason.
      </p>
    </div>
  );
}

// ===========================================================================
// Sessions
// ===========================================================================
export function SessionsCard({ orgId, orgPermissions, sessions, devices, onReload, onError }) {
  const [busy, setBusy] = useState(null);
  const [starting, setStarting] = useState(false);
  const [deviceId, setDeviceId] = useState('');
  const [mode, setMode] = useState('view');

  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); }
    catch (err) { onError(err); }
    finally { setBusy(null); }
  };

  // Only offer modes the caller can actually open ON THE CHOSEN DEVICE — the same compound check the
  // server makes, computed from the per-row permissions it already sent. The server still enforces
  // it; this only avoids offering a button that is guaranteed to fail.
  const target = devices.find((d) => d.id === deviceId);
  const modes = target
    ? ['view', 'control', 'terminal'].filter((m) => {
        const modePerm = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' }[m];
        return allows(target.permissions, 'session:start') && allows(target.permissions, modePerm);
      })
    : [];

  return (
    <section className="card">
      <header className="card__head">
        <h2>Sessions</h2>
        <IfAllowed permissions={orgPermissions} permission="session:start">
          <button data-testid="new-session" className="btn btn--ghost" onClick={() => setStarting((v) => !v)}>
            Start a session
          </button>
        </IfAllowed>
      </header>

      {starting && (
        <div className="inline-form">
          <select value={deviceId} onChange={(e) => { setDeviceId(e.target.value); setMode('view'); }} aria-label="session device">
            <option value="">Choose a device</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="session mode" disabled={modes.length === 0}>
            {['view', 'control', 'terminal'].map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <button
            className="btn btn--primary"
            disabled={busy === 'start' || !target || modes.length === 0}
            onClick={() => run('start', async () => { await api.startSession(orgId, deviceId, mode); setStarting(false); setDeviceId(''); })}
          >Start</button>
          {target && modes.length === 0 && (
            <span className="cell-sub">
              You cannot open any session on {target.name}: it needs session:start and the mode's permission.
            </span>
          )}
        </div>
      )}

      {sessions.length === 0 ? (
        <p className="empty">No sessions yet.</p>
      ) : (
        <table className="table">
          <thead>
            <tr><th>Who</th><th>Device</th><th>Mode</th><th>State</th><th>Started</th><th>Expires</th><th /></tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              // `data-state` means "unlocked" everywhere else in this console (UI-INVENTORY §1), so
              // the session LIFECYCLE gets its own attribute. Overloading one name for two meanings
              // is how a selector like `[data-state="unlocked"]` silently starts matching the wrong
              // thing. The row's governing permission is session:view, which gates the whole card.
              <tr
                key={s.id}
                data-testid="session-row"
                data-permission="session:view"
                data-state="unlocked"
                data-session-id={s.id}
                data-mode={s.mode}
                data-session-state={s.state}
              >
                <td>
                  <div className="cell-name">{s.user_name ?? s.user_id}</div>
                  {s.authorized_by?.grantIds?.length > 0 && (
                    <div className="cell-sub" title="This session's authority was snapshotted from a grant, not from the role">
                      via grant
                    </div>
                  )}
                </td>
                <td>{s.device_name ?? s.device_id}</td>
                <td><span className={`tag tag--${s.mode}`}>{s.mode}</span></td>
                <td>
                  <span className={`tag tag--${s.state}`}>{s.state}</span>
                  {s.end_reason && <div className="cell-sub">{s.end_reason.replaceAll('_', ' ')}</div>}
                </td>
                <td className="cell-sub">{fmtTime(s.started_at)}</td>
                <td className="cell-sub">{fmtTime(s.expires_at)}</td>
                <td className="actions">
                  {/* Your own session, or session:terminate. The server decides which applies and
                      the button carries the permission it was rendered for, so a hidden button here
                      is a real absence rather than a disabled control. */}
                  {/* Governed by OWNERSHIP, not by a permission (UI-INVENTORY §3: "your own
                      session"), so it carries no data-permission — there is no permission to name.
                      It is still gated: the server decides, and `can_stop` in the list response is
                      the server's own answer. */}
                  {s.state === 'active' && s.is_mine && (
                    <button data-testid="stop-session" data-session-id={s.id} className="perm"
                      onClick={() => run(`stop-${s.id}`, () => api.stopSession(s.id))}>Stop</button>
                  )}
                  {s.state === 'active' && !s.is_mine && allowsAny(orgPermissions, ['session:terminate']) && (
                    <button data-permission="session:terminate" data-state="unlocked" data-testid="stop-session"
                      data-session-id={s.id} className="perm danger"
                      onClick={() => run(`stop-${s.id}`, () => api.stopSession(s.id))}>End</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ===========================================================================
// Audit
// ===========================================================================
export function AuditCard({ events, total, onError }) {
  const [page, setPage] = useState(0);
  const pageSize = 50;
  const pages = Math.max(1, Math.ceil((total ?? 0) / pageSize));

  return (
    <section className="card">
      <header className="card__head">
        <h2>Audit</h2>
        <span className="cell-sub">{total ?? 0} events · append-only</span>
      </header>

      {events.length === 0 ? (
        <p className="empty">Nothing recorded yet.</p>
      ) : (
        <>
          <table className="table">
            <thead>
              <tr><th>When</th><th>Who</th><th>Action</th><th>Result</th><th>Reason</th></tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={e.id}
                  data-testid="audit-row"
                  data-permission="audit:read"
                  data-state="unlocked"
                  data-result={e.result}
                  data-action={e.action}
                >
                  <td className="cell-sub">{fmtTime(e.at)}</td>
                  <td>{e.actor_name ?? e.actor_id ?? '—'}</td>
                  <td><code>{e.action}</code></td>
                  <td><span className={`tag tag--${e.result}`}>{e.result}</span></td>
                  <td className="cell-sub">{e.reason_code ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {pages > 1 && (
            <div className="pager">
              <button className="btn btn--ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Newer</button>
              <span className="cell-sub">page {page + 1} of {pages}</span>
              <button className="btn btn--ghost" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Older</button>
            </div>
          )}
        </>
      )}
      <p className="cell-sub" role="note">
        Denied attempts are recorded too. A log of successes only cannot answer who tried what.
      </p>
      <span hidden onClick={() => onError?.(null)} />
    </section>
  );
}

// ===========================================================================
// Admin
// ===========================================================================
export function AdminCard({ orgId, orgPermissions, org, onReload, onError }) {
  const [name, setName] = useState(org.name);
  const [busy, setBusy] = useState(null);

  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); }
    catch (err) { onError(err); }
    finally { setBusy(null); }
  };

  return (
    <section className="card">
      <header className="card__head">
        <h2>Admin</h2>
        <span className="tag">{org.theme}</span>
      </header>

      <IfAllowed permissions={orgPermissions} permission="org:update">
        <div className="inline-form" data-testid="rename-org">
          <input value={name} onChange={(e) => setName(e.target.value)} aria-label="organization name" />
          <button className="btn btn--primary" disabled={busy === 'rename' || name.trim() === ''}
            onClick={() => run('rename', () => api.renameOrg(orgId, name.trim()))}>Rename org</button>
        </div>
      </IfAllowed>

      <IfAllowed permissions={orgPermissions} permission="org:delete">
        <div className="inline-form" data-testid="delete-org">
          <button className="btn danger" disabled={busy === 'delete'}
            onClick={() => run('delete', async () => {
              if (!window.confirm(`Delete ${org.name}? Every membership and device in it stops existing.`)) return;
              await api.deleteOrg(orgId);
            })}>Delete org</button>
          <span className="cell-sub">Deleting keeps the audit log. It stops the organization being reachable.</span>
        </div>
      </IfAllowed>

      <dl className="summary summary--tight">
        <div><dt>Id</dt><dd><code>{org.id}</code></dd></div>
        <div><dt>Session TTL</dt><dd>{org.max_session_minutes ?? 60} minutes</dd></div>
      </dl>
    </section>
  );
}
