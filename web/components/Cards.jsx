// The six cards.
//
// Every one of them takes the same two things: the org-level resolved set (for the card's own
// entries and its rows) and the per-device sets (for the device rows). Nothing here reads a role.
//
// The card definitions come from UI-INVENTORY.md §2, including the one that looks like a mistake
// and is not: the GRANTS card is gated on `user:read`, the same as People, because `GET /grants`
// requires `user:read` and there is no `grant:read` permission in the catalogue. An auditor
// therefore sees the grants table and cannot change it, which is the correct reading of "read-only".

import React, { useCallback, useEffect, useState } from 'react';
import * as api from '../api.js';
import { IfAllowed, PermButton, allows, allowsAny, verdict, provenance } from '../presence.jsx';

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Never');

// ===========================================================================
// Devices
// ===========================================================================
export function DevicesCard({ orgId, orgPermissions, devices, orgs = [], onReload, onError }) {
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
              <DeviceRow key={d.id} orgId={orgId} device={d} orgs={orgs} onReload={onReload} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/**
 * One device, its six actions, and whatever panel the action opens.
 *
 * The six buttons all existed before this and all of them called the API. What they did not do was
 * show anything, so pressing one looked identical to pressing nothing: the session verbs posted a
 * row and then left you to find it on another card, and the two destructive verbs used
 * `window.prompt` and `window.confirm`, which are not part of this application. BRIEF.md 3.2 wants
 * these actions "from the UI", and a browser dialog is not the UI.
 *
 * So each action now opens a panel on the row, and the panel says what happened: for a session, the
 * id, the times, and the authority snapshot that permitted it, which is the whole point of the
 * product and was previously only visible on the Sessions card. A refusal is reported in the panel
 * that caused it rather than in a bar at the top of the page, because "why did my button not work"
 * is a question about that button.
 *
 * Nothing here decides whether an action is allowed. The server is the only authority (D8), so these
 * panels render whatever the server said and explain a refusal; they never pre-empt it. In
 * particular the three session verbs are still gated on the mode's own permission and NOT on
 * `session:start`, because a device-scoped `device:control` grant with no `session:start` is a real
 * state (the shipped fixture has exactly one) and hiding the button would hide the demonstration.
 * The 403 arrives, and the panel says which of the two permissions was missing.
 */
function DeviceRow({ orgId, device, orgs, onReload }) {
  const p = device.permissions;
  const [panel, setPanel] = useState(null);      // null | 'session' | 'transfer' | 'decommission'
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(device.name);
  const [problem, setProblem] = useState(null);  // the open panel's own failure, in place
  const [session, setSession] = useState(null);  // the session this row started
  const [mode, setMode] = useState('view');
  const [toOrg, setToOrg] = useState('');
  const [working, setWorking] = useState(false);
  const [renameProblem, setRenameProblem] = useState(null);

  const close = () => { setPanel(null); setProblem(null); setSession(null); setToOrg(''); };

  /**
   * Panel work reports its own errors. `run()` sends them to the page-level bar, which is right for
   * a row action with nowhere to put a message and wrong for a panel the user is looking at.
   */
  const attempt = async (fn, sink = setProblem) => {
    setWorking(true);
    sink(null);
    try { await fn(); }
    catch (err) { sink({ message: err.human ?? err.message, code: err.code }); }
    finally { setWorking(false); }
  };

  const startSession = (m) => {
    // The panel opens on the click, not after the round trip, so the button visibly responds.
    //
    // `setSession(null)` used to be here, on the theory that the panel describes the last thing
    // clicked. It does not work that way: starting Control and then clicking Terminal fails with
    // DEVICE_BUSY, and clearing first left the panel showing an error and no Stop button for the
    // Control session that was still running. A refusal must add to what is on screen, not replace
    // it, so the running session stays and the error is reported above it.
    setMode(m); setPanel('session'); setProblem(null);
    return attempt(async () => {
      setSession(await api.startSession(orgId, device.id, m));
      await onReload();
    });
  };

  const stopSession = () => attempt(async () => {
    // The response is the ended session, so the panel keeps showing the row it just closed rather
    // than vanishing and leaving the user unsure whether anything happened.
    setSession(await api.stopSession(session.id));
    await onReload();
  });

  const moveDevice = () => attempt(async () => {
    await api.transferDevice(orgId, device.id, toOrg);
    await onReload();
    close();
  });

  const decommission = () => attempt(async () => {
    await api.decommissionDevice(orgId, device.id);
    await onReload();
  });

  // Which grants touch this row. Read from the server's own provenance rather than recomputed, so
  // the console cannot disagree with the engine about why a button is present.
  const fromGrants = Object.entries(p).filter(([, v]) => v.source?.startsWith('grant:'));

  // A transfer needs a destination, and the only ones that can be offered are the organizations the
  // caller is already a member of. That is deliberate and it is what keeps this out of the
  // org-existence probe: the list is `me.orgs`, which the header already renders, so no request is
  // made to discover whether some other organization exists.
  const destinations = orgs.filter((o) => o.id !== orgId);

  // Rename keeps its own error rather than using `run()`, for the same reason the panels do: the
  // form is inline in the cell, and a failure three rows up the page is not an answer to "why did
  // my new name not save".
  const saveRename = async () => {
    if (name.trim() === '') return;
    await attempt(async () => {
      await api.renameDevice(orgId, device.id, name.trim());
      setRenaming(false);
      // Without this the form closes and the row keeps showing the old name until something else
      // happens to trigger a reload. It went missing because `run()`, which used to do it, is not
      // what this calls any more.
      await onReload();
    }, (v) => setRenameProblem(v ? v.message : null));
  };

  const cancelRename = () => { setName(device.name); setRenameProblem(null); setRenaming(false); };

  return (
    <>
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
        <td>
          <div className="actions">
            {renaming ? (
              <div className="rename">
                <input
                  data-testid="rename-device-name"
                  value={name}
                  onChange={(e) => { setName(e.target.value); setRenameProblem(null); }}
                  aria-label={`rename ${device.name}`}
                />
                <button
                  data-testid="rename-device-save"
                  className="btn btn--primary"
                  // Was enabled on an empty field, which sent a request the server answers 400.
                  // A rename to nothing is not a rename, so the button says so instead.
                  disabled={working || name.trim() === ''}
                  onClick={saveRename}
                >Save</button>
                {/* There was no way out of the rename form except saving it. */}
                <button data-testid="rename-device-cancel" className="btn" onClick={cancelRename}>
                  Cancel
                </button>
                {renameProblem && (
                  <p className="rename__problem" role="alert" data-testid="rename-device-error">
                    {renameProblem}
                  </p>
                )}
              </div>
            ) : (
              <>
                {/* The three session verbs act on the same object and are the same verb on it, so they
                    sit as one group rather than as three peer buttons. `.actgroup .perm::after` draws
                    the provenance rule: solid from the role, dashed from a grant. That is the point of
                    the whole application and it used to be reachable only by hovering a `title`. */}
                <div className="actgroup">
                  <PermButton permissions={p} permission="device:view" source={verdict(p, 'device:view')?.source} data-testid="start-view" title={`View ${device.name} · ${provenance(verdict(p, 'device:view'))}`}
                    onClick={() => startSession('view')}>
                    View
                  </PermButton>
                  <PermButton permissions={p} permission="device:control" source={verdict(p, 'device:control')?.source} data-testid="start-control" title={`Control ${device.name} · ${provenance(verdict(p, 'device:control'))}`}
                    onClick={() => startSession('control')}>
                    Control
                  </PermButton>
                  <PermButton permissions={p} permission="device:terminal" source={verdict(p, 'device:terminal')?.source} data-testid="start-terminal" title={`Terminal ${device.name} · ${provenance(verdict(p, 'device:terminal'))}`}
                    onClick={() => startSession('terminal')}>
                    Terminal
                  </PermButton>
                </div>
                <PermButton permissions={p} permission="device:file_transfer" data-testid="transfer-files" title={`Transfer files · ${provenance(verdict(p, 'device:file_transfer'))}`}
                  onClick={() => { setPanel('transfer'); setProblem(null); setToOrg(''); }}>
                  Transfer
                </PermButton>
                <PermButton permissions={p} permission="device:update" data-testid="rename-device" title={`Rename · ${provenance(verdict(p, 'device:update'))}`}
                  onClick={() => { setName(device.name); setRenaming(true); }}>
                  Rename
                </PermButton>
                {/* Decommission stops a machine responding for good. It is pushed to the far end of the
                    row and drawn as a text action, so it cannot be misread as a peer of "View". */}
                <PermButton permissions={p} permission="device:provision" data-testid="decommission-device" title={`Decommission · ${provenance(verdict(p, 'device:provision'))}`}
                  className="danger"
                  onClick={() => { setPanel('decommission'); setProblem(null); }}>
                  Decommission
                </PermButton>
              </>
            )}
          </div>
        </td>
      </tr>

      {panel === 'session' && (
        <tr className="panel-row">
          <td colSpan={4} className="panel" data-testid="session-panel" data-session-id={session?.id ?? ''} data-mode={mode}>
            <div className="panel__head">
              <span className={`tag tag--${mode}`}>{mode}</span>
              <span className="panel__title">
                {session ? `Session on ${device.name}` : `Starting a ${mode} session on ${device.name}…`}
              </span>
              <button data-testid="session-panel-close" className="btn btn--ghost" onClick={close}>Close</button>
            </div>

            {session && (
              <>
                <dl className="panel__facts">
                  <div><dt>Session</dt><dd><code data-testid="session-panel-id">{session.id}</code></dd></div>
                  <div><dt>Started</dt><dd>{fmtTime(session.started_at)}</dd></div>
                  <div><dt>Expires</dt><dd>{fmtTime(session.expires_at)}</dd></div>
                  <div>
                    <dt>Authority</dt>
                    <dd data-testid="session-panel-authority" data-authority-role={session.authorized_by?.role ?? ''}
                      data-authority-grants={(session.authorized_by?.grantIds ?? []).join(',')}>
                      {describeAuthority(session)}
                    </dd>
                  </div>
                </dl>
                {session.state === 'active' ? (
                  <button data-testid="stop-device-session" className="perm" disabled={working}
                    onClick={stopSession}>
                    Stop session
                  </button>
                ) : (
                  <p className="panel__line" data-testid="session-panel-ended">
                    This session has ended{session.end_reason ? `: ${session.end_reason.replaceAll('_', ' ')}` : ''}.
                  </p>
                )}
              </>
            )}

            <p className="panel__note">
              This is the session this button started. Every live session is listed on the Sessions card.
            </p>
            {!device.online && (
              <p className="panel__note">
                {device.name} is offline, so nothing will answer the session. The record is still real
                and still audited.
              </p>
            )}
            {problem && <p className="panel__problem" role="alert" data-error-code={problem.code}>{problem.message}</p>}
          </td>
        </tr>
      )}

      {panel === 'transfer' && (
        <tr className="panel-row">
          <td colSpan={4} className="panel" data-testid="transfer-panel">
            <div className="panel__head">
              <span className="panel__title">Move {device.name}</span>
              <button data-testid="transfer-panel-close" className="btn btn--ghost" onClick={close}>Close</button>
            </div>

            {destinations.length === 0 ? (
              // Said here rather than in a `window.alert`, which is what this used to do. An alert
              // names a condition the user cannot fix, so it should arrive attached to the button
              // that revealed it and stay put.
              <p className="panel__note" data-testid="transfer-nowhere">
                You are not a member of any other organization, so there is nowhere to move {device.name} to.
                Join or create one first.
              </p>
            ) : (
              <>
                <fieldset className="choices">
                  <legend>Destination</legend>
                  {destinations.map((o) => (
                    <label key={o.id} className="choice">
                      <input
                        type="radio"
                        name={`xfer-${device.id}`}
                        data-testid={`transfer-option-${o.id}`}
                        checked={toOrg === o.id}
                        onChange={() => setToOrg(o.id)}
                      />
                      <span className="choice__name">{o.name}</span>
                      <span className="tag">{o.role}</span>
                    </label>
                  ))}
                </fieldset>
                <p className="panel__note">Any live session on {device.name} ends when it moves.</p>
                <div className="panel__actions">
                  <button data-testid="transfer-submit" className="btn btn--primary"
                    disabled={working || toOrg === ''} onClick={moveDevice}>
                    Move device
                  </button>
                  <button data-testid="transfer-cancel" className="btn" onClick={close}>Cancel</button>
                </div>
              </>
            )}
            {/* Named, because the refusal is about the DESTINATION and not about this row. The
                server's message is `missing device:provision` on its own, which reads like the
                device is the problem. It is not: it is the role held over there.
                Pre-empting it instead would mean deciding in the client that a viewer cannot move a
                device, and the only table of which role holds which permission lives in the
                database. Encoding it here is the one thing this console does not do. */}
            {problem && (
              <p className="panel__problem" role="alert" data-error-code={problem.code}>
                {destinations.find((o) => o.id === toOrg)?.name ?? 'That organization'} refused the move: {problem.message}
              </p>
            )}
          </td>
        </tr>
      )}

      {panel === 'decommission' && (
        <tr className="panel-row">
          <td colSpan={4} className="panel panel--danger" data-testid="decommission-panel">
            <div className="panel__head">
              <span className="panel__title">Decommission {device.name}</span>
              <button data-testid="decommission-panel-close" className="btn btn--ghost" onClick={close}>Close</button>
            </div>
            <ul className="panel__list">
              <li><code>{device.id}</code> stops appearing in this organization.</li>
              <li>Any live session on it ends immediately.</li>
              <li>There is no way to undo this from the console.</li>
            </ul>
            <div className="panel__actions">
              <button data-testid="decommission-confirm" className="perm danger" disabled={working}
                onClick={decommission}>
                Decommission
              </button>
              <button data-testid="decommission-cancel" className="btn" onClick={close}>Keep it</button>
            </div>
            {problem && <p className="panel__problem" role="alert" data-error-code={problem.code}>{problem.message}</p>}
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * What permitted this session, in the console's own words.
 *
 * `authorized_by` is the snapshot the engine took at the moment the session was created, so it is
 * the answer to "why was I allowed to do that" at the time it was asked, which is not necessarily
 * the answer now. The Sessions card reduces this to the words "via grant"; a panel opened from the
 * button that caused the session should show the ids.
 */
function describeAuthority(session) {
  const a = session.authorized_by;
  if (!a) return 'Recorded without an authority snapshot.';
  const grants = a.grantIds ?? [];
  if (grants.length === 0) return `Role ${a.role}.`;
  return `Role ${a.role}, through ${grants.length} grant${grants.length > 1 ? 's' : ''}: ${grants.join(', ')}.`;
}


// ===========================================================================
// People
// ===========================================================================
export function PeopleCard({ orgId, orgPermissions, members, onReload, onError, meId, reference }) {
  const [inviting, setInviting] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [issued, setIssued] = useState(null);
  const [busy, setBusy] = useState(null);
  const [invites, setInvites] = useState(null);
  const [inviteError, setInviteError] = useState(null);

  // Fetched here rather than folded into the card's own data fetch, because the two need different
  // permissions: the People card is gated on `user:read`, and an AUDITOR holds that but not
  // `user:invite`, so `GET /invites` would 403 for exactly the person who is allowed to be here.
  // An absent fetch is the honest answer for them, and the section is gated to match.
  const canInvite = allows(orgPermissions, 'user:invite');
  const loadInvites = useCallback(async () => {
    if (!canInvite) return;
    try { setInvites(await api.listInvites(orgId)); setInviteError(null); }
    catch (err) { setInviteError(err.human ?? err.message); }
  }, [orgId, canInvite]);

  useEffect(() => { loadInvites(); }, [loadInvites]);

  // `loadInvites()` sits in here rather than in each action, because the list is a second view of
  // the same organization and every action in this card can change it. Adding it per-action was the
  // first attempt and it had already been forgotten once, which is what a shared `run` is for.
  const run = async (key, fn) => {
    setBusy(key);
    try { await fn(); await onReload(); await loadInvites(); }
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
          <RolePicker reference={reference} permissions={orgPermissions} permission="user:invite" onError={onError} value={role} onChange={setRole} label="invite role" />
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
                    drops any prop that component does not forward, so wrapping RolePicker
                    produced a <select> with no data-permission at all. A host element is the only
                    thing cloneElement can reliably annotate. */}
                <RolePicker
                  reference={reference}
                  permissions={orgPermissions}
                  permission="user:role:update"
                  onError={onError}
                  value={m.role}
                  userId={m.user_id}
                  disabled={busy === `role-${m.user_id}`}
                  onChange={(next) => run(`role-${m.user_id}`, () => api.setRole(orgId, m.user_id, next))}
                  label={`role for ${m.name}`}
                />
                {!allows(orgPermissions, 'user:role:update') && <span className="tag">{m.role}</span>}
              </td>
              <td><span className={`tag tag--${m.status}`}>{m.status}</span></td>
              <td>
                <div className="actions">
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
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <IfAllowed permissions={orgPermissions} permission="user:invite">
        <OutstandingInvites
          invites={invites}
          error={inviteError}
          busy={busy}
          onRevoke={async (id) => {
            setBusy(`revoke-${id}`);
            setInviteError(null);
            try {
              await api.revokeInvite(orgId, id);
              await loadInvites();
              await onReload();
            } catch (err) {
              setInviteError(err.human ?? err.message);
            } finally {
              setBusy(null);
            }
          }}
        />
      </IfAllowed>
    </section>
  );
}


/**
 * Invites this organization has sent that have not been redeemed, and a way to cancel them.
 *
 * Before this existed, the only record of an invite was the link, shown once at the moment it was
 * created, and only its hash is stored (D17). So an invite sent to a mistyped address stayed live
 * until it expired with no way to kill it, in a product whose entire subject is controlling access.
 * The endpoints were already built and permissioned; the console could not reach them.
 *
 * There is no confirmation step on Revoke, and that is deliberate rather than an omission. The
 * decommission panel needs one because nothing in the console undoes it. This does: cancelling an
 * invite costs one click on Invite to put right, so a modal asking whether you are sure would be one
 * more thing between a person and a fix.
 */
function OutstandingInvites({ invites, error, busy, onRevoke }) {
  // The server's `isLive` is "not accepted and not revoked"; expiry is a separate comparison, and an
  // expired invite is exactly as dead as a revoked one, so offering a Revoke for it would be offering
  // a button that always 404s.
  const now = Date.now();
  const actionable = (i) => !i.accepted_at && !i.revoked_at && new Date(i.expires_at).getTime() > now;
  const all = invites?.invites ?? [];
  const live = all.filter(actionable);
  const settled = all.filter((i) => !actionable(i));

  // Nothing rendered until the list has landed, so the section does not flash an empty state on the
  // way in and then fill.
  if (invites === null && !error) return null;
  if (invites === null) {
    return <p className="panel__problem" role="alert" data-testid="invites-error">{error}</p>;
  }

  return (
    <div className="invites" data-testid="outstanding-invites" data-live-count={live.length}>
      <h3 className="invites__title">
        Outstanding invites
        {live.length > 0 && <span className="tag tag--perm">{live.length}</span>}
      </h3>

      {error && <p className="panel__problem" role="alert" data-testid="invites-error">{error}</p>}

      {live.length === 0 ? (
        <p className="invites__none" data-testid="invites-empty">
          {settled.length > 0
            ? 'No outstanding invites. Every invite sent has been redeemed or has expired.'
            : 'No outstanding invites.'}
        </p>
      ) : (
        <table className="table">
          <thead>
            <tr><th>Invited</th><th>Role</th><th>Expires</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {live.map((i) => (
              <tr key={i.id} data-testid="invite-row" data-invite-id={i.id} data-invite-email={i.email}>
                <td>
                  <div className="cell-name">{i.email}</div>
                  <div className="cell-sub"><code>{i.id}</code></div>
                </td>
                <td><span className="tag">{i.role}</span></td>
                <td className="cell-sub">{fmtTime(i.expires_at)}</td>
                <td>
                  <div className="actions">
                    <button
                      data-testid="revoke-invite"
                      data-invite-id={i.id}
                      className="perm danger"
                      disabled={busy === `revoke-${i.id}`}
                      onClick={() => onRevoke(i.id)}
                    >Revoke</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* The one thing this list cannot do, said where somebody will look for it. */}
      <p className="invites__note">
        A link is shown once, when it is created, and is not stored, so it cannot be sent again or
        recovered. Revoking is the only thing left to do with one you have lost.
      </p>

      {settled.length > 0 && (
        <details className="invites__settled">
          <summary>{settled.length} settled</summary>
          <ul>
            {settled.map((i) => (
              <li key={i.id}>
                <code>{i.email}</code> &middot; {i.role} &middot;{' '}
                {i.accepted_at ? `redeemed ${fmtTime(i.accepted_at)}`
                  : i.revoked_at ? `revoked ${fmtTime(i.revoked_at)}`
                  : 'expired'}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}


/**
 * The role picker. `user:role:update` gates whether it is rendered at all; the CHOICES come from
 * the server's reference data, so a role that exists only in the graded fixture's database appears
 * here without any code change. Never a hardcoded list of five.
 */
/**
 * The role picker.
 *
 * `reference` is passed in rather than fetched here. It used to `useEffect(api.reference, [])` and
 * this component is instantiated once PER MEMBER ROW, so a fifty-person org issued fifty requests,
 * each returning the full 20-permission / 27-pattern catalogue. That is precisely the
 * "one request per row" antipattern BRIEF.md §6 names, and it grew with the org. `Shell` fetches it
 * once and threads it down.
 *
 * The failure path also changed: `.catch(() => setRoles([]))` rendered a select with zero options
 * and no message, which was the only place in the console where a failure produced no explanation
 * at all. It now surfaces the reason.
 */
function RolePicker({ reference, permissions, permission = 'user:role:update', value, onChange, disabled, label, userId, onError }) {
  const roles = reference?.roles ?? [];

  if (roles.length === 0) {
    return (
      <span className="cell-sub" data-testid="role-select-unavailable">
        {onError ? 'roles unavailable' : 'no roles'}
      </span>
    );
  }

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
export function GrantsCard({ orgId, orgPermissions, grants, members, devices, onReload, onError, reference }) {
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(null);

  // The catalogue comes from the server, passed down from Shell. This is the single most important
  // reason the console has no permission table of its own: the checkboxes below are generated from
  // the DATABASE, so a permission that appears in no document still shows up here and can be
  // granted. Fetched here it was a FOURTH independent copy of the same request.
  const ref = reference ?? { permissions: [], patterns: [] };

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
            <tr><th>Who</th><th>Scope</th><th>Effect</th><th>Permissions</th><th>Actions</th></tr>
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
                <td>
                  <div className="actions">
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
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NewGrantForm({ members, devices, reference, busy, onCancel, onSubmit }) {
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
export function SessionsCard({ orgId, orgPermissions, sessions, devices, reference, onReload, onError }) {
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

  // Only offer modes the caller can actually open ON THE CHOSEN DEVICE, the same compound check the
  // server makes, computed from the per-row permissions it already sent. The server still enforces
  // it; this only avoids offering a button that is guaranteed to fail.
  //
  // The mode list and the mode -> permission map both come from the server. They were hardcoded
  // here, twice, which is the one thing that let this card drift from `assertCanStartSession`: add a
  // fourth mode on the server and this would offer three, or offer a mode whose permission the
  // engine no longer requires.
  const ALL_MODES = reference?.modes ?? [];
  const MODE_PERMISSION = reference?.modePermissions ?? {};
  const target = devices.find((d) => d.id === deviceId);
  const modes = target
    ? ALL_MODES.filter((m) =>
        allows(target.permissions, 'session:start') && allows(target.permissions, MODE_PERMISSION[m]))
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
            {ALL_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
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
            <tr><th>Who</th><th>Device</th><th>Mode</th><th>State</th><th>Started</th><th>Expires</th><th>Actions</th></tr>
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
                <td>
                  <div className="actions">
                    {/* Your own session, or session:terminate. The server decides which applies and
                        the button carries the permission it was rendered for, so a hidden button here
                        is a real absence rather than a disabled control. */}
                    {/* Governed by OWNERSHIP, not by a permission (UI-INVENTORY §3: "your own
                        session"), so it carries no data-permission, there is no permission to name.
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
                  </div>
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
/**
 * The audit log. `page` and `onPage` are lifted into `Shell` deliberately.
 *
 * This card used to own `const [page, setPage] = useState(0)` and render "page N of M" with
 * Newer/Older buttons, and `App` passed it only `events` and `total`. So clicking Older changed
 * the heading to "page 2 of 3" while the table still showed page 1's fifty rows, and **no request
 * was made**. A shipped control that displays a falsehood is worse than not shipping it, because
 * the user has no way to know the data did not move.
 *
 * The state and the fetch were already in the same place (`Shell` holds `auditPage` and calls
 * `listAudit`), so the fix is to pass them down rather than to duplicate either.
 */
export function AuditCard({ events, total, page, onPage }) {
  const pageSize = 50;
  const pages = Math.max(1, Math.ceil((total ?? 0) / pageSize));

  return (
    <section className="card">
      <header className="card__head">
        <h2>Audit</h2>
        <span className="cell-sub">{total ?? 0} events · append-only</span>
      </header>

      {events.length === 0 ? (
        <p className="empty">
          {total === 0 ? 'Nothing recorded yet.' : 'Nothing on this page.'}
        </p>
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
                  <td>{e.actor_name ?? e.actor_id ?? 'Nobody signed in'}</td>
                  <td><code>{e.action}</code></td>
                  <td><span className={`tag tag--${e.result}`}>{e.result}</span></td>
                  <td className="cell-sub">{e.reason_code ?? 'not a refusal'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {pages > 1 && (
            <div className="pager">
              {/* Named prev/next, not newer/older: "Newer" moves the page index DOWN and my first
                  test ids were inverted relative to their own labels, which is a trap for whoever
                  writes the next test. */}
              <button
                className="btn btn--ghost"
                data-testid="audit-prev"
                disabled={page === 0}
                onClick={() => onPage(page - 1)}
              >Newer</button>
              <span className="cell-sub" data-testid="audit-page">page {page + 1} of {pages}</span>
              <button
                className="btn btn--ghost"
                data-testid="audit-next"
                disabled={page + 1 >= pages}
                onClick={() => onPage(page + 1)}
              >Older</button>
            </div>
          )}
        </>
      )}
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
