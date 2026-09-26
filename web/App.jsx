// The console shell: org identity, the switcher, navigation, and the six cards.
//
// Three rules shape this file, and all three exist because the documents insist on them:
//
//  1. THE ACTIVE ORG IS A TOKEN, NOT A FILTER (D18). `switchOrg` mints a new access token, and
//     every piece of state belonging to the previous org is dropped at the same moment. After a
//     switch the console is physically incapable of rendering the old org's data, because it no
//     longer holds a token that names it. `tests/ui.spec.js:179` runs two tabs on two orgs and
//     they must not bleed; the reason they cannot is here.
//
//  2. NAVIGATION IS THE SERVER'S ANSWER. Each card's visibility is one `allows()` call against the
//     org-level resolved set from `GET /auth/me`. There is no role check anywhere, including for
//     the role label, which is displayed rather than interpreted.
//
//  3. THE ORG IS VISIBLE AT A GLANCE. `data-org-theme` on the shell drives the whole palette from
//     CSS, so switching organizations changes the background, the sidebar and the accent together.
//     `tests/ui.spec.js:40` asserts the rendered background colour actually changes, so this is
//     measured rather than decorative intent.

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import * as api from './api.js';
import { allows, allowsAny } from './presence.jsx';
import { Login, AcceptInvite } from './components/Gate.jsx';
import { DevicesCard, PeopleCard, GrantsCard, SessionsCard, AuditCard, AdminCard } from './components/Cards.jsx';

// The card table. `permission` is the gate; `anyOf` is for the Admin card, which appears for
// org:update OR org:delete (UI-INVENTORY.md §2). The order is the order they appear in.
const CARDS = [
  { key: 'devices',  label: 'Devices',  icon: '▤', permission: 'device:list' },
  { key: 'people',   label: 'People',   icon: '◍', permission: 'user:read' },
  // The Grants card shares the People gate because GET /grants requires user:read and the
  // catalogue has no `grant:read`. See Cards.jsx for the full reasoning.
  { key: 'grants',   label: 'Grants',   icon: '⚿', permission: 'user:read' },
  { key: 'sessions', label: 'Sessions', icon: '▶', permission: 'session:view' },
  { key: 'audit',    label: 'Audit',    icon: '☰', permission: 'audit:read' },
  { key: 'admin',    label: 'Admin',    icon: '⚙', anyOf: ['org:update', 'org:delete'] },
];

export function App() {
  // ---- routing ------------------------------------------------------------
  // Two routes, decided from the path. The invite route is handled before anything else so that an
  // unauthenticated visitor never sees the shell, which is also what keeps the org name out of the
  // page for `tests/ui.spec.js:308`.
  const path = window.location.pathname;
  // `decodeURIComponent` throws on a malformed escape, and this runs during render, so `/invite/%ff`
  // would blank the page instead of showing the same "this link did not work" every other bad
  // token gets. An undecodable token is simply a token the server will refuse, so treat it as one.
  const inviteToken = (() => {
    const match = /^\/invite\/(.+)$/.exec(path);
    if (!match) return null;
    try { return decodeURIComponent(match[1]); } catch { return match[1]; }
  })();
  if (inviteToken !== null) return <AcceptInvite token={inviteToken} />;

  // ---- session ------------------------------------------------------------
  const [me, setMe] = useState(null);
  const [booting, setBooting] = useState(true);
  const [notice, setNotice] = useState(null);

  // /v1/auth/me failing during boot must not strand the page on "Restoring your session…".
  // `setBooting(false)` was only reached if `loadMe()` resolved, so one failed request left the
  // console hanging with no shell and no reason, which is the one state BRIEF.md §3.2(5) calls
  // indistinguishable from a broken app.
  const [bootError, setBootError] = useState(null);

  // A reload has no access token, there is nothing in web storage to restore one from. The
  // httpOnly refresh cookie is sent by the browser automatically, so one POST rebuilds the session.
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const refreshed = await api.tryRefresh();
        if (!live) return;
        if (refreshed) await loadMe();
        if (live) setBootError(null);
      } catch (err) {
        if (live) setBootError(err.human ?? 'Could not reach the server.');
      } finally {
        if (live) setBooting(false);
      }
    })();
    return () => { live = false; };
  }, []);

  // A 401 from anywhere drops back to the sign-in screen, because at that point the session really
  // is over. TOKEN_STALE is handled one level down in api.js, which refreshes and retries first.
  useEffect(() => {
    api.setUnauthenticatedHandler(() => {
      api.clearToken();
      setMe(null);
      setNotice('Your session ended. Sign in again.');
    });
    return () => api.setUnauthenticatedHandler(null);
  }, []);

  const loadMe = useCallback(async () => {
    const payload = await api.me();
    setMe(payload);
    return payload;
  }, []);

  async function signIn() {
    setNotice(null);
    await loadMe();
  }

  async function signOut() {
    // The local sign-out happens either way, the access token is dropped and the shell unmounts.
    // But the server call is NOT swallowed: if the refresh cookie survives, a reload signs the
    // person straight back in, and a sign-out that silently fails is the one failure mode a user
    // cannot detect. If it fails, say so on the gate.
    let failed = null;
    try {
      await api.logout();
    } catch (err) {
      failed = 'Sign-out did not reach the server, so this session may still be active. Reload to find out.';
    }
    api.clearToken();
    setMe(null);
    setNotice(failed);
  }

  if (booting) {
    // Matches the new split gate rather than the old centred card, so the app does not visibly jump
    // shape on a fast reload.
    return (
      <div className="gate">
        <div className="gate__split">
        <section className="gate__premise">
          <p className="gate__eyebrow">RemoteOps</p>
          <h1 className="gate__claim">Know who can do what, and why.</h1>
        </section>
        <div className="gate__panel">
          <div>
            <h2 className="gate__title">Restoring your session</h2>
            <p className="gate__sub">Checking your refresh token…</p>
          </div>
        </div>
        </div>
      </div>
    );
  }

  if (!me) return <Login onSignedIn={signIn} notice={bootError ? `Could not sign you in: ${bootError}` : notice} />;

  return <Shell me={me} onReload={loadMe} onSignOut={signOut} />;
}

/**
 * The signed-in console. Split out from App so that signing out unmounts ALL of the org's data at
 * once rather than leaving any of it in a parent.
 */
function Shell({ me, onReload, onSignOut }) {
  const orgId = me.org.id;

  // Per-view data, all of it belonging to `orgId` and all of it discarded when the org changes.
  // `null` means "not fetched yet", which is what makes a view show its skeleton rather than
  // someone else's stale rows.
  const [view, setView] = useState('devices');
  const [data, setData] = useState({ devices: null, members: null, grants: null, sessions: null, audit: null });
  const [auditPage, setAuditPage] = useState(0);
  const [error, setError] = useState(null);
  const [switching, setSwitching] = useState(false);

  // Reference data, the permission catalogue and the role list, fetched ONCE for the whole
  // console and threaded down. It used to be fetched independently by each RolePicker (one per
  // member row) and again by the grants card, so the request count grew with the number of members
  // and each response carried the full catalogue. See the note on RolePicker.
  const [reference, setReference] = useState(null);
  React.useEffect(() => {
    let live = true;
    api.reference()
      .then((r) => { if (live) setReference(r); })
      .catch((err) => { if (live) setError(err); });
    return () => { live = false; };
  }, []);

  // The org-level resolved set. Memoised so it is referentially stable between renders: it is read
  // on every render to decide which cards exist, and a fresh object each time would be a new
  // identity for no reason.
  const permissions = useMemo(() => me?.permissions ?? {}, [me]);

  // Everything from the previous organization goes at once, on every org change. Not a filter, a
  // reset, which is why org A's device ids cannot survive into org B's DOM.
  //
  // `load` is a dependency, so this also collapses the duplicate fetch an org switch used to make:
  // the reset and the load both ran in the same commit, `load()` fired once with the PREVIOUS
  // view's closure and then again when `view` changed. Two requests per switch, and the second
  // one's data landed in a slot for a card that was no longer on screen. Resetting `view` first
  // means the load that follows reads the view it is actually going to render.
  useEffect(() => {
    setView('devices');
    setAuditPage(0);
    setError(null);
    setData({ devices: null, members: null, grants: null, sessions: null, audit: null });
  }, [orgId]);

  // Fetch the active view. Re-runs whenever the view OR the org changes, so a nav click is always a
  // refetch, which is what `tests/ui.spec.js:139` relies on when it rewrites the devices response
  // and clicks away and back.
  const load = useCallback(async () => {
    setError(null);
    try {
      // Each branch computes first and calls setData once, rather than awaiting inside a state
      // updater: an updater must be pure, and an `await` inside one silently reorders the update.
      if (view === 'devices') {
        const { devices } = await api.listDevices(orgId);
        setData((d) => ({ ...d, devices }));
      } else if (view === 'people') {
        const { members } = await api.listMembers(orgId);
        setData((d) => ({ ...d, members }));
      } else if (view === 'grants') {
        // The grants table needs the member and device lists to render its form's pickers. That is
        // two extra requests on entering this view, not per row, and the card is only reachable
        // by someone who already holds user:read, so both are permitted.
        const [grants, members, devices] = await Promise.all([
          api.listGrants(orgId), api.listMembers(orgId), api.listDevices(orgId),
        ]);
        setData((d) => ({ ...d, grants: grants.grants, members: members.members, devices: devices.devices }));
      } else if (view === 'sessions') {
        const { sessions } = await api.listSessions(orgId);
        // The start-a-session form needs devices, and listing devices needs device:list, which an
        // auditor does not hold. Rather than pre-judging that from the permission set, the console
        // asks and treats a 403 as "no device list here". Asking is one request either way, it
        // keeps `load` independent of the session object (so a mutation cannot trigger a second
        // fetch through a changed dependency), and it means a NEW permission appears in the form
        // the moment the server starts honouring it.
        let devices = [];
        try {
          devices = (await api.listDevices(orgId)).devices;
        } catch (err) {
          if (err.status !== 403) throw err;
        }
        setData((d) => ({ ...d, sessions, devices }));
      } else if (view === 'audit') {
        const page = await api.listAudit(orgId, { limit: 50, offset: auditPage * 50 });
        setData((d) => ({ ...d, audit: page.events, auditTotal: page.total }));
      }
    } catch (err) {
      setError(err);
    }
  }, [view, orgId, auditPage]);

  useEffect(() => { load(); }, [load]);

  // A change made on one card can alter what another card is allowed to show, so every mutation
  // re-reads the caller's own org-level set as well as the view. That is the "no propagation
  // window" property: the next fetch reflects the change.
  const reload = useCallback(async () => {
    await onReload();
    await load();
  }, [onReload, load]);

  async function switchTo(id) {
    if (id === orgId) return;
    setSwitching(true);
    setError(null);
    try {
      // A new token for the new org. Nothing about the old org survives this call.
      await api.switchOrg(id);
      await onReload();
    } catch (err) {
      setError(err);
    } finally {
      setSwitching(false);
    }
  }

  async function createOrg() {
    // A native prompt, deliberately: creating an organization is rare, needs one value, and a modal
    // form for a single text field would be more code than the feature deserves.
    const name = window.prompt('Name the new organization');
    if (!name || name.trim() === '') return;
    setError(null);
    try {
      const created = await api.createOrg(name.trim());
      // Straight into the new org: you just made it, you are its owner, and that is the view you
      // want to see. The token switch is what makes it the active org rather than a filter.
      await api.switchOrg(created.id);
      await onReload();
    } catch (err) {
      setError(err);
    }
  }

  const visible = CARDS.filter((c) => (c.anyOf ? allowsAny(permissions, c.anyOf) : allows(permissions, c.permission)));
  const current = visible.find((c) => c.key === view) ?? visible[0];

  return (
    <div className="shell" data-testid="app-shell" data-org-id={orgId} data-org-theme={me.org.theme} data-view={current?.key}>
      <aside className="side">
        <div className="side__brand">
          <span className="side__mark" aria-hidden="true">◈</span>
          <div>
            <div className="side__name">RemoteOps</div>
            <div className="side__org" data-testid="active-org-name">{me.org.name}</div>
          </div>
        </div>

        <div className="side__role">
          <span className="side__rolelabel">Your role</span>
          {/* Displayed, never interpreted. The console has no opinion about what an owner may do. */}
          <span className="side__rolevalue" data-testid="active-role">{me.role}</span>
        </div>

        <nav className="side__nav" aria-label="Sections">
          {visible.map((c) => (
            <button
              key={c.key}
              data-testid={`nav-${c.key}`}
              data-permission={c.anyOf ? c.anyOf[0] : c.permission}
              data-state="unlocked"
              className={`nav ${current?.key === c.key ? 'nav--on' : ''}`}
              aria-current={current?.key === c.key ? 'page' : undefined}
              onClick={() => { setAuditPage(0); setView(c.key); }}
            >
              <span className="nav__icon" aria-hidden="true">{c.icon}</span>
              {c.label}
            </button>
          ))}
        </nav>

        <div className="side__foot">
          <button className="btn btn--ghost" onClick={onSignOut}>Sign out</button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="topbar__org">
            <h1>{me.org.name}</h1>
            <span className="topbar__theme">{me.org.theme}</span>
          </div>

          <div className="topbar__orgs">
            <span className="topbar__label">Organization</span>
            {me.orgs.map((o) => (
              <button
                key={o.id}
                data-testid="org-option"
                data-org-id={o.id}
                data-active={o.id === orgId}
                className={`orgchip ${o.id === orgId ? 'orgchip--on' : ''}`}
                disabled={switching}
                onClick={() => switchTo(o.id)}
              >
                {o.name}
                <span className="orgchip__role">{o.role}</span>
              </button>
            ))}
            {/* Was "+ New", which says nothing about what it creates. A control should name the
                thing it makes; the test id stays `create-org` either way. */}
            <button data-testid="create-org" className="btn" onClick={createOrg}>
              New organization
            </button>
          </div>
        </header>

        {error && (
          <p className="error error--bar" role="alert" data-error-code={error.code}>
            {error.human}
            <button className="btn btn--ghost" onClick={() => setError(null)}>Dismiss</button>
          </p>
        )}

        <div className="content">
          {current?.key === 'devices' && (
            <DevicesCard
              orgId={orgId}
              orgPermissions={permissions}
              devices={data.devices ?? []}
              orgs={me.orgs}
              onReload={reload}
              onError={setError}
            />
          )}
          {current?.key === 'people' && (
            <PeopleCard orgId={orgId} orgPermissions={permissions} members={data.members ?? []} onReload={reload} onError={setError} meId={me.user.id} reference={reference} />
          )}
          {current?.key === 'grants' && (
            <GrantsCard orgId={orgId} orgPermissions={permissions} grants={data.grants ?? []} members={data.members ?? []} devices={data.devices ?? []} onReload={reload} onError={setError} reference={reference} />
          )}
          {current?.key === 'sessions' && (
            <SessionsCard orgId={orgId} orgPermissions={permissions} sessions={data.sessions ?? []} devices={data.devices ?? []} onReload={reload} onError={setError} />
          )}
          {current?.key === 'audit' && (
            <AuditCard
              events={data.audit ?? []}
              total={data.auditTotal ?? 0}
              page={auditPage}
              onPage={setAuditPage}
            />
          )}
          {current?.key === 'admin' && (
            <AdminCard orgId={orgId} orgPermissions={permissions} org={me.org} onReload={reload} onError={setError} />
          )}
          {current && data[current.key] === null && <p className="loading">Loading {current.label.toLowerCase()}…</p>}
        </div>
      </main>
    </div>
  );
}
