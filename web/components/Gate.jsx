// Sign in, and the invite-redemption page.
//
// The two failure-feedback rules from UI-INVENTORY.md §4 are the reason this file is careful with
// wording:
//
//   - a wrong password and an unknown account read IDENTICALLY. The server sends one message for
//     both ("invalid email or password") and `tests/ui.spec.js:333` asserts the screen does not
//     improve on it by saying the account does not exist. A screen that says "no such account" is
//     an account-enumeration oracle.
//   - the error is ANNOUNCED, not just painted: role="alert" so a screen reader reaches it, and
//     it stays put until the next attempt so it can be read rather than glimpsed.

import React, { useState } from 'react';
import * as api from '../api.js';

export function Login({ onSignedIn, notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(null);

    // The empty form is answered here rather than by the server, because "you left this blank" and
    // "those credentials are wrong" are different problems and a person needs to be told which.
    const missing = [];
    if (email.trim() === '') missing.push('email');
    if (password === '') missing.push('password');
    if (missing.length > 0) {
      setError({ message: `Enter your ${missing.join(' and ')}.`, code: 'VALIDATION' });
      return;
    }

    setBusy(true);
    try {
      const payload = await api.login(email.trim(), password);
      api.setToken(payload.token);
      onSignedIn(payload.org.id);
    } catch (err) {
      setError({ message: err.human, code: err.code });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <div className="gate__split">
      {/* The premise gets its own column because this is the one screen with room to say what the
          product actually is, and saying it is worth more than a logo. Three claims, each of which
          is a thing the console genuinely does, not a tagline. */}
      <section className="gate__premise">
        <p className="gate__eyebrow">RemoteOps</p>
        <h1 className="gate__claim">Know who can do what, and why.</h1>
        <ul className="gate__points">
          <li>Several organizations share this deployment. None of them can see each other, and a request for something that does not exist is answered as though it never did.</li>
          <li>Every power you see came from somewhere: your role, a grant someone made you, or a refusal someone made against you. The console shows which.</li>
          <li>Changing someone's access takes effect on their next request, not when their session happens to expire.</li>
        </ul>
      </section>

      <div className="gate__panel">
        <form className="gate__form" data-testid="login-form" onSubmit={submit} noValidate>
          <div>
            <h2 className="gate__title">Sign in</h2>
            <p className="gate__sub">Multi-organization permission console</p>
          </div>

          {notice && <p className="notice" role="status">{notice}</p>}

          <label className="field">
            <span>Email</span>
            <input
              data-testid="login-email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              data-testid="login-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>

          <button data-testid="login-submit" className="btn btn--primary" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>

          {error && (
            <p className="error" data-testid="login-error" data-error-code={error.code} role="alert">
              {error.message}
            </p>
          )}
        </form>

        {/*
          The invite path, stated on the sign-in screen, because there is no sign-up and the absence
          of a "Register" link reads as a missing feature rather than a decision.

          This line was missing while DECISIONS.md claimed the sign-in screen said so. It did not.
          Nothing tested the claim, which is the same class of gap as the device buttons: a thing
          asserted in prose that no check would have caught. `tests/ui.spec.js` now pins the words.
        */}
        <p className="gate__hint" data-testid="login-no-signup">
          <b>There is no sign-up.</b> Accounts are created by redeeming an invite: an owner or admin
          sends one from <b>People → Invite</b>, and the link they get back is the only way in.
          Already have a link? Open it directly.
        </p>

        <p className="gate__hint">
          <b>Demo accounts</b>, all with the password <code>demo1234</code>:<br />
          <code>owner@acme.test</code> sees everything · <code>viewer@acme.test</code> can only
          look · <code>dana@example.test</code> belongs to two organizations, so you can switch
          between them.
        </p>
      </div>
      </div>
    </div>
  );
}

/**
 * The invite page, at /invite/:token.
 *
 * `tests/ui.spec.js:308` requires that a bad token renders an error and leaks NOTHING, the page
 * must not contain the string "Acme" or "org_acme". So this component renders only what the public
 * peek endpoint returned, and that endpoint deliberately returns the org's NAME and not its id
 * (BRIEF.md §5.1, and the assertion at `scripts/check-api.js:172`). There is no org switcher, no
 * shell and no other content on this route for that reason.
 */
export function AcceptInvite({ token }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  React.useEffect(() => {
    let live = true;
    api.peekInvite(token)
      .then((data) => { if (live) setInvite(data); })
      .catch((err) => { if (live) setError({ message: err.human, code: err.code }); });
    return () => { live = false; };
  }, [token]);

  async function submit(event) {
    event.preventDefault();
    setError(null);

    const missing = [];
    if (name.trim() === '') missing.push('your name');
    if (password === '') missing.push('a password');
    else if (password.length < 8) missing.push('a password of at least 8 characters');
    if (missing.length > 0) {
      setError({ message: `This invite needs ${missing.join(' and ')}.`, code: 'VALIDATION' });
      return;
    }

    setBusy(true);
    try {
      await api.acceptInvite(token, name.trim(), password);
      setDone(true);
    } catch (err) {
      setError({ message: err.human, code: err.code });
    } finally {
      setBusy(false);
    }
  }

  if (error && !invite) {
    return (
      <div className="gate">
        <div className="gate__card">
          <h1 className="gate__title">This invite link did not work</h1>
          <p className="error" data-testid="invite-error" data-error-code={error.code} role="alert">
            {error.message}
          </p>
          <a className="btn" href="/">Go to sign in</a>
        </div>
      </div>
    );
  }

  if (done) {
    // The sign-in form, not a "go to sign in" link. Accepting does NOT sign anyone in, there is no
    // token issued by the accept route, so the honest next step is to sign in, and putting the form
    // here means the person is already standing on it. `tests/ui.spec.js:305` requires
    // `login-form` to be on the page at this point.
    //
    // The redirect is a full navigation, not a client-side route change: the access token lives in
    // the previous page's module memory, so the console has to boot again to pick up a new one.
    return (
      <Login
        notice={`You joined ${invite.orgName} as ${invite.role}. Sign in to continue.`}
        onSignedIn={() => { window.location.href = '/'; }}
      />
    );
  }

  if (!invite) {
    return (
      <div className="gate">
        <div className="gate__card">
          <h1 className="gate__title">Checking this invite…</h1>
        </div>
      </div>
    );
  }

  return (
    <div className="gate">
      <form className="gate__card" onSubmit={submit} noValidate>
        <div className="gate__mark" aria-hidden="true">◈</div>
        <h1 className="gate__title">Join {invite.orgName}</h1>
        <p className="gate__sub">You have been invited as:</p>

        <dl className="summary">
          <div>
            <dt>Organization</dt>
            <dd>{invite.orgName}</dd>
          </div>
          <div>
            <dt>Email</dt>
            {/* An input, not text: the address is part of what you are confirming, and a readonly
                field is still a field a person can check they read correctly. */}
            <dd><input data-testid="invite-email" value={invite.email} readOnly /></dd>
          </div>
          <div>
            <dt>Role</dt>
            <dd><span data-testid="invite-role" className="tag">{invite.role}</span></dd>
          </div>
        </dl>

        <label className="field">
          <span>Your name</span>
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
        </label>

        <label className="field">
          <span>Choose a password</span>
          <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        </label>

        <button data-testid="invite-submit" className="btn btn--primary" disabled={busy}>
          {busy ? 'Joining…' : `Join ${invite.orgName}`}
        </button>

        {error && (
          <p className="error" data-testid="invite-error" data-error-code={error.code} role="alert">
            {error.message}
          </p>
        )}
      </form>
    </div>
  );
}
