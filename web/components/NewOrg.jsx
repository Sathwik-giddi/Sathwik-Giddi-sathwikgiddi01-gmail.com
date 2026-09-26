// Creating an organization, as a form rather than a `window.prompt`.
//
// It was a prompt, and my own comment said a form "would be more code than the feature deserves".
// That was the wrong call, and a screenshot is what proved it. `BRIEF.md §3.2` asks for "create
// 2-3 organizations FROM THE UI", and a native prompt is not the UI: it cannot show the one error
// this form actually has (`CONFLICT | 409 | duplicate name`, which `PERMISSIONS.md §5` lists and no
// schema can enforce), it cannot offer the `theme` the endpoint already accepts, and it puts the
// app's one creation flow outside the app's own keyboard and focus handling.
//
// What this deliberately does NOT do is offer a public sign-up form. `AUTH-DATA-MODEL.md §6` is
// explicit: "Invites are the only way to add a person. One path means one set of edge cases." (D14).
// A stranger who can register an email can also register the email of somebody who has not arrived
// yet, and then that person can never accept an invite for it, because accept requires the existing
// account's password. Open registration would add a way to lock a colleague out of their own
// organization, which is the opposite of what this product is for.

import React, { useEffect, useRef, useState } from 'react';
import * as api from '../api.js';

// The six themes are `organizations.theme` in the reference data, so the list is read from the
// server rather than duplicated here. A hardcoded copy would be a second place to update when the
// reference data changes, which is the exact failure this codebase keeps guarding against.
const THEME_LABELS = {
  cobalt: 'Cobalt', amber: 'Amber', moss: 'Moss',
  plum: 'Plum', rust: 'Rust', teal: 'Teal',
};

const NAME_MAX = 120;

export function NewOrgDialog({ themes, onCancel, onCreated, onError }) {
  const [name, setName] = useState('');
  const [theme, setTheme] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState(null);
  const nameRef = useRef(null);
  const dialogRef = useRef(null);

  // Focus the field on open so the whole flow is reachable from the keyboard.
  useEffect(() => { nameRef.current?.focus(); }, []);

  // Escape closes, and Tab is kept inside the dialog. A modal that leaks focus to the page behind
  // it is not modal, and this one sits on top of a screen full of buttons.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') { e.stopPropagation(); onCancel(); return; }
      if (e.key !== 'Tab') return;
      const focusable = dialogRef.current?.querySelectorAll(
        'button, input, [href], select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable?.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [onCancel]);

  const submit = async (e) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed === '' || busy) return;
    setBusy(true);
    setProblem(null);
    try {
      // `theme` is only sent when one was picked. Left out, the server derives it from the name, so
      // an empty selection is a real answer rather than an error.
      const created = theme
        ? await api.createOrg(trimmed, theme)
        : await api.createOrg(trimmed);
      await api.switchOrg(created.id);
      await onCreated(created);
    } catch (err) {
      // 409 duplicate-name is the interesting one and it is shown here rather than in the page-level
      // error bar, because it is about this field and the fix is to change it.
      setProblem({ message: err.human ?? err.message, code: err.code });
      onError?.(null);
      nameRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  const trimmed = name.trim();
  const tooLong = name.length > NAME_MAX;
  const canSubmit = trimmed !== '' && !tooLong && !busy;

  return (
    <div className="scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="neworg-title"
        ref={dialogRef}
      >
        <h2 className="dialog__title" id="neworg-title">New organization</h2>
        <p className="dialog__sub">
          You become its owner, and you can invite people to it afterwards.
        </p>

        <form onSubmit={submit} noValidate>
          <label className="field">
            <span>Name</span>
            <input
              data-testid="new-org-name"
              ref={nameRef}
              value={name}
              maxLength={NAME_MAX}
              onChange={(e) => { setName(e.target.value); setProblem(null); }}
              placeholder="Acme Robotics"
              aria-invalid={tooLong || !!problem}
              aria-describedby={problem ? 'neworg-problem' : tooLong ? 'neworg-toolong' : undefined}
            />
          </label>

          {tooLong && (
            <p className="dialog__problem" id="neworg-toolong">
              {name.length} characters. The limit is {NAME_MAX}.
            </p>
          )}
          {problem && (
            <p className="dialog__problem" id="neworg-problem" role="alert" data-error-code={problem.code}>
              {problem.message}
            </p>
          )}

          {themes.length > 0 && (
            <fieldset className="themes">
              <legend>Colour</legend>
              <div className="themes__row">
                <button
                  type="button"
                  className={`themes__opt ${theme === '' ? 'themes__opt--on' : ''}`}
                  onClick={() => setTheme('')}
                  aria-pressed={theme === ''}
                >
                  <span className="themes__swatch themes__swatch--auto" aria-hidden="true" />
                  Match the name
                </button>
                {themes.map((t) => (
                  <button
                    key={t}
                    type="button"
                    data-testid={`new-org-theme-${t}`}
                    className={`themes__opt ${theme === t ? 'themes__opt--on' : ''}`}
                    onClick={() => setTheme(t)}
                    aria-pressed={theme === t}
                  >
                    <span className={`themes__swatch themes__swatch--${t}`} aria-hidden="true" />
                    {THEME_LABELS[t] ?? t}
                  </button>
                ))}
              </div>
            </fieldset>
          )}

          <div className="dialog__actions">
            <button type="button" className="btn" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="btn btn--primary" data-testid="new-org-submit" disabled={!canSubmit}>
              {busy ? 'Creating…' : 'Create organization'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
