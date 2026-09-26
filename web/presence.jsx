import React, { cloneElement, isValidElement } from 'react';
// The presence primitives.
//
// This file is the whole of the console's permission model, and it is four functions long on
// purpose. There is no role-to-permission table anywhere under web/ — the server resolved
// everything and sent it, and these helpers only decide whether to render.
//
// The rule (UI-INVENTORY.md §1, BRIEF.md §5.3): an element is PRESENT with data-state="unlocked",
// or ABSENT. Never disabled, never greyed out, never `data-state="locked"`. A permission console
// should not advertise actions a person cannot take.
//
// `tests/ui.spec.js:139` is the test that matters: it intercepts the devices response, makes the
// server say deny, and the button has to disappear. Anything that re-derives a permission in the
// browser fails it, which is the point of the test.

/** Does the server's resolved set allow this permission? The ONLY permission question asked here. */
export const allows = (permissions, key) => permissions?.[key]?.effect === 'allow';

/** Does the server's resolved set allow this, or any of these? For the Admin card (org:update OR org:delete). */
export const allowsAny = (permissions, keys) => keys.some((k) => allows(permissions, k));

/** The server's verdict, for explaining itself: { effect, source, reason } or null. */
export const verdict = (permissions, key) => permissions?.[key] ?? null;

/**
 * Render `children` only when the permission is held. This is the presence rule in one place —
 * every permission-gated element in the console goes through it, so there is exactly one place to
 * look when asking "why is this button here?".
 *
 * It also ATTACHES the two contract attributes to whatever it renders, by cloning the child. That
 * is not tidiness: `UI-INVENTORY.md §1` requires a rendered gated element to carry
 * `data-permission` and `data-state="unlocked"`, and I had written eight of them that were
 * correctly present-or-absent and carried neither attribute — the presence was right and the
 * contract was not, which is the half of the rule nobody notices is missing. Making the helper do
 * it means a ninth cannot be added without them.
 *
 * For an `anyOf` gate (the Admin card is `org:update` OR `org:delete`) the attribute names the
 * permission the caller ACTUALLY holds, not the first one listed, so `data-permission` is a true
 * statement about why the element is on the page.
 */
export function IfAllowed({ permissions, permission, anyOf, children }) {
  const candidates = anyOf ?? [permission];
  const held = candidates.find((key) => allows(permissions, key));
  if (!held) return null;

  if (!isValidElement(children)) return children;

  return cloneElement(children, {
    'data-permission': children.props['data-permission'] ?? held,
    'data-state': 'unlocked',
  });
}

/**
 * A permission-gated control. Carries the two attributes the tests read —
 * `data-permission` and `data-state="unlocked"` — plus `data-source`, which is mine: it is how a
 * rendered button explains where its authority came from, so "Control" on a viewer's row can say
 * `granted by grt_dana_control_one_device` rather than looking identical to an owner's.
 *
 * `state="unlocked"` is a constant, not a variable. It only ever appears on an element that is
 * allowed to exist, so there is no second value to get wrong.
 */
export function PermButton({ permissions, permission, title, source, className = '', children, ...rest }) {
  return (
    <IfAllowed permissions={permissions} permission={permission}>
      <button
        type="button"
        data-permission={permission}
        data-state="unlocked"
        data-source={source ?? undefined}
        className={`perm ${className}`}
        title={title}
        {...rest}
      >
        {children}
      </button>
    </IfAllowed>
  );
}

/**
 * Turn the server's provenance into something a person can read. Three cases, and they are
 * genuinely different stories, which is the whole reason `reason` exists on the wire:
 *
 *   role:operator      you can do this because of your role
 *   grant:grt_…        you can do this because somebody gave it to you, here
 *   (absent)           you cannot do this, and the element is not on the page
 */
export function provenance(verdict) {
  if (!verdict) return '';
  if (verdict.effect === 'allow') {
    return verdict.source?.startsWith('grant:')
      ? `granted by ${verdict.source.slice('grant:'.length)}`
      : `via ${verdict.source ?? 'your role'}`;
  }
  if (verdict.reason === 'explicit_deny') return `denied by ${String(verdict.source).slice('grant:'.length)}`;
  if (verdict.reason === 'suspended') return 'membership suspended';
  if (verdict.reason === 'not_a_member') return 'not a member of this organization';
  return 'nobody granted this';
}
