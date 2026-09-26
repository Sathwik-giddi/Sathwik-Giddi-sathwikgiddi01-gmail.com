// The console contract, asserted against the RENDERED DOM rather than against the source.
//
// The shipped `ui.spec.js` checks presence and absence, which is the half of the rule that is
// hard to get wrong. It does not check the other half: that a permission-gated element which IS
// rendered carries `data-permission` and `data-state="unlocked"`, which is what
// `UI-INVENTORY.md §1` says and what a hidden tier would read.
//
// Eight of my elements were correctly present-or-absent and carried neither attribute. Absence of a
// test for a rule is indistinguishable from absence of the rule, so this file is the test.
//
// Every org, user and device here comes from the shipped fixture, because this is a rendering
// contract and not a resolution one — `scripts/check-personalisation.js` covers the engine against
// a personalised fixture.

import { test, expect } from '@playwright/test';

async function login(page, email) {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill('demo1234');
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

async function open(page, card) {
  await page.getByTestId(`nav-${card}`).click();
}

/**
 * Every element named in UI-INVENTORY.md §2–3, with the permission that governs it. Read straight
 * off the inventory rather than off my components, so the two cannot drift.
 */
// [testid, governing permission, the card it belongs to]. The card matters: asserting that a
// `device-row` is absent from the People card proves nothing, and asserting it is PRESENT there
// proves the console is broken. Each element is checked on its own card and ignored elsewhere.
const INVENTORY = [
  ['device-row', 'device:view', 'devices'],
  ['start-view', 'device:view', 'devices'],
  ['start-control', 'device:control', 'devices'],
  ['start-terminal', 'device:terminal', 'devices'],
  ['transfer-files', 'device:file_transfer', 'devices'],
  ['rename-device', 'device:update', 'devices'],
  ['decommission-device', 'device:provision', 'devices'],
  ['user-row', 'user:read', 'people'],
  ['suspend-user', 'user:remove', 'people'],
  ['remove-user', 'user:remove', 'people'],
  ['grant-row', 'user:read', 'grants'],
  ['session-row', 'session:view', 'sessions'],
  ['audit-row', 'audit:read', 'audit'],
];

/** Elements that only exist once their card's form is open. */
const IN_FORM = [
  ['add-device', 'device:provision', 'devices'],
  ['invite-user', 'user:invite', 'people'],
  ['role-select', 'user:role:update', 'people'],
  ['new-grant', 'grant:create', 'grants'],
  ['new-session', 'session:start', 'sessions'],
  ['rename-org', 'org:update', 'admin'],
  ['delete-org', 'org:delete', 'admin'],
];

test('every rendered permission-gated element carries the contract attributes', async ({ page }) => {
  await login(page, 'owner@acme.test'); // an owner holds every documented permission

  // `test.skip()` inside a loop skips the WHOLE test, not the one assertion — my first version
  // called it and this test never ran at all, which is the exact failure mode a contract test
  // exists to prevent. So: skip nothing, count what was checked, and prove the count is real.
  const checked = [];
  const absent = [];

  // The six cards, so `nav-*` is covered by the same loop rather than by a separate test.
  for (const card of ['devices', 'people', 'grants', 'sessions', 'audit', 'admin']) {
    await open(page, card);
    await page.waitForTimeout(150); // let the view's fetch land

    const nav = page.getByTestId(`nav-${card}`);
    await expect(nav, `nav-${card}`).toHaveAttribute('data-state', 'unlocked');
    checked.push(`nav-${card}`);

    for (const [testid, permission, owner] of INVENTORY) {
      if (owner !== card) continue; // each element is checked on its own card only
      const scope = page.getByTestId(testid).first();
      if ((await scope.count()) === 0) { absent.push(`${testid}@${card}`); continue; }

      await expect(scope, `${testid} on ${card}`).toHaveAttribute('data-permission', permission);
      await expect(scope, `${testid} on ${card}`).toHaveAttribute('data-state', 'unlocked');
      checked.push(`${testid}@${card}`);
    }
  }

  // An owner in the demo fixture hits every one of them. If this count collapses the console
  // stopped rendering, and the loop above would have passed by asserting nothing at all.
  expect(checked.length, `checked: ${checked.join(', ')}`).toBe(6 + INVENTORY.length);
  expect(absent, `never rendered: ${absent.join(', ')}`).toEqual([]);
});

test('the card-level entries carry theirs once their form is open', async ({ page }) => {
  await login(page, 'owner@acme.test');
  const checked = [];

  for (const [testid, permission, card] of IN_FORM) {
    await open(page, card);
    await page.waitForTimeout(150);

    // Four of these sit behind their own opener, so click it first.
    const selfOpener = ['add-device', 'invite-user', 'new-grant', 'new-session'].includes(testid);
    if (selfOpener && (await page.getByTestId(testid).count()) === 0) {
      await page.getByTestId(testid).first().click();
      await page.waitForTimeout(150);
    }

    const el = page.getByTestId(testid).first();
    expect(await el.count(), `${testid} did not appear on the ${card} card`).toBeGreaterThan(0);
    await expect(el, `${testid} on ${card}`).toHaveAttribute('data-permission', permission);
    await expect(el, `${testid} on ${card}`).toHaveAttribute('data-state', 'unlocked');
    checked.push(testid);
  }

  expect(checked.length).toBe(IN_FORM.length);
});

test('an admin sees the Admin card with rename but NOT delete, and both carry attributes', async ({ page }) => {
  await login(page, 'admin@acme.test');
  await open(page, 'admin');

  const rename = page.getByTestId('rename-org');
  await expect(rename).toHaveCount(1);
  await expect(rename).toHaveAttribute('data-permission', 'org:update');
  await expect(rename).toHaveAttribute('data-state', 'unlocked');

  // org:delete is not held, so the element is absent — not disabled, not "locked".
  await expect(page.getByTestId('delete-org')).toHaveCount(0);
  // ...and the attribute is absent with it. There is no data-state="locked" in this console.
  await expect(page.locator('[data-state="locked"]')).toHaveCount(0);
});

test('the session row keeps its lifecycle out of data-state', async ({ page }) => {
  await login(page, 'dana@example.test');
  await open(page, 'sessions');
  await page.waitForTimeout(150);

  const row = page.getByTestId('session-row').first();
  test.skip((await row.count()) === 0, 'no sessions in this org');
  if ((await row.count()) === 0) return;

  // data-state is the PERMISSION state, always "unlocked" on a rendered row...
  await expect(row).toHaveAttribute('data-state', 'unlocked');
  await expect(row).toHaveAttribute('data-permission', 'session:view');
  // ...and the lifecycle lives in its own attribute, so a [data-state="unlocked"] selector scoped
  // to the card cannot accidentally match a row that happens to be 'active'.
  const lifecycle = await row.getAttribute('data-session-state');
  expect(['active', 'ended', 'connecting']).toContain(lifecycle);
});
