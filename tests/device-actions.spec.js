// What the six device buttons actually DO.
//
// Until this file existed, no test in the repository clicked any of them. `tests/contract.spec.js`
// checked that each one carried the right `data-permission` and `data-state`, and
// `scripts/check-http-seams.js` checked the endpoints underneath, so every layer of the stack was
// covered except the two lines that join them: the onClick handler and what the person sees
// afterwards. That gap is why a `window.prompt` and a `window.confirm` could sit in the middle of
// the product, and why a first-draft panel could drop the running session on a failed start.
//
// These tests assert the visible result of each action and, where a refusal is the correct answer,
// that the refusal is shown next to the button that caused it.
//
// Hermetic by construction. The suite shares one database, and three of these actions CONSUME their
// device: a transfer moves it to another organization and a decommission deletes it. My first draft
// ran all of them against `org_acme`, and the decommission tests quietly removed two of the four
// devices that `ui.spec.js:129` asserts the Acme viewer can see, so an unrelated test failed for a
// reason that had nothing to do with what it was checking. Anything that mutates a device therefore
// builds an organization and a device of its own first.

import { test, expect } from '@playwright/test';

const CREDS = { email: 'dana@example.test', password: 'demo1234' };

async function login(page, email = CREDS.email) {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill('demo1234');
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

/**
 * An organization and a device belonging to nobody else, with the console left looking at them.
 *
 * Set-up goes through the API on purpose. This file is about the six buttons on a device row, and
 * the console's own create-organization and add-device forms are covered in `ui.spec.js`. Doing it
 * here also buys something the form cannot do: `POST /devices` accepts `online`, and a device added
 * through the form is always created offline (`ctx.body.online ? 1 : 0`).
 */
async function scenario(page, label, { online = true, destinations = 0 } = {}) {
  const { token } = await (await page.request.post('/v1/auth/login', { data: CREDS })).json();
  const headers = { authorization: `Bearer ${token}` };

  const org = await (await page.request.post('/v1/orgs', { headers, data: { name: `Act ${label}` } })).json();

  // The token just minted is scoped to whichever organization it was minted for, and a request
  // naming any other one is answered 404 rather than 403, because "you are not a member" and "it
  // does not exist" must look the same. So creating a device INSIDE the new organization needs a
  // token scoped to it, which is what `POST /v1/auth/token` is for. Skipping this returns a 404
  // that looks exactly like a bad route.
  const scoped = (await (await page.request.post('/v1/auth/token', { headers, data: { orgId: org.id } })).json()).token;
  const device = await (await page.request.post(`/v1/orgs/${org.id}/devices`, {
    headers: { authorization: `Bearer ${scoped}` }, data: { name: label, kind: 'linux', online },
  })).json();

  const targets = [];
  for (let i = 0; i < destinations; i += 1) {
    targets.push(await (await page.request.post('/v1/orgs', { headers, data: { name: `Act ${label} to ${i}` } })).json());
  }

  // The console learns which organizations exist from /auth/me, so it has to be re-fetched before
  // the new one appears in the switcher.
  await page.reload();
  await page.locator(`[data-testid="org-option"][data-org-id="${org.id}"]`).click();
  await expect(page.getByTestId('device-row')).toHaveCount(1);
  return { orgId: org.id, deviceId: device.id, targets };
}

const row = (page, id) => page.locator(`[data-testid="device-row"][data-device-id="${id}"]`);
const panelAlert = (page) => page.locator('.panel [role="alert"]');

// ---------------------------------------------------------------------------
// The three session verbs.

test('View reports the session it started, and where the authority came from', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'view-one');

  await row(page, deviceId).getByTestId('start-view').click();
  await expect(page.getByTestId('session-panel')).toBeVisible();

  // The id is the server's, not a client-side guess, and it is the row the Sessions card will show.
  const id = (await page.getByTestId('session-panel-id').textContent()).trim();
  expect(id).toMatch(/^ses_/);
  await expect(page.getByTestId('session-panel')).toHaveAttribute('data-session-id', id);

  // She owns the organization she just made, so the snapshot names the role and lists no grant.
  const authority = page.getByTestId('session-panel-authority');
  await expect(authority).toContainText('owner');
  await expect(authority).toHaveAttribute('data-authority-grants', '');

  // And it is a real session: the stop control is there because the record is active.
  await expect(page.getByTestId('stop-device-session')).toBeVisible();
  await expect(panelAlert(page)).toHaveCount(0);
});

test('a session opened by a GRANT names the grant, which is the whole point of the product', async ({ page }) => {
  // The fixture gives the Acme viewer `session:start` and `device:view` on exactly one device, by
  // grant, and that is a viewer, whose role holds neither. So this session is possible only because
  // a grant was made, and the panel has to say so. Read-only apart from the session it starts, so it
  // is safe to run against the shipped fixture.
  await login(page, 'viewer@acme.test');
  const target = row(page, 'dev_lab_mac_01');
  await expect(target.getByTestId('start-view')).toHaveCount(1);

  await target.getByTestId('start-view').click();
  const authority = page.getByTestId('session-panel-authority');
  await expect(authority).toBeVisible();
  await expect(authority).toHaveAttribute('data-authority-role', 'viewer');
  // The Sessions card reduces this to the words "via grant". A panel opened from the button that
  // caused the session should carry the id, so the claim is checkable rather than decorative.
  expect(await authority.getAttribute('data-authority-grants')).toMatch(/^grt_/);
  await expect(authority).toContainText('grant');
});

test('a busy device refuses the second mode in place, and the first session stays stoppable', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'busy-one');
  const r = row(page, deviceId);

  await r.getByTestId('start-control').click();
  const id = (await page.getByTestId('session-panel-id').textContent()).trim();

  // control and terminal are exclusive per device (D10), enforced by a partial unique index.
  await r.getByTestId('start-terminal').click();
  await expect(panelAlert(page)).toBeVisible();
  await expect(panelAlert(page)).toContainText('exclusive session');
  // The refusal names the holder, so the message is actionable rather than a bare 409.
  await expect(panelAlert(page)).toContainText(id);

  // The regression this file was written for: a refusal must ADD to the panel, not replace it. My
  // first draft cleared the session on every click, so a failed second start left the running
  // Control session on screen with no way to stop it and no id.
  await expect(page.getByTestId('session-panel-id')).toHaveText(id);
  await expect(page.getByTestId('stop-device-session')).toBeVisible();
});

test('stopping a session keeps the panel and says how it ended', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'stop-one');

  await row(page, deviceId).getByTestId('start-view').click();
  await page.getByTestId('stop-device-session').click();

  await expect(page.getByTestId('session-panel-ended')).toContainText('ended');
  // Stopped once, so the control is gone rather than left to fail a second time.
  await expect(page.getByTestId('stop-device-session')).toHaveCount(0);
  // The name of the reason is the server's, spaced out from `user_stopped`.
  await expect(page.getByTestId('session-panel-ended')).toContainText('user stopped');
});

test('an offline device says so instead of pretending a session will be answered', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'offline-one', { online: false });
  await expect(row(page, deviceId)).toContainText('offline');

  await row(page, deviceId).getByTestId('start-view').click();
  await expect(page.getByTestId('session-panel-id')).toBeVisible();
  // The record is still created and still audited; only the expectation of a response is wrong.
  await expect(page.getByTestId('session-panel')).toContainText('offline');
});

// ---------------------------------------------------------------------------
// Transfer. Was a `window.prompt` asking for a number.

test('somebody in one organization is told there is nowhere to transfer to', async ({ page }) => {
  await login(page, 'owner@acme.test'); // a member of org_acme only, and it is left untouched
  await row(page, 'dev_lab_mac_01').getByTestId('transfer-files').click();

  await expect(page.getByTestId('transfer-nowhere')).toBeVisible();
  // No form at all, rather than a form whose every submission is guaranteed to fail.
  await expect(page.getByTestId('transfer-submit')).toHaveCount(0);
});

test('transfer offers only the source\'s other organizations, and submits nothing until one is chosen', async ({ page }) => {
  await login(page);
  const { deviceId, orgId, targets } = await scenario(page, 'pick-one', { destinations: 1 });

  await row(page, deviceId).getByTestId('transfer-files').click();
  await expect(page.getByTestId(`transfer-option-${targets[0].id}`)).toHaveCount(1);

  // The source is not offered as its own destination. `POST .../transfer` answers 400 `same_org`
  // for it, and a list containing it would be offering a guaranteed error.
  await expect(page.getByTestId(`transfer-option-${orgId}`)).toHaveCount(0);

  // A radio group with nothing chosen submits nothing.
  await expect(page.getByTestId('transfer-submit')).toBeDisabled();
  await page.getByTestId(`transfer-option-${targets[0].id}`).check();
  await expect(page.getByTestId('transfer-submit')).toBeEnabled();
});

test('a transfer refused for lack of authority names the organization that refused', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'refuse-one');

  // A destination she is not an owner of. The only such organization in reach is one somebody else
  // runs, so the fixture provides it: she owns Acme and is a VIEWER in Globex, and a transfer needs
  // `device:provision` on both sides.
  await row(page, deviceId).getByTestId('transfer-files').click();
  await page.getByTestId('transfer-option-org_globex').check();
  await page.getByTestId('transfer-submit').click();

  // The server's own reason is `missing device:provision`, which on its own reads as though the
  // device were at fault. The panel names the destination so the message is answerable.
  await expect(panelAlert(page)).toBeVisible();
  await expect(panelAlert(page)).toContainText('Globex Industries');
  await expect(panelAlert(page)).toContainText('device:provision');
  // Nothing moved, and the form is still there to choose differently.
  await expect(row(page, deviceId)).toHaveCount(1);
  await expect(page.getByTestId('transfer-submit')).toBeVisible();
});

test('a transfer that is allowed moves the device, and the device is in the other organization after', async ({ page }) => {
  await login(page);
  const { deviceId, orgId, targets } = await scenario(page, 'move-one', { destinations: 1 });

  await row(page, deviceId).getByTestId('transfer-files').click();
  await page.getByTestId(`transfer-option-${targets[0].id}`).check();
  await page.getByTestId('transfer-submit').click();

  // Gone from here, and the panel closed with it.
  await expect(row(page, deviceId)).toHaveCount(0);
  await expect(page.getByTestId('transfer-panel')).toHaveCount(0);

  // And present there, which is the half that proves the device moved rather than being deleted.
  await page.locator(`[data-testid="org-option"][data-org-id="${targets[0].id}"]`).click();
  await expect(row(page, deviceId)).toHaveCount(1);
  // The source organization itself is untouched otherwise.
  await page.locator(`[data-testid="org-option"][data-org-id="${orgId}"]`).click();
  await expect(page.getByTestId('devices-empty')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Rename. Worked, but could not be cancelled and sent an empty name to the server.

test('rename refuses an empty name without asking the server, and can be cancelled', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'rename-no');

  await row(page, deviceId).getByTestId('rename-device').click();
  const field = page.getByTestId('rename-device-name');
  await expect(field).toHaveValue('rename-no');

  // Whitespace is not a name. The button used to be enabled here, and the server answers 400.
  await field.fill('   ');
  await expect(page.getByTestId('rename-device-save')).toBeDisabled();

  // Cancelling is a control that did not exist: the only way out of this form was to save it.
  await field.fill('something else');
  await page.getByTestId('rename-device-cancel').click();
  await expect(page.getByTestId('rename-device-name')).toHaveCount(0);
  await expect(row(page, deviceId).locator('.cell-name')).toHaveText('rename-no');
});

test('rename saves, refreshes the row, and closes the form', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'rename-yes');

  await row(page, deviceId).getByTestId('rename-device').click();
  await page.getByTestId('rename-device-name').fill('renamed-device');
  await page.getByTestId('rename-device-save').click();

  // The row has to show the new name without anything else happening to trigger a reload. It did
  // not, at first: `run()` used to call `onReload()` and this path stopped using `run()`.
  await expect(row(page, deviceId).locator('.cell-name')).toHaveText('renamed-device');
  await expect(page.getByTestId('rename-device-name')).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// Decommission. Was a `window.confirm`.

test('decommission states its consequences and can be declined without touching the device', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'decom-no');

  await row(page, deviceId).getByTestId('decommission-device').click();
  const panel = page.getByTestId('decommission-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText(deviceId);
  await expect(panel).toContainText('live session');

  await page.getByTestId('decommission-cancel').click();
  await expect(panel).toHaveCount(0);
  await expect(row(page, deviceId)).toHaveCount(1);
});

test('decommission removes the device once confirmed, and the panel goes with it', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'decom-yes');

  await row(page, deviceId).getByTestId('decommission-device').click();
  await page.getByTestId('decommission-confirm').click();

  await expect(page.getByTestId('device-row')).toHaveCount(0);
  await expect(row(page, deviceId)).toHaveCount(0);
  await expect(page.getByTestId('decommission-panel')).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// The regression guard for the two native dialogs this replaced.

test('no device action opens a browser dialog', async ({ page }) => {
  await login(page);
  const { deviceId } = await scenario(page, 'no-dialogs');
  const r = row(page, deviceId);

  // Any `alert`, `confirm` or `prompt` in this flow is a failure, and `dialog` fires for all three.
  // Nothing here answers it, so an unexpected dialog hangs the test rather than passing quietly.
  let opened = null;
  page.on('dialog', (d) => { opened = d.type(); d.dismiss(); });

  for (const id of ['start-view', 'transfer-files', 'decommission-device']) {
    await r.getByTestId(id).click();
    await page.waitForTimeout(120);
  }
  await r.getByTestId('rename-device').click();
  await page.waitForTimeout(120);
  await page.getByTestId('rename-device-cancel').click();

  expect(opened, `a native dialog opened: ${opened}`).toBeNull();
});
