// Outstanding invites, and cancelling one.
//
// `GET /v1/orgs/:org/invites` and `DELETE /v1/orgs/:org/invites/:id` were built in Phase 3 and, until
// Phase 15, reachable by nothing. The console showed an invite link once and forgot it, and only the
// hash is stored, so an invite sent to a mistyped address was a live bearer credential with no way to
// kill it until it expired. `DELETE` had no test at all.
//
// The property that matters is the last one in this file: revoking makes the LINK stop working, not
// just the row disappear. A revoke that only hid the row would pass every other test here.

import { test, expect } from '@playwright/test';

const CREDS = { email: 'owner@acme.test', password: 'demo1234' };

async function login(page, email = CREDS.email, password = 'demo1234') {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill(password);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

/**
 * A brand-new organization for this test, with the console looking at it.
 *
 * The suite shares one database, and an invite is the one artifact in it that does not go away when
 * you are finished with it: revoke it and it is still on the server, settled. So a test that asserts
 * `data-live-count` is exactly 0 sees whatever the tests before it left behind. My first draft ran
 * all six against org_acme and four failed for that reason. Each builds its own org, which the
 * creator owns, so the counts are exact.
 */
async function freshOrg(page, label, email = CREDS.email) {
  const { token } = await (await page.request.post('/v1/auth/login', { data: { ...CREDS, email } })).json();
  const org = await (await page.request.post('/v1/orgs', {
    headers: { authorization: `Bearer ${token}` }, data: { name: `Inv ${label}` },
  })).json();
  await page.reload();
  await switchTo(page, org.id);
  return org.id;
}

/**
 * A reload puts the console back in the org it boots into, NOT the one that was active, so any test
 * that reloads has to switch again. I missed this in the first version of the redeemed test and it
 * failed with an empty invite list, which looks exactly like "the list does not include redeemed
 * invites" and is in fact "the list is for a different organization".
 */
async function switchTo(page, orgId) {
  await page.locator(`[data-testid="org-option"][data-org-id="${orgId}"]`).click();
  await expect(page.getByTestId('app-shell')).toHaveAttribute('data-org-id', orgId);
}

const openPeople = async (page) => {
  await page.getByTestId('nav-people').click();
  await page.getByTestId('user-row').first().waitFor();
};

/** Issue an invite through the UI and return the link, which is shown exactly once. */
async function issue(page, email, role = 'operator') {
  await page.getByTestId('invite-user').click();
  await page.getByLabel('invite email').fill(email);
  await page.getByLabel('invite role').selectOption(role);
  await page.locator('.inline-form').getByRole('button', { name: 'Create invite' }).click();
  await expect(page.locator('.notice code')).toBeVisible();
  const link = (await page.locator('.notice code').textContent()).trim();
  return link;
}

test('an invite appears in the outstanding list as soon as it is sent', async ({ page }) => {
  await login(page);
  await freshOrg(page, 'appears');
  await openPeople(page);
  await expect(page.getByTestId('outstanding-invites')).toHaveAttribute('data-live-count', '0');

  await issue(page, 'new.hire@acme.test', 'auditor');

  // Not on a reload. The list is refreshed by the card's own `run`, so the person who just pressed
  // the button can see the result without navigating away.
  const list = page.getByTestId('outstanding-invites');
  await expect(list).toHaveAttribute('data-live-count', '1');
  const row = page.locator('[data-testid="invite-row"]');
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('new.hire@acme.test');
  // The role the admin chose is the role the invite carries.
  await expect(row).toContainText('auditor');
});

test('revoking removes the invite and moves it to settled, and the link stops working', async ({ page, context }) => {
  await login(page);
  await freshOrg(page, 'revoke');
  await openPeople(page);
  const link = await issue(page, 'typo@acme.test');

  // Before: the link is live, in a browser that has never signed in.
  const before = await context.newPage();
  await before.goto(link);
  await expect(before.getByTestId('invite-email')).toHaveValue('typo@acme.test');
  await before.close();

  await page.locator('[data-testid="revoke-invite"]').first().click();

  await expect(page.getByTestId('outstanding-invites')).toHaveAttribute('data-live-count', '0');
  await expect(page.getByTestId('invite-row')).toHaveCount(0);
  // It is not deleted, it is settled, and it says so.
  await expect(page.locator('.invites__settled summary')).toContainText('1 settled');

  // THE POINT. Same link, no account, no session: it must not be redeemable.
  const after = await context.newPage();
  await after.goto(link);
  const refusal = after.getByTestId('invite-error');
  await expect(refusal).toBeVisible();
  await expect(refusal).toContainText(/cancelled|no longer valid/i);
  await expect(after.getByTestId('invite-submit')).toHaveCount(0);
  await after.close();
});

test('a redeemed invite is not listed as outstanding', async ({ page, request }) => {
  await login(page);
  const orgId = await freshOrg(page, 'redeemed');
  await openPeople(page);

  // Redeem one out of band, through the API, so the list is not simply reloaded empty.
  // Scoped to the NEW org, not the one the login token names. A request naming any other org is
  // answered 404 rather than 403, which is indistinguishable from a bad route if you forget.
  const { token: base } = await (await request.post('/v1/auth/login', { data: CREDS })).json();
  const { token } = await (await request.post('/v1/auth/token', {
    headers: { authorization: `Bearer ${base}` }, data: { orgId },
  })).json();
  const headers = { authorization: `Bearer ${token}` };
  const inv = await (await request.post(`/v1/orgs/${orgId}/invites`, {
    headers, data: { email: 'redeemed@example.test', role: 'viewer' },
  })).json();
  expect(inv.inviteToken, `invite was not created: ${JSON.stringify(inv)}`).toBeTruthy();
  await request.post(`/v1/invites/${inv.inviteToken}/accept`, {
    data: { name: 'Redeemed', password: 'password123' },
  });

  await page.reload();
  await switchTo(page, orgId);
  await openPeople(page);

  // It is settled, not outstanding, and the count of actionable invites is unaffected.
  await expect(page.getByTestId('outstanding-invites')).toHaveAttribute('data-live-count', '0');
  await expect(page.locator('.invites__settled')).toContainText('redeemed@example.test');
  await expect(page.locator('.invites__settled')).toContainText(/redeemed/);
});

test('the list shows the invite id but never the link, because the link is not stored', async ({ page }) => {
  await login(page);
  await freshOrg(page, 'nolink');
  await openPeople(page);
  const link = await issue(page, 'secret@example.test');
  const token = link.split('/invite/')[1];

  const row = page.locator('[data-testid="invite-row"]');
  await expect(row).toHaveCount(1);
  // The id, which is safe to show, is there.
  await expect(row.locator('code')).toHaveText(/^inv_/);
  // The token is not, and cannot be, because only its hash exists server-side (D17). This is the
  // property that makes the list safe to render: it is a list of things to cancel, not a list of
  // links to re-send.
  await expect(row).not.toContainText(token);
  const html = await page.getByTestId('outstanding-invites').innerHTML();
  expect(html, 'the token must not appear anywhere in the section').not.toContain(token);
});

test('somebody without user:invite sees the People card and not the invites', async ({ page }) => {
  // The People card is gated on `user:read`, and a viewer holds that without `user:invite`. The
  // invites list therefore cannot be folded into the card's own data fetch: it would hand every
  // viewer a 403 and break a page they are entitled to. It is fetched separately and gated.
  await login(page, 'viewer@acme.test');
  await openPeople(page);

  await expect(page.getByTestId('user-row').first()).toBeVisible();
  await expect(page.getByTestId('outstanding-invites')).toHaveCount(0);
  // And no error is shown for a request that was never made.
  await expect(page.getByTestId('invites-error')).toHaveCount(0);
});

test('an admin can invite, and cannot hand out a rank above their own', async ({ page }) => {
  await login(page, 'admin@acme.test');
  await openPeople(page);
  await expect(page.getByTestId('outstanding-invites')).toBeVisible();

  // Not a fresh organization: whoever creates one OWNS it, and an owner may invite an owner, so the
  // thing under test cannot be set up that way. `org_acme` is shared with every other test, so this
  // compares against a baseline instead of expecting zero.
  const count = () => page.getByTestId('outstanding-invites').getAttribute('data-live-count').then(Number);
  const before = await count();

  await issue(page, 'under.admin@acme.test', 'viewer');
  await expect.poll(count).toBe(before + 1);

  // Above their own rank. D8: handing out a role above your own is the same rule as assigning one,
  // so the invite path cannot be used to sidestep the role-change path.
  await page.getByTestId('invite-user').click();
  await page.getByLabel('invite email').fill('too.hi@acme.test');
  await page.getByLabel('invite role').selectOption('owner');
  await page.locator('.inline-form').getByRole('button', { name: 'Create invite' }).click();

  // The refusal is shown, and the list does not grow, so a refusal is never mistaken for a send.
  await expect(page.locator('.error').first()).toBeVisible();
  await expect.poll(count).toBe(before + 1);
  await expect(page.getByTestId('outstanding-invites')).not.toContainText('too.hi@acme.test');
});
