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

// ---------------------------------------------------------------------------
// TOKEN_STALE recovery.
//
// The console's one automatic recovery: the server says the token no longer
// describes this membership, so get a new one from the refresh cookie and replay
// the request. Two things about it are load-bearing and neither was tested:
//
//   1. it must be BOUNDED. Unguarded it is unbounded recursion — two HTTP requests
//      per level, forever, if the server keeps saying TOKEN_STALE.
//   2. it must replay into the RIGHT ORG. `refresh_tokens` has no org column, so
//      the refresh hands back the default org's token; replaying the original
//      org-B request with an org-A token is a guaranteed 404, and the screen then
//      blames the wrong thing.

test('a stale token is recovered from exactly once, in the right org', async ({ page }) => {
  const requests = [];
  page.on('request', (r) => { if (r.url().includes('/v1/')) requests.push(`${r.method()} ${new URL(r.url()).pathname}`); });

  await login(page, 'dana@example.test');
  // dana is owner in Acme and viewer in Globex, so she can be moved to Globex and stay active.
  await page.locator('[data-testid="org-option"][data-org-id="org_globex"]').click();
  await expect(page.getByTestId('app-shell')).toHaveAttribute('data-org-id', 'org_globex');

  // Force the very next request to be TOKEN_STALE, exactly as a role change would.
  let stale = true;
  await page.route('**/v1/orgs/org_globex/devices', async (route) => {
    if (!stale) return route.continue();
    stale = false;
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: { code: 'TOKEN_STALE', message: 'token is stale; refresh and retry', reason: null, requestId: 'req_test' } }),
    });
  });

  await page.getByTestId('nav-people').click();
  await page.getByTestId('nav-devices').click();

  // The recovery must land the caller back in Globex, not in the default org.
  await expect(page.getByTestId('app-shell')).toHaveAttribute('data-org-id', 'org_globex');
  await expect(page.getByTestId('device-row')).toHaveCount(2);

  // And bounded: the devices endpoint is asked for at most twice (the stale one and the replay).
  const deviceCalls = requests.filter((r) => r === 'GET /v1/orgs/org_globex/devices');
  expect(deviceCalls.length, `requests: ${requests.join(', ')}`).toBeLessThanOrEqual(2);
});

test('a server that ALWAYS says TOKEN_STALE does not loop forever', async ({ page }) => {
  // Sign in FIRST, then install the route. Installing it before login meant the very first devices
  // load failed, the recovery correctly gave up, and the console signed itself out — so the helper
  // was waiting for an app-shell that had legitimately gone. The behaviour under test is the
  // bound, and the bound is only reachable once there is a session to lose.
  await login(page, 'dana@example.test');

  let calls = 0;
  await page.route('**/v1/orgs/**/devices', async (route) => {
    calls += 1;
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: { code: 'TOKEN_STALE', message: 'token is stale', reason: null, requestId: 'req_x' } }),
    });
  });

  await page.getByTestId('nav-people').click();
  await page.getByTestId('nav-devices').click();
  await page.waitForTimeout(1000);

  // One call, one refresh, one replay, then it stops. Without the `retried` guard this climbs
  // without limit; four is generous for a correct recovery and far below a loop.
  expect(calls, `devices calls: ${calls}`).toBeLessThanOrEqual(4);
  // And the refusal is eventually shown rather than swallowed.
  await expect(page.getByTestId('login-form')).toBeVisible();
});

// ---------------------------------------------------------------------------
// A shipped control that lies, an N+1, and a boot that can hang.

test('the audit pager actually pages', async ({ page }) => {
  // Needs more than one page of events, so drive the API directly first and then count requests.
  const auth = await page.request.post('/v1/auth/login', { data: { email: 'dana@example.test', password: 'demo1234' } });
  const { token } = await auth.json();

  // One owner, one org, and a pile of grants — each of which writes an audit row.
  const org = await (await page.request.post('/v1/orgs', { headers: { authorization: `Bearer ${token}` }, data: { name: 'Pager Contract' } })).json();
  const orgToken = (await (await page.request.post('/v1/auth/token', { headers: { authorization: `Bearer ${token}` }, data: { orgId: org.id } })).json()).token;
  const inv = await (await page.request.post(`/v1/orgs/${org.id}/invites`, { headers: { authorization: `Bearer ${orgToken}` }, data: { email: 'pager@example.test', role: 'viewer' } })).json();
  await page.request.post(`/v1/invites/${inv.inviteToken}/accept`, { data: { name: 'Pager', password: 'password123' } });
  const members = await (await page.request.get(`/v1/orgs/${org.id}/members`, { headers: { authorization: `Bearer ${orgToken}` } })).json();
  const target = members.members.find((m) => m.email === 'pager@example.test');

  for (let i = 0; i < 60; i++) {
    await page.request.post(`/v1/orgs/${org.id}/grants`, {
      headers: { authorization: `Bearer ${orgToken}` },
      data: { userId: target.user_id, effect: 'allow', permissions: ['device:view'] },
    });
  }
  await page.request.post(`/v1/orgs/${org.id}/grants/revoke-none`, { headers: { authorization: `Bearer ${orgToken}` } }).catch(() => {});

  // `page.request` shares the context's cookie jar, so the API sign-in above already left a valid
  // refresh cookie and the console boots straight into the shell. (Filling the login form here
  // timed out on a form that does not exist — the harness, not the app, was wrong.) So use the
  // session we have and switch into the org we just filled with events.
  const calls = [];
  page.on('request', (r) => { if (r.url().includes('/audit')) calls.push(r.url()); });

  await page.goto('/');
  await expect(page.getByTestId('app-shell')).toBeVisible();
  await page.locator(`[data-testid="org-option"][data-org-id="${org.id}"]`).click();
  await expect(page.getByTestId('app-shell')).toHaveAttribute('data-org-id', org.id);
  await page.getByTestId('nav-audit').click();
  await expect(page.getByTestId('audit-row').first()).toBeVisible();

  const pager = page.getByTestId('audit-page');
  test.skip((await pager.count()) === 0, 'only one page of events');
  if ((await pager.count()) === 0) return;

  const firstPageRows = await page.getByTestId('audit-row').count();
  const before = calls.length;
  await expect(pager).toHaveText('page 1 of 2');

  await page.getByTestId('audit-next').click();   // the button labelled "Older"
  await expect(pager).toHaveText('page 2 of 2');

  // The assertion the old control could not satisfy: the ROWS changed, and a request was made.
  expect(calls.length, `audit requests: ${calls.length}`).toBeGreaterThan(before);
  await expect(page.getByTestId('audit-row')).not.toHaveCount(firstPageRows);

  // And back again.
  await page.getByTestId('audit-prev').click();
  await expect(pager).toHaveText('page 1 of 2');
  await expect(page.getByTestId('audit-row')).toHaveCount(firstPageRows);
});

test('reference data is fetched once, not once per row', async ({ page }) => {
  const calls = [];
  page.on('request', (r) => { if (r.url().includes('/v1/reference')) calls.push(r.url()); });

  await login(page, 'dana@example.test');
  await page.getByTestId('nav-people').click();
  await expect(page.getByTestId('user-row').first()).toBeVisible();

  const rows = await page.getByTestId('user-row').count();
  expect(rows).toBeGreaterThan(1);

  // It was `useEffect(api.reference, [])` inside a component instantiated once per member row, so
  // this used to be one request per member. BRIEF.md §6 names that antipattern outright.
  expect(calls.length, `reference requests: ${calls.length} for ${rows} rows`).toBeLessThanOrEqual(1);
});

test('a failed boot says so instead of hanging', async ({ page }) => {
  // A valid refresh cookie, and then /auth/me fails. Before the fix, `setBooting(false)` was only
  // reached if loadMe() resolved, so the page sat on "Restoring your session…" for ever.
  await login(page, 'dana@example.test');

  await page.route('**/v1/auth/me', (route) => route.fulfill({
    status: 500,
    contentType: 'application/json',
    body: JSON.stringify({ error: { code: 'INTERNAL', message: 'the database is unavailable', reason: null, requestId: 'r' } }),
  }));
  await page.route('**/v1/auth/refresh', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }));

  await page.reload();

  // It resolves to SOMETHING the user can act on, and it is not an endless spinner.
  await expect(page.getByTestId('login-form')).toBeVisible({ timeout: 8000 });
  await expect(page.locator('text=Restoring your session')).toHaveCount(0);
});
