// Does the Content-Security-Policy actually DO anything?
//
// This file exists because of a specific near-miss. The first version of `server/headers.js` sent
// the policy as `X-Content-Security-Policy`. That name was an abandoned draft: no browser has ever
// implemented it. Every other header was present, the header dump looked correct, all 34 UI tests
// passed, and the policy was enforcing nothing at all, because the browser did not recognise the
// header and treated the document as having no policy.
//
// A header-presence test cannot catch that. It reads the same either way. Only a browser can tell
// you whether a policy is being applied, so that is what this does: it serves a document with an
// injected inline script and asks Chrome whether the script ran.
//
// The distinction being tested throughout: a CSP that is PRESENT is not a CSP that is ENFORCED.
// Both halves are asserted, because a policy that broke the application would be equally useless.

import { test, expect } from '@playwright/test';

const PORT = 8124;

/** The policy the server is expected to send, read from the live server rather than duplicated. */
async function policyFrom(page) {
  const res = await page.request.get(`http://localhost:${PORT}/`);
  return res.headers()['content-security-policy'] ?? '';
}

test.describe('Content-Security-Policy', () => {
  test('the header the server sends is the one browsers implement', async ({ page }) => {
    const csp = await policyFrom(page);
    expect(csp, 'a CSP must be present to be tested').not.toBe('');
    // The failure this file was written for: a policy under a name no browser reads.
    expect(csp, 'must not be the inert X-Content-Security-Policy draft').not.toBe('');
  });

  test('an inline script injected into the document does NOT execute', async ({ page }) => {
    // Serve the real document with an injected inline script. If the policy is enforced, the
    // browser refuses to run it and reports a violation. If it is absent, misnamed or permissive,
    // the script runs and the flag appears.
    await page.route(`http://localhost:${PORT}/`, async (route) => {
      const res = await route.fetch();
      const html = await res.text();
      await route.fulfill({
        status: 200,
        headers: res.headers(),
        body: html.replace(
          '</body>',
          `<script>window.__cspBypassed = true;</script>\n</body>`,
        ),
      });
    });

    const violations = [];
    await page.addInitScript(() => {
      window.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        window.__cspViolations.push(e.violatedDirective);
      });
    });

    await page.goto(`http://localhost:${PORT}/`);
    // Give the parser a moment; an injected inline script would have run during parse.
    await page.waitForTimeout(500);

    const bypassed = await page.evaluate(() => window.__cspBypassed === true);
    expect(bypassed, 'an injected inline script executed, the CSP is not being enforced').toBe(false);

    const reported = await page.evaluate(() => window.__cspViolations ?? []);
    expect(
      reported.some((d) => /script-src/.test(d ?? '')),
      `expected a script-src violation to be reported, got ${JSON.stringify(reported)}`,
    ).toBe(true);
  });

  test('the real application still runs under the policy', async ({ page }) => {
    // The other half. A policy that blocks the app's own bundle is not a policy, it is an outage,
    // and it is the failure mode a strict CSP introduces.
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto(`http://localhost:${PORT}/`);
    await expect(page.getByTestId('login-email')).toBeVisible();
    await expect(page.getByTestId('login-password')).toBeVisible();

    // And it must still be a working application, not just a rendered form.
    await page.getByTestId('login-email').fill('dana@example.test');
    await page.getByTestId('login-password').fill('demo1234');
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('app-shell')).toBeVisible({ timeout: 10_000 });
    // The bundle loaded, resolved data and rendered a card, a blocked module script would leave
    // the sign-in form on screen forever, so reaching the shell proves the external script ran.
    await expect(page.getByTestId('nav-devices')).toBeVisible();

    const policyErrors = errors.filter((e) => /Content Security Policy|Refused to/i.test(e));
    expect(policyErrors, `the app's own resources were blocked: ${policyErrors.join(' | ')}`).toEqual([]);
  });

  test('an external script origin is refused', async ({ page }) => {
    // `script-src 'self'` means a script from anywhere else is refused. This is the property that
    // makes a CSP worth having: it is what turns a stored-XSS foothold into a non-event.
    const csp = await policyFrom(page);
    expect(csp).toMatch(/script-src 'self'/);
    expect(csp).not.toMatch(/script-src[^;]*\*/);
    expect(csp, 'no wildcard script source').not.toMatch(/script-src[^;]*\*\s*;/);
  });
});
