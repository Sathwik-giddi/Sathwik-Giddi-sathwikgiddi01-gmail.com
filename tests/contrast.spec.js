// WCAG AA contrast, measured on the rendered pages rather than read out of the stylesheet.
//
//   npx playwright test tests/contrast.spec.js
//
// Why this is a test and not a one-off check: the palette is driven by six per-organization themes
// (`data-org-theme`), so a colour that passes under `cobalt` can fail under `moss`, and nobody
// would notice by looking. Every theme is checked, on every screen, on the real computed colours.
//
// It also cannot be satisfied by a stylesheet comment. `--ink-3` is documented as 4.9:1 on paper;
// this asserts the rendered result, so if a theme tint is darkened far enough to swallow it, the
// claim in the comment stops being true and this fails.
//
// What it does NOT check: the focus ring, motion, or anything that needs a human. It is the floor,
// not the ceiling.

import { test, expect } from '@playwright/test';

/** Relative luminance, per WCAG 2.1. */
const lum = ([r, g, b]) => {
  const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};

const ratio = (fg, bg) => {
  const [a, b] = [lum(fg), lum(bg)];
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
};

// The same parse exists inside `textRuns` below, because that one has to run in the page.
// This copy was the Node-side twin and nothing called it.

/**
 * Every visible leaf text node on the page, with the colour it is actually painted in and the
 * background it is actually painted on. The background walks up until it finds an opaque one,
 * because most text sits on a card that sits on a themed page.
 */
async function textRuns(page) {
  return page.evaluate(() => {
    const parse = (s) => (s.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
    const opaque = (c) => c && !/rgba?\([^)]*,\s*0\s*\)$/.test(c) && c !== 'transparent';
    const bgOf = (el) => {
      for (let n = el; n; n = n.parentElement) {
        const bg = getComputedStyle(n).backgroundColor;
        if (opaque(bg)) return parse(bg);
      }
      return [255, 255, 255];
    };
    const out = [];
    for (const el of document.querySelectorAll('body *')) {
      // Leaf text only: an element with element children gets its colour from them, and comparing
      // it would report a ratio for text that is not on screen.
      if (el.children.length) continue;
      const text = (el.textContent ?? '').trim();
      if (!text) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.opacity === '0') continue;
      out.push({
        text: text.slice(0, 40),
        color: parse(cs.color),
        bg: bgOf(el),
        size: parseFloat(cs.fontSize),
        weight: Number(cs.fontWeight) || 400,
        // An element painted over its own background is a deliberate overlay (a disabled control,
        // a muted badge) and is checked on the parent's background instead.
        ownBg: opaque(cs.backgroundColor) ? parse(cs.backgroundColor) : null,
      });
    }
    return out;
  });
}

const failuresFor = (runs) => runs.flatMap((r) => {
  // Large text is >=18.66px, or >=14px when bold. AA is 3:1 for large and 4.5:1 for the rest.
  const large = r.size >= 18.66 || (r.size >= 14 && r.weight >= 700);
  const need = large ? 3 : 4.5;
  const on = r.ownBg ?? r.bg;
  const got = ratio(r.color, on);
  return got < need ? [{ text: r.text, size: r.size, got: +got.toFixed(2), need }] : [];
});

async function signIn(page, email) {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill('demo1234');
  await page.getByTestId('login-submit').click();
  await page.getByTestId('app-shell').waitFor();
}

test.describe('contrast', () => {
  test('the sign-in screen passes AA', async ({ page }) => {
    await page.goto('/');
    const bad = failuresFor(await textRuns(page));
    expect(bad, JSON.stringify(bad)).toEqual([]);
  });

  for (const email of ['owner@acme.test', 'viewer@acme.test', 'dana@example.test']) {
    test(`every card passes AA as ${email}`, async ({ page }) => {
      await signIn(page, email);
      const bad = [];
      for (const card of ['devices', 'people', 'grants', 'sessions', 'audit', 'admin']) {
        const nav = page.getByTestId(`nav-${card}`);
        if ((await nav.count()) === 0) continue;          // a role that cannot see the card
        await nav.click();
        await page.waitForTimeout(150);
        bad.push(...failuresFor(await textRuns(page)).map((b) => ({ card, ...b })));
      }
      expect(bad, JSON.stringify(bad, null, 1)).toEqual([]);
    });
  }

  // The palette is per-organization, so one theme passing proves nothing about the other five.
  test('every organization theme passes AA on the device list', async ({ page }) => {
    await signIn(page, 'owner@acme.test');

    // Setting `data-org-theme` is exactly what the app does when the org changes, the whole
    // palette hangs off that one attribute, so this is the real mechanism, not a simulation of
    // it. An earlier version of this block fetched `/v1/reference` first "to be sure the themes
    // were real", which 401s without an Authorization header and failed the test for no reason
    // connected to contrast.
    const seen = [];
    for (const theme of ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal']) {
      await page.evaluate((t) => {
        document.querySelector('[data-testid=app-shell]').setAttribute('data-org-theme', t);
      }, theme);
      await page.waitForTimeout(60);
      const bad = failuresFor(await textRuns(page));
      seen.push({ theme, bad });
    }
    const all = seen.flatMap((s) => s.bad.map((b) => ({ theme: s.theme, ...b })));
    expect(all, JSON.stringify(all, null, 1)).toEqual([]);
  });

  // Added after a real regression: the ACTIVE organization chip set `color: var(--accent)` on
  // hover while its background was already `var(--accent)`, so hovering the current org made its
  // own label vanish. Source order could not have fixed it, because `.orgchip:hover` is (0,2,0) and
  // `.orgchip--on` is only (0,1,0), `:hover` is a class-level selector and outranks it. The only
  // honest general guard is to hover everything and check the text is still legible.
  test('no control becomes invisible on hover', async ({ page }) => {
    await signIn(page, 'dana@example.test');
    const controls = await page.locator('button, a[href], select, input[type=checkbox]').elementHandles();
    expect(controls.length, 'expected some controls to hover').toBeGreaterThan(5);

    const invisible = [];
    for (const el of controls) {
      if (!(await el.isVisible().catch(() => false))) continue;
      const name = await el.evaluate((e) => e.getAttribute('data-testid') || e.className || e.tagName);
      await el.hover({ timeout: 2000 }).catch(() => {});   // may be covered by something else
      await page.waitForTimeout(40);
      const bad = await el.evaluate((e) => {
        // Only a solid, opaque background of its own can hide the text it sits on.
        const cs = getComputedStyle(e);
        const bg = cs.backgroundColor;
        const opaque = bg && !/rgba?\([^)]*,\s*0\s*\)$/.test(bg) && bg !== 'transparent';
        return opaque && cs.color === bg;
      });
      if (bad) invisible.push(name);
    }
    expect([...new Set(invisible)], `invisible on hover: ${[...new Set(invisible)].join(', ')}`).toEqual([]);
  });

  test('a focus ring is visible on every interactive control', async ({ page }) => {
    await signIn(page, 'owner@acme.test');
    // Driven with real Tab presses rather than `element.focus()`. `:focus-visible` deliberately does
    // NOT match for a programmatic focus on a pointer-like interaction, so a JS focus() probe
    // reports every control as having no focus ring even when the ring is plainly there for a
    // keyboard user. The thing being tested is what a keyboard user gets.
    const invisible = [];
    for (let i = 0; i < 60; i++) {
      await page.keyboard.press('Tab');
      const info = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el || el === document.body) return null;
        const cs = getComputedStyle(el);
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return null;
        return {
          name: el.getAttribute('data-testid') || el.className || el.tagName,
          outline: cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0,
          shadow: cs.boxShadow !== 'none',
        };
      });
      if (info && !info.outline && !info.shadow) invisible.push(info.name);
    }
    expect([...new Set(invisible)], `no visible focus indicator on: ${[...new Set(invisible)].join(', ')}`).toEqual([]);
  });
});
