// Relative timestamps in the fixture.
//
// The fixture writes times as offsets from now ('-2h', '+7d', 'now') so it never goes stale and a
// seeded grant never silently expires.
//
// This was three copies of one regex, one in each fixture builder, and all three were wrong in the
// same way. The pattern was `^([+-])(\d+)([dhm])$`, which matches `-2h` and `+7d` and does NOT
// match a COMPOUND offset. The hand-out fixture contains one: `auditEvents[2].at` is `-2h30m`. The
// regex fell through to its "already absolute ISO-8601" branch and wrote the literal text
// `-2h30m` into `audit_events.at`. The column is a timestamp, the console formats it, and the audit
// screen rendered **"Invalid Date"** on that row.
//
// Nothing caught it because the value is only wrong at the point of display, and no suite asserted
// on the rendered date. `assertSeedTimesParse` below is what catches it now.

const UNIT_MS = { d: 864e5, h: 36e5, m: 6e4 };

/** One or more `<number><unit>` groups behind a single sign: '-2h30m', '+7d', '-90d'. */
const OFFSET = /^([+-])((?:\d+[dhm])+)$/;

/**
 * Resolve a fixture timestamp to an absolute ISO-8601 string.
 *
 * A compound offset is a sum, not a repeat: `-2h30m` is two hours and thirty minutes ago, not two
 * hours ago thirty times. `Date.now() - 2h - 30m` is what the fixture means, and treating the sign
 * as applying to each group in turn would make `-2h30m` mean -2h -30m which happens to agree here
 * but is not why it is written that way. The sign is applied once, to the total.
 *
 * Anything that is not an offset is returned untouched, on the assumption that it is already an
 * absolute timestamp. That assumption is what silently produced the bug above, so it is checked
 * rather than trusted: see `assertSeedTimesParse`.
 */
export function resolveRelativeTime(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return value;
  const m = OFFSET.exec(value);
  if (!m) return value;
  const total = [...m[2].matchAll(/(\d+)([dhm])/g)]
    .reduce((ms, [, n, u]) => ms + Number(n) * UNIT_MS[u], 0);
  return new Date(Date.now() + (m[1] === '-' ? -1 : 1) * total).toISOString();
}

/** True when `value` is a relative offset this module understands. */
export const isOffset = (value) => typeof value === 'string' && OFFSET.test(value);

/**
 * Every timestamp-shaped field in the fixture must either be an offset we can resolve or something
 * `Date` can actually parse. Called by the loader so a format the parser does not handle fails at
 * load time, loudly, instead of becoming an "Invalid Date" on a screen three phases later.
 *
 * Returns the list of bad paths rather than throwing, so the caller decides how loudly to fail.
 */
export function assertSeedTimesParse(seed, fields = ['at', 'startedAt', 'expiresAt', 'joinedAt']) {
  const bad = [];
  const walk = (node, path) => {
    if (Array.isArray(node)) return node.forEach((v, i) => walk(v, `${path}[${i}]`));
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      // Keys beginning with `_` are the fixture's own commentary, not data.
      if (k.startsWith('_')) continue;
      const here = `${path}.${k}`;
      if (typeof v === 'string' && fields.includes(k)) {
        if (isOffset(v)) continue;
        if (Number.isNaN(new Date(v).getTime())) bad.push(`${here} = ${JSON.stringify(v)}`);
        continue;
      }
      walk(v, here);
    }
  };
  walk(seed, 'seed');
  return bad;
}
