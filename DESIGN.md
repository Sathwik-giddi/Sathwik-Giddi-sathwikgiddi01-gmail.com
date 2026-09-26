# DESIGN.md

The visual rules for this console, and why each one is here. Written before the CSS, so the CSS can
be checked against it rather than rationalised after the fact.

## The subject

An **access-authority console for remote machine fleets**, used by people who have to answer two
questions: *who can do what* and *can I prove it*. It is used across several organizations that share
one deployment and must never see each other.

That second question is the product. A generic admin panel answers the first. Nothing else on the
market answers the second, because nothing else has to.

## The one memorable thing

**Authority has a provenance, and the console shows it without being asked.**

Every permission in this system resolves to one of three places: the person's role, a grant someone
made them, or an explicit refusal someone made against them. That is not decoration — it is the
`source` field on every permission the engine returns, and it is the thing that makes an access review
possible at all.

The first version of this UI put that in a `title` attribute. Which means the product's entire
reason for existing was available **on hover, to nobody**, on a control most people never hover.

So: provenance is rendered, not tooltipped.

- A permission that comes from a **grant** rather than from your role is drawn with a dashed edge.
  The existing `.perm[data-source^="grant:"]` rule did this already; the redesign makes it read at a
  glance instead of hiding in a border style nobody notices.
- The device row's session actions sit on a **provenance rule** — a 2px bar under the label, solid
  when the power comes from the role, dashed when it came from a grant. At a glance, across five
  machines, you can see which of your powers are your job and which were handed to you.
- `+N grants` on a row stays, because "this row is not like the others" is worth knowing before you
  read the row.

Everything else is deliberately quiet so this reads.

## Colour

**The accent is not a choice — it is the data.** `organizations.theme` carries one of six values
(`cobalt`, `amber`, `moss`, `plum`, `rust`, `teal`) and `tests/ui.spec.js` asserts that switching
organization measurably changes the shell's *computed* background. So the per-organization palette
is the brand, and the job here was to build a neutral ramp good enough that six different accents can
sit on it without any of them looking borrowed.

The accent is spent in exactly three places:

1. the active navigation item
2. the primary action on a card
3. provenance marks

Everywhere else is neutral. An accent on everything is not an accent.

| token | value | used for |
|---|---|---|
| `--paper` | `#ffffff` | cards, table body |
| `--shell` | *per org, from `data-org-theme`* | the page behind the cards |
| `--sunken` | theme-tinted | inset areas: table head, code, hovered rows |
| `--line` | theme-tinted hairline | card and row borders |
| `--ink` | `#0f1520` | headings, primary text |
| `--ink-2` | `#47526b` | body, control labels (8.0:1 on paper, >=5.8:1 on any theme surface) |
| `--ink-3` | `#5c6675` | column heads, secondary (>=5.2:1 on every theme tint) |

Semantic colours are fixed rather than themed, because a refusal must read the same in every
organization: `--allow #0f7a52`, `--deny #b3261e`, `--warn #8a5a00`. Each is paired with a tinted
background, and every pairing clears 4.5:1.

**These ratios are measured, not asserted.** `tests/contrast.spec.js` walks every visible text node
on every card, for three roles and all six themes, and fails on anything under AA. It is the reason
`--ink-3` is `#5c6675` and not the `#6b7688` this file originally claimed: 4.9:1 is true on white and
false on a theme tint, where the table header actually sits, and it measured 4.11:1 on the plum
tint. A contrast number quoted against "the background" is only as good as the least likely
background.

## Type

No webfonts. The Content-Security-Policy is `font-src 'self'` and has to stay that way, so the type
is a system stack — which means the personality has to come from *how* it is set, not which face it
is.

The rule that fixes the biggest problem in the old UI:

> **Mono marks data, never structure.**

The old stylesheet set structural labels — `DEVICE`, `KIND`, `STATE`, `YOUR ROLE` — in monospace.
That is the visual costume of "technical product" and it says nothing. Mono is now reserved for the
things that genuinely are machine values: device ids, permission keys, counts, timestamps,
`+N grants`. Those are worth marking because they are copy-paste targets.

Structural labels are 11px sans, uppercase, `letter-spacing: .06em`, weight 600, `--ink-3`. The
uppercase convention stays — it is a legitimate table convention — it just stops pretending to be
data.

Headings get tight tracking (`-.015em`); body is 14px/1.5. Counts are tabular so columns of numbers
line up.

## Radius and elevation

Three radii, used for three different jobs:

- `--r-sm 4px` — chips, tags, inputs
- `--r-md 8px` — buttons, cards
- `--r-lg 14px` — the sign-in card only

The old sheet used `999px` on org chips, kind tags, status tags, the role block and the theme pill.
When everything is a pill, radius stops carrying information. Pills now mean one thing: *a status or
a count*.

One shadow, on two elements: the sign-in card and the sticky top bar. Everything else is separated by
a hairline. A page where every card floats has no ground plane.

## Layout

The old shell was a 244px full-height slab of saturated accent. That made the navigation louder than
the content, which is backwards — the content is the access decision, the navigation is a list of six
places to look.

The sidebar is now a **quiet rail**: paper, a hairline on the right, the accent only on the active
item. Organization identity survives as an accent-tinted brand mark at the top, which is enough.

The content column is capped (`--measure 1240px`) and left-aligned, so a 2560px display does not
stretch a table to unreadable width.

## Motion

120ms on hover, focus and the row-entering transition, and nothing else. No loops, no pulses, no
entrances on scroll. `prefers-reduced-motion: reduce` removes all of it. The online indicator is a
static ring, not a pulse — a fleet console that blinks is a console people stop trusting.

## What was deliberately not done

- **No dark mode.** Six organization themes is already a lot of palette. A theme toggle would be a
  seventh thing to get wrong, and there is no user request for it.
- **No icons replaced.** The navigation glyphs are geometric unicode, not emoji and not an icon
  library, and they are consistent. Replacing them with inline SVG is a real improvement but it is
  not this pass's job.
- **No stat cards.** There is no metric on this screen worth a card, and inventing one would be
  decoration. The row counts in the card headers are real and come from the data.
- **No dashboard above the content.** A "summary" block of invented numbers in front of the actual
  table would be the single most templated thing this screen could do.
