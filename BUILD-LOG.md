# BUILD-LOG

## How to run this

```sh
npm install
npm run db:reset     # schema + reference data + demo fixture + the personalised overlay
npm run dev          # http://localhost:8080  — one process, API and console
```

Then sign in as `sam@example.test` / `demo1234` and switch between Acme Robotics and Globex
Industries. She can control devices and cannot read the audit log in one; she can read the audit log
and cannot control anything in the other. Same person, the two items swap.

To run everything:

```sh
npm run check        # all six dependency-free suites, 371 assertions
npx playwright install chromium   # once; the CDN is unreachable from some networks
npm test             # builds the SPA (pretest), then the 25-case UI contract
```

`npm run check` needs only `better-sqlite3`. Two extras are mine and are not part of the graded
contract: `npm run inspect` prints the resolved permission model for the loaded database with its
provenance, and `npm run measure` counts executed statements per request and measures latency.

Append each entry as you go, and commit it with the code it describes — the timestamps are part of
the evidence, and a log that arrives in one commit at the end reads as what it is. Five lines is a
real entry; short and dated beats long and reconstructed. The categories of event the brief looks
for are listed in `DISCOVERY-BRIEF.md`.

Entries below are in the order they happened, including the parts where I was wrong.

---

## 2026-09-26 · Phase 0 — orientation

Installed, `npm run db:reset`, read the five documents, ran all four public suites against the
untouched skeleton. Starting line, exactly:

| suite | skeleton result |
|---|---|
| `check-jwt.js` | 0 passed, **43 failed** — every case reports `Error: TODO: ...` |
| `check-permissions.js` | never reaches its harness; dies at import with `code: 'NOT_IMPLEMENTED'` |
| `check-personalisation.js` | `FAIL could not resolve at all: resolve() is yours to write` |
| `check-api.js` | aborts on assertion 2 — `dana.body.orgs` is `undefined` |

The one that surprised me: `check-permissions.js` does not report 43 failures, it reports
**nothing**. `resolve` is called at module scope in the `effect()` helper, so the first call
throws during the import of the test file and the whole process dies before `pass`/`fail` are
declared. A missing engine and a wrong engine look completely different from the outside. Noted
because it means "the suite printed nothing" is a signal, not a silence.

### The database is not the fixture the documents describe

`npm run db:reset` printed `permissions=20 patterns=27` and `organizations=3`. The sanity
comment at the bottom of `db/reference.sql:104-107` says to expect 19 permissions, 26 patterns
and (implicitly) two organizations. All three are wrong in my database, and all three are wrong
*on purpose*: `.candidate-nonce` holds `starter-demo`, so `scripts/personalise.js` adds a third
organization — **Ironside Labs** (`org_p_bb3398`) — carrying a role `reviewer` (rank 35) and a
permission `device:reboot` that appear in no document, with a device-scoped `allow` of
`device:reboot` on `dev_p_bb3398_a` and a device-scoped `deny` of the same on
`dev_p_bb3398_b`. Login for it is `robin.bb3398@example.test / demo1234`.

So the reference comment is only true when there is no nonce. Treating it as the contract would
have made the engine wrong on the first boot, not on the graded run.

### Reading the personalisation overlay before writing the engine

`scripts/personalise.js` is given to me, so I read it rather than guessing what "personalised"
means. Two things in there shape the engine and are not in any prose document:

1. `applyOverlay` inserts the new permission into `permission_patterns` as well as
   `permissions` (`personalise.js:240`). That is what keeps the `grant_permissions` foreign key
   meaningful for `device:reboot` — without that row, inserting the overlay's own allow-grant
   would raise `FOREIGN KEY constraint failed` and `db:reset` would not complete.
2. `ROLE_POOL`/`RANK_POOL` are drawn so the new role's rank never collides with 10/20/30/40/50
   (`personalise.js:55`), and `device:list`+`device:view` are forced into every personalised
   baseline (`personalise.js:123`) so a device row can always render. Both are hints about what
   the graded fixture will look like: an arbitrary rank, and a baseline that is not any of the
   five documented bundles.

Consequence for my code: nothing may assume a fixed permission count, a contiguous rank set, or
that `roles.rank` has five members. `roleRanks()` reads the table.

## Phase 1 — token verification

_Wrote `verifyAccessToken` in `server/auth.js:50-142`. `check-jwt.js` went 0/43 → 43/43 on the
first run, which made me suspicious rather than pleased, so I went looking for the cases where
my implementation could pass for the wrong reason._

### The failure I did not predict: a malformed signature was going to be a 500

Before writing the signature comparison I assumed a non-base64url signature would fail loudly.
It does not. Two measurements:

```
decoded '!!!not-base64!!!' -> 7 bytes "9e8b7e6dab1eeb"      // Buffer.from(_, 'base64url') did not throw
timingSafeEqual(4 bytes, 32 bytes) -> RangeError: Input buffers must have the same byte length
```

`Buffer.from(x, 'base64url')` **silently discards** every character outside the alphabet, so
`'!!!not-base64!!!'` decodes to 7 bytes instead of raising. And `timingSafeEqual` throws a
`RangeError` when the lengths differ, which `sendError` maps to `500 INTERNAL`, not `401`. So the
three short-signature cases — `signature truncated`, `signature empty`, `signature is not
base64url` — would each have been a **500 on an authentication path** with a guard written the
obvious way (`timingSafeEqual(unb64(sig), expected)` inside a try).

Fixed by refusing the segment on its characters *before* decoding
(`B64URL = /^[A-Za-z0-9_-]+$/`, `auth.js:63`) and by comparing lengths before `timingSafeEqual`
(`auth.js:104`). This is the same class of bug as the `PRAGMA foreign_keys` trap the README
warns about: the check that is supposed to refuse the bad thing is not the check that runs.

### One client-facing message, seven internal causes

Every rejection throws `unauthenticated('invalid access token')` and hangs the specific cause on
`err.detail`, which `sendError` does not serialise. I wanted the log to be debuggable, and I did
not want a 401 that says *which* check failed — that is an oracle for whoever is trying to forge
one. Verified the property is real rather than assumed: `sendError` (`server/http.js:52`) copies
only `status`, `code`, `message` and `reason`.

### What I added beyond the seven listed failure modes

The stub lists seven. I also require `sub`, `org`, `role` to be non-empty strings and `pv` to be
an integer, because `authenticate()` reads all four and a token with `org` absent would otherwise
be read as "the empty org" — a scoping bug rather than a 401. `issueAccessToken` always sets them,
so this cannot reject a token the server minted.

### Order is the decision, not the checks

Signature before claims. `check-jwt.js:111` (`payload swapped, old signature kept`) is the case
that forces it: the swapped payload is perfectly well-formed and unexpired, so a verifier that
reads claims first would sail through it on the `exp` check and only trip on the signature later.
The suite passes either way; I put the signature first because the only safe time to trust a
claim is after the bytes carrying it are authenticated.

## 2026-09-26 · Phase 2 — caller context and the resolution engine

`check-permissions.js` 35/35 and `check-personalisation.js` 18/18, both green on the first run.
Again suspicious, so most of this entry is about the things the green did *not* settle.

### The model I started with, and the line that broke it

My first mental model was one line of code:

```
if any applicable grant denies -> deny
else if baseline has it        -> allow
else if any applicable grant allows -> allow
else                           -> deny (implicit)
```

with "applicable" meaning `device_id IS NULL OR device_id = <the device in the question>`.
`check-permissions.js:85` is the case aimed at that model — a device-scoped `allow
device:terminal` against an org-wide `deny device:terminal` — and my ordering handles it, so I
recorded the suite as agreeing with me and moved on. That was the mistake: the suite agreeing
with the model I already had is not evidence.

So I went looking for the question the model does not have an answer for, and it is the one
`resolve()` is called with most often in production code: **`deviceId: null`**. Nothing in the
engine's own suite pins it. `tests/ui.spec.js` and `check-api.js` only ever assert device-level
answers.

PERMISSIONS.md §3 says the org-level context is "the union across all devices in the org". So
the question is not "which grants name no device" but "what can this person do *anywhere* in
this org". Two consequences I had to settle, and neither is written down anywhere:

- a **device-scoped allow** must be visible org-wide, or the Grants nav card (gated on
  `user:read`, per UI-INVENTORY.md §2) would be absent for someone who can in fact read grants on
  one machine;
- a **device-scoped deny** must **not** be promoted org-wide, or Acme's viewer — who is denied
  `device:view` on the lobby kiosk and allowed it on four other machines — would resolve
  `device:view` to *deny* at org level, which is a lie about a permission they demonstrably hold.

That is an asymmetry: allows travel up, denies stay down. I do not like it, and I could not
construct a case where the alternative is better. What convinced me it is right is a
self-consistency property, which I then wrote a test for
(`scripts/check-seams.js`, "org-level gating and org-level authorisation cannot disagree"):
`GET /auth/me` hands the console one org-level set to gate navigation on, and the org-level
endpoints authorise with the same org-level question. If the console's answer and the endpoint's
answer came from different sets, the console would eventually render a card whose endpoint
refuses — or hide a card whose endpoint allows. Same set, same instant, same function: the two
cannot drift. Pinned at 8 permissions × can/assertCan agreement.

### A bug my own test found, in code the shipped suite was happy with

`assertMayGrant` originally reported a `scope_mismatch` when the caller held a permission
org-wide but not on the device being granted. My test asserted that reason and got
`missing_permission` instead. Chasing it:

**`scope_mismatch` is unreachable.** An org-wide allow is collected at *every* device scope — that
is what `decide()` does — so the only way to hold a permission org-wide and not on one device is
a device-scoped deny, which is the `explicit_deny` case. I had written a branch for a state the
engine cannot be in. Deleted, and the reason now comes from the resolution verdict itself, so a
laundering attempt blocked by an org-wide deny answers `explicit_deny` and **names the grant that
has to be revoked first** — which is a thing the caller can go and do. `PERMISSIONS.md §5` lists
`scope_mismatch` as a reason code; under §3's algorithm it cannot occur. Written up in
DECISIONS.md rather than left in as decoration.

### Three tests of mine were wrong, and one was wrong in an interesting way

Worth recording because two of them would have shipped as false confidence:

1. I asserted a `foreign_keys`-off probe would let a nonsense permission through. It came back
   `refused` — because my probe had no `grants` row, so the `grant_id` FK fired first and the
   test passed **for the wrong reason**. A green assertion that was never testing its subject.
   Fixed by inserting a real grant, and the trap now demonstrates properly: `device:teleport`
   inserts with the pragma off, is refused with it on, and `device:*` still inserts.
2. I asserted a `memberships.role` pointing at a nonexistent role resolves to an empty baseline.
   It cannot: `role REFERENCES roles(key)`, so the write is refused. I had planned a defensive
   branch in the engine for a state the schema forbids — untestable, therefore worthless. The
   test now asserts the FK instead, which is the guarantee I am actually leaning on.
3. I expected four forged tokens to be rejected by the token parser. Three of them are correctly
   signed, so accepting them is right: `pv: -1`, `exp: 9e15`, and `org: "../../org_globex"`. The
   parser answers "is this authentic and well-formed"; `context.js` answers "does it still
   describe a real (user, org) pair". The tests now assert the outcome instead of the layer, and
   the traversal case is worth having as a written property: the `org` claim is only ever used as
   a **bound parameter**, so `../../org_globex` cannot reach outside — it just fails to match.

### Measured, not assumed: the exclusive-session race

better-sqlite3 is synchronous, so a loop in one process cannot interleave two transactions and
proves nothing about D10. `scripts/check-seams.js` forks **8 processes** that all try to take
`dev_lab_mac_01` at once, against one file-backed database:

```
8 processes raced for dev_lab_mac_01: 1 won, 7 refused
losers reported SQLITE_CONSTRAINT_UNIQUE (not SQLITE_BUSY)
the raced database holds exactly one active exclusive session
```

One winner, seven refusals, no `SQLITE_BUSY` anywhere — which is what `busy_timeout = 5000` plus
WAL is for. I did not write a line of application code for this; the partial unique index
`one_exclusive_session_per_device` is the entire implementation, and the route only has to
translate the constraint error into `409 DEVICE_BUSY`.

### Offboard/rehire, which the schema answers and I had not thought about

`grants` reference `(org_id, user_id)`, **not** the membership. So a removed member's grants
survive their removal, and re-inviting them restores the grants they had before they left —
including the deny that was on them. Verified both directions: removed → `not_a_member` on every
scope including their granted device; re-hired → baseline and both grants back; re-hired as a
*different* role → the baseline follows the membership, the grants do not. Not a bug, and not my
choice — a consequence of where the schema hangs authority. It is the kind of thing that should
be a product decision, so it is going in DECISIONS.md.

### Non-members: one word or three

`suspended`, `invited` and `removed` are three states and `resolve()` has to say something for
each. I report `suspended` for suspended — the console has to be able to say "suspended" rather
than "not a member", because one is reversible and the other is not — and `not_a_member` for
both `invited` and `removed`. A third word would only give the console something to say that is
not true: a removed member is not a member, full stop. The resolver reads the status from the
database rather than from a list, so a status the schema gains later needs no change here.

### On caching, since the brief asks

The cache scope is **one request**. `createResolver` reads the catalogue, the baseline and every
live grant once, and `authenticate()` builds exactly one per request and hands it to the routes
as `ctx.resolver`. It cannot serve stale authority because it does not outlive the request that
created it — there is no window in which a revoked grant, a lapsed `starts_at`/`expires_at`
window (D7), or a role change could be answered from a previous request's conclusion. Freshness
across requests is `perm_version`, checked in `context.js` on every single one. The alternative
I rejected is a process-wide cache keyed by `(userId, orgId)` with a short TTL: it is faster
still, and it is the thing `AUTH-DATA-MODEL.md §3(2)` warns about by name, because a TTL is a
window in which a revocation is not yet true.

## 2026-09-26 · Phase 3 — orgs, members, invites

Fourteen endpoints and three genuine design decisions, of which one is a place the documents
contradict themselves and one is a hole I only found by writing the test.

### The documents' modification table and the shipped test disagree, and both cannot be right

`PERMISSIONS.md §6` gives the table as:

| Attempt | Result |
|---|---|
| modify a user of strictly lower role | allowed |
| modify a user of equal role (admin → admin) | `403` |

I implemented that as `targetRank < callerRank`, and `scripts/check-api.js:150` failed: it has
**dana (owner) demote usr_acme_owner (also owner) in a two-owner org, and expects 200**. Taken
literally, "strictly lower" makes owner → owner a 403, so the table and the test are in
contradiction. The rule that satisfies both is two clauses rather than one: strictly lower is
allowed, and *equal is allowed when the caller is an owner*. Owners are peers by definition, and
an org that cannot demote one of its owners has no way to change its own ownership.

I caught this one by reading the test before running it, which is not the same as the tests
catching it — so I wrote a test for it too, and the assertion now names both halves.

The same reconciliation produced `assertRoleAssignable` for free: "assign `owner` unless you are
an owner" is just `rank(newRole) <= rank(callerRole)`, because `owner` holds the top rank. An admin
assigning `admin` is fine; an admin assigning `owner` is 403. One comparison, two rules.

### The invite lifecycle is computed, never stored

There is no status column on `invites`. An invite is live when
`accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now`, and the partial unique index
`one_live_invite_per_email` keys off only the first two — so an **expired** invite does not block a
fresh one for the same address. My first instinct was to add an application-level "is there
already an invite?" check before inserting, and then not to: it would have had to reproduce that
three-part rule, and any drift between my check and the index would be a race the index then had
to clean up. The route does the insert and lets the index refuse, translating the error into a 409
with a sentence. Check-then-act loses; let the constraint win.

### A hole the documents do not mention: who can join an org that already has their address

An invite is the only way in (D14), and the accept route is public. So: an existing user accepts
an invite for a second org. The obvious implementation asks for a name and password and either
(a) overwrites the existing user's password, which is an unauthenticated password reset, or
(b) creates a second user row, which the `users.email` unique index refuses.

I did not see this until I wrote the offboard/rehire test, and it is worse than it looks: a person
who has been **removed from their only organization cannot sign in at all** (login requires an
active membership, because a token must be scoped to an org), so the authenticated path is
unreachable for exactly the person who most needs to redeem a re-invite.

Three cases now, and the third is the one I had missed:

| who | what happens |
|---|---|
| signed in, and it is their address | the org is attached to the account they hold |
| signed out, address is new | an account is created with the password given |
| signed out, address is taken | **the existing password re-authenticates them** |

The third is not a password reset and must not become one: the link proves the *invite*, the
password proves the *person*, and nothing about the stored credential changes. A wrong password
gets the same generic refusal a sign-in would. `scripts/check-http-seams.js` asserts all three,
including that the old password still works afterwards.

### Denied, or invisible? The two invites endpoints answer differently

`GET /v1/invites/:token` on a spent token is **410 GONE**; `POST .../accept` on the same token is
**409 CONFLICT**. Same state, two verbs, two different questions: the GET is *describing* a
resource that no longer exists, the POST is *conflicting* with the current state of one that does.
`check-api.js:178` pins the 409, and I had to make the GET's 410 a deliberate choice rather than an
accident of sharing one helper.

---

## 2026-09-26 · Phase 4 — devices and grants

### Where a grant's scope and the question's scope differ

Two cases the documents do not resolve, both of which I had a wrong prior on.

**A device-scoped `allow` of a permission nobody holds org-wide.** The compound session check
needs `session:start` *and* the mode permission, and `assertMayGrant` needs the caller to hold
everything being granted, at that scope. So granting `device:terminal` to a viewer on one device
requires the *granter* to hold `device:terminal` on that device — which for an owner they do not
unless someone granted it to them first. I expected this to be unusable in practice. It is not: the
owner grants it once, and now the owner holds it at that scope and can pass it on. The rule is
self-consistent, which is the only reason I trust it.

**A wildcard that contains a permission you lack.** `device:*` names seven permissions. If the
caller holds six, is the seventh enough to refuse? I wrote the check by expanding the pattern
against the catalogue and testing every permission it covers, so yes — and the reason is the one
that matters: an admin carrying an org-wide `deny device:terminal` must not be able to hand
`device:terminal` to anyone by naming a wider bundle. The test asserts `device:*` and a bare `*`
are both refused for exactly that caller.

### D19: I could not implement it the way the document describes, and the reason is better-sqlite3

`PERMISSIONS.md §4` says the foreign key rejects a typo and "you don't reimplement this". True —
and then unusable, because to turn the FK's error into a 400 I need to know *which* FK fired. I
wrote the translation to match on the error text:

```js
if (/grant_permissions/.test(message) && /permission/.test(message)) ...
```

and every unknown-permission grant came back **500**. Measured, in a throwaway script:

```
bad permission -> SQLITE_CONSTRAINT_FOREIGNKEY | "FOREIGN KEY constraint failed"
bad grant id   -> SQLITE_CONSTRAINT_FOREIGNKEY | "FOREIGN KEY constraint failed"
```

Identical strings. better-sqlite3 reports the bare message with no table and no column, so there
is no text to match and my check could never fire. The FK is still the only thing enforcing the
rule; all I do afterwards is ask `permission_patterns` which value it objected to, so the 400 can
name it. That is a diagnosis, not a second implementation — and it is the difference between a
typo being a 400 a caller can act on and a typo being a 500.

The same trap bit me in the test suite: my first "foreign_keys off" probe inserted a
`grant_permissions` row with **no parent grant**, so the `grant_id` FK fired first and the test
passed for the wrong reason. It needed a real `grants` row to demonstrate the actual trap.

---

## 2026-09-26 · Phase 5 — sessions

### The compound check, and the order that keeps the two reasons apart

`assertCanStartSession` tests `session:start` **first**, then the mode permission, and the refusal
reason differs: `missing_permission` versus `missing_device_permission`. Order is the whole design
here, and it is not arbitrary — "you cannot open sessions at all" and "not on this device" are
different problems, and a caller who is told the wrong one will go looking in the wrong place. The
shipped suite pins both (`check-permissions.js:121-123`), and the fixture is built so both are
reachable: the Acme viewer has `session:start` on one device and not another.

### The one place I over-read the documents, in the direction of extra safety

`device:view` decides whether a device is **in the list response** (§4). I first also gated
`POST /sessions` on it, reasoning that you should not be able to open a session against a machine
you cannot see. Then I read §5.1's table again:

> `POST /v1/orgs/{org}/sessions` | `session:start` **and** the mode permission

No `device:view`. And the grant that makes a device-scoped `device:control` meaningful stops being
usable if the same person is denied `device:view` on that device. So I removed the gate. The
endpoint table is the contract for *endpoints*; §4's sentence is about *list responses*, and I had
let one leak into the other. Written up in DECISIONS.md.

### D10 needs no application code at all, and proving that took processes

The partial unique index `one_exclusive_session_per_device` is the entire implementation. The route
only translates the constraint error into `409 DEVICE_BUSY` and adds the holder's session id, so
the refusal is actionable.

Testing it honestly needed real concurrency. better-sqlite3 is synchronous, so a loop in one
process cannot interleave two transactions — my first attempt would have passed whatever I wrote,
because the interleaving it claims to test cannot occur. Two tests instead:

- `scripts/check-seams.js` forks **8 processes** against one file-backed database
- `scripts/check-http-seams.js` fires **8 parallel HTTP requests** at a real server

```
8 processes raced for dev_lab_mac_01: 1 won, 7 refused
losers reported SQLITE_CONSTRAINT_UNIQUE (not SQLITE_BUSY)
8 simultaneous starts: 1x 201, 7x 409 DEVICE_BUSY, 0x other, 0x 500
5 concurrent VIEW sessions on the busy device: 5x 201
```

One winner every time, and no `SQLITE_BUSY` anywhere — which is what `busy_timeout = 5000` plus
WAL is for. **Zero lines of application code implement D10.**

---

## 2026-09-26 · Phase 6 — audit

### What counts as auditable, decided by asking what the log is for

I settled it on one question: *can this log answer "who tried to change what"?* That requires
denials, and it also draws the line — 403 only.

- **403 is audited.** A real person, in a real org, asking for something they may not have.
- **404 is not.** A 404 is the deliberate absence of information. Writing "someone probed org_x and
  got 404" into a table that `audit:read` holders can read turns the audit trail into a map of what
  exists, which is the exact leak `PERMISSIONS.md §5` spends a paragraph preventing.
- **401 is not.** The request never established who the caller was, so there is no actor to
  attribute it to. And `audit_events.org_id` is `NOT NULL`, so a failed sign-in is not auditable in
  this schema at all — a real limitation, not a choice, and it means "someone tried to log in as our
  admin account" is not answerable from this table.
- **Reads are not.** `audit:read` on a hot list would make the table grow with traffic rather than
  with decisions, and the append-only triggers mean there is no way to prune it afterwards.

`AUDITED_ACTIONS` in `server/audit.js` states the list once, so the decision is made in one place
rather than per route.

### One row per action, and where it is written

The success row goes **inside the same transaction** as the change it describes, written by the
route that makes the change. Not by a wrapper. A wrapper that logs both the attempt and the
success cannot tell you which one committed, and a success row describing a rolled-back transaction
is worse than no row. `auditDenials` is the only wrapper, and it writes *only* the denial.

---

## 2026-09-26 · Phase 7 — the console

### Where the server's answer and my instinct disagreed

**The Grants card.** `UI-INVENTORY.md §2` gates it on `user:read` — the same gate as People. My
instinct said that was a typo for `grant:create`, because a card called Grants obviously belongs to
the people who manage grants. It is not a typo. The catalogue has no `grant:read`, the API gates
`GET /grants` on `user:read`, and an auditor therefore sees the grants table and cannot change it —
which is the correct reading of "read-only". The instinct was about the *label*; the contract is
about the *gate*.

**A device the caller cannot see.** My first instinct was to render the row with its metadata
stripped, on the grounds that showing "kiosk-lobby-01 exists but you cannot open it" is more
informative. It is forbidden, twice: §4 ("never shown with redacted metadata") and the UI suite
(count 4, not 5). Absence is the design. I had to write the filter to drop the row *before*
rendering rather than hide it with CSS, because a hidden row is still in the DOM and still
assertable.

### The four console bugs, and what each one was really

| bug | what it was |
|---|---|
| `signOut is not defined` | a mistyped prop; threw on every render, so nothing mounted |
| `await` inside a `setData` updater | an updater must be pure; esbuild caught it |
| `switchOrg` never stored the token it minted | the switch silently did nothing — `/auth/me` was still asked with the OLD org's token and duly returned the old org |
| `ApiError.human` rewrote the server's message | I had 401 → "Your session has expired", which broke the sign-in contract *and* was exactly the "improving on the server's answer" `UI-INVENTORY.md §4` forbids |

The last one is the one I would have defended in a walkthrough and been wrong about. I had written
a helper whose entire job was to phrase errors nicely, and it was overwriting the server's wording
— including collapsing "invalid email or password" into something that both failed
`tests/ui.spec.js:327` and made a wrong password look like an expired session.

### The catalogued, measured thing

The console has no permission table. The grant form's checkboxes are generated from
`GET /v1/reference`, which reads `permissions` out of the database — so `device:reboot` (which
exists only because of my nonce) appears in the UI as a checkbox with no code change. That
endpoint is not in §5.1's table; adding it was necessary, because the alternative is a second copy
of the catalogue in `web/`, which is the drift the whole design is trying to prevent.

---

## 2026-09-26 · Phase 8 — hardening, and the bugs that only my own tests found

Every suite the organisers shipped was green before I wrote a line of this section, and **all four
bugs below were live in code those suites were passing.**

### 1. A cascade that did nothing, and returned 200

`endActiveSessions` guarded `userId` and `deviceId` with `? IS NULL OR col = ?` and wrote
`org_id = ?` unguarded. Device transfer calls it with only a `deviceId`, because the sessions to
end may be in *either* org — so it compared `org_id = NULL`, which is never true, updated **zero
rows**, and the transfer returned 200 looking like it had worked.

No shipped test transfers a device with a live session on it. `check-http-seams.js` does, and
failed. A silently-inert cascade is worse than no cascade, because the audit row says it happened.

### 2. A green assertion for the wrong reason

```js
const assertUsable = (invite, fail) => {
  if (!isLive(invite) || isExpired(invite)) fail();   // fail() RETURNS an HttpError
  return invite;
};
```

Every `fail` callback in that file *returns* an error rather than throwing it, and I threw the
return value away. So neither the 410 nor the 409 path ever fired and a spent invite sailed
through as though it were live.

`check-api.js:178` asserts the 409 and **passed the entire time** — because the code that actually
fired was `ALREADY_MEMBER`, which is also a 409. I found it only because I happened to assert the
*code* as well as the status. Fix is `throw fail()`, which works whether the callback throws or
returns, and the shipped test now passes for the right reason.

### 3. A removed member could never come back

The "already a member" check on invite creation did not filter on membership status, and a removed
member still has a row. So the one moment the offboard/rehire flow most needs to work — inviting
somebody back — was the one moment it returned 409. Offboard/rehire is a *named* seam in the
organiser README and I had it broken in the direction that matters.

### 4. `x !== null` is true for `undefined`

My own seam helper returned `undefined` for a failed sign-in, and my assertion read
`check('the invitee can sign in', helper !== null, true)` — which **passes for `undefined`**. The
real failure surfaced four lines later as `missing Authorization header` on a session POST, which
is a symptom with nothing to do with the cause. Fixed to return `null` explicitly and to assert
`typeof x === 'string'`. Worth recording because I would have shipped that assertion as evidence.

### Measured, with `scripts/measure.js`

Counting *executed* statements (not prepared ones — the registry compiles each query once per
connection, so counting `prepare` undercounts every endpoint by its number of distinct queries):

| request | statements |
|---|---|
| `GET /devices` (5 devices, per-row permission maps) | **7** |
| `GET /devices` (viewer: 4 visible of 5) | **7** |
| `GET /grants` | 8 |
| `GET /audit?limit=50` | 8 |
| `GET /members` | 7 |
| `GET /auth/me` (console boot) | 10 |
| `GET /devices` in another org (404 path) | 6 |

The device list is 1 membership + 1 user + 1 org liveness + 1 device list + catalogue + baseline +
grants. A per-device resolution loop would be 8 for five devices and would grow with the org; this
is 7 for nine devices and would grow only when the device row itself grows.

Latency, over real HTTP against the production server, 40 runs:

```
  1.6 ms p50   1.8 ms p95   GET  /auth/me               (console boot)
  1.6 ms p50   2.0 ms p95   GET  /orgs/:o/devices       (the first screen)
  1.6 ms p50   1.9 ms p95   GET  /orgs/:o/audit?limit=50
 34.3 ms p50  36.6 ms p95   POST /auth/login            (scrypt password verify)
```

Sign-in is 22x everything else, and it is entirely `scryptSync` in the given `auth.js`. That is
the right place for the cost to be — it is the only thing in the system that is meant to be
expensive — and it is why I did not add rate limiting or a login attempt counter (both listed as
out of scope anyway): the hash is already the floor.

### Playwright's CDN is unreachable from this machine

`npx playwright install chromium` times out after 30s against `cdn.playwright.dev`, so the UI suite
could not run at all. Google Chrome *is* installed, so I added `playwright.local.config.js`: it
imports the **shipped** `playwright.config.js` unchanged and overrides one thing, which browser
binary the `chromium` project uses. It is gitignored, so the repository contains the harness
exactly as it was issued, and `npx playwright install chromium && npx playwright test` is all
anyone with network access needs. I mention it because the alternative — editing the shipped
config — would have made the graded test run non-reproducible, and because "the suite did not run"
is otherwise indistinguishable from "the suite passed".

### What I measured that changed nothing, and left alone

I looked for a place where a process-wide permission cache would pay, and could not find one: 7
statements and 1.6 ms means there is no hot path to cache. The per-request resolver stays, and the
argument for it is now a measurement rather than a precaution.

## 2026-09-26 · Phase 9 — an audit of my own code, after reading other people's

The plan for this phase came from an odd source. I was asked to compare my submission against three
other teams' public submissions and find what they had that I did not. I expected a feature list.
What I got instead was the opposite: my route surface is a strict superset of all three, my five
shipped test files are byte-identical to theirs, and of the twenty invariants in the one suite any
of them wrote that I do not have, my build already passed eighteen. One competitor submitted an
unmodified stub.

So the useful move was not to read theirs. It was to point two adversarial agents at **my** code
and tell them to break it. Thirty-eight findings came back — five critical, twelve major, twenty-one
minor — and the first three are the subject of this entry, because they are the worst kind of bug:
each one is a control I wrote a comment *claiming* works, and which does nothing at all.

### 1. One unauthenticated request killed the server

`server/index.js` shipped with `serveStatic`, and its first line was
`normalize(decodeURIComponent(url.pathname))`. `decodeURIComponent` **throws** `URIError` on a
malformed escape. I had read that line, and read it as obviously-fine, because the `%` in a URL is
something you decode and move on from.

```
$ curl 'http://localhost:8391/%ff'
curl rc=52
$ curl localhost:8391/v1/auth/me
CONNECTION REFUSED
$ lsof -ti:8391 | wc -l
0
```

No token, no valid route, one request, and the process is gone — no supervisor under `npm start`.
This is a denial of service on the exact process the live walkthrough is run against, and it came
from **given code**, which is why the twelve shipped assertions never found it. They test the
engine, and the engine is fine; the engine is not what crashed.

Fixed by guarding the decode and returning `400 VALIDATION` for a malformed path, plus a
last-resort `uncaughtException` / `unhandledRejection` net that logs and keeps serving. I argued
myself into the net reluctantly: swallowing exceptions is normally wrong, and this is not a licence
to ignore them. The argument for it is that SQLite is synchronous, so a throw inside a handler
cannot leave a transaction half-applied — the state really is intact — and the cost of being wrong
in this direction is a server that never comes back.

The assertion that actually pins the bug is not the 400. It is the next line: *and the server is
still serving*. A test that only checks the status code would have passed against the crashing
version, because the crash also means no status code.

### 2. The refresh-replay defence was decorative

`server/routes/auth.js` — the comment, verbatim, on the branch that handles a replayed token:

> *"reuse of an already-rotated token means the cookie leaked: kill the whole family, so the attacker
> and the victim both lose the lineage"*

And `issueFor` mints `newId('fam')` on **every** issue, including every rotation. A family is a
family of one. `revokeFamily` updates `WHERE family_id = ?` and matches the one row that is already
revoked — zero rows changed, and the control is inert. Verified end to end:

```
login                    200   cookie1
refresh(cookie1)         200   cookie2 (rotated)
REPLAY cookie1           401   <- detection fires, as designed
refresh(cookie2)         200   <- and the new lineage is STILL ALIVE
```

That last line is the bug. Detection worked; the consequence did not. An attacker who burns the
stolen token *triggers* my detection and keeps a working session. And my `BUILD-LOG.md` and
`DECISIONS.md` both repeat the false claim, which is worse than the bug: a reviewer reads the
write-up, believes the control works, and never looks.

**This is the finding I would open in the walkthrough**, because the shape of it is the lesson: I
tested that the refusal happened and never tested what the refusal was *for*.

### 3. Sign-out was cosmetic, and a reload undid it

`PUBLIC_ROUTES` in `server/index.js` lists the four unauthenticated endpoints. `POST /auth/logout`
is not among them, so it requires a bearer token — and `web/api.js` calls it with `{ auth: false }`,
sending no `Authorization` header at all. The route was unreachable from the only client that calls
it, and the console discarded the failure in a bare `catch {}`.

```
login                    200   cookie set
logout (no Authorization)      401   <- what the console actually sends
refresh after logout      200        <- still signed in
```

So: sign in, click Sign out, press F5, and the console comes back. The one control whose entire
job is to end the session did not end it. The fix is one line — the cookie *is* the credential, so
the route belongs in `PUBLIC_ROUTES` — and it is in the next commit with the family fix, because
both are about the same thing: I never verified that a security control had a *consequence*.

### The fixes, and the tests that would have caught them

Both of these are now pinned by assertions about the **consequence** rather than the response:

```
A rotates into B                                  ok
B rotates into C — C is the live, unspent tip     ok
replaying a spent ancestor is refused             ok    401
  ...and the WHOLE family is revoked              ok    was 200
  ...reported as a used token                     ok
a new sign-in still works (families are per-lineage, not per-user)   ok
logout needs no bearer token (the cookie is the credential)          ok    204, was 401
  ...and the session is gone afterwards            ok    was 200
  ...including a token rotated out of the same family                 ok
```

I wrote that block wrong twice before it passed, and both failures are the same mistake: I asserted
on a cookie I had already spent. Every refresh *consumes* the token it is given, so the lineage is a
chain — A → B → C, with only the tip live — and a test that refreshes with C and then checks C is
asserting about a dead token. A test that cannot fail is not evidence, which is the sentence this
whole phase keeps arriving at.

`POST /auth/logout` is now in `PUBLIC_ROUTES` (the cookie is the credential, so signing out must
work without a bearer token), revokes the whole **family** rather than one row, and returns **204**
because there is nothing to say. The console no longer swallows a failed sign-out in a bare
`catch {}` — if the server cannot be reached it says so on the gate, because a sign-out that
silently fails is the one failure a user cannot detect for themselves.

### 4. One rule, two answers, because I wrote it on one route and not the other

`PERMISSIONS.md §6` is about *modifying a user*, not about a particular verb. I had implemented it
on the role-change route and not on suspend/reinstate, and never noticed, because no shipped test
suspends anybody of a higher rank. An audit did:

```
admin POST   /orgs/org_acme/members/usr_dana/suspend    -> 200   (usr_dana is the OWNER)
admin PATCH  /orgs/org_acme/members/usr_dana {"role":…} -> 403   a admin cannot modify a owner
```

Same caller, same target, same question, two answers — and the 200 also ended the org owner's live
sessions with `user_suspended`. `assertCanModify` is now called on the suspend path, and the test
asserts the thing that actually matters: **both verbs agree.** A rule enforced on one route and not
its sibling is not a rule, it is a coincidence that happens to hold on the paths someone tested.

### 5. Removal is not a pause

Reinstatement wrote `status = 'active'` unconditionally, without looking at what the status had
been. So a `removed` membership could be walked back in: no invite, no role check — and because
grants hang off `(org, user)`, **every grant they had before they left came back too**, including
the deny that existed to stop them. `AUTH-DATA-MODEL.md` is explicit that invites are the only way
in (D14) and that users are never deleted (D15); a `reinstate` verb that undoes a removal without
an invite is a third way in that nobody sanctioned.

Reinstatement now revives a `suspended` membership and refuses anything else, with a 409 that says
which. The only way back from removal is an invite, and the test walks the whole loop: remove →
reinstate refused → still out → invite → redeem → new role applied.

### 6. A grant staged for someone who cannot use it

`AUTH-DATA-MODEL.md §8` says a grant's `userId` must be "an **active** member of this org → 404".
I had excluded only `removed`, so a grant could be attached to a `suspended` or a not-yet-accepted
`invited` membership — authority with nobody to use it, pre-loaded for the moment they came back.
Now only `active` is accepted.

### 7. A row filter, undone by the field next to it

`GET /devices` filtered correctly — a device the caller cannot `device:view` is genuinely absent
from `devices` — and then returned `total: devices.length`, the **unfiltered** count. So a viewer
received 4 rows and was told there were 5, which discloses exactly how many machines they cannot
see. It is the same rule as "absence is not redaction", defeated in one field, one line below the
code that got it right.

This is the finding I keep coming back to. The row filter was right. The `total` was wrong. Both
were in the same three lines, and the audit that found it read the object rather than the filter.

### 8. An information leak I wrote a comment defending

The device-transfer route took a `toOrgId` from the body — an org id the caller could name freely —
and answered `403` for an org that exists and `404` for one that does not:

```
toOrgId=org_globex            -> 403   you hold device:provision nowhere in there
toOrgId=org_nonexistent_zzz   -> 404   no such org
```

Walk the id space and you enumerate every organization in the deployment, plus its soft-delete
state, from one org you legitimately belong to. And the comment I had written argued **for** the
403 — I wrote that a 404 "would confirm the org exists", which is word-for-word the reasoning
`PERMISSIONS.md §5` rejects. I did not misread the rule; I restated it, inverted, and agreed with
myself.

Both branches are now the same 404, because the honest question is not "does this org exist" but
"can you address it" — and membership is part of being able to. The test asserts the two responses
match by status **and by body**, since a different `message` between the two cases is the same leak
in a different field.

Writing the test also caught a mistake in the test: my first version transferred to an org that the
same owner had created, so the transfer legitimately succeeded and the assertion failed against a
leak that was not present. The destination is now created by a different account.

### A crash I introduced fixing the above, which the test caught immediately

The `reinstate` guard calls `conflict()`, and I had removed that from the import list in Phase 3
while tidying unused imports — so it was a `ReferenceError` and a `500`. Caught on the first run of
the new tests, which is the argument for writing the test in the same commit as the fix: the fix
and its regression test were never both green at the same time otherwise.

### 9. The half of the presence rule nobody notices is missing

`UI-INVENTORY.md §1` says a rendered gated element carries `data-permission` and
`data-state="unlocked"`. I had **eight** elements that were correctly present-or-absent and carried
neither. The presence was right, which is why the shipped suite passed and why I never looked: it
asserts `[data-permission="device:control"]` inside a device row, and the two places that matter
most happened to be annotated.

The fix is structural rather than eight edits. `IfAllowed` now attaches the attributes by cloning
its child, so a ninth cannot be added without them. And writing the test for it immediately paid for
itself twice:

- **`cloneElement` cannot reach inside a composite.** `role-select` was wrapped in `IfAllowed` in
  the parent, so the attributes were cloned onto the `<RolePicker>` *component*, which drops props
  it does not forward — the `<select>` rendered with no attributes at all. `RolePicker` now gates
  itself, so the clone lands on a host element. **A wrapper that annotates its child is only a
  guarantee about host elements**, and I had assumed it was a guarantee about all of them.
- **Six device buttons had no `data-testid` at all.** `start-view`, `start-control`,
  `start-terminal`, `transfer-files`, `rename-device`, `decommission-device` are named in the
  inventory; I had implemented the permission gating and the provenance and never the test ids, so
  the six entries were unaddressable by the contract. `suspend-user` and `remove-user` were the same.

Both were found by `tests/contract.spec.js`, which asserts the attributes on the **rendered DOM**
against a table transcribed from `UI-INVENTORY.md` rather than from my own components — so the
inventory and the console cannot drift without a test failing.

I also had to fix the test twice before it was worth having. `test.skip()` inside a loop skips the
**whole test**, not the one assertion, so my first version skipped itself and never ran a single
check while reporting as a skip. And my "nothing should be absent" assertion was nonsense: a
`device-row` is not supposed to appear on the People card. It now checks each element on its own
card and asserts how many checks ran, so a console that stopped rendering entirely cannot pass by
asserting nothing.

`session-row` also overloaded `data-state` for the session *lifecycle* while `data-state` means
`unlocked` everywhere else in the console. One attribute, two meanings, and a selector like
`[data-state="unlocked"]` scoped to a card would quietly match the wrong thing. The lifecycle moved
to `data-session-state`.

### The pattern across all three

Every one is a check I ran, and none of them was a check that could fail. I asserted the 401 and
did not assert that the token died. I asserted the 400 and did not assert that the process lived.
I asserted the sign-out and did not reload. A test that cannot fail is not evidence, and the tell
is always the same: **the assertion stops one step short of the thing you actually care about.**

### Four more of the same shape, from the same audit

- `GET /v1/orgs/{org}/devices` returned `total: 5` to a caller who received **4 rows** — the row
  filter was correct and then `total` undid it, telling the viewer exactly how many machines they
  cannot see. A real information leak, sitting one field away from code that was right.
- Suspending a member never called `assertCanModify`, so an **admin suspended the org owner** —
  while changing that same owner's *role* correctly returned 403. Two answers to the same question
  from two routes.
- The device-transfer route returned 403 for an org you belong to and 404 for one you do not, so
  the id space distinguishes "exists" from "does not exist". `PERMISSIONS.md §5` forbids exactly
  this in a paragraph.
- `POST /auth/refresh` re-scopes to the alphabetically-first org, so refreshing can hand back a
  credential for a *different organization* than the one you were in. I had written this up as a
  harmless schema consequence; it is a credential-scope change, which is a different category.

## Open threads

Things I know are wrong, unfinished, or that I would do differently. Listed honestly because they
would be found anyway, and because the shape of what I left out is part of the judgement.

### Known limitations, in the order I would fix them

1. **The UI suite has flaked once and I could not attribute it.** `an element vanishes when the
   server withdraws the permission` failed on one full run out of five and passed on the other four
   and in isolation. My best theory is a request-ordering effect between two in-flight `load()`
   calls when two nav items are clicked quickly; I removed one duplicate-fetch path while chasing
   it (the `permissions` dependency in `load`) but never proved the cause. With another day I would
   add a request-generation counter and drop stale responses, which removes the whole class.

2. **A reload always returns you to your default org.** `refresh_tokens` has no org column, so
   `POST /auth/refresh` cannot know which org you were in and re-issues for the alphabetically
   first active membership. `GET /auth/me` and `POST /auth/token` return the org, so a *switch* is
   remembered for the life of the page, but a reload drops it. The console masks it by re-issuing
   immediately. The alternative was a second, client-readable cookie holding the org, which is
   client-controlled state and exactly what D18 argues against — so I left the schema's shape
   visible rather than papered over it.

3. **Audit pagination is the one place I guessed a boundary.** `limit` is capped at 1000 and
   defaults to 50. `check-api.js:189` pins that `0`, `-1` and `99999` are 400s and that a huge
   `offset` is a 200 with an empty page, so the *shape* is right, but 1000 is my number. Nothing
   states a maximum. If a hidden tier uses `limit=5000` expecting 200, that is where it breaks.

4. **`decodeSegment` requires a JSON *object* for the payload.** A token whose payload were a
   legitimate non-object could not exist, since `issueAccessToken` always writes an object, so this
   is safe — but it is stricter than the specification requires and I would rather know why than
   assume.

5. **Reads are not audited, and a session list is a read.** So "who has been watching this session"
   is not answerable. I think that is right (the table would grow with traffic and cannot be
   pruned) and I would defend it, but it is a product question rather than a technical one.

6. **No `grant:read` means the Grants card is gated on `user:read`.** An auditor sees every grant
   in the org, including grants aimed at people they cannot otherwise see the detail of. That
   follows from the catalogue, not from me, and the fix would be a new permission — which is a
   reference-data change nobody asked for.

7. **Cross-org transfer leaves the source org's device-scoped grants in place.** They are inert
   (a question in that org can no longer name the device) and they revive if the device comes
   back. Defensible, argued in DECISIONS.md, and a product owner might disagree.

8. **The transfer route resolves authority in the destination org directly**, from the caller's
   membership, because their token only speaks for the source. That is a genuine cross-org
   authorisation and it is the only one in the system. It is worth being aware of when reading
   `server/routes/devices.js`.

### What I would do with another day, in priority order

- Request-generation guarding in the console (removes limitation 1 entirely).
- A `sessions` list that paginates. `GET /sessions` returns every session in the org and has done
  so since phase 5; at 10k sessions that response stops being reasonable, and the audit endpoint's
  `limit`/`offset` machinery is already written and tested.
- Server-side filtering on the grants table (effect, target, scope). I left it out because the
  fixture has four grants and the console shows them all; a filter nobody needs is a filter with
  bugs in it.
- A test that the console renders the **personalised** org correctly — my UI suite work used the
  shipped fixture's accounts throughout, and while `check-personalisation.js` proves the engine,
  nothing yet proves the console *renders* an undocumented role and permission. That is the one
  gap between "my engine is correct" and "my product is correct on the graded fixture".
