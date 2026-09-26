# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

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

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
