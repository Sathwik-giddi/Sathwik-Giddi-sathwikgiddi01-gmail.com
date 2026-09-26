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

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

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
