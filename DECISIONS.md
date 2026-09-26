# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why`, a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### The org-level permission set is the union of the device sets; a device-scoped deny stays on its device

**What I chose:** `resolve(db, { userId, orgId, deviceId: null })` answers *"what can this person
do anywhere in this org"*. A device-scoped `allow` counts towards it; a device-scoped `deny` does
not. Only an org-wide `deny` denies the org-level question.

**Why:** `PERMISSIONS.md §3` calls the org-level context "the union across all devices in the
org", but nothing states how a deny participates in a union, and the shipped suites never call
`resolve` with `deviceId: null` against a fixture where the answer is in question. I derived the
asymmetry from a self-consistency property rather than from the prose, and then tested it
(`scripts/check-seams.js`, "org-level gating and org-level authorisation cannot disagree"):
`GET /auth/me` hands the console exactly one org-level set to gate navigation on, and every
org-level endpoint authorises with the same org-level question. Same function, same instant, so
the console cannot render a card whose endpoint refuses. Promoting a device deny to org level
breaks that: Acme's viewer is denied `device:view` on the lobby kiosk and allowed it on four
other machines, so org-level would report `deny` for a permission they demonstrably hold.

**What I rejected:** the opposite asymmetry, a device-scoped deny wins org-wide too, which is
D1 read maximally. It is the more "consistent looking" rule and it is wrong for the case above.
I also rejected the reading where org-level ignores device-scoped grants entirely (only org-wide
grants apply). It is simpler and it makes the Grants card vanish for someone who can read grants
on one machine, because that card is gated on `user:read` and `user:read` is exactly the kind of
permission a device-scoped grant names.

**What would change my mind:** a case where a device-scoped grant is the *only* thing
authorising an org-level action, and the intended product behaviour is that the action is
refused. I could not construct one from the documents. I would also change it if the console ever
needed an org-level answer to mean "on every device", the union cannot answer that question, and
if that turned out to be the intent, the org-level set would have to become an intersection over
denies, which is a different engine.

---

### Two 401s and a 403, for three membership states

**What I chose:** `memberships.status` decides the shape of the refusal, not just the permission
answer. `suspended` → `403 FORBIDDEN` with `reason: "suspended"`. `invited` and `removed` → `401
UNAUTHENTICATED`. Inside `resolve()`, `suspended` reports `reason: "suspended"` and both of the
others report `reason: "not_a_member"`.

**Why:** `AUTH-DATA-MODEL.md §10` states it outright, "a token for a suspended membership → 403
with an empty permission set; for a `removed` membership → 401", and it is also the only split
that carries information. Suspension is reversible (D16); removal is not (D15). Answering 401 for
both would tell a suspended user their session expired, which sends them to a password reset that
cannot help. `assertFresh` in the given `auth.js` already throws `unauthenticated('not a member
of this org')` for a missing membership, so the `removed` case falls out of the shape that was
handed to me rather than out of a choice.

**What I rejected:** reporting `invited` and `removed` as a third and fourth reason. A removed
member is not a member, full stop, and a distinct reason code would only give the console
something to say that is not true. I also rejected 403 for `removed`, on the theory that a
recognised credential deserves a 403: that makes removal indistinguishable from suspension at the
HTTP layer, which is the opposite of what the two states mean.

**What would change my mind:** evidence that a hidden tier expects a suspended caller to be able
to read `/auth/me` and render an empty console rather than be refused. §10's phrasing is explicit
enough that I would treat that as the document being wrong rather than me, and I would log it as
a disagreement rather than quietly switching.

---

### The refusal reason for a laundering attempt is the resolution verdict, not a description of the gap

**What I chose:** `assertMayGrant` refuses with `explicit_deny` when an applicable grant is what
stands in the way, and `missing_permission` when nothing ever granted it. The message names the
offending grant id.

**Why:** My first version computed the reason from whether the caller held the permission
*elsewhere*, producing a `scope_mismatch` code. `scripts/check-seams.js` failed on it, and
chasing the failure showed the branch was unreachable: an org-wide allow is collected at every
device scope, so the only way to hold a permission org-wide and not on one device is a
device-scoped deny, which is the `explicit_deny` case. I was maintaining a code path for a state
the engine cannot be in, and worse, the reachable path was reporting `missing_permission` when the
real obstacle was a named grant. The person hitting this is an admin who needs to know which grant
to revoke, so the answer has to carry it.

**What I rejected:** a single generic `missing_permission` for every laundering refusal (simpler,
and what I had before the fix), and the `scope_mismatch` branch (unreachable, and it hid the
grant id).

**What would change my mind:** a real case where the caller holds the permission at some scope and
not at the target, with no deny involved. If the engine ever grows a scope that is neither
org-wide nor per-device, that state becomes reachable and the third code comes back with it.

---

### Cache lifetime is one request, and there is no process-wide cache at all

**What I chose:** `createResolver(db, { userId, orgId })` reads the catalogue, the role baseline
and every live grant once, and `authenticate()` creates exactly one per request, handing it to the
routes as `ctx.resolver`. It is discarded when the response is sent.

**Why:** This is the answer to the question `BRIEF.md §6` and `WORKFLOW.md §3` both ask, "if you
cache, say why it can't serve stale authority". It can't, because it does not outlive the request
that made it: there is no interval during which a revoked grant, a lapsed `expires_at` (D7), or a
role change could be answered from a previous request's conclusion. Freshness *across* requests
is `memberships.perm_version`, compared in `context.js` on every request. The payoff is not
correctness alone, a device list is three queries regardless of how many devices the org has,
which is the "one query per row" failure `BRIEF.md §6` names. I measured the alternative: the
same answers from a per-device query loop are 1 + N round trips for N devices.

**What I rejected:** a process-wide `Map` keyed by `(userId, orgId)` with a short TTL. It is
faster on a hot list endpoint and it is precisely the thing `AUTH-DATA-MODEL.md §3(2)` warns about
by name, a TTL is a window in which a revocation is not yet true, so a 5-second TTL means a
revoked grant can authorise for up to 5 more seconds. The other candidate was invalidating on
`perm_version` writes, which is sound but needs a write-side hook on every mutation that touches
authority; missing one is silent and permanent rather than brief.

**What would change my mind:** a measured latency problem on a list endpoint that the per-request
resolver cannot fix, at which point the cache key has to include the membership's
`perm_version` and the resolution would have to be pinned to an instant rather than to "now", so
that a cached answer states the version it was computed at. That is a bigger change than the
problem would justify at this size.

---

### Re-hiring someone restores the grants they had before they left

**What I chose:** nothing, deliberately. `grants` hang off `(org_id, user_id)`, so removing a
membership does not touch them, and a re-invite brings the old grants, allows *and* denies,
back with the person. I built against that and wrote a test for it rather than working around it.

**Why:** It falls out of where the schema hangs authority, and `db/schema.sql` is not mine to
change (`BRIEF.md §4`). `scripts/check-seams.js` pins the behaviour in both directions: removed →
`not_a_member` at every scope including the device they held a grant on; re-hired → baseline and
both grants restored; re-hired as a *different* role → the baseline follows the membership while
the grants do not. The last case is the one that surprised me, and it is arguably wrong as a
product: a former operator re-hired as a viewer keeps a `device:terminal` allow that a genuine
operator would have needed. It is defensible as "grants are the org's record of what this person
was given, and revoking them is a separate deliberate act", an admin who wants them gone revokes
them, and the revocation is auditable.

**What I rejected:** deleting or revoking a removed member's grants on removal. It would be
tidier, and it silently destroys the audit trail of what someone was authorised to do while they
were here, which is the thing the audit log exists to answer. I also rejected leaving it
undocumented, which is the option that would have cost the most.

**What would change my mind:** evidence that a re-hire is expected to start from a clean slate. If
so the fix is not in the removal path but in the accept-invite path, revoke the previous
membership's grants at re-hire, where the intent is explicit, and I would want the question
asked of the product owner rather than decided by me.

---

### Every token rejection carries one message, and the cause goes somewhere the client cannot read

**What I chose:** all seven-plus failure modes in `verifyAccessToken` throw
`unauthenticated('invalid access token')` and record the specific cause on a non-serialised
`detail` property.

**Why:** A 401 that says *which* check failed is an oracle: it tells someone attempting to forge a
token that their signature was fine and their `exp` was not, which is a measurement of how close
they got. I wanted the server log to be diagnosable, so I checked that `sendError`
(`server/http.js:52`) copies only `status`, `code`, `message` and `reason`, the `detail` never
reaches the response. The property is asserted by the suite's own design: `check-jwt.js:47-53`
collapses every outcome to a string and requires the exact value `401 UNAUTHENTICATED`, so a
wrong error type is visible.

**What I rejected:** distinct messages per failure mode, which is what I would write for a CLI
where the operator is trusted. For a network endpoint the debugging gain does not pay for the
oracle.

**What would change my mind:** nothing in the current threat model. If this were an internal
service on a trusted network I would use specific messages, because the operator is the attacker
in that scenario and detail is worth more than obscurity.

### Modification authority is two clauses, because the document and the shipped test disagree

**What I chose:** you may modify a user of strictly lower rank, **or** of equal rank if you are an
owner. You may also assign any role whose rank is not above your own. One comparison
(`rank(newRole) <= rank(callerRole)`) covers "assign `owner` unless you are an owner", because
`owner` holds the top rank in the table.

**Why:** `PERMISSIONS.md §6` says "modify a user of strictly lower role → allowed" and "modify a
user of equal role (admin → admin) → 403". Implemented literally, that also makes owner → owner a
403, and `scripts/check-api.js:150` failed against it: one owner demoting another owner in a
two-owner org, expecting 200. The two cannot both be right. Owners are peers by definition, and an
org that cannot demote one of its owners has no mechanism to change its own ownership, the
last-owner guard would then be a dead end rather than a protection. `server/lifecycle.js:60-84`
carries both clauses and the reasoning; the equal-rank allowance is scoped to `owner` and to nothing
else, so admin → admin is still 403.

**What I rejected:** reading the table as authoritative and returning 403 for owner → owner, which
would have meant editing a test or shipping a known failure. I also rejected making the rule
purely numeric ("you may modify anyone at or below your rank"), which is simpler and would let two
admins modify each other.

**What would change my mind:** evidence that peer-owner demotion is meant to be impossible, for
instance a product where the founder's ownership is permanent. Then the table is right, the test is
wrong, and I would want that argument in writing rather than inferred from one assertion.

---

### A grant is a membership-scoped fact, so a device transfer leaves the old grants behind

**What I chose:** moving a device between orgs does not touch grants that named it. The source
org's device-scoped grants stay, inert, and revive if the device is ever transferred back.

**Why:** `grants.org_id` is `NOT NULL` and resolution filters on it before anything else, so a
grant in org A naming a device that has moved to org B is already unreachable, no question asked
in org A can name that device, so the grant cannot apply. Deleting them would be a write with no
protective effect, taken at a moment (a transfer) when the operator is thinking about a machine and
not about a grant history. Reviving them on return is also the more defensible reading: the org
granted that person access to *that machine*, and the machine came back. `server/routes/devices.js`
says so at the point of the decision.

**What I rejected:** revoking the source org's grants on transfer, which is tidier and prevents a
stale grant from surprising anyone later. It is also destructive and unlogged, there is no
`grant:revoke` audit row for a grant nobody chose to revoke, so the trail would show a transfer and
a silent disappearance.

**What would change my mind:** a product where a transfer means "this person must not have access to
this machine any more", which is a reasonable reading of a transfer between companies. Then the
transfer route should revoke them, in the same transaction, with an audit row each.

---

### `device:view` gates list rows and nothing else, so session start does not require it

**What I chose:** `POST /sessions` checks `session:start` and the mode permission, and nothing
else. A device-scoped `allow device:control` works on a device where `device:view` is denied.

**Why:** I built the opposite first, a 404 for invisible devices on the session route, on the
reasoning that you should not operate a machine you cannot see. Then I read §5.1's table again,
which gives this endpoint exactly two requirements and does not mention `device:view`; and §4, whose
sentence about `device:view` is explicitly about *list responses*. The stronger argument is
practical: making `device:view` a precondition means a device-scoped `device:control` grant is
unusable on any device where `device:view` is also denied, so the grant does not do what it says.
The endpoint table is the contract for endpoints, and I had let a list-shaping rule leak into it.

**What I rejected:** the 404-on-invisible version, which is the more conservative-sounding rule and
which I still think is defensible on security grounds. It makes a documented grant inert in a
documented case, and nothing in the documents asks for it.

**What would change my mind:** a requirement that a caller may only act on resources they can see.
If that is the intent, the fix belongs in one place, `assertCan`, rather than in each route, and
it would make every device-scoped grant conditional on `device:view`, which I would then want to see
stated somewhere.

---

### Recovery from a stale token is one mechanism, and org-switching is not it

**What I chose:** `POST /auth/token` (switch org) goes through the same `perm_version` freshness
gate as every other authenticated route, so a stale token cannot mint a new scope. The only way
past it is `POST /auth/refresh` from the httpOnly cookie.

**Why:** I hit this while testing and my first instinct was that it was a bug, the user clicked
"switch org" and got a 401. It is not: `perm_version` moving is how the server knows authority
changed, and minting a fresh token from a stale one would mean the freshness check could be
side-stepped by switching orgs. Recovery being *one* mechanism matters more than it being
convenient, two ways back is how one of them ends up unguarded. The console's `api.js` already
handles it: on `TOKEN_STALE` it refreshes from the cookie and retries the original request once, so
the switch lands in the org the person asked for.

**What I rejected:** exempting `POST /auth/token` from the freshness check, which would have made
the UX complaint go away. It would also mean a demoted user could still mint tokens for their other
orgs, which happens to be defensible, and it would be a special case in the pipeline for a route
that is not special.

**What would change my mind:** evidence that org-switching needs to work offline from freshness, for
instance a console that switches org from a stale token with no cookie available. Then the
exemption belongs on the route, with a comment saying exactly why that route is exempt.

---

### An invite proves the invite; a password proves the person. Neither resets the other

**What I chose:** accepting an invite has three paths, signed in and it is your account, signed out
and the address is new (create the account), or signed out and the address is taken (**re-authenticate
with the existing password**). No path ever changes an existing password.

**Why:** `BRIEF.md §2` makes an invite the only way to add a person, and the accept route is public,
so "the email already exists" has to be answered. The two obvious answers are both unacceptable: ask
for a new password and you have built an unauthenticated password reset; create a second user and
`users.email` refuses. The third case is forced by a fact I only noticed while writing the test, a
person removed from their only organization **cannot sign in at all**, because login requires an
active membership (a token has to be scoped to an org), so the authenticated path is unreachable for
precisely the person who most needs to redeem a re-invite. Re-authenticating against the stored
credential is not a reset: nothing about the stored value changes, and a wrong password gets the
same generic refusal a sign-in would, so the endpoint is not a password oracle for addresses that
happen to exist. `scripts/check-http-seams.js` asserts all three paths, plus that the old password
still works afterwards.

**What I rejected:** refusing the accept with "sign in first" and leaving the person stuck, which is
what I had. Also rejected: a password-reset token, which is out of scope per `starter/README.md` and
would be a larger feature than the problem.

**What would change my mind:** a requirement that redeeming an invite never requires typing an
existing password anywhere. Then the answer is not in this route, it is a magic link scoped to the
invite, which is a different product and a bigger build.

### Duplicate org name is an application check, because the schema cannot make it a guarantee

**What I chose:** `POST /v1/orgs` refuses a name that already exists (case-insensitively) with
`409 CONFLICT` and `reason: "duplicate_name"`, checked in application code.

**Why:** `PERMISSIONS.md §5` has a table row for it, `CONFLICT | 409 | duplicate name`, and **no
submission could produce it**, because `organizations.name` carries no UNIQUE index. The only unique
indexes in `db/schema.sql` are `roles.rank`, `users.email`, `invites.token_hash`,
`memberships(org_id, user_id)` and the two partial ones. `BRIEF.md §2` says the schema wins, so a
defensible answer is to emit nothing.

I went the other way, for a reason I want to be honest about: a documented code that no
implementation can ever emit is a code that should not be in the table, and a caller who reads the
table and never sees the status has learned something false about the system. `check-hardening.js`
now walks that table row by row and asserts every documented code is reachable.

It is built as `new HttpError(409, 'CONFLICT', …, 'duplicate_name')` and not through
`conflict(msg, code)`, because that helper's second argument is the **code** and it leaves `reason`
null, so the obvious call puts `duplicate_name` where the specification says `CONFLICT` belongs and
leaves the specific cause unreported. Same split as `GRANT_EXPIRED`/`expired_grant`.

**What I rejected:** emitting nothing, which follows `BRIEF.md §2` most literally. It leaves a
documented behaviour undelivered, and I would rather deliver it and label the weakness than not
deliver it.

**What would change my mind:** a migration adding `UNIQUE (name)`, which would move this to a
guarantee and make the application check redundant. `db/schema.sql` is not mine to change, so until
it is, the check-then-act race is real: two simultaneous creates with the same name can both
succeed. The consequence is a cosmetic duplicate, which is the only reason I am comfortable shipping
a check-then-act in a build that otherwise refuses to use one, and it is stated in the code comment
rather than left to be discovered.

**The check was wrong for its whole life, and only the UI found it.** The lookup carried an
`id <> ?` clause excluding `ctx.orgId`, the caller's *current* org. The org being created does not
exist yet, so its own id cannot match anything, so the exclusion removed exactly the row most likely
to collide: copying the name of the organization you are looking at. The first duplicate was
accepted, and only the second was caught, because by then some other row carried the name. It went
unnoticed because every test that exercised the check used a name belonging to an org the caller was
*not* in, which is the one case that worked. It was found by the new-organization form's own
duplicate-name test, the first thing in this repository to try creating a same-named organization.
The clause is gone, and `tests/contract.spec.js` now pins the case that was broken, verified to fail
when the clause is put back.

---

### Every rejection carries the same client-facing message; the cause goes where the client cannot read it

**What I chose:** all of `verifyAccessToken`'s failure modes throw
`unauthenticated('invalid access token')` and record the specific cause on a non-serialised `detail`
property. Sign-in answers one message for a wrong password and for an account that does not exist.

**Why:** A 401 that says *which* check failed is an oracle: it tells someone forging a token that
their signature was fine and their `exp` was not, which is a measurement of how close they got. But I
wanted the server log to be diagnosable, so I checked rather than assumed that `sendError`
(`server/http.js:52`) copies only `status`, `code`, `message` and `reason`, `detail` never reaches
the response. `check-jwt.js:47-53` collapses every outcome to a string and demands the exact value
`401 UNAUTHENTICATED`, so a wrong error type is visible rather than tolerated.

The sign-in half is the same principle applied to accounts: `UI-INVENTORY.md §4` says a wrong
password and an unknown account must read identically, because a screen that says "no such account"
is an enumeration oracle. `tests/ui.spec.js:333` asserts the screen does not improve on the server's
answer, and I had it the other way round, `ApiError.human` rewrote every 401 into "Your session has
expired", which both failed that test and did the thing the document forbids.

**What I rejected:** a distinct message per failure mode, which is what I would write for a CLI where
the operator is trusted. On a network endpoint the debugging gain does not pay for the oracle.

**What would change my mind:** nothing in the current threat model. On a trusted internal network I
would use specific messages, because there the operator is the attacker and detail is worth more than
obscurity.

### A JWT `role` claim is an input, and `AUTH-DATA-MODEL.md §1` calls it one

**What I chose:** `ctx.role` is `membership.role`, read from the database, and a token whose `role`
claim disagrees with the row is rejected with 401 rather than corrected.

**Why:** I read D11, "the token carries the authorization *inputs*, the server resolves the
permissions", as being about payload size. Resolve permissions per request; do not bake the set
into the token. So the resolver read the database, and `ctx.role` came from `claims.role`.
`server/lifecycle.js` then ranks `ctx.role` in `assertRoleAssignable` and `assertCanModify`, which
made the token's `role` field load-bearing after all.

`scripts/pentest.js` found it. A token byte-identical to a real admin's except `role:"owner"`:

```
real   -> PATCH /v1/orgs/org_acme/members/usr_acme_viewer {"role":"owner"} -> 403
forged -> PATCH /v1/orgs/org_acme/members/usr_acme_viewer {"role":"owner"} -> 200
          {"user_id":"usr_acme_viewer","role":"owner","perm_version":2}
```

An admin promoted a viewer to owner, in the database, in the audit log. Every other control held,
the endpoint, the rank table, the last-owner guard, because all of them trusted the wrong input.

The part worth keeping is *why* a mismatch is an error instead of a silent correction. By the time
`authenticate()` reaches the check, `assertFresh` has already proved the token's `perm_version`
still matches the row, and every role change bumps `perm_version`. The two values are therefore
equal by construction for any honestly-minted token. Unequal means the signing key leaked or the
token was forged; there is no legitimate state in which they differ, so tolerating one would be
tolerating an attack.

**What I rejected:** trusting the claim and letting the resolver catch up, which is what the code
did. Also rejecting the whole token as a `TOKEN_STALE`, the credential is not stale, it is
inauthentic, and conflating the two would send a legitimate client into a refresh loop that cannot
fix anything.

**What would change my mind:** a deployment where the membership row is genuinely unavailable on the
request path. Then the claim would have to stand in for it, and the honest answer would be a signed
short-lived assertion that is re-validated against the database before any *write*, not before
every read.

The general rule: **a claim is a cache of something the server already knows. If acting on the claim
is cheaper than reading the source of truth, the claim will eventually be acted on alone.**

### A dev default is fine; a dev default reachable in production is not

**What I chose:** `JWT_SECRET` and `APP_HASH_KEY` keep their development literals, and a missing key
in production is fatal at boot, the error message carries the command that generates one.

**Why:** both were `process.env.X ?? '<literal>'`, and both fallbacks were reachable in production,
because the hand-out's own `npm start` sets `NODE_ENV=production` and sets neither. The documented
way to run this application therefore signed every access token with a value published in the
repository, and `scripts/pentest.js` mints one with it and reads four devices as a user who has
never authenticated. `APP_HASH_KEY` was the same mistake one line away, three lines below a comment
in `server/auth.js` saying the key "is an application secret, not a hardcoded literal".

**What I rejected:** warning loudly and booting anyway, which is the option that looks responsible.
A server that starts with a known signing key looks healthy, passes its own suite, and fails open.
A server that refuses to start is inconvenient for about four seconds and is correct forever. This
is the entire difference between a default and a vulnerability.

It forced one change to a hand-out file: `playwright.config.js`'s `webServer.env` set `JWT_SECRET`
and would no longer boot. I changed the env block and nothing else, because a repository whose
`npm test` does not run is worse than one that departs from the issued harness in a way that is
written down in `BUILD-LOG.md`.

**What would change my mind:** a hosting target where the operator genuinely cannot set environment
variables, and generating a random key at boot persisted to a file would then be correct. It would
still have to fail if that file were missing, because an ephemeral key silently invalidates every
refresh token on restart.

### `npm run check` asserts the security property; `npm run pentest` attacks it

**What I chose:** the forgery regressions live in `check-hardening.js` beside every other hardening
assertion. `scripts/pentest.js` is a separate `npm run pentest`.

**Why:** the gate that runs in CI should be the one that fails if a fix is reverted, and that is
`check-hardening.js`. The pentest stays separate because it spawns two servers and because its
output reads like an argument rather than a report; folding it in would mean the headline "509
assertions" could only be quoted with a footnote about 9 of them being an attacker.

The reason this is a decision at all: I wrote the nine regression assertions, watched them pass, and
they were **passing against the vulnerable code**. Two reasons, both unrelated to the bug, a
hardcoded `sub: 'ln'` that is not a user, so every token died at the membership lookup, and a
missing `jti`, so every token died again at the verifier. Two layers of a test that could not fail.

**What I rejected:** trusting a green run. The only thing that found this was reverting the fix and
requiring the test to go red, which is now the rule I would apply to every assertion I write: a test
is not finished when it passes, it is finished when it has been seen to fail for the right reason.

**What would change my mind:** nothing, but I would want the revert-and-confirm step written into
the harness rather than remembered, because it is exactly the step that gets skipped under deadline
and the suite still looks green.

## Where this repo argues with itself


Four places. Two are document-versus-document, two are document-versus-schema.

### 1. `PERMISSIONS.md §5` lists a reason code that §3's algorithm cannot produce

> §5: "`reason` is the machine-readable cause, `missing_permission`, `explicit_deny`,
> `suspended`, `expired_grant`, `scope_mismatch`."

But §3's step 3 says to collect "the grants that apply to this question **right now**", and D7
says a grant is active when `starts_at <= now < expires_at`. A grant that has expired is
therefore never collected, so the answer falls through to step 5: `deny`, `source: null`,
`reason: "implicit"`. There is no path by which `expired_grant` is the reason for a resolved
permission. `scope_mismatch` has the same problem, and I found it the hard way: an org-wide allow
is collected at every device scope, so holding a permission org-wide but not on one device
requires a device-scoped deny, which is `explicit_deny` (`DECISIONS.md`, decision 3).

**Built against §3**, and both codes are absent from a *resolved permission*, which is where I
originally read the list as applying, and where it cannot apply.

I also got the second half of this wrong and said so in a draft of this file: I wrote that
`expired_grant` "does appear as an HTTP reason on grant *creation* with an expiry in the past". At
the time I emitted `reason: "invalid_window"` and not `expired_grant`, so the sentence described an
intent rather than the code. It now emits the documented string, and the test asserts it:

```
POST /grants { expiresAt: <past> }  ->  400 GRANT_EXPIRED, reason 'expired_grant'
```

`GRANT_EXPIRED` is named twice by `PERMISSIONS.md §5`, once in the code table and once in the
prose list of reasons, and the two want different fields. So the code is `GRANT_EXPIRED` and the
reason is `expired_grant`. `scope_mismatch` has no such second life and remains unreachable.

### 2. `AUTH-DATA-MODEL.md §10` wants 403 for a suspended token, and "an empty permission set" in the same breath

> §10: "a token for a suspended membership → `403` with an empty permission set"

A 403 means the request failed, so there is no response to carry a permission set. The two halves
can only be reconciled by splitting them across layers, which is what I did: the *request* is
refused with 403, and the *engine* independently resolves a suspended membership to an empty set
with `reason: "suspended"`. `check-permissions.js:126-129` asserts the engine half directly
against a suspended membership, so both halves are separately checked.

**Built against both**, by splitting rather than choosing.

### 3. `db/reference.sql`'s own sanity comment is wrong in a personalised database

> `db/reference.sql:102-107`: "Expect 19 permissions, and owner=19, admin=18, operator=7 … expect
> 26 (19 concrete + 6 wildcards + '*')"

`npm run db:reset` prints `permissions=20 patterns=27 organizations=3`. The overlay in
`scripts/personalise.js` adds one role, one permission and one organization, and it adds the
permission to `permission_patterns` too so its own grants satisfy the foreign key. The comment is
only true when there is no nonce.

**Built against the tables, obviously**, but the comment is a trap for anyone who treats it as
a contract, which is why it is in this file rather than only in `BUILD-LOG.md`. Nothing in my code
may assume a permission count, and `check-personalisation.js` is the thing that enforces it.

### 4. `PERMISSIONS.md §6` and `scripts/check-api.js:150` disagree about owner-to-owner

> §6: "modify a user of strictly lower role → allowed" / "modify a user of equal role (admin → admin)
> → `403`"

and `scripts/check-api.js:150` demotes one owner to `viewer` in a two-owner org and expects **200**.
Taken literally the table makes that a 403. **Built against the test**, with the reconciliation
written out in `server/lifecycle.js:60-84` and argued as decision 6 above. This is the one place I
chose a shipped assertion over a shipped document.

### 5. `UI-INVENTORY.md §3` bundles grant *visibility* into `user:read`, which reads oddly and is deliberate

> `UI-INVENTORY.md §3`: "The Grants card shares its gate with People because the API does,
> `GET /grants` requires `user:read`. There is no `grant:read` permission."

This one is not a contradiction so much as a design that looks like a mistake until you read it
twice, and I got it wrong first: my instinct was that the Grants card was gated on `user:read` by
typo and should be `grant:create`. It is not a typo, and the consequence is the point.

So the ability to *see* who holds what is bundled with the ability to see the people list, and an
auditor, who cannot otherwise manage anyone, can read every grant in the organization, including
grants aimed at people whose details they cannot see. **Built against it**, because the catalogue is
reference data and adding a permission is not mine to do. Logged as an open thread rather than
worked around.

### 6. `PERMISSIONS.md §5` documents a `CONFLICT / duplicate name` that the schema cannot enforce

The code table says `CONFLICT | 409 | duplicate name`, and `db/schema.sql:81-88` gives
`organizations.name` no UNIQUE index, so no implementation can produce that status from a
guarantee, and `BRIEF.md §2` says the schema wins. **Built against the table**, with the race stated
in the code and written up as decision 12 above, because a documented code nothing can emit is a
code that misinforms. This is the only place in the build where I use check-then-act.

### 7. `PERMISSIONS.md §5` names `GRANT_EXPIRED` in the code table and `expired_grant` in the prose

The table says `GRANT_EXPIRED | 400 | creating a grant that is already expired`; the paragraph
below says `reason` is one of `… `expired_grant` …`. So the two want different fields for the same
error. I originally emitted `GRANT_EXPIRED` as the code and invented `invalid_window` for the
reason, a word in none of the five documents, and then wrote a `DECISIONS.md` paragraph claiming
the invented one was deliberate. **Built against both**: code `GRANT_EXPIRED`, reason `expired_grant`,
asserted.

### 8. `README.md` says the first suite "fails until you implement `verifyAccessToken`"; `check-permissions.js` cannot report a failure at all

> `starter/README.md:37-39`: "`check-jwt.js` fails until you implement `verifyAccessToken` in
> `server/auth.js`, that function is a stub. `check-api.js` and the UI suite fail with it."

True, and incomplete in a way that cost me time. `check-permissions.js` does not *fail* on the
skeleton, it **dies during import**, before its assertion harness exists, because `resolve` is
called from a module-scope helper (`check-permissions.js:48`). The output is a stack trace, not
"0 passed, 35 failed". So there are three distinct states of "not implemented", and only one of
them is a test failure.

**Not a disagreement so much as a gap in the hand-out's own instructions.** Worth recording
because the instinct on seeing a stack trace is to assume the harness is broken rather than that
the thing under test is missing.


### Throttle failures, not requests, and count them per credential

**What I chose:** `server/ratelimit.js` throttles *consecutive failures for one credential from one
address*, with a looser per-address ceiling on total attempts. A correct password clears the
counter. Limits are 5 failures per 60s and 300 attempts per address per minute, both env-overridable.

**Why:** the obvious implementation is wrong here for a measured reason. The shipped suites sign in
about fifty times from 127.0.0.1, so any per-IP ceiling low enough to matter breaks `npm run check`;
and any ceiling that does not break them, several hundred a minute, stops nothing, because one
login costs about 40ms of scrypt and 300 of them is twelve seconds of threadpool time.

Counting failures is both the correct security property and the reason the test suite still passes.
A person who types their password correctly is never throttled however often they sign in.
Credential stuffing fails every time, so it is the thing that gets slowed.

**What I rejected:** a global per-IP request cap, as above. Also a lockout that persists, an
attacker who learns five wrong passwords for a victim can lock that account out indefinitely, which
converts a rate limiter into a denial-of-service tool pointed at a third party. The window slides
and a success clears it, so the worst outcome is a slow attacker, not a permanently unavailable
account.

**What would change my mind:** a shared store. Across more than one instance, in-process counters
mean an attacker gets the limit per instance, and the honest answer is Redis or the database. I did
not add a dependency to solve a problem a single-process deployment does not have, but I would not
ship this horizontally scaled without one.

One detail that is easy to skip: the counter map is **pruned**, because its keys are attacker-
controlled. Every distinct address/credential pair is a key, so a script sending ten thousand unique
emails grows the map by ten thousand entries and turns a rate limiter into a memory-exhaustion
vector. Pruning runs at most once per window, so the cost is amortised against the traffic that
caused it.

### A security header is not a security control until a browser agrees to it

**What I chose:** `server/headers.js` owns one header set, applied where a response is created. The
CSP is environment-dependent: production gets `script-src 'self'; style-src 'self';` with no inline
and no eval; only dev gets `'unsafe-inline'`, for Vite's inline module preamble.

**Why:** it went through three wrong versions before that, and the reason each was wrong is the
point. First, `X-Content-Security-Policy`, an abandoned draft no browser implements, so the policy
was inert while every other header was present and all 34 UI tests passed. Second,
`script-src 'self' 'unsafe-inline'`, added for the dev client: `'unsafe-inline'` permits inline
script, which is the one thing a CSP exists to stop, and a browser test that injects an inline
script found it **executing**. Third, a policy assembled from bare source expressions that read
`… font-src 'self'; 'self'; 'self'; connect-src 'self'`, two nameless directives Chrome discards,
with blocking accidentally working via the `default-src` fallback.

**What I rejected:** one policy for both environments. The permissive form has to exist for Vite, and
shipping it to production because dev needs it trades a real control for developer convenience.

**What would change my mind:** a build that genuinely needs an inline script. Then the answer is a
per-response nonce or a hash of the one inline script, not a global `'unsafe-inline'`.

The lesson I would keep: **every one of those three passed the test suite.** A header-presence
assertion cannot distinguish a policy the browser enforces from a policy the browser ignores,
because in both cases the header is there. Only a browser can tell you, so
`tests/csp.spec.js` serves the real document with an injected script and asks Chrome whether it ran.
It also signs in afterwards, because a policy that blocks the app's own bundle is an outage wearing
the costume of a security control.

### A declaration that nothing reads is documentation, not a constraint

**What I chose:** `audit()` now consults `AUDITED_ACTIONS` and throws in production on an undeclared
action or a `targetType` mismatch. The audit asserts the table and the routes agree, in both
directions, from source.

**Why:** a dead-code sweep found `AUDITED_ACTIONS` declared, frozen, and documented as *"stated once,
because the alternative is deciding per route and drifting"*, read by nothing. Every route passed
its own `targetType` inline, so the table could disagree with every caller indefinitely and nothing
would notice. A table that is not consulted cannot prevent drift; it can only record it, and this one
was not even recording correctly.

Consulting it failed a test on the first run. `audit.read` was being emitted by the audit-log route
and was not in the table. Static analysis then found eight more undeclared read actions, and revealed
that `audit.js`'s own header comment was wrong: it said "reads are not audited", while reads *are*
audited on refusal, because a refusal is an authorization event like any other. Successes are not
audited; refusals are. The comment now says exactly that.

**What I rejected:** deleting the table as dead code. It was the better-kept artefact, the intent was
right and only the wiring was missing, and deleting it would have discarded the one place that knew
which actions exist.

**What would change my mind:** if the action set were genuinely open-ended, a caller-supplied action
name, say, a fixed table would be the wrong shape. Nothing here is.

The check that came out of it is written to fail loudly on the *shape* of the problem: the audit
scrapes every dotted literal in the route files rather than a regex shaped like `action: '…'`,
because three of the twenty-nine actions are produced by a ternary assigned to a local, and a
literal-shaped regex reported them as "declared but never emitted". A check that cries wolf gets
ignored, which is the same failure as one that cries wolf in the other direction.

### The KDF cost lives inside the hash, and the default does not move

**What I chose:** the stored form is `scrypt$N$r$p$salt$derived`. Verification reads the parameters
back out, `SCRYPT_N` sets the default for *new* hashes, and a successful sign-in re-derives a stale
hash at the current cost. **The default stays at N=16384.**

**Why:** asked to make sign-in faster, I went looking for the lever and found a latent bug on the
way. The cost lived only in `server/auth.js` and the stored value was `scrypt$salt$derived`, so
changing N in *either* direction would have made every already-stored password unverifiable. Raising
it to harden an install would have bricked the install exactly as surely as lowering it to speed up
sign-in. A cost you cannot change without a data migration is not a parameter; it is a constant
that happens to look like one.

Carrying N in the hash makes the change safe in both directions, and rehash-on-login is what makes it
*take effect*, without it, `SCRYPT_N` only affects new accounts, so lowering it on a live database
does nothing and the login screen does not get faster while the config looks ignored. My own
measurement harness fell into precisely that trap: three runs at three different N all returned
35ms, because the harness had never forwarded the variable to the server.

**What I rejected:** lowering the default. This is the part I would argue for. N=8192 is 2.75x
cheaper to attack offline *and* 2.75x faster, the tradeoff is not linear and the two goals are the
same request, so there is no version of "make login fast" that is not also "make passwords weaker".
These parameters decide what a stolen `password_hash` column costs to crack, which is a risk
decision, and the risk belongs to whoever deploys it rather than to a login screen feeling slow.
The knob is explicit; the default is not moved.

**What would change my mind:** a deployment with a stated, written-down threat model in which the
offline cost of the password column does not matter, a local demo, a fixture with published
passwords, anything where the database is not the asset. Then `SCRYPT_N=4096` is simply correct and
the default should follow. I would want that in writing rather than inferred from a latency
complaint.

`maxmem` is derived from `128 * N * r` rather than fixed, because Node silently clamps the cost when
`maxmem` is short, and a clamped cost is indistinguishable from a change that did nothing, which is
the same trap one level down.

### A pepper, because the KDF cost was being spent on the wrong threat

**What I chose:** `HMAC(pepper, password)` before scrypt. `PASSWORD_PEPPER` is required in production
beside `JWT_SECRET` and `APP_HASH_KEY`, its id is stored in the hash, and the id is DERIVED from the
pepper value rather than configured beside it.

**Why:** asked whether sign-in could be cheaper and stronger at once, and the honest answer has two
halves. The KDF cost is a straight line, `N=8192` is 2.75x cheaper to attack and 2.75x faster, so
"make it fast" and "make it weak" are one request and nothing clever changes that. But a KDF cost buys
exactly one thing: making an offline attack on a stolen `password_hash` column slow. It does nothing
about an attacker holding the column and nothing else. So the money was going to the wrong threat,
and it is paid linearly by the defender on every sign-in.

A pepper moves the threat. Without the server secret a stolen column is not a cracked column, at any
`N` including `N=1`; the attacker's problem becomes "compromise the server". Measured cost: **−0.4%**,
i.e. one SHA-256 in front of a 32ms memory-hard KDF is below the noise floor. This is the one place in
the application where cheaper and stronger is not a tradeoff but a genuine both, and it is stronger in
kind rather than in degree.

**What I rejected:** deriving the pepper id from the environment with a default of `'1'`, which is what
I wrote first. Change the pepper and leave the id and every hash now points at an id that resolves to a
different secret, total lockout, surfaced as 401, indistinguishable from forgotten passwords. Found by
measurement. Deriving it from the value makes the two unable to disagree; an explicit
`PASSWORD_PEPPER_ID` still overrides for an operator who wants a readable label in an audit.

I also rejected interpolating a null id into the stored format, which wrote the literal string `"null"`
and made a pepperless process unable to verify its own hashes. Caught by a test that exercises the KDF
in a process without a pepper in its environment, which is the sort of coverage that only exists
because someone was looking for a specific class of bug.

**What would change my mind:** a deployment where the database is not the asset, a local demo, a
fixture with published passwords. Then a pepper buys nothing and is one more secret to lose, and I would
drop it. The operational cost is real and worth stating: **losing the pepper invalidates every stored
password**, because there is nothing left to re-derive from, so it belongs beside `JWT_SECRET` in the
same secret store and in the same backup.

### Argon2id, measured, and not adopted

**What I chose:** scrypt, at its current cost, plus a pepper.

**Why:** Argon2id at 16 MB / t=2, approximately the OWASP first recommendation, benchmarked at
**22.6ms against scrypt's 32.1ms**, so it is 30% faster *and* has better time-memory-tradeoff and
side-channel resistance, because it separates memory from iteration count where scrypt ties them as
`128 * N * r`. The numbers are real: I installed `hash-wasm` in a throwaway directory outside the repo
and measured it rather than quoting the literature.

Not adopted anyway. It puts a new dependency on the authentication path, which is the worst possible
place to add supply-chain risk, in a repository whose entire Phase 11 was spent establishing that its
six dependencies are what they claim to be. `hash-wasm` is WASM, so those timings are roughly 2-3x
worse than a native build; the native `argon2` package needs node-gyp, and a reviewer without a
compiler gets a broken checkout. And the security half of the claim is a standards judgement, not a
measurement I made, I measured throughput only. The pepper captures most of the same benefit for zero
dependencies at zero cost, which is a better trade than the one on offer.

**What would change my mind:** this is the clearest "ask again later" in the repository. On Node 24+,
where `node:crypto` may carry Argon2 natively, the dependency objection disappears and the migration is
a one-function change, the format already carries cost parameters, so an algorithm field slots in
alongside them. I would want a native implementation and a benchmark on the target hardware before
making the swap, not a WASM number from a laptop.

### A latency budget with a floor as well as a ceiling

**What I chose:** `npm run audit` measures p50/p95 over real HTTP for login and five read endpoints.
Budgets are 200ms for login and 50ms for reads, and the login budget asserts `p50 > 5ms` as well as
`p50 < 200ms`.

**Why:** two numbers because one would be meaningless, a 200ms read budget would permit a 100x
regression and still pass, and a 5ms login budget would fail the moment anyone touched the KDF. The
floor is the part I would defend hardest: a latency win bought by removing the password hash is a
security regression that looks like an improvement on a dashboard, and no ceiling can catch it. Both
sides have to be asserted or one of them is theatre.

**What I rejected:** asserting on `measure.js`'s in-process timings. It bypasses the HTTP layer, so
it cannot see a slow response path, a serialised write, or a header that costs something to build.

**What would change my mind:** a real deployment with a latency SLO. Then the budget belongs in
config and in a monitoring alert rather than in a test, and a test that fails on a slow CI runner is
worse than no test. Both are true today, the budget here is a regression guard for a single-process
demo, and it is labelled as one.

### Creating an organization is a form in the app, and there is no signup page at all

**What I chose:** `window.prompt` is replaced by a real dialog: a name field, six colour choices plus
"match the name", inline `role="alert"` error reporting, focus trapping, Escape and scrim-click
cancellation. The six themes are served by `GET /v1/reference` so the client never holds a second
copy of the list. There is still **no public registration route**, only invite acceptance.

**Why the form was not optional:** `BRIEF.md §3.2` asks for 2 to 3 organizations created "from the
UI", and a native prompt is not part of this app. It cannot report a 409, cannot show which names
are taken before submitting, cannot offer the theme choice, and is not reachable by keyboard or read
by a screen reader the way the rest of the console is. It was the only control in the product that had
never been designed.

**Why no signup page, since this was asked directly:** `AUTH-DATA-MODEL.md §6` says "Invites are the
only way to add a person. One path means one set of edge cases", and D14 repeats it. A public
registration route would also be a denial of service against our own users: register
`dana@acme.test` first and, when the real Dana is later invited to that address, the invite can no
longer be accepted, because the address is held by someone who was never entitled to it. That attack
needs no credentials and works against a named colleague. Invite-only is both the specified design
and the safer one, so an account is created by redeeming an invite.

The sign-in screen now says so, and I only found that it did not while checking before a
submission. This file claimed the screen carried the explanation and it carried nothing but the demo
account list, so a person arriving with no account saw a form with no "Register" link and no reason
given, which reads as a missing feature rather than a decision. Nothing tested the claim, which is
the same gap as the six device buttons: a statement in prose that no check would have caught. It is a
pinned test now.

**What I rejected:** a signup form, for the reason above. A "request access" form would have been
cosmetic, since it would need a table the schema does not have.

**What would change my mind:** a specification that adds a registration route, or a deployment where
the member directory is not reachable by the people being invited.

### A refusal is reported in the panel that caused it, and it does not replace what is already there

**What I chose:** each of the six device actions opens a panel on the row. A refusal is rendered in
that panel as a `role="alert"` carrying the server's error code, next to the button that was pressed,
rather than in the page-level error bar. And a failed action adds to the panel rather than clearing
it: starting Control and then being refused Terminal leaves the running Control session on screen
with its Stop button.

**Why:** the first version cleared the session on every click, on the reasoning that the panel
describes the last thing you pressed. That is not what a panel is. The outcome was a user with a
live Control session, an error about Terminal, and no way to stop the session. `tests/device-actions.spec.js`
fails if the clearing comes back.

**What I rejected:** routing these errors to the page bar, which is what every other card action
does. That is right for an action with nowhere to put a message, and wrong for a form the user is
looking at, where the error is about the field in front of them.

**What would change my mind:** a row with more simultaneous panels than fit, at which point one
region per row with a list of outcomes would be more honest than whichever panel is open.

---

### The device row does not pre-empt the compound session check

**What I chose:** the three session buttons on a device row are gated on the mode's own permission
and NOT on `session:start`, so a row can offer Control and still be refused. The 403 is then shown
in the panel, which names which of the two permissions was missing.

**Why:** `ui.spec.js` has a test for a device-scoped `device:control` grant held by somebody whose
role has no `session:start` at all, and that is the shipped fixture rather than an invention. Adding
the compound filter to the row would delete that grant's only visible effect and make the
demonstration of D6 impossible to see in the product. The Sessions card, which offers a mode
*chooser* rather than three separate buttons, does apply the compound check, and that is the right
place for it.

**Why not decide it in the client anyway:** the only table of which role holds which permission lives
in the database, and encoding it in the console is the one thing this codebase does not do. Same
reason the transfer panel does not pre-empt its own refusal by hiding organizations where you are a
viewer: it shows your role beside each one and lets the server answer.

---

### A missing asset is a 404, and the SPA fallback is only for client routes

**What I chose:** a request path containing a file extension is a request for that file. If it is not
on disk, the answer is 404. Only an extensionless path falls through to `index.html`.

**Why:** the fallback existed for the client router, which owns `/invite/<token>`. It was answering
the index document for everything, which meant a missing stylesheet arrived as `200 text/html` and
the browser complained about a MIME type instead of naming the file. The cost was not the confusion,
though that is real. It was that `GET /vite.svg` returned 200 for a file this repository does not
contain, so "does this asset exist" became unaskable, and this audit is full of questions of that
shape.

**What I rejected:** a content-negotiation fallback (`Accept: text/html`), which is the usual
refinement. It is more machinery for the same decision, and a fetch or an `<img>` that 404s would
still be answered with a document.

---

### One copy of the session cross-org check, and one component that owns the hooks

**What I chose:** `sessionInOrg` is the only place that decides whether a session id belongs to the
caller's organization, and both routes call it. `App` is a router that owns no hooks and renders
either `<AcceptInvite>` or `<Console>`, and `<Console>` calls all of its hooks unconditionally.

**Why:** both were triplications or violations that happened to be correct. The session check existed
as a function and was inlined at both call sites, so the rule that stops one organization reading or
ending another's session existed three times; the next change would have been made in one of them
with every test still green. The hooks sat below an early `return`, which is legal only because the
path cannot change without a full page load, and which fails with a blank console the day it can.

**What would change my mind:** a client-side router. That is the thing that makes the second one
matter rather than being pedantic, and it is the reason to fix it before writing one.

### An invite you cannot cancel is a credential you cannot manage

**What I chose:** the People card lists outstanding invites with a Revoke button, and settled invites
fold away under a count.

**Why:** `GET /invites` and `DELETE /invites/:id` have existed since Phase 3, permissioned and audited,
and the console could not reach them. The link is shown once and only its hash is stored, so the
window between "sent" and "expires" was seven days during which a mistyped or forwarded address held
working access to the organization and no one could take it back. This is the only finding from the
Phase 14 audit that is a control rather than a feature, which is why it was done first.

**What I rejected:** showing the link in the list. It cannot be done, and pretending otherwise would
be worse than the gap. A section that looked like it could recover a link would mislead. A test
asserts the token appears nowhere in it.

**What I rejected:** a confirmation step on Revoke. The decommission panel has one because nothing
here undoes it. Re-inviting is one click, so a modal is one more obstacle between a person and a fix.

**What would change my mind:** an invite that grants something irreversible before it is redeemed. It
does not; the membership is only created on acceptance, which is also why a revoked invite leaves no
trace to clean up.

## Deliberately not built

Stated now for the things already decided; this section grows as the build does.

- **A process-wide permission cache.** See `DECISIONS.md` decision 4. The per-request resolver
  already makes a device list three queries; a shared cache trades a correctness window for
  latency I have not measured a need for.
- **Search, pagination and sorting on list endpoints, beyond the `limit`/`offset` the audit
  endpoint is required to validate.** `check-api.js:189` pins the audit endpoint's boundaries as
  `400`/`400`/`400`/`400`/`200`/`200`, and I implement exactly that. The other list endpoints
  take no parameters, because the console renders the whole set and the fixture is nine devices.
  Adding pagination to a list the console always shows in full would be building for a scale this
  product does not have.
- **A second resolution path for "does this person hold this on EVERY device".** I considered it
  for the org-level view and rejected it in decision 1: no shipped contract needs it, and it
  cannot be derived from the union without a second pass over the device list.
- **Rate limiting, email delivery, password reset, anything from Q2.** Listed as out of scope by
  `starter/README.md` and agreed with; invite tokens are returned in the API response instead of
  emailed, which is a substitution the brief sanctions rather than a gap. Sign-in is already the
  expensive operation at 34.3 ms p50, all of it `scryptSync`, so a rate limiter would be
  defending something that is not undefended.
- **Session pagination.** `GET /sessions` returns every session in the org. The audit endpoint has
  tested `limit`/`offset` boundaries; reusing that here would be a small change, and I left it out
  because the fixture has three sessions and the console shows them all. A filter nobody needs is a
  filter with bugs in it.
- **Filtering or searching the grants table** by effect, target or scope. Same reasoning, and the
  console's whole value is that you can *see* the grants.
- **A background TTL sweeper for sessions.** Expiry is applied lazily on every read and write that
  touches sessions. A sweeper would be a second writer racing the request path, and a session past
  its TTL holds no authority that needs protecting.
- **A `grant:read` permission**, which would decouple the Grants card from `user:read`. Adding a
  permission to reference data is not mine to do, and inventing one in code would be the exact
  "two copies of the model" failure the brief is about.
- **Console tests against a personalised fixture.** Still the one real gap, and still listed first
  in `BUILD-LOG.md`'s open threads: `check-personalisation.js` proves the *engine* is correct on any
  nonce, and nothing yet proves the console *renders* an undocumented role and permission. The
  contract tests added in Phase 9 run against the published fixture, so the rendering path for
  `device:reboot` is unexercised.
- **Rate limiting and a login attempt counter.** Sign-in is already 34.3 ms p50 and all of it is
  the given `scryptSync`, so the hash is the floor; both are listed as out of scope anyway.
  **Superseded in Phase 11**, this was the reasoning that left an unauthenticated endpoint able to
  stall the whole server, and it was wrong in an instructive way. "The hash is the floor" treated
  the KDF cost as a fixed price rather than as work that queues behind itself on one thread. Both
  halves are now built: the hash runs on the threadpool, and the failures are throttled. The entry is
  left in place because the error is the useful part, an expensive operation reachable without a
  credential is a lever, whatever its per-call cost.
- **Bulk member and grant operations.** Creating fifty people is fifty requests. The engine and the
  endpoints are per-item by specification, and a bulk endpoint is a new authorisation surface rather
  than a convenience.
- **A real logout on the access token.** The refresh lineage is revoked and the cookie cleared, but
  an access token already in flight stays valid for its remaining TTL (at most 15 minutes). Making it
  revocable needs a deny-list keyed by `jti`, which is a second mechanism for a job `perm_version`
  and the refresh rotation already do.
- **Token revocation lists / `jti` deny-listing.** The `jti` claim is required to be present and
  non-empty because §10 says so, but nothing in the model needs per-token revocation: authority
  changes are caught by `perm_version`, and the access TTL is 15 minutes. A deny-list would be a
  second mechanism for a job `perm_version` already does.
