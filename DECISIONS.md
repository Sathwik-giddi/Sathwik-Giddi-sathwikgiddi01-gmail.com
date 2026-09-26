# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
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

**What I rejected:** the opposite asymmetry — a device-scoped deny wins org-wide too, which is
D1 read maximally. It is the more "consistent looking" rule and it is wrong for the case above.
I also rejected the reading where org-level ignores device-scoped grants entirely (only org-wide
grants apply). It is simpler and it makes the Grants card vanish for someone who can read grants
on one machine, because that card is gated on `user:read` and `user:read` is exactly the kind of
permission a device-scoped grant names.

**What would change my mind:** a case where a device-scoped grant is the *only* thing
authorising an org-level action, and the intended product behaviour is that the action is
refused. I could not construct one from the documents. I would also change it if the console ever
needed an org-level answer to mean "on every device" — the union cannot answer that question, and
if that turned out to be the intent, the org-level set would have to become an intersection over
denies, which is a different engine.

---

### Two 401s and a 403, for three membership states

**What I chose:** `memberships.status` decides the shape of the refusal, not just the permission
answer. `suspended` → `403 FORBIDDEN` with `reason: "suspended"`. `invited` and `removed` → `401
UNAUTHENTICATED`. Inside `resolve()`, `suspended` reports `reason: "suspended"` and both of the
others report `reason: "not_a_member"`.

**Why:** `AUTH-DATA-MODEL.md §10` states it outright — "a token for a suspended membership → 403
with an empty permission set; for a `removed` membership → 401" — and it is also the only split
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
device-scoped deny — which is the `explicit_deny` case. I was maintaining a code path for a state
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

**Why:** This is the answer to the question `BRIEF.md §6` and `WORKFLOW.md §3` both ask — "if you
cache, say why it can't serve stale authority". It can't, because it does not outlive the request
that made it: there is no interval during which a revoked grant, a lapsed `expires_at` (D7), or a
role change could be answered from a previous request's conclusion. Freshness *across* requests
is `memberships.perm_version`, compared in `context.js` on every request. The payoff is not
correctness alone — a device list is three queries regardless of how many devices the org has,
which is the "one query per row" failure `BRIEF.md §6` names. I measured the alternative: the
same answers from a per-device query loop are 1 + N round trips for N devices.

**What I rejected:** a process-wide `Map` keyed by `(userId, orgId)` with a short TTL. It is
faster on a hot list endpoint and it is precisely the thing `AUTH-DATA-MODEL.md §3(2)` warns about
by name — a TTL is a window in which a revocation is not yet true, so a 5-second TTL means a
revoked grant can authorise for up to 5 more seconds. The other candidate was invalidating on
`perm_version` writes, which is sound but needs a write-side hook on every mutation that touches
authority; missing one is silent and permanent rather than brief.

**What would change my mind:** a measured latency problem on a list endpoint that the per-request
resolver cannot fix — at which point the cache key has to include the membership's
`perm_version` and the resolution would have to be pinned to an instant rather than to "now", so
that a cached answer states the version it was computed at. That is a bigger change than the
problem would justify at this size.

---

### Re-hiring someone restores the grants they had before they left

**What I chose:** nothing, deliberately. `grants` hang off `(org_id, user_id)`, so removing a
membership does not touch them, and a re-invite brings the old grants — allows *and* denies —
back with the person. I built against that and wrote a test for it rather than working around it.

**Why:** It falls out of where the schema hangs authority, and `db/schema.sql` is not mine to
change (`BRIEF.md §4`). `scripts/check-seams.js` pins the behaviour in both directions: removed →
`not_a_member` at every scope including the device they held a grant on; re-hired → baseline and
both grants restored; re-hired as a *different* role → the baseline follows the membership while
the grants do not. The last case is the one that surprised me, and it is arguably wrong as a
product: a former operator re-hired as a viewer keeps a `device:terminal` allow that a genuine
operator would have needed. It is defensible as "grants are the org's record of what this person
was given, and revoking them is a separate deliberate act" — an admin who wants them gone revokes
them, and the revocation is auditable.

**What I rejected:** deleting or revoking a removed member's grants on removal. It would be
tidier, and it silently destroys the audit trail of what someone was authorised to do while they
were here — which is the thing the audit log exists to answer. I also rejected leaving it
undocumented, which is the option that would have cost the most.

**What would change my mind:** evidence that a re-hire is expected to start from a clean slate. If
so the fix is not in the removal path but in the accept-invite path — revoke the previous
membership's grants at re-hire, where the intent is explicit — and I would want the question
asked of the product owner rather than decided by me.

---

### Every token rejection carries one message, and the cause goes somewhere the client cannot read

**What I chose:** all seven-plus failure modes in `verifyAccessToken` throw
`unauthenticated('invalid access token')` and record the specific cause on a non-serialised
`detail` property.

**Why:** A 401 that says *which* check failed is an oracle: it tells someone attempting to forge a
token that their signature was fine and their `exp` was not, which is a measurement of how close
they got. I wanted the server log to be diagnosable, so I checked that `sendError`
(`server/http.js:52`) copies only `status`, `code`, `message` and `reason` — the `detail` never
reaches the response. The property is asserted by the suite's own design: `check-jwt.js:47-53`
collapses every outcome to a string and requires the exact value `401 UNAUTHENTICATED`, so a
wrong error type is visible.

**What I rejected:** distinct messages per failure mode, which is what I would write for a CLI
where the operator is trusted. For a network endpoint the debugging gain does not pay for the
oracle.

**What would change my mind:** nothing in the current threat model. If this were an internal
service on a trusted network I would use specific messages, because the operator is the attacker
in that scenario and detail is worth more than obscurity.

## Where this repo argues with itself


Four places. Two are document-versus-document, two are document-versus-schema.

### 1. `PERMISSIONS.md §5` lists a reason code that §3's algorithm cannot produce

> §5: "`reason` is the machine-readable cause — `missing_permission`, `explicit_deny`,
> `suspended`, `expired_grant`, `scope_mismatch`."

But §3's step 3 says to collect "the grants that apply to this question **right now**", and D7
says a grant is active when `starts_at <= now < expires_at`. A grant that has expired is
therefore never collected, so the answer falls through to step 5: `deny`, `source: null`,
`reason: "implicit"`. There is no path by which `expired_grant` is the reason for a resolved
permission. `scope_mismatch` has the same problem, and I found it the hard way: an org-wide allow
is collected at every device scope, so holding a permission org-wide but not on one device
requires a device-scoped deny, which is `explicit_deny` (`DECISIONS.md`, decision 3).

**Built against §3**, and both codes are absent from resolved permissions. `expired_grant` does
appear as an HTTP reason on grant *creation* with an expiry in the past, which is the one place
the phrase is actually true — the request is refused because the window has closed, not because
resolution reached a verdict.

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

**Built against the tables, obviously** — but the comment is a trap for anyone who treats it as
a contract, which is why it is in this file rather than only in `BUILD-LOG.md`. Nothing in my code
may assume a permission count, and `check-personalisation.js` is the thing that enforces it.

### 4. `README.md` says the first suite "fails until you implement `verifyAccessToken`"; `check-permissions.js` cannot report a failure at all

> `starter/README.md:37-39`: "`check-jwt.js` fails until you implement `verifyAccessToken` in
> `server/auth.js` — that function is a stub. `check-api.js` and the UI suite fail with it."

True, and incomplete in a way that cost me time. `check-permissions.js` does not *fail* on the
skeleton — it **dies during import**, before its assertion harness exists, because `resolve` is
called from a module-scope helper (`check-permissions.js:48`). The output is a stack trace, not
"0 passed, 35 failed". So there are three distinct states of "not implemented", and only one of
them is a test failure.

**Not a disagreement so much as a gap in the hand-out's own instructions.** Worth recording
because the instinct on seeing a stack trace is to assume the harness is broken rather than that
the thing under test is missing.


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
  emailed, which is a substitution the brief sanctions rather than a gap.
- **Token revocation lists / `jti` deny-listing.** The `jti` claim is required to be present and
  non-empty because §10 says so, but nothing in the model needs per-token revocation: authority
  changes are caught by `perm_version`, and the access TTL is 15 minutes. A deny-list would be a
  second mechanism for a job `perm_version` already does.
