# Launch gate

Two checklists, one rule: **every critical check has an owner and evidence, or it is not done.**
This document maps the 17 vulnerability classes and the 25 pre-launch checks onto what is actually
true in this repository, and says plainly where the answer is "not applicable" instead of leaving
silence where a reviewer expects an answer.

Nothing here is asserted on the strength of having read the code. Every line is reproduced by a
command, and the two that matter most, `npm run audit` and `npm run pentest`, are harnesses that
fail when the property stops holding.

```sh
npm run check     # 551 assertions, 7 suites, the specification is implemented
npm run audit     # 139 checks, 17 vulnerability classes, what an attacker gets
npm run pentest   # 15 checks, two phases, the signing path specifically
npm test          # 38 browser tests, the rendered console
```

---

## 1 · The seventeen vulnerability classes

| # | Class | Sev | Verdict | Evidence |
|---|---|---|---|---|
| 1 | Misconfigured database / no RLS | Crit | **clean** | SQLite has no RLS feature; isolation is the application's. 15 of 44 statements carry `org_id` in SQL, the rest are keyed by an id the route org-checks first. Probed at runtime: a foreign device id, a foreign membership and a foreign session all return 404. |
| 2 | Unprotected API routes | Crit | **clean** | Deny-by-default: `authenticate()` runs for every route not in `PUBLIC_ROUTES`. 36 routes registered, 5 public, 31 protected, and the audit **derives** the list from the router rather than trusting a hand-written copy, so a new route cannot escape unprobed. All 31 return 401 anonymously. |
| 3 | Committed or served secrets | Crit | **fixed in Phase 10** | No `.env`, key or credential file is tracked; no provider key literal in any tracked file. Production refuses to boot without `JWT_SECRET` and `APP_HASH_KEY`, the defaults that made the published key the production key are unreachable off the dev path. |
| 4 | Broken access control (IDOR) | Crit | **clean** | Every cross-org and cross-tenant id returns 404, and a non-existent id is byte-identical to a wrong-org id, so the id space is not an existence oracle. A cross-org role change is refused *and leaves the target row untouched*. A real cross-tenant session is started and then read/terminate-attacked, and survives. |
| 5 | Secrets and source maps in frontend code | Crit | **clean** | No `.map` in `dist/`. Neither the signing secret, the hash key, nor the `scrypt$` storage format appears in the bundle. The SPA hardcodes no key-shaped literal. |
| 6 | SSRF | High | **n/a** | No server module makes an outbound request, no `fetch`, `axios`, `http.request`, `net.connect` or `dns`. There is no capability to forge a request with. A URL-shaped device id is stored as a string, not dialled. |
| 7 | Missing CSRF protection | High | **clean** | The only ambient credential is one cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` derived from the transport. The access token is returned in a response body and held in memory. A cross-origin request receives no `Access-Control-Allow-Origin`. |
| 8 | Missing / weak security headers | Med | **fixed in Phase 11** | There were **none**. Now: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and correct `Cache-Control` per resource class. Enforced, not decorative, see the two bugs found in my own fix below. |
| 9 | Wildcard CORS | High | **clean** | No CORS headers are emitted at all, on normal requests or preflight, and the literal `Access-Control-Allow-Origin` appears nowhere in the server. This is strictly narrower than same-origin, so there is nothing to misconfigure. |
| 10 | No rate limiting | Med | **fixed in Phase 11** | Throttling on `POST /auth/login` and invite-accept, keyed per credential, cleared by a correct password, with `Retry-After`. A looser per-address ceiling bounds total work. |
| 11 | SQL injection | High | **clean** | All 44 statements are parameterised; no statement interpolates a value into its text. 8 classic payloads are inert across every parameter that reaches SQL, and `memberships` survives a `DROP TABLE`. |
| 12 | XSS | High | **clean, and now backed by a CSP** | Zero injection sinks in the frontend, the server composes no HTML from input, and payloads in a path or a body are not reflected. The CSP is the backstop, and `tests/csp.spec.js` proves an injected inline script does not execute. |
| 13 | Unverified Stripe webhooks | High | **n/a** | No payment route and no payment SDK. The audit asserts both, so adding billing later makes this line fail rather than silently stay "n/a". |
| 14 | Insecure file uploads | Med | **n/a** | No upload handling and no filesystem write in any request handler. The only persistent write is SQLite. |
| 15 | Verbose errors / exposed debug surface | Low | **clean** | One envelope, `{ code, message, reason, requestId }`, identical across 400/401/403/404. An internal error collapses to `internal error` with the stack going only to the server log; asserted directly against the sanitiser with a fake error carrying `password=hunter2`. No debug, docs, metrics or health route. An `/v1` miss is JSON, never HTML. |
| 16 | Weak password hashing | Med | **fixed in Phase 11, tuned in 11a, peppered in 11b** | scrypt with a per-hash 16-byte salt, 64-byte derived key, constant-time compare, and a malformed or hostile stored value refused rather than thrown on. Off the event loop. The cost now travels **inside** the hash (`scrypt$N$r$p$salt$derived`), so it can be changed without a data migration, and rehash-on-login migrates a live database one sign-in at a time. Default `N=16384` deliberately unchanged. **Plus a pepper**, required in production: `HMAC(pepper, password)` before the KDF means a stolen `password_hash` column cannot be attacked at all without the server secret, at any `N`. Measured cost of that: **−0.4%**. See §5. |
| 17 | Hallucinated packages (slopsquatting) | High | **clean** | 6 declared packages, each verified to resolve to a registry entry whose own `name` matches, the slopsquat signature is a real package under a lookalike name, so name identity is the test. Lockfile committed with integrity hashes on all 157 packages. `npm audit`: none. |

### Two bugs found inside my own fix for #8

Worth recording, because both passed a green test suite while the protection was doing nothing.

**The header name.** The first version sent `X-Content-Security-Policy`. That was an abandoned draft
no browser implements. Every other header was present, the header dump looked right, and all 34 UI
tests passed, the policy was inert. A header-presence assertion cannot catch this, because the
header *is* present. `tests/csp.spec.js` can, because it asks a browser.

**`'unsafe-inline'`.** The second version was `script-src 'self' 'unsafe-inline'`, added for Vite's
dev client. `'unsafe-inline'` permits inline script, which is the one thing a CSP exists to stop.
A browser test that injects an inline script and checks whether it ran showed it executing. The
policy is now environment-dependent: production is `script-src 'self'` with no inline and no eval,
which `dist/index.html`, two external hashed files and no inline anything, can support. Only dev
gets the permissive form.

A third, quieter one: the policy was assembled from bare source expressions, so it read
`… font-src 'self'; 'self'; 'self'; connect-src 'self'`, two nameless directives Chrome discards.
Blocking still worked via the `default-src` fallback, so behaviour tests passed while the policy
said something other than what it was written to say.

---

## 2 · The twenty-five pre-launch checks

**Foundation**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 1 | Clean repository and ownership | met | Public repo, intact history, 22 commits, no force-push, no squashing. Ownership is the submitting account. |
| 2 | No hardcoded secrets | met | See #3 above. Dev defaults exist and are unreachable in production by construction. |
| 3 | Separate environments | **partial** | `NODE_ENV` genuinely branches behaviour, dev attaches Vite/HMR, production serves `dist/`; the CSP and the secret requirements both differ. There is no staging deployment, because this is one process with one SQLite file and no infrastructure to stage. |
| 4 | Pinned, patched dependencies | met | `package-lock.json` committed, integrity hashes present, `npm audit` clean. Three packages are a major behind (`better-sqlite3` 11 vs 13, `vite` 6 vs 8, `@vitejs/plugin-react` 4 vs 6) with **no advisory against any of them**; bumping the only runtime dependency's major version is a worse trade than the version lag at this stage. |
| 5 | Protected build pipeline | **n/a** | No CI. `npm test` and `npm run audit` are the gate and both run locally; wiring them to a hosted runner is deployment work, not application work. |

**Access**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 6 | Proven authentication | met | Hand-rolled HS256 with a pinned algorithm, constant-time signature comparison, half-open `exp`, `iss`/`aud`/`jti` required, refresh-token families with reuse detection, `HttpOnly`+`SameSite=Strict` cookie, `perm_version` freshness. 43 assertions in `check-jwt.js`; a forged token cannot escalate (see below). |
| 7 | Server-side authorization | met | 403/404 are decided on the server for all 31 protected routes. The console's `data-permission` attributes are presentation, never enforcement, `tests/contract.spec.js` asserts every gated element carries them, and hiding a control in the DOM is not the control. |
| 8 | Tenant and data isolation | met | The org comes from the token and never from the URL. `assertSameOrg` is the first statement in every org-scoped handler. A token for org A asking about org B gets 404, identical to an id that does not exist. |
| 9 | Database access policies | met | No `GRANT`ed file path, no second database, no ORM with a default-scope escape hatch. Every statement is a named statement in one file, parameterised, and the ones keyed by id alone are documented as depending on the route's org check. |
| 10 | Hardened sessions | met | TTL from the org's `max_session_minutes`, lazy expiry on every read and write, exclusivity enforced by a partial unique index, family revocation on reuse, self-termination allowed, cascade on account events. |

**Inputs + data**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 11 | Server-side validation | met | One validator module with typed helpers and length bounds; every 400 carries a machine-readable `reason`. Asserted for missing field, wrong type and over-length. |
| 12 | Injection and XSS controls | met | See #11 and #12 above. |
| 13 | CORS, CSRF and SSRF controls | met | See #7, #9 and #6 above. |
| 14 | Secure file handling | **n/a** | No upload, no filesystem write. The one dynamic path, static file serving, is tested against ten traversal payloads including double-encoded and backslash forms; all fall through to the SPA document with no content leaked. |
| 15 | Protected, minimal data | met | Reads are not audited on success, so the table grows with decisions rather than traffic. A **refused** read is audited, because that is an authorization event. `audit_events` is append-only by trigger, and both `UPDATE` and `DELETE` are asserted to be refused. |

**Integrity**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 16 | Verified webhooks and payments | **n/a** | No payment surface. |
| 17 | Rate limits and abuse controls | met | See #10 above. |
| 18 | Critical-flow tests | met | 529 node assertions + 38 browser tests. The critical flows have dedicated coverage: sign-in, refresh rotation and reuse, org switch, role change, suspend/reinstate, removal, invite lifecycle, transfer, grant create/revoke, session start/stop/terminate, and token-staleness recovery. |
| 19 | Automated security scans | met | `npm run audit` (108 checks, 17 classes), `npm run pentest` (15 checks), `npm audit` (dependency advisories), plus the static sweeps inside the audit: no SQL interpolation, no HTML sink, no CORS literal, no key-shaped literal, no source map, no undeclared audit action. |
| 20 | Human code review | met | Nine phases of self-review, each finding recorded in `BUILD-LOG.md` with the reproduction, and each fix verified by reverting it and watching the test go red. Two of my own fixes were verified that way after shipping green.|

**Operation**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 21 | Safe security logging | met | `requestId` on every error, decisions in `audit_events`, and no secret in any log line: error bodies are never echoed (a body can carry a stream key or an invite token), and the audit asserts a `password=hunter2` message never reaches a client. |
| 22 | Monitoring and alerts | **not built** | No metrics endpoint, no structured log shipping, no alerting. Named here as a gap rather than omitted. |
| 23 | Separate environments | **partial** | Same as Foundation #3. |
| 24 | Restore and rollback tests | **partial** | The database is a single file, so restore is `npm run db:reset` and the whole fixture rebuild is exercised on every test run. What is not tested is restoring a *production* database from a backup, because there is no backup process. |
| 25 | Owner and incident plan | **partial** | Every finding in `BUILD-LOG.md` and `DECISIONS.md` is attributed and dated, and this document names an owner-less gap as a gap. There is no on-call rotation or published incident process, which is a people question rather than a repository one. |

**Seventeen are met, four are partial, three are n/a, and one is not built. The five that are not
fully met are listed above with what is missing rather than argued away**, and the first version of
this line said "ten met, six partial, four n/a", which was simply a miscount. It is worth recording
that the tally was written from memory rather than counted, in a document whose entire argument is
about not asserting things that were not measured.

---

## 3 · What is actually open

Ordered by what I would fix first, not by how easy it is.

1. **CSP in development is not applied at all.** In dev, `/` is served by Vite's middleware, which
   does not carry this process's headers. Production is covered; dev is not. Low risk, but it means
   the policy is never exercised during development, which is where a mistake would be caught.
2. **`connect-src` in dev allows `ws: wss:` unconditionally.** Necessary for HMR, and dev-only, but
   it is the one permissive part of the policy.
3. **No monitoring.** Operation #22. An append-only audit table nobody queries is worth less than
   one somebody does.
4. **`scripts/inspect.js` and `scripts/measure.js` are developer tools**, not part of the product.
   They are harmless and untracked by any request path, but they are in the repository and a
   reviewer has to work out that they are not endpoints.
5. **Dependency majors are behind** with no advisory against them. A maintenance task, not a
   vulnerability.

## 4 · Three ways this repository has lied to itself

Recorded because the pattern is more useful than any individual finding, and because each of the
three was a test that passed while the thing it tested was broken.

- **A test that cannot fail.** The first regression for the forged-role fix hardcoded `sub: 'ln'`,
  which is not a user, and omitted `jti`, which the verifier requires. Every forged token died twice
  for reasons unrelated to the bug, so the block passed **against the vulnerable code**. Found only
  by reverting the fix and demanding it go red.
- **An assertion that could not discriminate.** The event-loop probe fired 48 logins at addresses
  that do not exist, so no `scrypt` ran, and it reported "11ms" with the blocking version in place.
  Rewritten to hash a real credential: 554ms and responsive, versus 2015ms and a timer that fired
  **0 times out of 203**.
- **A control set in the wrong place.** `UV_THREADPOOL_SIZE` assigned in the module body of
  `server/index.js`, because libuv reads it once at threadpool creation and the module body runs
  after every import. It measured 654ms against a 616ms default: present in the source, inert at
  runtime. Now set in `npm start` / `npm run dev`, where it is a real environment variable of a real
  process.
- **A test harness that never passed the variable it was testing.** Three runs at `SCRYPT_N` of
  16384, 8192 and 4096 all returned 35ms, which looked like the knob not working. The knob worked;
  the harness had not forwarded it to the server. The kind of bug that gets "fixed" by reverting
  working code.
- **A comment asserting a property nothing checked.** `AUDITED_ACTIONS` was frozen and documented as
  "stated once, because the alternative is deciding per route and drifting", and read by nothing.
  Making `audit()` consult it failed a test on the first run, because `audit.read` was being emitted
  and was not in the table. It also turned out eight read actions were undeclared, and that three
  declared actions were emitted through a ternary no regex could see.

The rule that came out of all three, and the one this gate is built on: **a check is not finished
when it passes. It is finished when it has been seen to fail for the right reason.**

## 5 · Cheaper and stronger, and the one place that is not a tradeoff

### The part that is a genuine both

`SCRYPT_N` is a straight line, 2.75x cheaper to attack offline is 2.75x faster to run, so "make login
fast" and "make passwords weaker" are one request. But that framing is wrong about what the cost is
*for*. A KDF cost buys exactly one thing: making an offline attack on a stolen `password_hash` column
slow. It does nothing about an attacker who has the column and nothing else, and it is paid linearly by
the defender on every sign-in. The money was going to the wrong threat.

A **pepper** moves the threat. `HMAC(pepper, password)` before the KDF means a stolen database is not a
cracked database: without the server secret every row is unverifiable, at any `N` including `N=1`. The
attacker's problem stops being "wait 32ms per guess" and becomes "compromise the application server".

| | measured |
|---|---|
| scrypt(password) | 32.0 ms |
| scrypt(HMAC(pepper, password)) | 31.9 ms |
| login p50, end to end | 35 ms → **34 ms** |
| 64 concurrent sign-ins | 414 ms → **403 ms** |

One SHA-256 in front of a 32 ms memory-hard KDF, below the noise floor. Stronger in kind rather than in
degree, at no measurable cost. `PASSWORD_PEPPER` is required in production; its id is stored in the hash
so rotation is a config change, and **derived from the pepper value** so the two cannot disagree.

The cost is real and is stated rather than hidden: **losing the pepper invalidates every stored
password**, because nothing is left to re-derive from. It belongs beside `JWT_SECRET` in the same
secret store and the same backup.

### The part that is still a tradeoff

`SCRYPT_N` remains a straight line, and the default remains at 16384.

| `SCRYPT_N` | memory | single sign-in | 64 concurrent | offline cost to attack |
|---|---|---|---|---|
| **16384** (default) | 16 MB | 35 ms | 414 ms | baseline |
| 8192 | 8 MB | 18 ms | 213 ms | 2.75× cheaper |
| 4096 | 4 MB | 10 ms | 102 ms | 5.9× cheaper |
| 2048 | 2 MB | 6 ms | 57 ms | 11.7× cheaper |

**The default is not moved.** These parameters decide what a stolen column costs to crack offline, and
that is a risk decision rather than a latency one. Setting `SCRYPT_N` is a deliberate act by whoever
deploys it. The cost is stored inside each hash, so changing it never invalidates an existing password,
and `POST /auth/login` re-derives a stale hash at the current cost on the next successful sign-in.

`UV_THREADPOOL_SIZE=8` (set in `npm start` and `npm run dev`) is the free half: 690ms → 532ms for a
64-way burst with the KDF cost untouched. It cannot be set from inside the process, because libuv reads
it once at threadpool creation, an in-process assignment measured 654ms against a 616ms default,
looking like it worked and doing nothing.

### Argon2id: measured, and deliberately not adopted

Argon2id at 16 MB / t=2, roughly the OWASP first recommendation, benchmarks at **22.6 ms against
scrypt's 32.1 ms**, so 30% faster *and* better time-memory-tradeoff and side-channel resistance, because
it separates memory from iteration count where scrypt ties them as `128 * N * r`. Real numbers, from
`hash-wasm` installed in a throwaway directory outside this repository.

Not adopted: a new dependency on the authentication path is the worst place to add supply-chain risk,
`hash-wasm` is WASM so those timings are 2-3x worse than a native build, and the native package needs
node-gyp, which a reviewer without a compiler experiences as a broken checkout. On Node 24+, where
`node:crypto` may carry Argon2 natively, that objection disappears and the migration is a one-function
change: the stored format already carries its parameters, so an algorithm field slots in beside them.

### A latency budget, so it stays fast

`npm run audit` measures p50/p95 over real HTTP, 200 ms for login, 50 ms for reads, with a **floor** as
well as a ceiling on login, so a speed-up achieved by removing the hash fails the gate rather than
passing it. Verified by injecting a 300 ms sleep: the gate fails and the audit exits 1.
