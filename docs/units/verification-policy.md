# Unit: verification policy loader (`platform/verification_policy.py`)

**File(s):** `local_observe/platform/verification_policy.py` (loader only).
**Tests:** `tests/test_verification_policy.py`, `tests/test_verification_policy_boundary.py`;
the schema is pinned in `tests/test_verification_records.py`. **Example:** `examples/platform/verification-policy.json`
(synthetic: one mapping, no credentials). **Item:** the verification policy loader, split out of the verification workflow. Contracts only:
nothing here reports a test result, a suite outcome or a deployment.

## Purpose

`VerificationPolicy` (see [verification records](verification-records.md)) validates and snapshots a
reviewed policy *document*, but it takes that document as an argument — until recently the only such callers
were tests. This unit is the missing operator contract: the variable that names the service file, one
strict read of it, and one crosscheck of the verifier list against the credentials the process mounts.
A loader, not a feature: it mounts nothing itself and enables nothing itself — since the verification API the service
startup calls it once and hands the result to the store, which is the only enabling that happens here.
`LO_VERIFICATION_POLICY` is **not** `LO_VERIFY_CONFIG`, the evidence-only worker's own configuration in
`platform/verification.py`, and that worker's loading and behaviour are unchanged.

## Public API

- `policy_from_environment(credentials, *, environ=None) -> VerificationPolicy | None` — read the
  environment **at call time** (`os.environ` unless a mapping is supplied) and load what it names.
  **Absent key means off:** `None`, with no file opened, no `credentials` iteration and no parsing. A key
  present but blank, whitespace-only or not a string is a `PolicyLoadError`: an operator who meant to
  mount a policy is never answered with the off switch.
- `load_policy(path, credentials) -> VerificationPolicy` — read *path* once and return the policy, after
  the credential crosscheck. *path* must be a non-empty `str` or `pathlib.Path`.
- `PolicyLoadError(ValueError)` — every refusal: one fixed sentence naming no path, no value and no
  parsed content, chaining no underlying exception.
- `CONFIG_ENVIRONMENT = 'LO_VERIFICATION_POLICY'`.

The result is the same immutable `VerificationPolicy` that `Store(path, verification_policy=…)` already
accepts — no wrapper and no second policy type.

## What is refused, and by whom

The **file**: a missing path, a directory, anything that is not a regular file, an unreadable path, a
document over `MAX_POLICY_BYTES` (65 536 — the bound `VerificationPolicy` already owns, counted on the
bytes as stored, so whitespace and comments count), bytes that are not valid UTF-8, or a byte-order mark.
The file is opened with `O_NONBLOCK` where the platform has it and `fstat` on that descriptor decides
regularity, so **a FIFO is refused instead of hanging the caller**; it is read once, in binary, never
retried.

The **document**: not one JSON object; a syntax error, trailing content or comments; a key stated twice
**at any depth** (`json` alone keeps the last one); `NaN`, `Infinity`, `-Infinity` or a literal that
overflows to infinity; nesting or size past the bounds `verification_records._plain` owns. The schema —
key sets, the strict `schema_version: 1`, the verifier/mapping limits — stays `VerificationPolicy`'s and
is **not** duplicated here. Any parser failure, `RecursionError` included, leaves as one
`PolicyLoadError`. No YAML, no default policy, no fallback to a cached or previous document, no hot
reload, no cache, no network, no database, and no log line carrying a path, a variable value or a policy.

## The credential crosscheck (and what it is not)

Parsing comes first and `credentials` is touched only afterwards, so a broken policy reports as a broken
policy. `credentials` must be a list/tuple of 1–256 plain dict rows with exactly `identity`, `role`,
`token`; the identity is checked with `state.label` and the role against the six `api.create_app` knows
(`reader, producer, proposer, human, executor, summary`). Then, for every identity the policy names as a
verifier: **at least one `producer` row must carry it and no row of any other role may.** Two producer
rows for one verifier (a pair across a token rotation) are fine, and valid rows for roles that never
verify are nobody's business here.

**Token values are never read** — presence is checked on the *keys* only (`set(row)`). No token is
stringified, retained, lengthed or strength-checked, and `credentials` is untouched when the variable is
absent. So this is **not** token or authentication validation: `api.create_app` keeps that job (the
duplicate-token and minimum-length rules, the bearer match, building the `Actor`). Nothing here can
authorise a request.

## Configuration, as an operator declaration

| key | required | bounds | what it does |
| :-- | :-- | :-- | :-- |
| `LO_VERIFICATION_POLICY` | no | a regular file's path | absent = no policy mounted (verification stays off); present-but-bad = refusal to load, never a default |
| `verifiers` | yes | `state.label`, 1–32, distinct | who may file an observation — each one must also be mounted as a `producer` credential row |
| `mappings` | yes | 0–64, one reviewed meaning per detector revision | what a bound signal numerically means; see [verification records](verification-records.md) |

Like the inventory declaration, the document is reviewed content: authored in the repository, mounted
read-only, not edited by the service. `examples/platform/verification-policy.json` is a complete
one-mapping example with a synthetic resource UUID and artifact pin; neither names a live resource.

## Immutability, backup and restore

The loaded policy snapshots the reviewed document. Changing the source file or accessor results
cannot change that object. Stored action bindings preserve their original meaning when a later caller
loads a changed policy. This helper performs no reload, and the service does not either: one policy is
resolved at start and lives for that process, so editing the mounted file changes nothing until a restart.

Back up the operator's versioned policy declarations before edits and restore the reviewed revision
alongside the appropriate credential configuration. Tokens stay in their separate secret store.
Existing database bindings are not rewritten by a restored policy. There is no new state schema,
retention rule, component mount or backup mechanism in this slice.

## Consumed by the service now — and what that still does not do

Since the verification API the application factory calls `policy_from_environment(credentials)` in `app_factory`,
immediately after the credential validation `create_app` already performed (extracted verbatim as
`api.validate_credentials`, called from both entry points) and **before** any store or notification client is
constructed; the result goes to `Store` by keyword. `api.create_app` accepts the same object through
`verification_policy=`, and neither path reads the environment twice or re-reads the credential file. An unset
variable still yields `None` with no policy I/O; a bad credential set or a bad policy file fails before a
database, a thread or a client exists — which is not a promise that every other startup failure is I/O-free,
and no automatic migration is invoked by any of this.

The credential crosscheck is not authentication; `create_app` retains bearer validation.
A mounted policy authorizes listed producers to submit observations and discover follower candidates.
With no policy mounted, those operations refuse; existing authorized saved-history reads remain
available. The [CLI](verification-cli.md) and execution UI already expose records independently
of the loader. The opt-in [follower](verification-follower.md) needs its own configuration and
credential; mounting a policy alone starts no process. `LO_VERIFY_CONFIG` still controls only the
older evidence worker. This source change claims no deployment or live verification.
