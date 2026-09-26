# Unit: Gmail identity-alert parser, its trust gate and its offline collector (`identity_mail/`)

**File(s):** `local_observe/identity_mail/providers.py` (the closed vocabularies and the shipped Google
lexicon), `rfc822.py` (bounded structure: levels, headers, encoded words, size limits), `trust.py` (the
attestation model, RFC 8601/9077 `Authentication-Results` parsing, the gate), `parser.py` (bytes → one
classified `ParseOutcome`), `events.py` (a believed finding → the canonical events `Store.intake` admits),
`collector.py` (a bounded tick over an injected `MailSource`, its cursor, its pending batch and its
coverage). **Tests:** `tests/test_identity_mail.py` — 82 tests, offline; one of them replaces `socket.socket`
and `socket.create_connection` with raisers and runs a full tick, so "no network here" is asserted and not
asserted-about. **Item:** the identity mail collector. **Not delivered here:** live Gmail authentication, live IMAP
transport, scheduling and a real DKIM signature check — see *Open* at the end.

## Purpose

Answer one question about one fetched message, fail closed on everything else: *is this a sign-in or
account-change alert from a provider, believed by an authority the operator named, rather than mail that
merely claims to be?* A `yes` becomes one canonical `security` event through the existing product
boundary; every other answer becomes a counted, categorized fact about the feed. This is an **anomaly
feed, not a sign-in ledger** — no consumer API exposes Google's sign-in history, so silence can never be
read as "all clear", which is why the collector's own coverage and parse-failure counts are part of the
product and not diagnostics.

## The trusted input is a receiver's attestation — not the message's headers

`Authentication-Results` is sender-adjacent attacker-writable text: anyone can mail a header saying
`dkim=pass header.d=accounts.google.com`. So the gate (`trust.assess`) reads a separate, required
input — `trust.Attestation`, "the word of receiver *R* about exactly these bytes" — and the header text
inside the message is only ever a **diagnostic**. Consequences, each pinned by a named test:

* **No attestation, no belief.** `attestation=None` is `attestation-absent` → `untrusted`, and the
  diagnostics say `forged-authentication-header-observed` when the message did claim `dkim=pass`.
* **The attestation must come from an operator-named receiver** (`policy.trusted_receivers`) over a
  named channel (`policy.channels`), and must be fresh (`max_attestation_age_seconds`, default 86400,
  with a bounded clock-skew allowance; an attestation from the future is `attestation-from-the-future`).
* **Belief is bound to bytes.** Each `LevelAttestation` names the `sha256` of one level's bytes —
  the fetched blob for the outer level, the embedded message's own bytes (minus the boundary's preceding
  CRLF, RFC 2046) for a forwarded one. A carried-over attestation is `attestation-binding-mismatch`, and
  a transport that re-wraps or normalises mail on the way through fails loudly for every message rather
  than quietly trusting the wrong thing. `trust.sha256_text` is the single definition of what is hashed.
* **Nesting is attested per level.** A `message/rfc822` alert inside a forwarding message needs one
  entry per level *and* the container's signer in `policy.forwarder_dkim_domains`, which is **empty by
  default** — so forwarded alerts are refused until the operator names the forwarders. `arc=pass` alone
  never opens the gate; it is recorded as a diagnostic.
* **A passing attestation is not overturned by a contradictory header.** The digest binding is the
  authority; a verdict that fluctuated with attacker-chosen text would be no gate at all.
* **Content stops at the gate.** An untrusted message is refused before its subject or body is read, so
  no `SecurityAlert` can exist for it and no field text can reach its reasons or codes.

What this deliberately does **not** do: run DKIM's RSA cryptography. It consumes a *verified result*
attested by a receiver. That makes the receiver a security dependency of this unit, stated as such in
*Open* rather than assumed away.

## What is believed, and what the four answers are

Provider identity and alert type come from two closed vocabularies (`providers.PROVIDERS`,
`providers.ALERT_TYPES`) matched against the **last** message level's sender domain and subject/body
lexicon, so a rule id can never contain a subject, an address or a domain a sender chose.
`parse_message` returns exactly one of `event` / `untrusted` / `parse-failure` / `unsupported` with a
fixed code, and never raises for hostile input: missing or duplicated identity headers, a colon-free
line, an undecodable encoded-word `From`, a base64 nested part, a missing boundary, an oversized blob and
a future-dated message each land in a counted category. `now` is a required argument — a gate or a parser
that reads its own clock cannot be tested at a fixed second.

## The event boundary, and one rule that is easy to break

Every event is built by `platform/detections.py`'s own `event` factory and by nothing else — the same
fourteen fields, the same evidence-reference contract, `condition == rule_id`. `events.validate` runs each
one through `state.validate_event`.

* **Windows run backwards from the mail** (`occurred_at - window_seconds .. occurred_at`), because
  `validate_event` refuses a window ending more than 60 s ahead of the instant judging it, and a
  forward window is refused for every alert less than a minute old. This also makes an event's bytes a
  pure function of the message, so re-reading one mail re-files one row (`accepted` → `duplicate`)
  instead of the `Event retry changed contents` refusal.
* **Evidence is `source-heartbeat` and no number is invented for it.** A sign-in alert has no reading to
  reference; manufacturing a `1` sample would be the synthesised reference `docs/CONTRACTS.md` §6 refuses
  by name. So a finding from this feed proves *the collector received and believed this mail* — and only
  the feed's own coverage events make that claim checkable. `Batch.samples` is therefore always empty.
* **No severity mapping.** Firing → `warning`, resolved → `info`, from the factory. How loud "your
  password changed" is next to "a new device signed in" is operator policy, not a producer's choice.
* **An event is identified by `source` + `source_event_id`, and `source_event_id` carries no `status`.**
  This is the trap in the coverage path: two different verdicts sharing one window are *one event* to
  `Store.intake`, and the second is refused as a changed-contents retry — which does not lose a row, it
  wedges delivery (the batch is already persisted as `pending` and is replayed until accepted, so the
  cursor stops and no further coverage is ever filed). `validate_event` cannot see it, because each event
  taken alone is valid. So a coverage window names **this tick** (second resolution) while
  `window_seconds` states the *span claimed*, and the rule id set stays closed to three:
  `identity-mail.source.coverage`, `.parse-failure.coverage`, `.untrusted.coverage`. Same verdict at the
  same instant is byte-identical (that is what makes the pending replay safe); a verdict that changes is a
  strictly later `conditions.watermark`. Pinned by
  `test_a_coverage_recovery_is_a_new_event_and_not_a_changed_contents_retry`.
* **The three coverage rules are `coverage`, not `security`.** Mail that failed the gate is a statement
  about the feed ("something that looked like a provider alert arrived and could not be believed").
  Filing it as a security finding is the mistake the gate exists to prevent; dropping it makes a forgery
  campaign look like a quiet mailbox. Separate condition keys mean a read gap cannot mask a trust gap or
  be masked by one.

## The tick, and what it refuses to pretend

Bounds per tick: `max_messages`, `max_message_bytes`, `max_tick_bytes` (`truncated` and coverage, never a
silent stop), `finding_window_seconds`, `coverage_window_seconds`, `max_silence_seconds`. The batch is
written to the cursor *before* the sink sees it; a failing sink leaves both the pending batch and the
cursor, and the next tick replays before reading. A transport failure files firing source coverage and
leaves `last_success_at` where it was, so a permanently broken read cannot time itself out of the check
that exists to catch it. A changed mailbox generation (`UIDVALIDITY`, stored only as a digest) restarts
the cursor and fires coverage instead of silently skipping or silently re-reading. `Report.reasons` carries
fixed codes and exception class names only — never provider text, never mail text — and the batch JSON is
asserted free of any address, subject, body or generation token.

### The pending record, and which clock it commits on

The pending entry is one read's **commit intent**, not a batch on its own: `batch`, `through_uid`,
`tally`, `generation_digest`, `source_read` — five fields under one fingerprint taken over the whole
record, not over the batch alone, so the intent cannot be edited while the hash still verifies. Replaying
it is then the same source/cursor transition a first delivery would have landed: a generation seen only
in a tick whose sink failed still lands on the replay (so the *next* generation change is recognised),
and a generation restart that read nothing clears `last_uid` rather than keeping the previous mailbox's
position — assigned, not guarded — so the new instance's UID 1 is not skipped. A coverage-only batch whose
`through_uid` equals the cursor replays too: it is level with the cursor, not behind it.

Two clocks, never merged: `batch.observed_at` is when the mailbox was read, and that is what stamps the
cursor, the generation and `last_success_at`; the replay instant is only when the sink was asked again and
lands nowhere. Consequences worth stating: a sink that refuses forever ages the feed into `stale` instead
of looking healthy, and a batch whose read never completed (`source_read: false`) is deliverable as
coverage only — it clears itself and moves no cursor, no generation and no success stamp, and its `Report`
carries the `source-read-failed` reason so no reader can take it for a source success.

What is refused at load time, each leaving the file untouched for inspection: a pending record of the
pre-binding shape (missing `generation_digest` / `source_read`), a fingerprint that does not match the
whole record, a `through_uid` behind `last_uid` with no generation change to explain the rewind, a
`through_uid` that would move the cursor when the read did not complete, an untyped read verdict or
generation digest, and a batch observed after the clock it is replayed on. `schema_version` stays **1**:
no installed or live cursor exists to migrate, so the old pending shape is declared unsupported and
refused rather than quietly migrated or discarded — an operator holding one gets a refusal naming the
shape, and the feed restarts from a cursor this module can verify.

`MailSource` and `EventSink` are the two injection points, and both are abstract here: this unit ships no
IMAP client, no socket, no credential and no scheduler.

## Configuration

| key | bound | what it costs when wrong |
|---|---|---|
| `max_messages` / `max_message_bytes` / `max_tick_bytes` | per tick | too small: backlog + `truncated` coverage, never silence |
| `finding_window_seconds` | 60–86400 | the span a finding claims backwards from the mail's own date |
| `coverage_window_seconds` | 60–86400 | the span claimed by a coverage verdict; also the window-rotation horizon (×4) |
| `max_silence_seconds` | operator | too generous: a dead feed stays quiet instead of firing source coverage |
| `policy` | `trust.TrustPolicy` document | `providers` (≤8), `trusted_receivers`, `channels`, `forwarder_dkim_domains` (default empty ⇒ forwarded mail refused), `max_attestation_age_seconds` |
| cursor path | absolute | its own state file; a bad shape refuses the tick rather than starting over |

## Open — what must exist before this feed is real

1. **A receiver that attests, and the operator's decision about who that is.** The gate's trust is
   borrowed from a named receiver's verification of DKIM/SPF over the exact bytes collected. Gmail's own
   `Authentication-Results`, ARC headers and "mailed by"/"signed-by" text are **not** a substitute and are
   not treated as one anywhere in this unit: they arrive inside the data the gate is judging. The
   integration slice must run the collection at a receiver that performs and records its own
   verification (e.g. the collector's own MX, with its `Authentication-Results` and a digest computed on
   the bytes it accepted), and name it in `trusted_receivers`. Until then the code path is fully wired and
   fully refusing.
2. **Mailbox authentication and transport.** Configure a dedicated mailbox, a supported
   authentication method and a protected credential source; nothing here
   reads a credential, opens a socket or spells a hostname. A real `MailSource` (IMAP `UID`/`UIDVALIDITY`
   mapping, verbatim `BODY[]` fetch — any normalisation of the bytes produces
   `attestation-binding-mismatch`) plus an `EventSink` over `/v1/evidence` then `/v1/events` remain.
3. **Calling `events.validate` at the sink.** `collector.collect` persists and hands over the batch
   without it, because the stub sink accepts anything; the transport must run it before its first request.
   It cannot catch a `source_event_id` collision — that is a property of the pair, and only `intake`
   judges it.
4. **Scheduling, and the producer identity.** The unit is scheduled elsewhere and must be admitted as an
   intake producer whose authenticated identity equals the event `source` `identity-mail`
   (`Store.intake` refuses any other pairing).
5. **Inventory linking.** `resource_id` stays `None` — an alert about an account is not an alert about a
   machine, and deriving a UUID from an address digest is identity invention. It needs a resource kind
   that means "identity account".
6. **One provider template (Google) and no backfill.** The mail backfill integration owns backfills; other providers land when
   their mail actually appears in the feed.
7. **Repo bookkeeping outside this unit's writable scope:** no `DEPENDENCIES.md` row exists for the unit
   yet, and the card's `docs/aiops-reasoning/PLAN.md` is not a path in this tree.
