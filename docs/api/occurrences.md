# Alert occurrences: the measurement, the disposition and the delivery

An **alert occurrence** is one episode of one alert condition, and an operator can do two things to it
without touching the rule that produced it: **acknowledge** it ("I have seen this, stop repeating it") or
**dismiss** it ("this episode is not actionable, close it"). Both are durable, both name who did them, what
kind of credential that was, and why — and neither edits a rule, a condition or a measurement.

The three states below are separate columns of one row, and the whole document exists to keep them
separate. A reviewer who conflates any two of them will produce a system that either loses a real page or
re-pages someone who already answered.

| Axis | Question it answers | Where it lives | Who may move it |
|---|---|---|---|
| Measured condition | Is the source still reporting this? | `incidents.status`, `conditions.status` (`state.py`) | Only a producer, by filing a verdict. |
| Operator disposition | What has an operator decided about this episode? | `occurrence_dispositions`, `occurrence_disposition_history`, `occurrence_dismissals` (schema v12, `dispositions.py`; the role column arrives at v15) | A `human` credential or an `operator-agent` one, through `POST …/acknowledgements` or `POST …/dismissals`. The two have the same effect and are stored apart (§3, D16). |
| Delivery state | Has a message about this gone out? | `outbox.status`, `notification_suppressions`, `notification_attempts` | Only the delivery rail, under `notification_safety.reserve`. |

Nothing in this document changes the first axis: a disposition is not a resolution, and a resolution is not
a disposition. `GET /v1/records/incidents` keeps answering exactly as it did.

## 1. Episode identity: what an occurrence id names

An occurrence id **is** the incident id (`incidents.id`, a canonical UUID) of the episode. That is not a
shortcut; it is the claim that this platform already mints the right identity, and that minting a second
one beside it would give one episode two names.

`Store.intake` opens an incident on a `firing` verdict that finds no open incident for its condition, and
closes it when the last condition pointing at it reports `resolved`. One incident is therefore exactly one
episode, and:

* **It survives a restart and a replay.** The identity is a stored row, so an API process restart, a
  notifier restart and a re-send of verdicts this platform has already seen all resolve to the same
  occurrence id. A replay of an identical verdict is a duplicate to `intake` (`UNIQUE(source,
  source_event_id)`) and creates nothing at all.
* **A boot event's identity must include its boot identity.** A producer reporting discrete occurrences —
  one per boot, one per session, one per run — must put the discrete identity into the event's `condition`
  (for example `condition: "boot-2f6c1a"`), so each occurrence is its own condition and therefore its own
  episode. Dismissing the episode of one boot then cannot silence the next boot, because the next boot is
  not the same condition. A producer that omits it gets one continuous condition, and the bullet below
  applies.
* **A continuous condition is delimited by its recovery/re-fire boundary.** For a condition that reports
  state rather than discrete events (`disk-usage-high`), the episode ends at a genuine `resolved` verdict
  and the next `firing` verdict after it is a new episode with a new id. This is why an acknowledgement
  needs no expiry: it is attached to the episode, and the episode has an end of its own.
* **Message text and evaluation timestamps are never identifiers.** Both change between two reports of the
  same episode: a detector re-renders its sentence, and every evaluation window is new by construction
  (`window.end` is the watermark, and `intake` refuses two verdicts that agree on it). An id built from
  either would give one episode a new name every tick, and every disposition would be forgotten by the next
  report. The `window`, `observed_at` and evidence parameters of a verdict are deliberately absent from the
  identity `intake` uses.
* **A grouped incident is one occurrence with several conditions inside it.** `platform/correlation.py` can
  point several conditions at one incident; the incident id stays the occurrence id, and the read reports
  `members` (how many conditions the group holds) and `rung` (whether this episode is an escalation stage
  of another rule). See §4.

## 2. Disposition states

`state` is what a read reports. It is derived, never stored directly, from the operator's act and the
measurement — which is what keeps a replay from desynchronising it.

| `state` | Meaning | Derived from |
|---|---|---|
| `unacknowledged` | Nobody has spoken for this episode. | No disposition row, episode still open. |
| `acknowledged` | An operator has seen it — a person or an automated operator. Repeats stop; the condition stays open. | `kind = acknowledged`, episode still open. |
| `dismissed` | An operator closed this episode as not actionable. | `kind = dismissed`, episode still open. |
| `source-resolved` | The source cleared it. The episode is over, whatever an operator said before. | `incidents.status = resolved`. |

Transitions an operator may cause, and the one the source causes:

```
unacknowledged ──POST acknowledgements──▶ acknowledged ──POST dismissals──▶ dismissed
       │                                        │                              │
       └──────────── POST dismissals ───────────┴────── a resolved verdict ────┴──▶ source-resolved
```

* **An acknowledgement stops repeats and resolves nothing.** The pending, not-yet-leased deliveries of this
  episode are folded in the same transaction (§3), later escalation rungs of the same episode are held
  (§5), and the condition stays open until a genuine `resolved` verdict arrives — which then resolves the
  incident and is still delivered, because an operator who acknowledged an episode wants to learn it ended.
* **An acknowledgement does not expire.** There is no timer, no re-page-on-silence, and no "ack aged out"
  transition in this contract. A real clear followed by a re-fire is a **new episode**, which is un-
  acknowledged and pages. That is the only way forward: an ack that quietly expired would page someone who
  is working on it, and an ack that never expired but attached to the *condition* would silence every future
  episode of that condition forever.
* **A dismissal closes the episode for alerting, including its own recovery message.** The tombstone in
  `occurrence_dismissals` (§3) is what makes that durable: a later verdict that books another delivery for
  one of the covered conditions is refused by `notification_safety.reserve`, so it cannot page after an API
  restart, a notifier restart or a replay. The *next* episode — a new boot identity, or a re-fire after the
  source genuinely cleared — is a different occurrence with no tombstone and pages normally. A later
  failure of a different rule or resource is a different occurrence too.
* **A dismissal does not resolve the condition.** Nothing here writes `incidents.status` or
  `conditions.status`. A dismissed episode whose source never clears stays measured-open forever, and the
  read says so in two fields at once (`measured.status = open`, `state = dismissed`) rather than pretending
  one is the other. That is a deliberate cost of "neither action edits a rule": the measurement of a
  condition nobody fixed is allowed to look unresolved.
* **An operator may change their mind forward, not backward.** `acknowledged → dismissed` is accepted.
  `dismissed → acknowledged` is refused with `409 conflict` and one sentence, because an acknowledgement
  after a dismissal asserts that somebody is working on this and is better served by the new episode the fix
  will produce than by quietly re-arming a tombstoned one. A dismissal restated with a **different reason**
  is refused too, with `409 conflict` and its own sentence: the tombstones name the conditions that existed
  when the first dismissal ran, so a second one would cover a member that joined since, which is a wider
  silence than the statement the operator made. A restatement with the *same* kind, actor and reason is the
  no-op below and writes nothing. Revoking a dismissal is not offered in this
  contract; it is a row in `docs/api/coverage.yaml`.
* **Repeating a disposition changes nothing.** The same kind, actor and reason against an episode already
  in that state is a no-op: the stored row keeps the *first* actor, reason and instant (durable
  who/when/why means one of each), the revision does not move, and no history row is added. `created:
  false` says so in the answer. Retrying with an `Idempotency-Key` replays the stored answer instead
  (`X-Idempotency-Replayed: true`); retrying with the same key and a **different** body is `409
  idempotency_conflict` and nothing runs.
* **A new reason on an acknowledged episode is a real statement** and is appended to history with a new
  revision. History is append-only and holds every accepted disposition, so "who said what about this
  episode, in what order" is readable after the effective state has moved on.

## 3. What one disposition writes, atomically

One `Store.transaction()` (`BEGIN IMMEDIATE`), in this order, committing or unwinding as a unit:

1. the effective row (`occurrence_dispositions`): kind, actor, reason, instant, integer revision;
2. the history row (`occurrence_disposition_history`), append-only under the same triggers as `audit`;
3. for a dismissal, the tombstones (`occurrence_dismissals`): **one row per (episode, condition) pair the
   group held at that instant**. Keyed by that pair and nothing else — never by the condition alone, which
   is how a dismissal would otherwise swallow the next episode of the same condition, which is the defect
   this whole document is written to prevent;
4. the fold of every delivery of this episode still `pending` (`outbox.status = dead`, a
   `notification_suppressions` row, one `notification.suppressed` audit row naming the disposition), reusing
   `state.record_suppression` so `presentation.delivery_route` and `Store.retry_notification` see the same
   fact they already see for every other fold;
5. one `occurrence.disposed` audit row carrying the actor, the actor's role, the kind, the revision and the
   counts;
6. the retryable projection records (§5).

The audit actor is the identity in the bearer credential the transport compared with
`secrets.compare_digest`, and the audit detail names the **role** that credential presented: `human` for a
person, `operator-agent` for an automated operator acting under its own identity (D16). That role is stored
beside the identity in the effective row, in every history row (`actor_role`) and in the projection payload,
so an answer given by a machine is never read back as an answer given by a person — and never read back as a
weaker answer either, because the fold, the tombstone and the state move are the same code for both.

A body field naming an identity, a role or a credential is refused with `400 actor_claim_refused` before
anything is written (`api_contract.assert_no_actor_claim`), so an agent token cannot acknowledge on a human's
behalf, a human credential cannot act as somebody else, and `"role": "human"` typed into an acknowledgement is
a refused claim rather than a credential.

The identical-restatement rule is role-sensitive for the same reason: a restatement is the same decision only
when kind, reason, identity **and role** all match. One operator mounted twice — a person's bearer and an
agent's bearer sharing a name — has said two different things, and the second statement earns its own history
row instead of being folded into the first.

**A leased or dispatched message is not recalled.** `claim_notification` may be holding a lease on a row of
this episode, or the channel may already have taken it. Neither is undone — there is no recall verb in the
delivery rail and inventing one would be a claim about a provider this platform cannot make. What the
disposition does instead is say so in the answer and in every later read:

```json
"delivery": {"queued": 0, "in_flight": 1, "dispatched": 0, "sent": 0, "suppressed": 0,
             "exhausted": 0, "recalled": false, "uncertain": true}
```

`recalled` is `false` because it is always false in this contract, and `uncertain` is `true` while a row of
this episode is leased (`in_flight`) or has an attempt whose outcome nobody obtained (`dispatched`). An
operator reading "one delivery was in flight" knows the page may still arrive; nobody has to guess.

The two dispositions then part company, and the difference is the tombstone rather than the fold. A leased
row on an **acknowledged** episode returns to `pending` when its lease lapses and is delivered — the operator
said they had this, not that the message was wrong. The same row on a **dismissed** episode returns to
`pending` and is then refused by `notification_safety.reserve`, which asks `occurrence_dismissals` before it
takes a send slot; it never pages again, and the suppression row says which episode and which condition the
refusal is about. Neither case unsent anything: a recall is still not a claim this platform makes.

## 4. Groups, rungs and independent conditions

* **A disposition belongs to an episode, not to a rule or a resource.** `POST …/acknowledgements` on an
  occurrence says nothing about any other occurrence: a second condition with its own incident keeps
  paging, including one that is firing at the same time on the same resource.
* **A new member joining an acknowledged group still pages.** `correlation` moves a newly opened condition
  onto an existing incident, and its opening delivery is booked by the same transaction that moved it
  (`_join_group` keeps `transition = opened`, because pages stay per condition — `docs/CONTRACTS.md` §4).
  A disposition recorded *before* that member existed does not cover it: the fold at §3 reached the rows
  that existed, and the tombstone names the pairs that existed. Silence that grows by inheritance is how a
  dismissed group ends up swallowing an unrelated failure.
* **A disposition recorded after a member joined does cover it**, and covers its rows: the tombstone is
  written per member condition of the group at the instant of the dismissal, so the group is quiet from
  that instant and not before it. It has to be recorded *after*: a second dismissal is refused (§2), so a
  member that joined an already-dismissed episode is not covered by that silence and keeps paging until its
  own episode ends.
* **Later rungs of the same episode stop.** An escalation stage is filed under its own condition
  (`rule.stage2`) and so has its own incident, but the scheduler holds the ladder from the *base* incident
  it tracks. The acknowledgement read in `platform/escalation_reader.py` therefore asks the disposition
  table about the base episode, and an authenticated disposition outranks every legacy signal it already
  reads (§6). Independent conditions are separate tracked entries and page as they always did.
* **A rung's own incident can be dispositioned too**, like any episode, and does not reach back to change
  its base.

## 5. Projections: the downstream that may be down

Committing a disposition is a fact about this database. Two surfaces outside it are expected to learn
about it — a **telemetry metric** (an operator counts acknowledgements and dismissals) and the **rule
card** (the rule's own operator-visible state). Both may be unavailable, and neither may undo the action,
so neither is called inside the transaction:

* the same transaction writes one `occurrence_projections` row per target, `status = pending`;
* a drain (`local_observe.platform.dispositions.drain`) attempts each due row through an **injected** sink
  and records `sent`, or keeps it retryable with `attempts` incremented, a backoff and the exception *class*
  name (`last_error` — never a response body, a URL or a credential);
* no sink configured for a target is a *reported* state, not a silent one: the row stays `pending` with
  `last_error = not-configured` after a drain attempt, and the occurrence read says `pending`;
* a disposition whose every projection failed still reads back `acknowledged`/`dismissed`, still stops the
  pages, and its `GET` answer carries the projection statuses. The action is never undone by a downstream.

```json
"projections": {"telemetry-metric": {"status": "pending", "attempts": 2, "available_at": "…", "last_error": "TransportError"},
                "rule-card":        {"status": "sent",    "attempts": 1, "available_at": "…", "last_error": ""}}
```

The optional sinks are mounted by the deployment; this build ships no default sender and reaches no network
on its own. With nothing mounted, `GET` answers `pending` with `attempts: 0`, which is the truth.

## 6. Legacy acknowledgement reads

Before this contract existed, "a human has acted on this incident" was inferred from two durable side
effects: an `actions` row whose status is past a decision, and an `action.approval_intent` audit row — the
latter written when someone taps the single-use link in a delivered page (`Store.record_callback`). Those
rows stay exactly what they were, and `platform/escalation.py` still holds its ladder when it sees them,
because holding is the direction that does not page somebody twice.

They are **not** acknowledgements on this surface, and cannot be made into one:

* a page-link tap proves that a message reached a human surface and that *someone holding the token*
  answered it. It names nobody — no identity and no role — and `docs/CONTRACTS.md` §5 forbids reading a
  payload field as a claim about which credential is asking. So it yields no `actor`, no `reason`, and no row in
  `occurrence_disposition_history`;
* the disposition reads answer `unacknowledged` for an episode whose only evidence is a tap, and
  `legacy_evidence` names what was seen (`action-decided`, `approval-intent`) beside it. An operator can see
  that somebody tapped, and can see that nobody has given a reason;
* where both exist, the disposition wins: it is the authenticated, reasoned statement, and the scheduler's
  own audit row records which evidence it acted on (`escalation.acknowledged` detail `evidence`).

## 7. Routes

All five are under the boundary's rules: the machine error envelope, one `x-request-id` echoed on every
answer, `Idempotency-Key` on the two writes, `If-Match` (or `expected_revision` in the body) for the
conditional write, and the bounded `limit`/`cursor` page helper. Roles and refusals are in
`docs/api/openapi.yaml`; `docs/api/coverage.yaml` owns the census.

| Route | Role | Notes |
|---|---|---|
| `GET /v1/alert-occurrences` | `reader`, `proposer`, `human`, `executor`, `operator-agent` | One bounded page of episodes, oldest first, with disposition and delivery roll-ups. No filters: `page_params` accepts only `limit` and `cursor`, and refusing rather than clamping is the rule (`docs/api/COVERAGE.md`). |
| `GET /v1/alert-occurrences/{id}` | `reader`, `proposer`, `human`, `executor`, `operator-agent` | One occurrence, with `ETag` = its revision. |
| `GET /v1/alert-occurrences/{id}/history` | `reader`, `proposer`, `human`, `executor`, `operator-agent` | Append-only history, oldest first, bounded page. Every row names its actor and the role that actor presented. |
| `POST /v1/alert-occurrences/{id}/acknowledgements` | `human`, `operator-agent` | Body: `reason` (required), `expected_revision` (optional). Honours `Idempotency-Key`. |
| `POST /v1/alert-occurrences/{id}/dismissals` | `human`, `operator-agent` | Body: `reason` (required), `expected_revision` (optional). Honours `Idempotency-Key`. |

Two of the answers on these addresses do not wear the machine envelope, because they are the transport's
gates and not refusals of this route family:

* a `producer` credential on any of the three reads gets `400 {"error": "not_authorised"}` from the gate
  every `GET` in this product passes through — a producer files verdicts and reads nothing;
* a `summary` credential gets `403 {"error": "summary_only"}` on a read, and `403` plus its audited refusal
  row on a write, both from the pre-existing `summary` gate that runs ahead of routing and so never reaches
  `dispositions`.

A write from `reader`, `producer`, `proposer` or `executor` is the one this module refuses itself: `403
not_authorised` in the envelope.

* A `reason` is required on both kinds and is one printable line bounded by
  `dispositions.MAX_REASON_CHARS`. An empty or whitespace-only reason is `400 invalid_request`: a
  disposition nobody can explain later is the artifact this feature exists to replace.
* No revision expectation is an unconditional write. A mismatch is `412 stale_revision`; the revision tag
  moves when a disposition is recorded **or** when the episode's own status changes, so a recovery that
  happened while the operator was reading refuses their ack rather than silently acknowledging an episode
  that already ended.
* `404 not_found` in the envelope for an unknown occurrence id, for an id that is not a canonical UUID, and
  for a `GET` whose id segment is empty (`/v1/alert-occurrences/`, `/v1/alert-occurrences//history`). Those
  three are deliberately one answer, so the route is not an oracle for id shape. A `POST` to an address with
  an empty id segment, or with extra segments after the command, is answered by the transport instead — the
  flat `404 {"error": "not_found"}` every unmatched address gets — and that asymmetry is load-bearing: the
  idempotency gate claims a key before dispatch, so a malformed address that reached the route would file
  its 404 under the caller's key and hand that 404 to the next real command reusing the key. The gate runs
  only for addresses that really are this route.
* `400 invalid_request` for an address under the prefix that names neither an episode nor its history
  (`/v1/alert-occurrences/<id>/nonsense`): a path this family does not have is a broken caller, not an
  absent episode, and `docs/api/COVERAGE.md` makes that difference mandatory.
* `400 invalid_revision` for an `If-Match` or `expected_revision` that cannot be read as a tag at all, or
  that names a number, a list or an object where a tag belongs. A value that *survives* the tag
  normalisation and merely disagrees is a `412`: as far as the state layer can tell, that caller stated a
  serious expectation about a different revision.
* `403 not_authorised` in the envelope for `reader`, `producer`, `proposer` or `executor` on a write, and
  `401 {"error": "authentication_required"}` in the transport's flat shape for no credential at all —
  authentication precedes routing, so it is not this module's answer to give.

## 8. What is deliberately not here

* **No expiry, no auto-rearm, no "re-acknowledge" timer.** The reasons are in §2.
* **No un-dismiss, and no resurrecting a folded delivery.** A fold writes the durable suppression list
  `Store.retry_notification` refuses to replay; that refusal is the correct one for every fold cause, and a
  dismissal is a fold cause.
* **No disposition over a group as an addressable unit** beyond the incident the operator already sees. A
  grouped incident *is* one occurrence (§1); there is no second id to disposition.
* **No disposition from a CLI flag that mints a human.** The role comes from a mounted credential — a person's
  or an automated operator's, never one a command line asserted. The MCP surface stays excluded for the reason
  §6 gives and `docs/api/DECISIONS.md` D16 states: an automated operator acknowledges with its own bearer on
  these routes, where the role that acted is recorded.
* **No automatic dismissal of repeats.** Repetition is `platform/suppression.py`'s subject (flap folding,
  dependency, declared windows), and it is a measurement judgement. A dismissal is an operator's judgement
  about one episode, and the two must not be conflated: a fold says "this platform has decided not to page", a
  dismissal says "a named credential decided this episode is not actionable, in this role", and only the second
  names who.
