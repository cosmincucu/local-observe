# Conformance — component `crowdsec`

Status: **not run**. Every runtime row below is `not-run`, including the ones that look trivial: no
container has been started from `components/control/crowdsec/compose.yaml`, no `docker compose config`
has rendered it on a host, no alert has reached `/v1/intake/crowdsec` over a socket, and no decision has
been read from a Local API. What *is* executed on every commit is the deterministic half, listed first,
because that half is the part that can lie silently if nobody pins it.

## The scenario this component owes

There is no CrowdSec row in `docs/COMPONENTS.md` §5 — §3 says crowdsec is *"not a matrix row"* but a
treatment — so this component proves itself against the two scenarios it can actually be seen in, and
says which it is borrowing:

* **`Security detection`** (*"Positive and negative reference-schema fixtures; absent sensor detected;
  replay does not multiply findings"*). Borrowed because a CrowdSec alert is a security verdict arriving
  from outside, and those clauses are exactly the things an inbound normaliser can get wrong. It is the
  *same* scenario Sigma owes; Sigma compiler owns the Sigma half and nothing here claims that row moves.
* **`Approved action`** (*"Authenticated human approval, exact parameter binding, expiry, agent
  self-approval rejection, outcome reconciliation"*). Borrowed for the apply/remove path, with the one
  clause it cannot complete named below.

### `Security detection`, one clause per row

| Clause | Test | What it would catch |
|---|---|---|
| positive fixture — a real-shaped alert becomes coverage (resolved) then one `security` finding, in that order, and both pass `state.validate_event` | `tests/test_crowdsec_intake.py::SecurityDetectionTests::test_positive_fixture_a_declared_alert_becomes_coverage_then_a_security_finding`, `::test_both_events_are_admissible_canonical_events` | a finding with no coverage row, which reads as "the sensor was fine" on a path nobody has watched |
| negative fixture — an undeclared scenario yields coverage about the intake source and opens nothing | `::SecurityDetectionTests::test_negative_fixture_an_undeclared_scenario_is_coverage_and_opens_no_condition` | a guessed kind: intake paging for a scenario nobody declared |
| the evidence rule — a missing or invalid native event count files coverage; existing metadata selectors retain numeric and boolean readings | `::SecurityDetectionTests::test_a_declared_alert_with_no_keepable_reading_is_coverage_and_not_a_verdict`, `::test_existing_metadata_selectors_keep_numeric_and_boolean_readings`, `::IntakeRouteTests::test_shipped_rules_preserve_native_count_and_replay_through_authenticated_http` | a synthesised evidence reference — §6 `aiops/ingest`'s named failure |
| absent sensor detected — the coverage row names the condition it is coverage *of* | `::SecurityDetectionTests::test_absent_sensor_the_coverage_condition_is_the_one_intake_wrote` | a coverage event on a condition nobody reads, which stays firing forever and pages once |
| replay does not multiply findings — the same notification is byte-identical, folds to `duplicate`, and two alerts of one window do not collide on one row | `::IdentityTests::test_reposting_the_same_notification_is_byte_identical`, `::test_the_same_id_is_the_row_intake_holds_and_no_other_alert_shares_it`, `::test_two_alerts_in_one_window_do_not_answer_event_retry_changed_contents`, and over the route `::IntakeRouteTests::test_a_repeated_notification_is_duplicate_and_not_a_second_incident` | `Event retry changed contents` as a 400 for the whole envelope, or one lost alert becoming nine |
| linking is enrichment — a declared address resolves to its UUID, an undeclared one is admitted with `resource_id = null` and a visible `resource_link` | `::LinkingTests::test_an_address_the_declaration_names_is_linked_to_its_uuid`, `::test_an_address_no_one_declared_is_admitted_unresolved_and_says_so`, `::test_no_index_configured_links_as_not_configured_rather_than_as_unknown` | a resource identity invented from a hostname, which is the defect `docs/CONTRACTS.md` §4 refuses |
| a malformed payload is refused whole, and the sentence names the alert's position | `::RefusalTests::test_a_malformed_alert_refuses_the_whole_envelope`, `::test_the_envelope_must_hold_an_alert_array_and_little_else`, `::test_windows_that_cannot_be_honest_are_refused` | a partially admitted envelope: five of nine alerts stored is a worse outage than none |

### `Approved action`

| Clause | Test | What it would catch |
|---|---|---|
| exact parameter binding — the address is in `parameters`, in canonical spelling, one `type`, a bounded `duration`, a required `reason` | `tests/test_crowdsec_actions.py::ProtectedDestinationTests::test_the_canonical_spelling_rule_closes_the_padding_evasion`, `::test_a_duration_that_never_ends_is_not_a_valid_parameter`, `::test_an_unexplained_block_is_refused`, `::test_a_type_other_than_ban_is_refused_because_the_kept_half_of_q11_has_no_other_verdict`, `::test_a_removal_cannot_smuggle_a_ban` | a proposal that approves a number, or `192.000.002.007` approving what `192.0.2.7` would be refused |
| protected destination refused, audited, and nothing half-written | `::ProtectedDestinationTests::test_blocking_a_protected_address_is_refused_with_an_auditable_reason` (see "The refusal proof" below) | a gate that lives in a prompt instead of in the mounted policy document |
| authenticated human approval | `tests/test_crowdsec_actions.py::SeparationTests::test_the_proposer_role_cannot_approve_its_own_proposal`, `::test_an_executor_role_cannot_approve_either`, `::test_a_human_approves_and_the_audit_trail_names_proposer_and_approver_separately` | an agent approving its own block. **Read the correction below** — this repository's invariant is role separation, not identity separation |
| expiry | inherited: `state.propose_action` refuses an expiry outside the next 24 h, pinned in `tests/test_action_invariants.py`; nothing here re-implements it, so a second expiry rule cannot disagree with the first |
| outcome reconciliation | **not-run**, and un-run-able from this component: nothing claims an outcome because nothing claims an action (no writer ships — `CONTRACT.md` §3). The lifecycle methods are tested elsewhere; the CrowdSec-shaped end of them is not |

**Correction to the borrowed clause.** §5's "agent self-approval rejection" and this card's brief line
"the actor who proposed it cannot be the actor who approved it" are *not* what `Store.decide` implements:
it requires the `human` role and never compares identities, and
`tests/test_action_invariants.py::test_a_human_who_proposed_may_approve_and_both_sides_are_durable`
pins that on purpose. The enforced separation is by role, and both identities are durable
(`actions.requester`, `actions.decided_by`, plus `action.proposed`/`action.approved` audit rows). The
tests above assert that shape; changing it is a `docs/CONTRACTS.md` §5 decision, not a worker's edit.

## The refusal proof that matters

`tests/test_crowdsec_actions.py::ProtectedDestinationTests::test_blocking_a_protected_address_is_refused_with_an_auditable_reason`:
propose `crowdsec-decision-apply` for an address inside the shipped protected list, over a real `Store`
and a real `policy.action_policy` built from the shipped `actions.example.json`, with the incident behind
it produced by the real normaliser from a fixture alert. It asserts three things at once, because any one
alone is satisfiable by accident: the proposal raises `Action parameters do not match allowlisted
schema`; **no `actions` row exists afterwards** (the refusal rolled back, it did not half-write); and
exactly one `action.refused` audit row was written, naming the proposing identity and classifying to
`policy-parameters-schema` — a word `refusals.SENTENCES` already knows, not `unclassified`.

The mirror tests prove it is a gate and not a wall: the same proposal for an address outside the
protected list lands `pending`
(`::test_an_allowlisted_address_is_proposable_and_lands_pending`), a neighbour of a protected `/32` is
proposable while the whole protected `/24` is not (`::test_a_protected_host_does_not_swallow_its_neighbours`),
and the strongest refusal in the component is not the allowlist at all — an **unedited** deployment stops
at `policy-target-opt-in`, because nothing in the shipped inventory is opted into remediation
(`::test_an_unedited_deployment_refuses_every_block_before_the_address_matters`).

## The read-only proof, and the envelope seam

Two promises are not about actions and are pinned separately, because both are one-line edits away from
breaking:

* **The Local API client cannot block anything.** `tests/test_crowdsec_client.py::SurfaceTests` names the
  two public methods, refuses a list containing any write verb, and reads the module's own syntax tree to
  assert every `self.client.request(...)` call site is a literal `GET` with no payload — a method list can
  grow by one line, and that line now has to be reviewed as the change in power it is. The key rides
  `X-Api-Key` and never `Authorization` (`::test_the_key_is_an_api_key_and_never_an_authorization_header`),
  matching upstream's split between an API key (reads) and a machine credential (writes).
* **The inbound body is an object with one `alerts` key, not upstream's bare array.** `api.py` answers 400
  `Expected a JSON object body` to a non-object POST body for *every* route, so upstream's shipped
  `format: {{.|toJson}}` cannot be posted as-is; the example wraps it. Both ends are pinned:
  `tests/test_crowdsec_intake.py::IntakeRouteTests::test_a_bare_array_body_is_refused_by_the_transport_before_this_source_sees_it`
  and `tests/test_crowdsec_component.py::ExampleCompositionTests::test_the_shipped_notification_template_wraps_the_array_the_transport_refuses`.
  The transport's **64 KiB** body ceiling — not `MAX_ALERTS` — is the operative bound on one notification,
  pinned by `::IntakeRouteTests::test_a_body_over_the_transports_ceiling_is_refused_without_being_normalised`.

## 1. Deterministic half — runs in CI today

Command (repository root, the base tier of `docs/testing-standards.md`):

```
python -B -m unittest discover -s tests
python -B scripts/check_foundation.py
python -B scripts/check_foundation.py --compose examples/crowdsec/compose.yaml
python -B -m local_observe.platform.crowdsec --check-rules examples/crowdsec/intake-rules.json
python -B -m local_observe.platform.crowdsec --check-actions components/control/crowdsec/actions.example.json
```

| Claim | Test | What it would catch |
|---|---|---|
| the five artefacts, the manifest and the two JSON fragments exist and parse | `tests/test_crowdsec_component.py::ShippedArtefactsTests` | a component directory no `check_example` walk ever reaches — exactly what "optional, in no example" makes possible |
| the manifest passes the model rules the gate uses, declares one service and no bouncer, and gives both upstream-required directories a volume | `::ModelGateTests` | a `privileged`/`network_mode: host` line appearing here, which is the check this component deliberately does not weaken |
| the example gates clean through its `include`, and every required variable has a template line and vice versa | `::ExampleCompositionTests::test_the_example_gates_clean_through_its_include_entry`, `::test_env_template_covers_every_required_variable_and_nothing_else` | a manifest demanding a variable no template names: a boot failure an operator discovers, not a test |
| the two defaulted variables default to the safe reading (online API off, nothing collected) | `::ExampleCompositionTests::test_the_two_defaulted_variables_default_to_the_safe_reading` | a default that enrols the machine against the Central API, which community blocklist dependency says is opt-in |
| nothing is published, and `HOST_PUBLISHED_SERVICES` is untouched | `::PublicationTests` | a `127.0.0.1:` line added here silently widening the exposed surface of the whole product |
| the pin names a release digest, the date and URL it was read from, the licence and where it was read, and carries the UNVERIFIED list | `::PinTests` (six rows) | a `latest`-channel digest passing as a pin, and the unverified half being dropped on a re-pin |
| no bouncer image is pinned anywhere, and the name appears only where the file says it was not verified | `::PinTests::test_no_bouncer_image_is_pinned_anywhere_and_is_named_only_where_it_is_refused` | a manifest pulling a repository nobody resolved (the Docker Hub name 404s, measured 2026-09-09) |
| the action definitions are the generated ones, and the readable protected list cannot drift from the enforcing schema | `tests/test_crowdsec_actions.py::DefinitionDocumentTests` (nine rows) | a hand-edited regex that protects less than the file claims it does |
| no estate identifier or credential value appears in the component or the example, and the bearer line is a placeholder | `::PrivacyTests` (and the gate's own privacy walk) | a topology leak in an "optional integration" directory, which is where the last one was found |
| the adapter holds the vocabulary line: no severity literal, no resolved verdict, and the sample parser equals `intake`'s | `tests/test_crowdsec_intake.py::SurfaceTests` | loudness decided in an adapter instead of in `vocabulary` — the defect event vocabulary exists to prevent |
| `crowdsec` registers once, admits only its vocabulary's kinds, and its bounds are the documented ones | `tests/test_crowdsec_intake.py::RegistrationTests` | a second emitter bypassing the normaliser, and a rules file widening a closed type space |

## 2. Runtime half — every row `not-run`

Each row is a recipe, a host and an expected answer. None has been executed. A row cannot be closed by
reading upstream documentation; that is what `versions.json` is for.

| # | Recipe | Expected | Status |
|---|---|---|---|
| 1 | `docker compose config` then `up -d` on the example with a real image | starts with `read_only: true` and `cap_drop: [ALL]`; if it does not, the fix is a tmpfs line in the manifest, not a writable root | **not-run** |
| 2 | `docker compose exec crowdsec cscli machines list` | the entrypoint minted its own machine; whether the container can run as a non-root uid is conformance, not a manifest line | **not-run** |
| 3 | `LO_CROWDSEC_CAPI_DISABLED=false` after human enrolment, then `cscli capi status` and a decision whose `origin` is the community blocklist | the blocklist either arrives or does not, and the shipped `true` is proven to stop it. The pinned README only claims this variable "disable[s] online API registration for signal sharing" | **not-run**, and blocked on a human (an account, a key, possibly 2FA: community blocklist dependency, `CONTRACT.md` §8) |
| 4 | Render `examples/crowdsec/{profiles.yaml,http-notification.yaml}` with a real token, `up -d`, then `cscli decisions add --ip 203.0.113.9` and watch the platform's answer and the store | `{"source":"crowdsec","events":[…]}` with `accepted`, one coverage row and one `security` row, `resource_link` matching what the inventory says about that address — and this is the run that proves the wrapped-`alerts` template, which today is only proven against the in-process app | **not-run** |
| 5 | Stop the engine, leave the rules document pointing at source `crowdsec`, restart the platform | starts normally and refuses every POST (today's truth, `CONTRACT.md` §10); the row is here so a later reader can see it was measured and not assumed | **not-run** |
| 6 | Restore `backup.md`'s verified tar into a scratch volume, start a second project, `cscli decisions list` | the same decisions, with their original expirations | **not-run** |
| 7 | Upgrade across one release boundary with a live decision, then roll the digest back with the same volume | a *named* answer to "is the newer schema readable by the older binary?", which is what `upgrade.md`'s rollback section currently refuses to claim | **not-run** |
| 8 | One ssh brute-force burst against a test host, end to end: log → acquisition → scenario → notification → intake → incident → approval | the §5 `Security detection` clauses on real data, and the alert volume this component adds to the outbox — the number `CONTRACT.md` §7 declines to invent | **not-run** |
| 9 | `GET /v1/decisions` through `LocalApi` against a running engine, with `cscli decisions list` beside it | the same decision set, `simulated`/`until` read as the pinned model spells them. The four query keys this client sends (`ip`, `range`, `scope`+`value`) are upstream's own — `pkg/apiclient/decisions_service.go::DecisionsListOpts` at v1.8.1 — but no CrowdSec endpoint has ever answered one from this checkout, and `type=`/`contains=` are deliberately not sent (`crowdsec.py::LocalApi.decisions` says why) | **not-run** |

## 3. What this file cannot make true

The bouncer is not here, so no row proves anything about a firewall. `check_foundation.py` does not walk
this component on its default run (it is in no `EXAMPLE_MANIFESTS`), which rows above close for the
shipped files and **cannot** close for an operator's own overlay: a bouncer added there — its
`privileged`, its `network_mode: host`, its blast radius — is outside every check this repository runs.
Neither can it see the notification plugin's `Authorization` header, which travels inside a mounted YAML
rather than in a Compose model that `check_credential_files` polices. `CONTRACT.md` §9 keeps both
sentences where a reviewer will read them.
