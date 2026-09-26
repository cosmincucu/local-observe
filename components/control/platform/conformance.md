# Platform conformance

Run these checks against your selected installation. Record the source revision,
configuration, results and limitations outside product source.

## Delivery and callback recipes

Each recipe below is what a reviewer runs to see the clause, and what it must show. None of them
requires a real phone, a real Telegram bot or a reachable inbound URL; the last one names what
none of them can substitute for.

1. **Channel isolation.** Two channels configured, the first given `max_attempts: 2`. Send five
   alerts. Expect: two sends on the first, three on the second, `GET /v1/notifications/safety`
   reporting `channels.primary.circuit_open` true with `channels.oncall.circuit_open` false, and
   `notification_reservations` charging 2 and 3. The same numbers are asserted in
   `tests/test_notification_channels.py`. A second breaker that opens because the first one did is
   the failure this recipe exists to catch.
2. **Cause, and what a cause must not carry.** Point a live channel at an endpoint that refuses
   connections, deliver once, then read the attempt row. Expect `result=failed`, `cause=transport`,
   and one row whose every value is an identifier, a status or a timestamp: grep the attempt row,
   the audit rows and the log lines for the credential and the endpoint path and find neither. The
   same grep against a forced Telegram opener failure is
   `tests/test_notification_attempts.py::TelegramRedactionTests`.
3. **Approval through the callback (§5 "Approved action").** Open an incident, propose one action
   against it, deliver the alert to a webhook receiver that can post back, then
   `POST /v1/callbacks/<channel>` with `{"token": <code from the delivery>, "action_id": <id>}` and
   a `human` credential. Expect `200 {"status": "intent_recorded", "decided": false}`, one
   `action.approval_intent` audit row naming the credential's identity, the action still `pending`,
   and no execution row. Then: `/v1/actions/decision` under that human credential moves it, and a
   `proposer` token is refused the decision. Expired code, spent code, wrong code, a code minted for
   another channel, an action from another incident and a `reader` token are each refused with the
   answer named in `local_observe/platform/README.md`, and every refusal leaves the action
   `pending` and the code unconsumed where the refusal was not about the code. `tests/
   test_notification_callbacks.py` asserts all of it against the ASGI app itself.
4. **Schema v3 across a copy.** Migrate a v2 file with `lo-platform migrate`, check the verified
   copy, then open the migrated file and read `GET /v1/records/notification_attempts`: every v2
   attempt must name a cause that its own recorded boolean implied, and no v2 row may have been
   rewritten into something more informative than it was. Migration 2 and migration 3 each
   retain their own `schema.migrated` audit row when starting from v1; current builds then
   apply migration 4 separately.
5. **What these do not prove.** The staged webhook receiver is a test fixture, not a phone. That a
   human tapped a message, that the tap reached this platform over the deployed edge rather than a
   loopback, and that the operator could tell which approval a code belonged to on a small screen,
   remain the live-receipt gate named above: they need one inbound route a real device can reach,
   which is a deployment and staging decision, not a unit test. The UI's own wiring of the approval
   code and the per-channel safety view is the operator-surface item's work, not this one.

Not yet exercised at runtime: the credential-file mount and the `recording` default,
which the manifest (`LO_NOTIFICATION_MODE`) and the code (`api.py`, since api errors) now
agree on. The rehearsal above passed credentials in the environment and ran under the
earlier code default of `live`. Both need a staging run before this component can
claim the safer boot.

## Verification storage migration  and the copied-state rehearsal

On a synthetic copy, prove that a normal current-build open refuses a v3 database without changing
its bytes, then run `lo-platform --database <copy.db> migrate`. Read back the verified
pre-v3 backup, both new tables, retained action/execution rows and migration audit.
Prove that SQL UPDATE/DELETE are refused on both verification tables and that
binding/observation content survives reopen and whole-file backup/restore. Tests:
`tests/test_verification_records_migration.py` and `tests/test_verification_records.py`.

One stale claim in this section is corrected here: verifier HTTP routes **do** exist now. The service
mounts `platform/verification_api.py`  — four operations over three paths: `/v1/verification/binding`,
`/v1/verification/records` (GET discovery, POST submission) and `/v1/verification/record`. A write still
requires a mounted, configured verification policy (with none it answers `503 verification_unavailable`);
reads are not gated on that document. None of that is runtime validation for this component: the routes
have not been exercised against a running container here, and the storage checks above are in-process ones.

The copied-state rehearsal's **offline** slice is the copied-state migration regression in
`tests/test_upgrade_copy_rehearsal.py`: a real schema-v3 file built by executing migrations 1, 2 and 3,
copied with `local_observe/deployment/state_copy.py::copy_state` into a new sibling directory with
checkpointing left off, then carried to this build's `VERSION` through the explicit
`Store(..., migrate=True)` door — with an independent per-table row census, both verification tables and
their append-only refusals read back, and the pre-migration copy restored as a file. Its contract and the
limits it states about itself: [copied-state upgrade rehearsal](../../../docs/units/copied-state-upgrade.md).

That is fixture evidence, and three gaps between it and host evidence are load-bearing:

* **Rolling a file back is not rolling the platform back.** Restoring the pre-migration copy returns
  bytes; it says nothing about whether an older image or process starts against them, and no old image
  has been run against a v3 file. Nothing in that suite patches `VERSION` to claim otherwise.
* **The driver now has an explicit isolated migration sequence.**
  `scripts/upgrade_driver.py` uses `scripts/upgrade_rehearsal.py` to obtain the candidate
  image's migration contract, migrate its stopped copy, verify the new backup and all historical
  durable rows, then pin and start the candidate. Offline command-boundary regressions are in
  `tests/test_upgrade_driver.py`; they do not execute Docker. The normal
  `deployment/release.py::transition` still refuses cross-schema deployment. Release documents retain
  `migration: 'none'`; the separately recorded rehearsal sequence grants no production apply.
* **Still open on the copied-state rehearsal:** one authorised isolated runtime rehearsal of `migrate` with
  old-image-plus-verified-copy rollback —
  executors, producers and notification dispatch disabled. No production state, service or credential is
  in scope for any of it, and an older binary refuses a v4 file outright, so no downgrade path exists.

Cross-schema runtime upgrade and rollback are **not yet verified**; earlier same-schema runs above do not
cover v4, and the offline fixture does not close the copied-state rehearsal.

## Agent tool surface and the private overlay (chat integration)

Each step is what a reviewer runs to see the clause, and what it must show. Nothing here needs a
phone, a forge, a model or the store's write path. The reads are HTTP calls to the platform API made
with the agent's own token (the series read is the exception: it goes through
`local_observe/platform/query.py`'s bounded analysis reader; the topology read opens the inventory
snapshot). The deployment this authorises is an example path, not a production host.

The manifest change alone boots nothing. The `mcp` service now exists as
`components/control/mcp/compose.yaml` (MCP component) but no shipped example includes it, and the platform image
still does not carry the SDK (`Dockerfile`: "Optional extras (mcp, pySigma) are not installed and stay
unimported here"), so the surface runs from a source tree with `pip install -e '.[mcp]'` — or from that
component's image once an operator builds it (`docs/BUILD.md`). Nothing has been built or started;
the packaging's own runtime rows are in `components/control/mcp/conformance.md`, all `not-run`.

What that packaging changed about the nine steps below, stated once so neither file has to be read to
find it: the `mcp` component carries **eleven runtime rows** of its own (`components/control/mcp/conformance.md`
§1, every one `not-run`), and steps **1–7 and 9** here can now be run against a built image
(`docs/BUILD.md`, the `components/control/mcp/Dockerfile` line) instead of against a source tree with the
extra pip-installed. Step **8** was never a container recipe — it registers a throwaway tool in a scratch
source tree and asks the static gate to refuse it — so it reads the same wherever the surface runs. And
the sentence that covers both files: none of it has been executed, in either document; a built image would
be the first, and the row that says `not-run` stays `not-run` until someone reads an answer off a running
container.

1. **Stage the map, and see it is a file the operator made.** Write the rows in the policy directory
   that already holds `actions.json` (`LO_PLATFORM_POLICY_DIR`), then check the mode before the boot:
   `install -m 600 mcp-identities.json "$LO_PLATFORM_POLICY_DIR/"` and `stat -c '%a' …`. Expect `600`.
   Expect the same file inside the container at `/config/mcp-identities.json`, owned by the host uid
   and mounted `ro`: `docker compose exec -T platform findmnt -no SOURCE,FSTYPE,OPTIONS /config`.
   `create_host_path: false` is what makes a missing map a refusal that names the path rather than an
   empty directory Docker made.
2. **One credential source, decided before the boot.** With both `LO_MCP_IDENTITIES` and
   `LO_MCP_TOKEN_FILE` exported, no server is needed to see the rule:
   `python -B -c "from local_observe.platform import tools, os; print(tools.credential_source(__import__('os').environ))"`
   raises the refusal that names both variables and neither value. Clearing one of them returns the
   other as a `(kind, path)` pair; clearing both raises `No MCP credential source`; setting
   `LO_MCP_TOKEN` (the value form this surface never reads) is refused on sight. Expect no traceback
   in any of the four to contain a token.
3. **A refused boot boots nothing.** Put a `human`-role row in the map and run
   `python -B -m uvicorn local_observe.platform.mcp:app_factory --factory --host 127.0.0.1 --port
   18000` from a tree with the extra installed. Expect the process to die at boot with an `OSError`
   naming the identity and the role, and expect the port closed afterwards
   (`curl -sS http://127.0.0.1:18000/mcp` refuses the connection). Repeat with a duplicated
   `bearer_token`, a repeated `identity`, a fifth key in a row, a document that is not a list, an
   empty file, and a file over 16 KiB: six refusals, one boot. Then put in a `platform_token` that is
   well-formed but **not** in `LO_PLATFORM_CREDENTIALS` and note what you actually get: the boot
   succeeds and the agent's first request answers `401` — the map is validated on its own, not against
   the role file it is not mounted with. The CONTRACT says so in as many words; if a reviewer wants
   that caught at boot, the change is to mount and check the role file here, and that is a decision,
   not an omission.
4. **One credential names one agent, and the list is not the authority.** Mount two rows, two bearer
   values, roles `reader` and `executor`. From each, `POST /mcp` with `tools/list`, and then with no
   `Authorization`, a second `Authorization`, a blank one and a wrong one. Expect: the two tool lists to
   be **identical** — the whole registered surface is advertised to every mounted agent, because
   hiding a tool is not a gate and an agent should hear "you may not" rather than invent a reason for
   an absent tile; and every unauthorised variant is one 401 with `authentication_required` and no tool
   list, so a list is granted by a credential and never by reaching the port. The one legitimate
   difference in the list is a capability with nothing behind it: with no analysis reader configured,
   `signal_series` is absent, and with no index mounted, `topology_neighbourhood` is absent.
5. **A read carries its provenance and nothing extra.** Call `records` as either agent and read the
   answer: block one is the same document `GET /v1/records/incidents?limit=10` returns to that same
   platform token (compare byte for byte), and block two is `{"query_type","parameters","window",
   "source","read_at"}` whose `window` is the 10-row (maximum 20) slice the tool was allowed to ask
   for. Call `evidence_window` with a `source` and a `sample_id` and expect the platform's own three
   words — `available`, `expired`, `unavailable` — and on `available` the stored sample. Then send the
   same call with `path="../evidence/…"`: expect the refusal that names the argument, raised before
   anything is opened, because `path` is not one of the two this tool takes. Ask for a result over
   64 KiB and expect the sentence v0.1 already sent — `Read exceeds evidence budget; use a smaller
   result limit` — never a truncated document wearing a success.
6. **The action pair's gate, and what each half answers.** With a `reader` row, `propose_action` comes
   back as a tool error reading `propose_action needs role proposer; this credential is a reader`, and
   the same for `execute_action` — refused by the registry, before a request leaves the process, which
   is the version of this test that proves a refusal cost no mutation. Skip the surface and `POST
   /v1/actions` with that reader's platform token directly and the platform's own gate answers
   `400 not_authorised`: two layers, and neither is a 404 hiding the capability. With a `proposer` row
   against a deployment whose `actions.json` allows the target, `propose_action` returns an `action_id`
   with `outcome: "filed, pending human decision"` and `not_performed: ["approved", "executed"]`; `GET
   /v1/actions` shows the proposal, and `GET /v1/audit` carries the `action.proposed` row naming that
   agent's identity — the audit trail chat integration asks for, written by a request no human signed. Approve
   that proposal with a human credential. As the `proposer`, `execute_action` still returns
   `execute_action needs role executor`; as the `executor`, it returns the tool error
   `Execution unavailable: no trusted runner handoff exists; no action was claimed`.
   Repeat the execution call: the action remains approved, execution rows are unchanged and no
   platform audit row is added. No response carries an execution id, runner credential or parameter
   document. The trusted Dagu runner can still claim the approved action directly and use its existing
   journal, dispatch and outcome path; exercise that path only with the isolated synthetic action
   and reviewed DAG binding described in the Dagu conformance procedure. MCP execution remains
   unavailable until a trusted handoff is implemented; there is no configuration switch that enables it.
7. **Nothing secret leaked while any of this ran.** `grep -R` the deployment directory, including
   container logs and the audit export, for each `bearer_token` and `platform_token` value in the map
   and for the runner token: zero hits. Expect the same from the tool list and the descriptions: no
   credential in a schema, and no tool description that names a path, a command or a URL.
8. **The private overlay stays outside (agent delivery pipeline).** Register one throwaway tool in a scratch tree that
   reads a value from outside the product's interfaces — a hostname, a vault path, a `SELECT` of your
   own — and run `python -B scripts/check_foundation.py` plus the suite. Expect the gate to fail on
   the estate identifier or the private path in the product tree, which is the same refusal that keeps
   the eight estate read backends out of `local_observe/`. Then delete that tool from the registry and
   confirm the exposed set shrinks to what `descriptors()` says it is — the surface is the registry,
   not whatever the operator's tree happens to import.
9. **Teardown, and what it must leave.** Stop the MCP process (`Ctrl-C`; nothing else holds its port,
   because none is published), and leave the platform, the store and the example's credentials
   untouched. The map file is the only artifact this feature writes to the deployment tree, and it is
   the operator's: nothing here creates, rotates or deletes a credential, and removing the file plus
   the `LO_MCP_IDENTITIES` line returns the install to exactly the state it was in — which is the same
   claim `docs/INSTALLATION.md` makes about an optional integration that failed.

What these steps cannot prove, and no recipe here should be read as proving it: the SSE resource
stream and stdio transport do not exist to test; the map's `platform_token` values are not checked
against the deployment's role credentials at boot (step 3 names what you get instead); no MCP client
library beyond the pinned SDK has been pointed at this surface; and the topology read has been run
against a synthetic inventory, never a declared estate, so its two-hop budget is untested against real
fan-out.

## Pending four-card staging acceptance

The copied-state driver now admits only source backups below 384 MiB and requires
more than 7 GiB free before creating rehearsal artifacts (eight capped copies plus
4 GiB image/work reserve). Source-volume free space must exceed three times current
SQLite page bytes. Growth during copying and completed size are checked before a
backup receipt is returned. See [the copied-state unit](../../../docs/units/copied-state-upgrade.md)
and the copied-state tests; these source checks do not establish host memory
headroom, successful migration or old-image rollback.
