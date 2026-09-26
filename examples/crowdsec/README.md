# `examples/crowdsec` — the optional CrowdSec integration (crowdsec)

One container that decides, and nothing that blocks. This directory is the shape an operator adds to
their own composition to get CrowdSec's Local API as a decision store (threat detection engine), its alerts arriving as
platform events through the intake normaliser (event intake), and every block still needing a human (auto-block authority).
The engine detects; **this integration blocks nothing**, because the thing that would block — a
bouncer, needing netfilter and host networking — is not shipped, and `CONTRACT.md` says why the
product's own gate is right to refuse it rather than an obstacle to work around.

Read first: [`components/control/crowdsec/CONTRACT.md`](../../components/control/crowdsec/CONTRACT.md)
(what this is, and the four sentences it must not be read as promising), then
[`versions.json`](../../components/control/crowdsec/versions.json) (the pin, the digests, the URL each
was read from, the date, and the list of what is still UNVERIFIED).

## What is in this directory

| File | Read by | What it is |
|---|---|---|
| `compose.yaml` | `docker compose`, `check_foundation.py --compose` | one `include:` of `components/control/crowdsec/compose.yaml`, and nothing else |
| `.env.example` | the two commands above | every variable those manifests read: five required, two defaulted |
| `profiles.yaml` | the CrowdSec container (`/etc/crowdsec/profiles.yaml`) | which alerts notify, and the `simulated: true` line — **on the decision, not on the profile** — that keeps CrowdSec from remediating on its own (`pkg/csconfig/profiles.go` decodes this file with unknown fields refused, so a profile-level `simulated:` is a start-up failure, not a flag) |
| `http-notification.yaml` | the CrowdSec container (`/etc/crowdsec/notifications/http.yaml`) | the URL and bearer token for posting alerts to the platform, and the `format` line that wraps the alert array in one `alerts` key (see step 2 of Bring-up: this is the one place upstream's shipped default must **not** be pasted); **carries a credential**, keep it 0400 |
| `intake-rules.json` | the platform container (`LO_INTAKE_RULES`) | the declared scenarios and rule identities; `alert.events_count` selects the native alert's event count as evidence |

Nothing here is in `scripts/check_foundation.py`'s `EXAMPLE_MANIFESTS` (a fixed three-name tuple this
card does not widen), so the plain gate run does not walk it and cannot tell you it is clean:

```
python -B scripts/check_foundation.py --compose examples/crowdsec/compose.yaml
python -B -m local_observe.platform.crowdsec --check-rules examples/crowdsec/intake-rules.json
```

Both are what `tests/test_crowdsec_component.py` and `tests/test_crowdsec_actions.py` run in CI, so a
shipped shape that stops validating fails a test rather than surprising an operator.

## Bring-up, in order

1. **Resolve the pin yourself.** `versions.json` names
   `crowdsecurity/crowdsec@sha256:dd16bad0…` for `linux/amd64` at tag v1.8.1, and the resolver that
   produced it (`scripts/resolve_images.py::resolve`). Pull by digest; the manifest sets
   `pull_policy: never`, so an image that is not already in the daemon is a start failure and not a
   pull you did not approve.
2. **Render the two operator files** from the shapes above into the paths your `.env` names, at 0400.
   `http-notification.yaml` needs the token of the `crowdsec` producer row in your platform role file —
   a role file may not have two rows with the same token, and `intake_target` refuses a path that names
   anyone other than the authenticated caller, so this row is one identity with one token.

   Keep the `format` block as shipped:

   ```yaml
   format: |
     {"alerts": {{.|toJson}}}
   ```

   Upstream's own default file renders `{{.|toJson}}` alone, which is a bare JSON **array**, and this
   platform's POST handler answers `400 Expected a JSON object body` to a body that is not a JSON object —
   a rule that guards every write route here, not an invention of this component. So the one-key wrap is
   what makes the two speak: the plugin's `format` is the operator's template, the array inside it is
   still byte-for-byte upstream's rendering, and no envelope contract is loosened for the four other
   intake sources. Paste the default instead and the engine retries against a 400 you will only find in
   the plugin's own log, and the platform stores nothing at all.
3. **Add the two platform-side lines.** The platform service you already run is the one that receives,
   so these belong to it and not to a second `include` entry (a second `platform:` block would not
   merge, and a second container would refuse to serve: the state database is exclusively locked):

   ```yaml
   environment:
     LO_INTAKE_RULES: /config/intake-rules.json
   ```

   …and put your rendered `intake-rules.json` inside `LO_PLATFORM_POLICY_DIR`, the directory already
   mounted read-only at `/config` (`components/control/platform/compose.yaml`). An unset
   `LO_INTAKE_RULES` is the documented off switch: every `/v1/intake/...` POST is then refused with a
   reason naming the variable, so a half-wired install cannot quietly turn alerts into nothing.
4. **Merge the two CrowdSec actions** into the platform's `LO_ACTION_POLICY` file
   (`/config/actions.json`) from
   [`components/control/crowdsec/actions.example.json`](../../components/control/crowdsec/actions.example.json),
   and replace its three protected networks with your VPN path, your LAN gateway and your ISP ranges
   (auto-block authority). Then check the merged file and restart the platform:

   ```
   python -B -m local_observe.platform.crowdsec --check-actions /path/to/actions.json
   ```

   **Until you edit those three lines, no block can be approved at all.** The shipped values are RFC
   5737 documentation ranges, which cannot be your hosts, so every address you would plausibly block
   passes the gate and every address you would regret blocking is inside one of them. That asymmetry is
   the intended default: an unedited file is a useless component, not a locked-out estate.
5. **Start it, and prove the path with one real alert** before believing anything else:

   ```
   docker compose --env-file <your .env> -f examples/crowdsec/compose.yaml up -d
   docker compose exec -T crowdsec cscli alerts list
   docker compose logs --since 5m platform | grep -i intake
   ```

   With no traffic to generate, `cscli decisions add --ip 203.0.113.9` is the way to make one alert
   exist; watch it arrive as one `security` event and one `coverage` event, and check the
   `resource_link` answer in the POST response is what your inventory says it should be. This is row 4
   of `conformance.md` and it has not been run from this checkout. (That address is inside one of the
   three shipped protected ranges on purpose: the same run then proves the refusal, if you get as far as
   proposing a block for it in step 4.)

## Journald instead of files

threat detection engine's kept half is "fed from files/journald". The pinned image README is explicit that journalctl
support exists only in the **debian** build, so the files-only shape above is not the whole decision:

1. pin `LO_CROWDSEC_IMAGE` to the debian digest in `versions.json`
   (`sha256:a5575ae7…` at v1.8.1, not the alpine default);
2. add one read-only bind to the service — the journal from the host, which the upstream README names
   as `/var/log/journal:/run/log/journal` — in your own overlay, not by editing the component;
3. point an `acquis.d` file at the journal source instead of a `filenames:` list.

Step 2 is not shipped in `components/control/crowdsec/compose.yaml` because a bind whose variable could
default to an empty source is a boot failure nobody can diagnose, and `create_host_path: false` cannot
help an unset path. That trade is stated rather than hidden: **the journald half of threat detection engine is an operator
edit and is unproven here.**

## What this integration never does

- **Blocks nothing.** No bouncer ships; no decision is applied to a firewall by anything in this
  repository. And the converse sentence matters more: **an address a bouncer you added yourself
  previously applied stays applied** when this component is disabled, removed or upgraded. There is no
  code here that can undo it, because undoing is the write path this repository does not ship.
- **Does not enrol.** `LO_CROWDSEC_CAPI_DISABLED=true` is the shipped default (community blocklist dependency), and turning it to
  `false` only works after a human registers this machine — an account, a key, possibly 2FA. That step
  requires explicit installation approval. `versions.json` also records that what upstream documents
  for this variable is "disable online API registration for signal sharing", so "off really means the
  blocklist is off" is a row `conformance.md` still owes.
- **Does not close what it opened.** CrowdSec's notification plugin reports new alerts and never a
  decision's expiry, so no CrowdSec alert can carry `status='resolved'`. An incident opened from a
  brute-force finding is closed by the platform's own judgement or by a human — the reason is in
  `CONTRACT.md`, and it is the thing an "auto-close on decision expiry" adapter would have to solve
  rather than route around.
- **Claims no alert budget.** notification budget's precision metric is Sigma compiler's to measure. `CONTRACT.md` says the
  number for this component has never been measured instead of inventing one.
