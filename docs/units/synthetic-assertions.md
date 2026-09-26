# Named synthetic assertions and certificate stages

The Gatus detector can retain which configured assertion failed, while keeping
raw response data out of platform evidence. Rules without `assertions` retain
the existing boolean availability behavior and cursor format.

## Gatus attribution

Add an optional mapping to the existing detector rule document:

```yaml
id: synthetic-http
source: synthetics
resource_id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1
kind: availability
max_age_seconds: 120
assertions:
  "[STATUS] == 200": status-ok
  "[HEADERS].X-Ready == yes": ready-header
```

Use the declared inventory resource and the authenticated producer identity.
Each key must exactly match a configured Gatus condition. Each value is an
operator-chosen public assertion name, 1..64 ASCII identifier characters
(`A-Z`, `a-z`, digits, `_`, `.`, `:`, `-`). Names must be unique. Neither a
credential nor a response value belongs in a name. The mapping accepts 1..16
entries; invalid configuration is refused before polling or saving a batch.
It is supported only for availability rules.

The wire contract comes from pinned Gatus v5.36.0
[result.go](https://github.com/TwiN/gatus/blob/v5.36.0/config/endpoint/result.go)
and [condition_result.go](https://github.com/TwiN/gatus/blob/v5.36.0/config/endpoint/condition_result.go):
`results[].conditionResults` is an optional array of
`{"condition": "expression", "success": true}` objects. Raw headers and body
are not exported by this API; certificate expiration is also omitted from
its JSON. The adapter consumes measured condition verdicts and never
reconstructs HTTP measurements from an overall success flag.

Every named assertion is referenced from the availability event as:

```json
{"rule_id": "ready-header", "sample_id": "<digest of the safe assertion sample>"}
```

This is the existing `evidence[].parameters` object. Its source is the rule's
source, matching the producer that stores its sample. The referenced sample
has exactly `sample_id`, `observed_at`, `ok`, `value`. A measured failure has
`ok: true, value: false`; an unmeasured assertion has `ok: false, value: null`.
That pair is the visible **not measured** reason, rather than a fictional
boolean measurement. In both cases overall availability fires even if Gatus's
aggregate success was true. All named results, including passes, are retained
so a reader can identify the failed expectation. No expression, response text,
upstream error string, header value, or certificate SAN is persisted.

An absent or stale overall result, malformed condition object, duplicate
expression or more than 16 upstream conditions opens source coverage and never
recovers availability. Upstream conditions outside the mapping still count
toward that bound. Missing individual configured conditions are visible
unmeasured failures. There is no truncation into a pass. At most 17 evidence
references occur on an event (one overall plus 16 named), inside the canonical
20-reference limit.

The worker saves the aggregate sample, named samples and completed events in
one pending batch, sends **all evidence before events**, then advances its
cursor. Retries deliver those same bytes without polling, rebuilding or using
changed mappings. Old pending batches without `assertion_samples` still replay.

`assertions.evaluate(subject, checks)` separately offers bounded in-memory
`StatusIs`, `HeaderEquals`, `BodyContains` and `TimingUnder` checks. Each returns
a safe named result whose detail is only `passed`, `failed`, or `not measured`.
It never prints expected or actual values. Gatus owns HTTP, DNS, TLS and API
probing under gatus for synthetics; their v0.1 engines are not ported. dead code excludes browser
transactions. This library is not a new probing service.

## Certificate helper and measured delivery

`certcheck.run_cert_check` accepts an injected certificate facts provider and
timezone-aware clock. It never opens a socket. The provider returns
`CertFacts(not_after, chain_valid, sans)` using an aware ISO expiry timestamp,
an exact boolean chain verdict and a bounded SAN list. Exact DNS/IP names and
a single leftmost DNS wildcard are supported. Invalid facts or a raising
provider return only firing `coverage` on `<rule>.fetch-error`, with a fixed
error code, no numeric days value, no samples and no recovery event.

The caller supplies an actual measurement provider; this illustrative wiring
assumes that provider and the existing authenticated platform client exist:

```python
import datetime as dt
from local_observe.platform.certcheck import run_cert_check

result = run_cert_check(
    'service-cert', declared_resource_id, 'service.example.com',
    measured_certificate_provider,  # (host, port) -> CertFacts
    source=authenticated_producer_identity,
    clock=lambda: dt.datetime.now(dt.timezone.utc),
    thresholds=(30, 14, 3),
)
# Persist result.samples and result.events as one pending batch first.
# Deliver every sample to POST /v1/evidence before any POST /v1/events.
# On any refusal/lost acknowledgement replay that saved batch, never refetch.
```

Successful measurements return only three minimal samples: days to expiry,
chain validity and hostname match. Events reference these recoverable samples.
Chain and hostname failures each name their own condition. Expiry emits only
the tightest crossed stage: `service-cert.expiry-30d`, then `...expiry-14d`,
then `...expiry-3d`. Repeated evaluations in a stage share the same condition;
identical event retries share the same event ID. Earlier expiry incidents stay
open until a healthy certificate outside every threshold resolves all stages.
A measured certificate with invalid chain or hostname never resolves expiry.

Thresholds are configurable, descending unique positive integer days
(1..36500, at most 16 stages), default **30/14/3**. This follows the v0.1
`synthetics/tls.py` implementation and synthetic assertions's explicit stage task; the older
port-table/component comment's **30/14/1** is a conflicting historical example,
not this helper's default. An operator can explicitly choose `(30, 14, 1)`.
The central severity crosswalk supplies the tightest stage's highest rung;
earlier stages use its existing warning/error mapping without a new vocabulary.

### Explicit certificate worker

`python -m local_observe.platform.cert_worker --config /etc/local-observe/cert.json`
runs one target once; add `--loop` for repeated rounds. With no argument and no
nonblank `LO_CERT_CONFIG`, it returns zero without files, credentials, clients,
locks, probes or sleeps. The module is included by existing package discovery;
no component is enabled and no platform CLI command is added.

The mounted JSON configuration accepts only these keys:

```json
{
  "schema_version": 1,
  "host": "service.example.com",
  "connect_ip": "192.0.2.10",
  "resource_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
  "rule_id": "service-cert",
  "source": "synthetics.tls",
  "platform_url": "https://platform.example.com/platform",
  "platform_token_file": "/run/secrets/certificate-producer",
  "cursor_path": "/var/lib/local-observe/cert-cursor.json",
  "port": 443,
  "timeout": 10,
  "interval": 60,
  "thresholds": [30, 14, 3],
  "tls_ca_file": "/etc/local-observe/target-ca.pem",
  "platform_ca_file": "/etc/local-observe/platform-ca.pem"
}
```

The first nine fields are required. The remaining fields default as shown,
except both CA files default to system trust. Paths are absolute; create the
cursor parent with private permissions before enabling the worker. The source
must equal the mounted token's producer identity and the resource must already
be declared in the platform inventory. A 200 response with a different evidence
or event ID is refused. This worker never has database access or dispatcher
credentials. Config contains credential references only; no environment token
fallback is used.

`connect_ip` is an explicit IP literal, while `host` selects TLS SNI and the SAN
expectation. DNS is deliberately not performed: an operator must update the
address after a routing change. The socket uses one connect/handshake deadline
of `timeout` seconds (1..20), with no retries or other addresses. It does not
send HTTP requests. `interval` is 5..3600 seconds and is both the minimum time
between newly measured observations and the delay after a loop round. Failed
configuration rounds use a fixed 60-second delay. Gatus remains the adopted
HTTP/DNS/TLS availability engine; this narrowly scoped provider supplies the
certificate facts omitted from its status JSON.

The provider verifies the chain using public stdlib SSL APIs, then lets the
existing helper separately assess SAN matching. Only IP Address SANs are supplied
for an IP host, and only DNS SANs for a DNS host; a DNS SAN spelling an IP does
not authenticate that IP. A rejected chain, including an
expired certificate, yields **fetch-error coverage only**, with no fabricated
expiry or chain-invalid sample. There is no unverified connection fallback,
private certificate decoder, external command or new runtime dependency. The
helper still accepts measured invalid-chain facts from other injected providers;
the shipped provider does not claim to supply those facts. No SAN, DER/PEM,
remote failure string or target address is persisted in evidence or the cursor.

One cursor has one kernel-held owner lock. Configuration is bounded to 16 KiB;
the cursor is bounded to 128 KiB, bound to normalized configuration, and holds
only the last completed observation plus one pending batch and its fingerprint.
Unknown keys, duplicate JSON keys, nonfinite values, malformed or foreign-scope
pending samples/events, changed configuration and symlink cursors are refused
without rewriting the cursor. Its fingerprint detects accidental changes, not
malicious replacement by an actor who can rewrite private state.

The complete batch is fsynced and atomically replaced before any POST. Every
retry resends all samples before all events, unchanged, without constructing the
measurement provider. Matching acknowledgements for the entire batch precede
cursor advancement. This includes an acknowledgement lost after server commit.
Evidence can expire while delivery is pending; retries still use the original
observation. A permanent refusal retains that batch and visibly blocks newer
measurements until the operator repairs the delivery/configuration problem.
Stopping releases the owner lock and retains the cursor. Do not delete pending
state to make a changed configuration appear accepted.

Deployment and authorized estate runtime acceptance remain unverified. The
local TLS test below proves a real loopback handshake and chain refusal, not
mounted deployment credentials, service scheduling or component conformance.

## Verification

`tests/test_assertions.py`, `tests/test_synthetic_attribution.py` and
`tests/test_cert_expiry.py` cover strict inputs, safe failure attribution through
real Store reads, canonical event validation, the 16-assertion bound, exact
pending replay, three stage identities, repeated-stage deduplication, renewal,
fetch failure, chain/hostname failure and absent gauges. These are deterministic
offline tests, not a conformance drill. Existing detection and vocabulary tests
remain unchanged. No dependency or platform storage schema is added.

`tests/test_cert_measurement.py` generates a temporary self-signed certificate
with OpenSSL when that executable is available, then exercises only loopback
TLS: trusted facts, named SAN mismatch and untrusted-chain refusal. This test
skips explicitly if OpenSSL is absent; OpenSSL is a test fixture tool, never a
runtime requirement. `tests/test_cert_worker.py` verifies real Store evidence
resolution/intake, durable acknowledgement-loss replay after expiry, wrong-ID
refusal, poisoned state, changed configuration, strict defaults and two scheduled
rounds without remeasurement. No test contacts an external endpoint.
