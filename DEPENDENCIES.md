# Dependency map

Update related implementation, tests and documentation in the same change.

| Change | Related files and checks |
|---|---|
| Component image build inputs | `components/**/{Dockerfile,requirements.in,requirements.lock,versions.json}`; update pins, build checks and lifecycle documents together. |
| Observer acceptance resources | The platform Dockerfile retains exact `examples/inventory/declared.yaml` and `examples/platform/forecast.yaml` bytes used by evaluation manifests. Verify the evaluation-to-acceptance path inside the built image after changing these resources, the evaluator or its acceptance consumer. |
| Deterministic CI | `.github/workflows/ci.yml`, `.gitea/workflows/ci.yml`, `requirements-dev.txt`, `requirements-test-base.txt`, `tests/tiers.py`, `ruff.toml` and `docs/testing-standards.md`. |
| Public source content | `scripts/check_public_tree.py`, `scripts/export_public_tree.py`, `scripts/check_public_history.py` and their tests; private policies stay outside source. |
| Deployment contracts | `docs/DEPLOYMENT.md`, `docs/RELEASING.md`, `local_observe/deployment/` and `tests/test_deployment.py`. |
| Documentation navigation | `README.md`, `STATUS.md`, `docs/STRUCTURE.md` and `docs/COMPONENTS.md`; repair links when paths change. |
| Example compositions | `examples/`, `scripts/check_foundation.py` and `tests/test_foundation_checks.py`; keep credentials, required variables and port bindings consistent. |
| Public command interfaces | `pyproject.toml`, CLI implementations, command tests and installation documentation. |
| Observer and learning records | `local_observe/observer/`, `tests/test_observer*.py`, `docs/units/observer.md`; update private-state schema, capture policy, adapters, limits and recovery together. Model provenance also covers the optional gateway deployment guard in `local_observe/observer/model_route.py` and the single-header response output in `local_observe/http.py`; change them with `tests/test_observer_model_route.py` and the AI client tests. |
| Guided setup and execution | `local_observe/deployment/guided*.py`, `local_observe/platform/runner_handoff.py`, action/API/MCP tests, `tests/test_guided_native_acceptance.py` and `docs/units/guided-setup.md`; preserve human approval and runner isolation. The native acceptance check also runs against an installed wheel outside the checkout. |
| Observer quality | `local_observe/evaluation/`, `examples/corpus/schema.json`, `tests/test_eval*.py`, `tests/test_observer_evaluation.py`, `tests/test_operator_held_out_corpus.py`, `tests/tiers.py`; preserve unknown labels and truth separation. |
| Review workload | `local_observe/evaluation/feedback.py`, `tests/test_feedback_measurement.py`, `docs/units/feedback-measurement.md`; distinguish response latency, self-reported effort and unknown grades. |
| Observer review API | `local_observe/platform/observer_review.py`, the `observer_review` wiring and `LO_OBSERVER_REVIEW_STATE` read in `local_observe/platform/api.py`, the `feedback` seam in `local_observe/observer/journal.py`, `tests/test_observer_review_api.py`, `tests/test_observer_review_acceptance.py` and the API contract in `docs/units/observer.md`; preserve authenticated identity, atomic review preconditions, bounded reads and correction/export withdrawal. |
| Observer review interface | `local_observe/platform/static/`, `tests/test_observer_review_browser.py` and `scripts/check_approval_browser.py`; preserve explicit human grades, escaped evidence, stale-session protection and phone usability. The dedicated browser gate refuses skipped workflows. |
| Vendor attribution | `LICENSE`, `NOTICE` and `local_observe/platform/static/LUCIDE-LICENSE`; preserve upstream notices. |
| Component: ai | `components/control/ai/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: anomaly | `components/control/anomaly/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: chat | `components/control/chat/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: crowdsec | `components/control/crowdsec/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: dagu | `components/control/dagu/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: homepage | `components/control/homepage/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: job-observe | `components/control/job-observe/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: mcp | `components/control/mcp/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: operator | `components/control/operator/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: platform | `components/control/platform/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: rca | `components/control/rca/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: sigma | `components/control/sigma/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: synthetics | `components/control/synthetics/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: agent-linux | `components/data/agent-linux/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: agent-windows | `components/data/agent-windows/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: front-door | `components/data/front-door/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: query-adapter | `components/data/query-adapter/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: store-signoz | `components/data/store-signoz/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Component: inventory | `components/knowledge/inventory/`; update its contract, manifest, pins, conformance, backup and upgrade instructions together with consumers in `examples/`. |
| Package: ai | `local_observe/ai/`, corresponding `tests/test_ai*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: catalog | `local_observe/catalog/`, corresponding `tests/test_catalog*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: ci_failures | `local_observe/ci_failures/`, corresponding `tests/test_ci_failures*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: deployment | `local_observe/deployment/`, corresponding `tests/test_deployment*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: evaluation | `local_observe/evaluation/`, corresponding `tests/test_evaluation*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: forecast | `local_observe/forecast/`, corresponding `tests/test_forecast*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: identity_mail | `local_observe/identity_mail/`, corresponding `tests/test_identity_mail*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: inventory | `local_observe/inventory/`, corresponding `tests/test_inventory*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: modules | `local_observe/modules/`, corresponding `tests/test_modules*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: platform | `local_observe/platform/`, corresponding `tests/test_platform*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: security | `local_observe/security/`, corresponding `tests/test_security*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: slo | `local_observe/slo/`, corresponding `tests/test_slo*.py` and component contracts; preserve public schemas and state compatibility. |
| Package: store | `local_observe/store/`, corresponding `tests/test_store*.py` and component contracts; preserve public schemas and state compatibility. |
