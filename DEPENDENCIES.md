# Dependency map

Update related implementation, tests and documentation in the same change.

| Change | Related files and checks |
|---|---|
| Component image build inputs | `components/**/{Dockerfile,requirements.in,requirements.lock,versions.json}`; update pins, build checks and lifecycle documents together. |
| Deterministic CI | `.github/workflows/ci.yml`, `.gitea/workflows/ci.yml`, `requirements-dev.txt`, `requirements-test-base.txt`, `tests/tiers.py`, `ruff.toml` and `docs/testing-standards.md`. |
| Public source content | `scripts/check_public_tree.py`, `scripts/export_public_tree.py`, `scripts/check_public_history.py` and their tests; private policies stay outside source. |
| Deployment contracts | `docs/DEPLOYMENT.md`, `docs/RELEASING.md`, `local_observe/deployment/` and `tests/test_deployment.py`. |
| Documentation navigation | `README.md`, `STATUS.md`, `docs/STRUCTURE.md` and `docs/COMPONENTS.md`; repair links when paths change. |
| Example compositions | `examples/`, `scripts/check_foundation.py` and `tests/test_foundation_checks.py`; keep credentials, required variables and port bindings consistent. |
| Public command interfaces | `pyproject.toml`, CLI implementations, command tests and installation documentation. |
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
