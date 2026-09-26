# Native Windows conformance

Runtime status: not-run. Use a Windows host and the executable verified by the
[provenance recipe](CONTRACT.md#provenance-download-verify-then-install):

```powershell
python -B scripts/check_windows_agent.py --executable C:/local-observe/agent/otelcol-contrib.exe --with-security
```

The executable flag is required. The check copies and hashes the binary into an isolated test
directory, validates its configuration and runs a separate process. It does not change the
installed service, original configuration or original state. Keep the generated report private.

Verify file delivery, stable resource identity, per-core metrics, queue/checkpoint recovery after
restart and duplicate handling. Compare observed series with the host's actual CPU count.

`--with-security` exercises `collector-security.yaml`; without it only the base agent is tested.
The Security channel requires `SeSecurityPrivilege`. An `Access is denied` result is a failed
permission check, not successful collection. `--security-channel` selects the channel for the
identity check and defaults to `Application`.

Record executable identity, source revision, configuration, test result and limitations. Native
service installation, least-privilege access, restore, upgrade and rollback require their own
acceptance checks. A Linux or synthetic protocol test cannot establish Windows behavior.
