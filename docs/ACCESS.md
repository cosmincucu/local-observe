# Deployment access

Use a dedicated, scoped identity for each deployment task. Keep SSH keys, tokens and passwords in
protected storage. This repository supplies no accounts, endpoints or grants for an installation.

Before a deployment, record the target, allowed operations, resource budget, backup and rollback
procedure. Verify SSH host keys through an independent trusted channel and verify TLS certificates.
Use a dedicated rootless container engine or isolated environment when practical. Access to a rootful
Docker socket or unrestricted container commands grants broad host control.

Inject product credentials through mounted files. A variable ending in `_FILE` names a file, not a
secret value. Use distinct credentials for producers, readers, operators and notification channels.
Give each identity only the paths and operations it needs. Never paste credentials into reports.

Conformance scripts are tools for an explicitly configured test environment. Review their help and
scope before running them. Source changes do not authorize live installation changes or messages.
