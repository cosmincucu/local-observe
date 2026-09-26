# Operator accounts

Choose a username and password once when installing local-observe. Operations,
Dagu and the Homepage access gate start with independent accounts using those
credentials. Changing one later changes only that component. This is not SSO and
there is no background password synchronization.

Homepage is the operator's starting page. Its address belongs to deployment
configuration, not product code. Setup produces an access directory for Homepage
and a readable handoff listing each selected interface, its username and its setup
status. Machine credentials are generated separately and are never the operator
password. An API-only component does not gain a human account merely by being
included in the installation.

## Fresh installation

Run `lo-operator-setup --help` (or
`python -m local_observe.deployment.operator_setup --help` from the checkout).
Supply the installation's Homepage and component URLs, the chosen username, a
new protected output directory and a local Caddy executable for generating the
Homepage password hash. Enter and confirm the password at the hidden prompt.
Unattended setup may read a password file; passwords are not command-line values.

For example, after creating the protected parent directory on your Docker host:

```sh
lo-operator-setup --output /srv/local-observe/private/operator-initial \
  --username operator --caddy-binary /usr/bin/caddy \
  --home-url https://portal.example.com \
  --operations-url https://ops.example.com \
  --overview-url https://overview.example.com \
  --jobs-url https://jobs.example.com \
  --signoz-url https://observe.example.com
```

Replace the example URLs with yours. `--healthchecks-url` adds that component to
the handoff if installed. The Homepage Caddy adapter accepts passwords up to 72
UTF-8 bytes without leading/trailing whitespace; setup explains incompatible
input before writing files. `--skip-homepage-auth` is an explicit partial-setup
option and leaves Homepage authentication marked pending.

The command prepares configuration; it does not start containers, contact existing
accounts or change passwords on a running installation. Read its `ACCESS.md`
before starting services. Generated files must be installed with permissions that
allow only the intended service identity and the owner to read them. POSIX output
is private by mode; on Windows the operator must use a directory protected by its
Windows ACL. Git history and public web roots must never contain these files.

Wire the generated files into the existing full-stack configuration:

`credential-paths.json` maps the generated files to deployment variable names;
it contains references, not credential values. Merge `homepage-links.yaml` into
Homepage's existing services configuration to expose the component links and
setup status. Do not replace existing custom tiles with this fragment.

* Operations: put `operator-account.json` in the directory named by
  `LO_PLATFORM_POLICY_DIR`, and set `LO_OPERATOR_ACCOUNT_FILE` to
  `/config/operator-account.json`. Use the generated platform role credentials,
  whose human identity matches the account. The browser sends the entered
  username/password over HTTPS; the machine bearer stays inside the server.
* Dagu: set `LO_DAGU_CONFIG_FILE` to the generated YAML credential file and
  `LO_DAGU_USERNAME` to the chosen username. The independent Dagu account uses the
  same initial password. Existing deployments retain `lo-runner` unless changed.
* Homepage: import the generated Basic-auth directive into the authenticated
  HTTPS site serving Homepage. Keep its upstream private. Homepage widget tokens
  remain separate from the password used to open the page.

If separate Homepage instances protect the main page and an overview page, copy
the initial directive into each site's own configuration. Sharing a single
editable auth snippet would also share later password changes.

Use HTTPS for browser access. An authenticated proxy must not log Authorization
headers. Operations keeps login details in page memory, clears them on logout,
and does not save them to browser storage. Existing bearer clients keep their
existing roles and continue to work when password login is enabled.

## Native-account exceptions

SigNoz and Healthchecks use native user registration and may require an email
address rather than the selected short username. They must be listed as pending
until that registration is completed with the chosen password and its actual
login is verified. Setup does not overwrite an existing administrator, reset a
database, claim an account from an HTTP success alone, or silently invent a
different password. Their native password rules still apply.

For an existing installation, first prepare the new configuration and retain the
old account/configuration backup. Installing it and changing native accounts are
explicit migration steps; running fresh setup cannot reset independent passwords
that an operator has already changed.

## Implementation and checks

`deployment/operator_setup.py` owns new setup artifacts and the access handoff.
`platform/operator_account.py` owns the password-hash format and validation;
`platform/operator.py` adapts password-authenticated human requests to the existing
role-enforced API. No state database schema or machine-role expansion is needed.
Focused tests cover generated configuration, malformed credentials, wrong logins,
unchanged bearer authorization, no secret output and output-directory refusal.
