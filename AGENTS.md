# Contributing with an agent

Read README.md, STATUS.md, docs/STRUCTURE.md and DEPENDENCIES.md before changing the product.
Keep changes focused and use a branch for changes spanning multiple areas. Review all generated
code and independently verify its behavior before accepting it.

- Product code, schemas, generic examples and tests belong here. Installation addresses, personal
  information, credentials, operational transcripts and deployment inventories do not.
- Use synthetic fixtures and reserved example domains and addresses. Keep private scan policies
  and audit reports outside this repository, including identifiers used as negative test inputs.
- Preserve API and state compatibility. Update component contracts, tests and related documentation
  together; DEPENDENCIES.md describes the main relationships.
- Pin dependencies and container images. A pin change needs a reason, appropriate validation and
  an upgrade or rollback procedure. Do not change third-party notices or remove required credits.
- Keep secret values outside source control. Product credentials use mounted files. Optional
  integrations must remain optional, and notification examples must default to recording or off.
- Use the test tiers in docs/testing-standards.md. Run scripts/check_foundation.py and the public
  tree check before submitting. Report failures and skipped checks accurately.
- Do not modify a deployment, send notifications, publish, merge or delete runtime state without
  authorization for the specific action. Preserve existing user changes and review backups before
  approved state changes. Repository access alone grants none of those permissions.
- Follow the contributor's configured tool, model and identity policies outside the repository.
  Never embed a contributor's machine paths, accounts or private workflow in product instructions.

Write documentation for someone installing the product for the first time. Explain current
behavior, prerequisites, limitations and recovery steps without internal task numbers or history.
