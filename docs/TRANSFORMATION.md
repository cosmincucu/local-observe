# Product boundaries

local-observe combines telemetry, inventory and incident workflows through explicit component
contracts. The [architecture](ARCHITECTURE.md) describes those boundaries; the
[component guide](COMPONENTS.md) identifies required and optional capabilities.

Keep installation bindings and custom content in a separate versioned repository. Runtime state
and secret values need protected backups. The product repository contains reusable implementation,
schemas, synthetic examples and tests. See [deployment](DEPLOYMENT.md) for upgrade and recovery rules.
