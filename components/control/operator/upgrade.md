# Upgrade

Back up platform state, retain old image/assets and run role-denial and browser
fixtures against the candidate before promotion. Static assets are packaged with
the same API build; cache-control is no-store. Verify API limits and SDK protocol
behaviour whenever upgrading MCP. Remove the optional UI override to recover the
plain API; do not start both factories against the same state owner.

No UI-specific state migration exists. Underlying platform migrations require
their own copied-state/rollback checks; do not downgrade migrated live state.
