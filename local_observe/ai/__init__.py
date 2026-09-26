"""The optional generation plane: endpoint, capability manifest, policy, evidence budget.

Nothing outside this package may import it. That is not tidiness, it is the `If disabled` column of
the `ai` row in `docs/COMPONENTS.md` ("Rules and operator workflows work without generation")
turned into an import graph: a rule, an incident, an approval or a notification must never acquire a
dependency on a model being up, so every consumer (rca in investigation component, chat in chat integration) imports
lazily and
keeps its own floor when the import or the call fails. `tests/test_ai_component.py` walks the tree
and fails if a second importer appears.

The package ships no default capability and no default permission: an unconfigured install cannot
construct a client, an unmeasured manifest cannot be used, and a class the policy refuses is refused
before any request text is built. Every module here is stdlib-only and knows nothing about the
telemetry store, which is what makes "never re-query the store to make an explanation look complete"
a structural property rather than a promise.
"""


class AiError(ValueError):
    """Base for every refusal this package raises; a refusal is an outcome, never a fallback.

    Subclasses carry a `code` naming the reason (`policy_refused`, `capability_unknown`,
    `budget_exceeded`, `expired_evidence`, …) so a caller can degrade without parsing prose, and a
    log line can carry the reason without carrying the payload.
    """

    code = 'ai_error'

    def __init__(self, message: str, *, code: str | None = None) -> None:
        """Store the human-readable reason and the machine-readable one, then behave as a `ValueError`."""
        super().__init__(message)
        if code:
            self.code = code


__all__ = ['AiError']
