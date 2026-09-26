# Backup and restore — component `ai`

**Nothing running here holds state.** The serve is a stateless process over read-only weights: no
volume is declared in `compose.yaml`, no database, no queue, no journal. So there is nothing to back
up *while it runs*, and "restore this component" means putting files back. Four kinds of file, four
different owners:

| What | Where it lives | Who backs it up |
|---|---|---|
| The GGUF weights | `${LO_AI_MODEL_DIR}` on the host, mounted read-only | the operator, or nobody: re-obtaining a weight file is a checksum comparison, not a restore — record the SHA256 of the exact file the capability manifest was measured against, because the same model name at a different quantisation invalidates every number in that manifest |
| `LO_AI_CAPABILITY`, `LO_AI_POLICY`, `LO_AI_BUDGET` files | operator paths outside the checkout | the operator's own versioned repository (`docs/OPERATOR-MODEL.md`); these three files *are* this component's configuration, and restoring them from a host that has drifted means restoring a decision nobody reviewed |
| the API key file (`LO_AI_API_KEY_FILE`) | operator path, mode 0400, mounted as a Compose secret | your protected credential store, with the procedure named in the operator's own documentation; a lost key is rotated, not restored — rotate by replacing the file and restarting the serve, since `--api-key-file` is read at start |
| the `model` observation document (`LO_OVERVIEW_PATH`) | written by `platform/overview_worker.py` | nobody: it is a 120-second freshness window over a live probe, and a restored copy of a stale observation says a model was resident at a moment in the past — the next tick replaces it, and `platform/overview.py:54-55` nulls anything older than its bound anyway |

## Restore procedure, and the one way it goes wrong

1. Restore the operator configuration files first, then the weights, then start the serve. A policy
   that permits a class the restored manifest does not support is not detected by the serve — the
   client decides, so the pair must be restored together.
2. Start it and read the tile: `disabled` means the overview worker has no `ai` block, `unknown` means
   the serve is not answering `/health`, `degraded` means it is answering and the manifest is not
   measured. Only the third of those is a restore that lost capability rather than configuration.
3. Confirm the identity of what came back without putting a secret on a command line. The client does
   this check on every call and refuses with `model_mismatch` when the endpoint answers as a name
   other than the configured `LO_AI_MODEL`, so a lost `--alias` shows up as a refusal rather than as an
   explanation attributed to a model nobody pinned. To look by hand, ask `GET /v1/models` **from inside
   the container**, where the key is already a mounted file and the expansion never reaches a host
   process list: `docker compose exec ai sh -c 'curl -fsS -H "Authorization: Bearer $(head -1
   /run/secrets/ai-api-key)" http://127.0.0.1:8080/v1/models'`. Two things in that line are inferred
   rather than verified against the pinned tag — that `/bin/sh` exists (the base image is Ubuntu, and
   only `curl` was confirmed in `.devops/cpu.Dockerfile`) and that the serve accepts the key as a
   `Bearer` header (CONTRACT.md §2) — and a command line that would show the key to every other user of
   the host is the reason it is written this way.

The defect this page exists to prevent: **restoring a capability manifest older than the image.** The
manifest is a measurement of one build of the serve with one weight file on one host. A restore that
brings back yesterday's `context_tokens` for yesterday's build and points at today's image re-opens a
budget the operator already measured shut, and the failure appears as an explanation whose evidence was
truncated. If the image digest and the manifest's `measured_tok_per_s` do not come from the same
change, re-measure — do not lower the numbers by hand.

No cold restore of anything in this component has been performed, because nothing in it survives a
restart except the files you put there.
