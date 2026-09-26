# Upgrade — component `ai`

Nothing infrastructure-grade upgrades itself: a `LO_AI_IMAGE` digest moves on a branch, with a reason
and a rollback line, and the merge authorises the promotion rather than performing it. There is no
auto-update path here — `pull_policy: never` means the daemon will not fetch an image at boot, so an
upgrade is always something a person did on purpose.

## Why a serve upgrade is a **capability** change, not only an image change

The capability manifest is a measurement of one build with one weight file on one host. A new build can
move every one of its eight fields — the context the KV cache can actually hold, the slot count,
whether `response_format` is honoured, and above all `measured_tok_per_s`. The image tag is a moving
pointer by design (`server` follows the latest build), so an upgrade that reuses yesterday's manifest is
this component's version of the defect types exists to prevent: a number that describes something else.

So the unit being upgraded is the pair **(image digest, capability manifest)**, never the image alone.

## Procedure

1. **Take and verify the backup** — the current digest, the current capability/policy/budget files by
   SHA256, and the weight file's checksum. `AGENTS.md` at the repository root, the standing rule: read
   the backup back before mutating, and name the artifact in public.
2. Resolve the candidate digest for a **named build tag** (`server-bNNNN`), not for `server`. Record the
   digest in the branch's `versions.json` note and the tag it came from — and state in the same change
   whether the mapping from that build to a release tag was verified or is still the UNVERIFIED line in
   CONTRACT.md §2.
3. Bring the candidate up **beside** the current one, in a separate Compose project with its own
   `LO_AI_MODEL_DIR` bind and its own `LO_AI_API_KEY_FILE`. It publishes no host port
   (CONTRACT.md §8), so reach it from a container on that project's network. Load the same weight file —
   a new build measured against a different quantisation is two changes in one branch.
4. Re-measure all eight fields against the candidate (CONTRACT.md §4 names how each one is obtained)
   and write a **new** capability file. Do not edit the live one in place.
5. Prove the four behaviours the product depends on, in this order, against the candidate:
   `GET /health` answers 200 `{"status":"ok"}` only once loaded; one bounded
   `POST /v1/chat/completions` returns content and a `usage` object; a `tools`-free refusal still holds
   (the serve must not have been started with `--tools` — CONTRACT.md §2 quotes what that flag does);
   and the tile reads `Healthy` for the candidate and `Unknown` for it while it is still loading.
6. Cut over by changing `LO_AI_IMAGE` and `LO_AI_CAPABILITY` in the operator's environment file — the
   same commit, always both, so a rollback cannot pair a new image with old numbers.
7. Keep the old digest and the old manifest until the acceptance checks below have run on the live
   service.

## Rollback

Change both variables back in one commit and restart the serve: the weights and the operator files were
never written to, so there is nothing to migrate and no state to reconcile. A rolled-back serve with a
manifest that names the newer build is the state to avoid — the client will refuse a `model_mismatch`
but it cannot know that a token/s number belongs to a build that is no longer running. That is what
step 6's pairing is for.

## Not yet done

No upgrade rehearsal has been executed for this component: no image has been pulled, no model loaded,
no pair swapped. `conformance.md` says what has to be run first, and this row stays `experimental`
until it has been, at least once, on a Linux host with the operator's own weights.
