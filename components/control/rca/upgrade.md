# RCA — upgrade

**There is no upstream version to move.** The component is this repository's own code
(`local_observe/platform/rca.py`) running in the platform image, and the executor that would have an
upstream version — HolmesGPT — was never fetched, so no version string of theirs is recorded anywhere
here and nothing in this file moves one. `versions.json` therefore pins an *image variable*
(`${LO_PLATFORM_IMAGE}`) and not a digest of its own: the platform image digest is owned by
`docs/COMPONENTS.md`'s `platform` row and moves with the platform, never inside a change to this
component.

The standing rule applies with no exception carved here: **nothing infrastructure-grade upgrades
itself.** A pin moves on a branch carrying a reason and a rollback line, seen running against its real
consumers before the PR merges.

## What "upgrading" this component actually is

Three things, and only three.

1. **The platform image.** The component rides it. Bump nothing here; the platform row's pin and its
   `versions.json` own that move, and the command's behaviour is covered by the tests listed below.
2. **A rule.** Tuning the floor is a PR that carries, in the same commit, the test that pins the new
   behaviour *and* the test that would have caught the old one. The `why:` line of the `Rule` is part of
   the tuple and is asserted by
   `tests/test_rca_rules.py::test_the_floor_is_four_rules_and_every_one_states_why_it_exists`, so a rule
   cannot be added as a bare lambda. Removing a rule is the same PR shape with the tests deleted in it,
   visibly.
3. **The record's shape.** `EXPLANATION_SCHEMA` is a version string on the record. A reader today
   tolerates `"rca-explanation/1"` or anything newer, and refuses anything older or unparseable rather
   than guessing at a shape it never saw. Bumping the version means: old rows still read, new rows carry
   the new string, and the change is in the same PR as the reader's tolerance test
   (`tests/test_rca_bundle.py::test_a_record_written_by_an_unknown_schema_is_refused_rather_than_guessed_at`).

## Before

The fair rotation uses the incidents/status index already installed by schema 6; it adds no schema
migration. The first configured tick creates its source-specific derived cursor and owner lock beside
the database. Keep the invocation arguments unchanged and allow the platform owner to write that
directory. A cursor with an unsupported schema/source/path binding refuses startup; it is not migrated
or reset silently. Preserve and verify it before reconciliation, as described in `backup.md`.

Stop and drain the RCA owner before `VACUUM` or a database rebuild. Those operations can reassign
hidden rowids; after verifying database/cursor backups and completing maintenance, reset the derived
RCA cursor so it starts a fresh cycle. Keep explanation audit history.

* Take and verify the operational database backup, per the rule in `AGENTS.md` and the restore probe in
  [`backup.md`](backup.md). Name the artifact and its checksum on the PR.
* Run the suite in the tier it belongs to (both commands from the repository root):

  ```
  python -B -m unittest discover -s tests
  python -B -m unittest discover -s tests/compiler
  ```

* If the change touches the fabrication guard, run the lying-model test on its own and read its output
  rather than its exit code:

  ```
  python -B -m unittest tests.test_rca_llm_fabrication -v
  ```

  The assertion worth reading by eye is that the ranked cause set is identical with the model lying and
  without it. A green run of a test whose fixture quietly stopped producing a rule floor proves nothing,
  which is why that test asserts its own precondition.

## Apply

There is no apply step for the code: a redeployed platform image carries the new command, and the
scheduled invocation (`lo-platform … rca --config …`) does not change unless the config schema changes.
When it does, the new document is written and validated **before** the image is swapped, because
`load_config` refuses an unknown field — an old round against a new document fails loudly and a new
round against an old document fails loudly, and either way the failures are the pair of
`config_refused` exits rather than a half-read config.

## Rollback

An older image ignores the new cursor but returns to its old newest-page scheduling behavior. Retain
the cursor and its verified backup while the owner is stopped; if the database is rebuilt or restored
to a different path, reconcile/reset derived progress before upgrading again. Resetting it repeats a
bounded cycle and does not delete or duplicate unchanged explanation records.

* **Turn the round off** by removing the scheduled invocation. Nothing else needs to change: no schema
  migration exists to reverse, because the record is an `audit` row and the table has been in the
  database since before this component existed.
* **Re-point the image** at the previous digest, the same way every other service in
  `examples/full/compose.yaml` is re-pointed.
* **Leave the records.** A rollback does not delete `rca.explained` rows. They are audit rows, and
  deleting audit rows is not a rollback operation — `docs/CONTRACTS.md` §4, and query adapter exists to keep
  that boundary honest. An explanation written by a build you no longer run is still a record of what
  that build claimed, which is the useful thing in a post-incident review.
* A digest rollback is not a data rollback (`docs/CONTRACTS.md` §7). If a round wrote records you now
  consider wrong, the correction is a new round after the fix, not an edit of history.

## What must not be "upgraded" in place

* The **rule floor's primacy.** If the model can produce the ranking, this component is a different
  product with a different risk profile, and that is `docs/DECISIONS.md` investigation policy's decision to revisit, not
  a refactor.
* The **evidence read path.** Changing `query.reauthorise` for a direct read of the `evidence` table is
  not an optimisation: it is the removal of the one function that cannot revive a dead reference
  (`platform/query.py::reauthorise`, *"no `StoreClient` is accepted here, on purpose"*). Expired evidence
  would come back as a citation, and a retention limit would become a fact about the reader instead of a
  fact about the data.
* The **absence of a `compose.yaml`.** See [`CONTRACT.md`](CONTRACT.md): the platform database has one
  writer, enforced by an OS lock held for the serving process's whole life.
