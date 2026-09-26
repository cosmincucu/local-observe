# Backup and restore — component `anomaly`

Runtime acceptance for this procedure is **not-run**. Test it against an isolated
installation and record backup readback, recovery and replay results before relying
on it for operational recovery.

## The only state

One file: `/state/cursor.json` on the named volume `anomaly-state` (Compose calls it
`<project>_anomaly-state`). Everything else this container touches is a read-only mount or a tmpfs.
Beside the cursor the producer keeps `<cursor>.owner.lock` — an advisory lock file, never unlinked by
anything in the product, carrying nothing worth restoring.

**What the document holds** (`anomaly_cursor.py`, `SCHEMA_VERSION = 1`, top-level keys
`schema_version`, `source`, `last_served`, `series`):

| field | what it is | what losing it costs |
| :-- | :-- | :-- |
| `source` | which producer identity wrote it | a restore under a different `LO_ANOMALY_SOURCE` is **refused**, not merged — see below |
| `series.<id>.last_acked_end` | the last window whose two POSTs were both accepted | the resume point: this is why a restart resumes at the cursor and never at the clock |
| `series.<id>.owed_end` | a window this producer *began* and did not finish (a failed read leaves no payload) | the hour it had already tried gets skipped and a later window is anchored instead |
| `series.<id>.pending` | the exact evidence-sample and event bytes still owed to intake | a re-send becomes a re-judgement, and a re-judgement can be a different verdict — see below |
| `series.<id>.binding` | the digest of every knob and the reviewed `sql_sha256` the entry was written under | not "just metadata": a changed binding refuses the **whole round** for every series, so a restore of a cursor that does not match the config file stops the producer by design |
| counters (`delivered`, `no_verdict`, `refusals`), `anchored_at`, `anchor_logged`, `last_served` | lifetime counts (they **saturate**, so a ceiling value is a lower bound), the once-only anchor warning, and the round-robin turn | the fairness position: without it the refused series at the head of the list is served again |

The digests stored beside a pending batch are **corruption checks and not authentication**: anyone who
can rewrite the file can rewrite both numbers. What a backup buys is the ability to put back the
producer's memory, not proof of whose memory it is.

## What losing the cursor costs, in the producer's own words

A missing cursor is not a crash and is not repaired. The producer re-anchors at its own newest
completed window and says so once (`anomaly.py:759-762`), verbatim:

```
Anomaly series anchored at a completed window; every evaluation window before it was never judged and is not being replayed
```

with `'replayed_history': False, 'missed_windows': 'unknown'` beside it — the count is stated as
`unknown` because it is not knowable from what the store still holds, and the code refuses to compute a
number from the oldest training point. That is a guess wearing a measurement, and it is not written.

So the cost of an absent or stale cursor is: every window between the old position and now was never
judged and will not be, **plus** — and this is the half a naive backup story loses — the producer can
**re-query a window the platform already accepted**. If the answer comes back identical, the store's
dedup folds it (`events UNIQUE (source, source_event_id)`); if it comes back different, it is a new
event under a new id, or a refused retry with changed contents. From the platform README, in words this
file does not soften: there is **no** guarantee of no duplicates or no extra incidents, and database
dedup "is not a correctness repair here — it is a symptom of the asymmetry, and reconciling it (keep,
delete the entry, or re-point the path) is an explicit operator decision. Nothing here automates a
reset, a delete or a re-anchor."

## Why it must be captured coherently with the platform database

The cursor's value is only meaningful against the state that decided whether its events were new:

> Detector cursors and witness state need their own recovery coverage; backing up platform SQLite alone
> is not whole-deployment protection. — `local_observe/platform/README.md` lines 264-266 (read 2026-09-10;
> the sentence sits at the end of the module tour, beside the witness's own recovery note)

Read the other way it is the same sentence: restoring the platform database *without* this cursor gives
a re-anchor and a loud `WARNING`, never a reconstructed backlog. Capture both in one stopped window,
and record the platform `state.VERSION` beside them. A partial restore (database newer than cursor, or
the reverse) is an operator reconciliation, not something this product automates.

## Copy-out — with the container stopped

`<project>` is the Compose project name (the directory the top-level model is composed from, or
whatever `-p` says); confirm it with `docker volume ls` before trusting it.

```
# 0. stop the only writer. The lock is advisory: a copy taken while the process runs can land
#    mid-rename, and `os.replace` is atomic but a byte-by-byte read of the same directory is not a
#    transaction. Stopping is also what makes the pair (cursor, database) coherent.
docker compose stop anomaly

# 1. copy the cursor out through a throwaway container from the pinned image (read-only mount)
docker run --rm -v <project>_anomaly-state:/state:ro ${LO_PLATFORM_IMAGE} \
  python -c "import sys;sys.stdout.buffer.write(open('/state/cursor.json','rb').read())" \
  > anomaly-cursor.json

# 2. verify the copy by READING IT BACK, not by checking a file exists:
#    `test -s` is true for a directory, and a tar can be non-empty and useless.
sha256sum anomaly-cursor.json
python -B -c "import json;d=json.load(open('anomaly-cursor.json'));print(d['schema_version'],d['source'],len(d['series']),sum(1 for s in d['series'].values() if s['pending'] is not None))"
```

Pass criterion for step 2: the JSON prints `1 <your LO_ANOMALY_SOURCE> <series count> <pending count>`
— a parseable document of the schema this build reads, with the identity you expect and the pending
count you can compare to the last `Anomaly round finished` log line. **Anything that cannot be opened is
not a backup** and the run stops there.

Then the platform database through `Store.backup()` and not a copy of a live file — the README is
explicit that the online backup API "stays the only safe copy of a running database", because a file
copied while a writer holds uncheckpointed commits is self-consistent and merely missing rows, and
nothing inside the `.db` reveals it (lines 636-641; WAL handling in the same passage). Record the
`state.VERSION` the copy names, beside the cursor.

## Restore

Restore into a **scratch** volume first, on a host where nothing pages, before pointing a producer at
it. The volume must already be prepared to mode `0700` owned `65532:65532` (`CONTRACT.md`, the D3
recipe) — a restore onto a fresh `root:root` `0755` volume produces the same startup refusal as a first
start would, not a partial write.

```
# 1. stop the producer, then put the file back through a throwaway container writing AS the runtime
#    user (uid 65532), with the payload mounted read-only so the restore cannot write through it
docker compose stop anomaly
docker run --rm -v <project>_anomaly-state:/state \
  -v "$PWD/anomaly-cursor.json:/in/cursor.json:ro" \
  ${LO_PLATFORM_IMAGE} python -c "import shutil,os;shutil.copy_file('/in/cursor.json','/state/cursor.json');os.chmod('/state/cursor.json',0o600)"

# 2. read it back from inside the volume and confirm it parses and names the identity you restored
docker run --rm -v <project>_anomaly-state:/state:ro ${LO_PLATFORM_IMAGE} \
  python -c "import json;d=json.load(open('/state/cursor.json'));print(d['schema_version'],d['source'])"

# 3. start, and read the first round rather than trusting the start
docker compose up -d anomaly
docker compose logs --tail 20 anomaly
```

Pass criterion for step 3: the first `Anomaly round finished` line, and **no** `Anomaly series anchored
at a completed window` line — that `WARNING` after a restore means the file is not being read as this
producer's memory (wrong path, wrong identity, or a refusal that sent it back to a first start).

Three things the restore must not silently change:

* **`LO_ANOMALY_SOURCE` must equal the `source` inside the file.** A cursor written by a different
  producer identity is another producer's memory, and `load` refuses it rather than re-anchoring over it
  and silently dropping what that identity still owes — verbatim
  (`anomaly_cursor.py:308-310`): `Anomaly cursor was written by a different producer identity, so this
  LO_ANOMALY_CURSOR points at another producer's state`. Changing the identity is an operator decision
  about a different producer, not a restore step.
* **The file's own mode is the operator's promise.** `private_parent` checks the **parent** directory
  (no group/other bits, mode `0700`) and the ancestry for symlinks; nothing in `load` inspects the
  cursor's mode bits, so a group-readable restore is not caught — the module's own promise is `chmod
  0600` on every write, and step 1 above re-states it. A cursor **file** that is a symlink is refused
  before it is read, so copy bytes rather than linking.
* **Do not restore onto a configuration the cursor does not match.** A binding, an owed batch, or a
  window position the current config could not have produced refuses the **whole round** before its
  first query, its first POST and its first byte, naming the series it is about. That refusal is the
  feature; do not delete the pending batch to make the producer start (the same advice
  `components/control/sigma/backup.md` gives about a changed artifact: drain or reconcile first).

## Never

* Do not run two producers against one volume "to check". The process holds `exclusive_owner` on the
  cursor for its whole life; the second copy exits 1 on the lock, which is the correct reading of
  "something else is already judging these series" — but a second copy on a *different* host with a
  copied volume is two writers with two opinions about what was said, and an advisory lock across
  machines grants nothing.
* Do not hand-edit the JSON to clear a refusal. Migrating or deleting an entry is an operator action
  with its own two failure modes, documented in `docs/units/anomaly-cursor.md`.
* Do not treat a move of this state between machines as a restore. It is a cutover, one host at a time,
  while its owner lock is held (`DEPENDENCIES.md`, "Seasonal anomaly baselines").
