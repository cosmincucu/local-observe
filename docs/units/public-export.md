# Reviewed public source export

`scripts/export_public_tree.py` builds a new directory from a full Git commit ID and an external,
private JSON policy. It reads immutable tracked blobs, applies simultaneous literal replacements
to UTF-8 text and filenames, and checks every selected output name and byte stream against the
private forbidden list. Untracked files, local Git history/configuration and worktree edits never
enter the export. The source repository is read only.

This creates a local review artifact. It does not publish, create a Git repository, authorise a
release, prove the forbidden list complete, rotate credentials, or certify a binary's visual content.
For an initial publication, create fresh public history and retain existing development history
privately. Source revision, excluded paths, source filenames and policy hash belong in the private
report, never inside the public tree. Later releases preserve established public history.

## Private policy

The six keys `version`, `include`, `exclude`, `replacements`, `forbidden`, `binary_sha256` are
required; `utf8_approvals` and `public_identity` are optional. Unknown keys, duplicate JSON keys and
malformed entries are errors. The illustrative identifiers are synthetic; the real `from` values are
private identifiers and are never shown in a public document. Keep the actual policy outside the
product source, with the output outside both source and the policy's directory. Review each
inclusion explicitly.

```json
{
  "version": 1,
  "include": ["local_observe/*", "components/*", "examples/*",
               "tests/test_public_export.py", "tests/test_public_history.py",
               "scripts/export_public_tree.py", "scripts/check_public_history.py",
               "docs/units/public-export.md", "pyproject.toml",
               "requirements-test-base.txt", "LICENSE", "NOTICE"],
  "exclude": [],
  "replacements": [
    {"from": "synthetic-host", "to": "nas"},
    {"from": "synthetic-domain.invalid", "to": "example.test"}
  ],
  "forbidden": ["synthetic-host", "synthetic-domain.invalid"],
  "binary_sha256": {},
  "utf8_approvals": [],
  "public_identity": {"name": "Example Project", "email": "project@example.invalid"}
}
```

This example demonstrates policy syntax and one self-contained exporter test/tool group. It is
not a complete release selection or a policy that anonymises this source as written: its synthetic
identifiers do not substitute for the private identifier inventory. Never include all documentation
or staging scripts by default. Select runnable tests together with every script, fixture and
document they read, then execute them against the exported tree.

Use an explicit path selection covering the implementation, runnable tests, supporting tools and
public documentation. Keep the selection and any prose replacements in the external policy.
Changing source or policy requires a new export and validation. Review newly added documents
before selecting them, and update retained links when their targets are excluded.
See [documentation style](../VOICE.md) for public writing conventions.

Selection uses case-sensitive Python `fnmatchcase` on POSIX relative paths: `*` also matches `/`,
so `components/*` includes descendants. Excludes override includes. The report lists every omitted
tracked path. There is no implicit safe extension or documentation exception. Replacements are
case-sensitive, longest-first and simultaneous; forbidden checks are case-insensitive. Supply all
spelling/case variants that need rewriting and verify functional references after filename changes.
The tool is not a prose editor or regex engine. Literal entries may replace an entire known text
with curated public text, but cannot express a general line-deletion rule; both replacement strings
must be nonempty. Rewrite reusable product prose in source, or retain a reviewed whole-text
replacement privately. Keep installation records in protected storage outside the product repository.
No private mapping is embedded in the tool or its tests. Files named `anonymise.map`,
`anonymize.map`, or the private policy's basename are refused if selected.

Use role placeholders `nas`, `ai`, `backup`, `router`, `hub`, `op-pc`, `probe-1`, domain `example.test`,
local example addresses in `10.11.0.0/16`, and users `operator`/`platform-agent`. Public-address
illustrations can use documentation ranges. Keep dependency hashes and upstream attribution intact.

Exclude private decision transcripts, agent instructions, research, incident/staging evidence,
history-scanner fingerprints and forge-specific metadata. Public docs need curated replacements
when they link excluded content. Choose runnable tests/scripts as a group; retained tests must not
depend on omitted private scripts or policy documents. A source gate that embeds private names
needs a generic public equivalent; rewriting its ban list into canonical example names would
incorrectly ban those examples.

UTF-8 containing NUL and non-UTF-8 files require `binary_sha256` entries keyed by exact source path
with exact lowercase SHA-256. Approved binary bytes are unchanged and still scanned for forbidden
UTF-8 literals. This cannot detect rendered or compressed identifiers: obtain independent content
review, and generate public screenshots from synthetic demo data.
Symlinks and submodules are refused. Rewritten paths reject traversal, drive/Windows device names,
Git metadata, case-insensitive collisions and file/directory collisions.

### UTF-8 exceptions (`utf8_approvals`)

An approval is the only way a forbidden token may survive in a text output: exact output `path`,
exact output `sha256` of the rewritten bytes, one `token` that must itself be a `forbidden` entry,
and a printable `reason` of at most 1000 bytes. Matching is on the casefolded token, so one approval
covers `Spark`/`spark`; duplicate path/token approvals and malformed entries are policy errors.

Approvals are narrow on purpose. They never exempt a filename or directory name, never exempt a
second token in the same file, never exempt a binary (a byte with NUL or non-UTF-8 bytes needs
`binary_sha256` instead), and never exempt bytes that hash differently — edit the file and the
approval stops matching. An approval that no output consumed is a stale approval and refuses the
export. The list is copied into the private report so a reviewer sees what was waved through; it
never enters the public tree.

### Publication identity (`public_identity`)

Optional in the policy: `name` (at most 100 bytes, no angle brackets) and one plain `email`, neither
containing a forbidden token. The exporter copies it into the private report only — it writes no Git
configuration and commits nothing. The read-only history checker treats it as required, because a
root commit is verified against it: export with a policy that omits `public_identity` and the
checker refuses the candidate.

## Run and verify

Create empty parent directories first. Destination and report must not exist. Invoke with a full
lowercase commit ID (40 or 64 hex characters); policy/report paths below are private operator paths.

```sh
python -X utf8 scripts/export_public_tree.py --source /work/source --revision FULL_COMMIT_ID --policy /work/private/policy.json --destination /work/public-candidate --report /work/private/export-report.json --dry-run
```

Remove `--dry-run` to create the reviewed artifact and private JSON report. Dry-run writes nothing.
The CLI prints only counts, output hash and dry-run status; refusal messages omit source values.
Validation completes before destination creation. Readback verifies each written file; I/O failures
leave any partial directory intact for inspection and do not claim success. Use a new destination
for a retry. No existing path is removed or overwritten.

### Private diagnostics (`--diagnose`)

Without `--diagnose` a refusal is one generic line on stderr and nothing is written. With it, the
run also writes a private JSON report — on refusal (`"status": "refused"`, the policy-validation
message and every finding collected so far) or on a successful dry-run (`"status": "validated"`). A
successful real export is unchanged by the flag: the success report stays the only file written.
Nothing else changes: the destination stays uncreated on refusal and on dry-run, and the diagnostic
report goes through the same location checks as the success report.

The diagnostic file is created with `O_EXCL` and mode `0600`, so an existing path or a link is
refused rather than overwritten, and only after the location checks below. It carries counts and
bounded metadata only: finding `kind` (`forbidden-path`, `forbidden-content`, `stale-utf8-approval`),
the output path, the matched token and an occurrence count. Never a line, never surrounding context.
Metadata is escaped and truncated at 128 characters per token and 512 per path (a truncated label
carries a literal `...[truncated]` marker), at most 100 findings are listed with `"truncated": true`
and correct totals above that, and the whole report is refused if it would exceed 128 KiB. Read it
with an editor, do not paste it into a card, an issue or a PR.

### Read-only history check (`scripts/check_public_history.py`)

After fresh Git initialisation, check the candidate against the same private policy and report:

```sh
python -X utf8 scripts/check_public_history.py --candidate /work/public-candidate --revision FULL_COMMIT_ID --policy /work/private/policy.json --report /work/private/export-report.json
```

It compares committed bytes to the report (`manifest_match`: every path, mode, size and SHA-256,
every row's shape, and the private `source_path` re-selected against the policy's own
`include`/`exclude` — the same key the exporter used, so a rewritten output path is never blamed for
a pattern it was not matched against — while the output path itself must equal the policy rewrite of
that source path; the manifest is not trusted wholesale) and independently re-scans those bytes here
(`content_rescan_clean`, same scanner, same exact path + token + output-hash approvals).
Binary blobs must also match the policy's exact `binary_sha256` approval keyed by private source
path; a matching manifest cannot waive an unapproved binary. It confirms a fresh root: own `.git` with no
alternate/graft/shallow/commondir path (checked lexically, so a dangling symlink is refused), no
remotes, no replacement refs, one parentless reachable commit, an object database equal to that
commit's reachable set (extra loose or packed objects and unreachable amended history both refuse),
and exactly one branch ref — a second benign branch on the same commit would publish private branch
topology without adding an object. Author and committer must both equal `public_identity`; no
forbidden token may appear in commit metadata, a ref name, an exported path or the bytes. The
working tree must be clean, including ignored leftovers, which are never published but must not sit
beside an artifact about to be treated as reviewed.

The check is read-only in the strong sense: every Git call runs with `--no-optional-locks` and
`GIT_OPTIONAL_LOCKS=0`, so `git status` cannot refresh and rewrite `.git/index`. Its test pins that
by comparing index bytes and mtime around the call, not porcelain text.
Every call also sets `core.fsmonitor=false`, preventing candidate configuration from launching a
monitor command during status checks. Symlink and Windows junction checks include intermediate
Git storage-path components.

It does not certify anything else: `publication_authorized` is always `false`, and neither verdict
claims the forbidden list is complete, that rendered or compressed identifiers are clean, that
credentials are rotated, or that licensing is reviewed. A refusal prints one generic line and exits
1; the verdict is the JSON on stdout.

The tool bounds the tree to 10,000 entries, each selected file to 8 MiB and aggregate selected input
and output to 128 MiB. The deterministic tree hash covers output paths, modes, sizes, hashes and
binary status, not private source identities. Repeated exports of the same revision/policy should
produce identical reports and file bytes. Timestamps are not source-derived.

Before treating the artifact as ready: independently scan all filenames and bytes using the private
identifier inventory; inspect retained docs and links; parse configuration; run selected tests and
foundation checks against the export. Review binaries separately. Initialise fresh Git only after
those checks, with a project identity, no remote or alternates, no copied object database and a root
commit without parents. Inspect commit metadata as well as files — then run the read-only checker
below over the candidate and keep its verdict with the private report. Credential/history scanning
and rotation, licensing review and the project maintainer's publication authority remain separate
release requirements.

Tests: `python -B -m unittest discover -s tests -p test_public_export.py` and
`python -B -m unittest discover -s tests -p test_public_history.py`. Synthetic repositories cover
nested JSON/arrays, hidden/untracked content, private history, malformed policy, simultaneous
rewrites, binaries, symlinks/submodules, path collisions, metadata, read-only source and determinism;
the history suite builds real single-commit roots to exercise identity, refs, unreachable objects,
manifest drift, approvals and the index-untouched claim.
