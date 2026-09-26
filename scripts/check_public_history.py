"""Verify a local first-public-root candidate against its private export receipt.

Read only: every Git call runs with --no-optional-locks, GIT_OPTIONAL_LOCKS=0 and an explicit
`core.fsmonitor=false`, so `git status` can neither refresh nor rewrite `.git/index`, nor run (or
believe) a program the candidate repository configured for itself. Never initializes Git, edits
history, configures a remote or publishes.

Two separate claims are reported, because neither implies the other. `manifest_match` says each
committed path, mode, size and SHA-256 equals the private export report. `content_rescan_clean`
says the committed bytes and every manifest path were re-scanned here against the private forbidden
list, exempting only exact path + token + output-hash UTF-8 approvals, and that every committed
binary carries its `binary_sha256` approval for its private source path: the exporter's own rule,
re-derived from the committed bytes so a forged report cannot smuggle an unreviewed blob. Neither
claim proves the forbidden list itself is complete; that stays a human inventory review.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from export_public_tree import (ExportError, MAX_FILE, MAX_FILES, MAX_TOTAL, _rewriter, _scan,
                                read_policy, safe_path)


def _git(root: Path, *args: str) -> bytes:
    # Optional locks are what let a read-only status refresh write the index; refuse them twice over.
    # core.fsmonitor is the one setting a candidate repository can set for itself that makes a
    # read-only command start an external program whose answer Git then trusts for the working tree.
    # A command-line -c outranks repository, global and GIT_CONFIG_PARAMETERS config, so the monitor
    # is disabled per invocation instead of assumed absent.
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "--no-optional-locks",
             "-c", "core.fsmonitor=false",
             "-c", f"safe.directory={root.as_posix()}",
             "-C", str(root), *args], capture_output=True, timeout=30, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExportError("candidate Git read failed") from exc
    if result.returncode:
        raise ExportError("candidate Git read failed")
    return result.stdout


def _linked(path: Path) -> bool:
    """Symlink or Windows junction: on Windows a junction reports islink() False, so test both."""
    return os.path.islink(path) or path.is_junction()


def _inherits_history(gitdir: Path, name: str) -> bool:
    """Lexical answer for one history-inheritance path: never follow a link, dangling or not.

    Every component is tested, not only the leaf: `objects` or `objects/info` linked elsewhere
    reaches the same foreign object store as an alternates file, by symlink or by junction.
    """
    parts = name.split("/")
    probe = gitdir
    for index, part in enumerate(parts):
        probe = probe / part
        if _linked(probe):
            return True
        if index == len(parts) - 1 and os.path.lexists(probe):
            return True
    return False


def check_history(root: Path, revision: str, policy_path: Path, report_path: Path) -> dict:
    """Check fresh history, both identities and every committed blob/mode, without writes."""
    root = root.resolve(strict=True)
    gitdir = root / ".git"
    if _linked(gitdir) or not gitdir.is_dir():
        raise ExportError("candidate must have its own Git directory")
    for name in ("objects/info/alternates", "info/grafts", "shallow", "commondir"):
        if _inherits_history(gitdir, name):
            raise ExportError("candidate must not inherit Git storage or history")
    if _git(root, "remote").strip() or _git(root, "for-each-ref", "refs/replace").strip():
        raise ExportError("candidate must have no remotes or replacement refs")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ExportError("candidate revision must be a full commit ID")
    if _git(root, "rev-parse", "HEAD").decode().strip() != revision:
        raise ExportError("candidate HEAD differs from reviewed revision")
    if _git(root, "rev-list", "--all", "--max-count=2").decode().splitlines() != [revision]:
        raise ExportError("candidate must contain exactly one reachable commit")
    commit = _git(root, "cat-file", "commit", revision)
    if len(commit) > MAX_FILE or any(line.startswith(b"parent ") for line in commit.split(b"\n\n", 1)[0].splitlines()):
        raise ExportError("candidate must be a bounded root commit without parents")
    # A root ref alone does not prove the private object database was not copied.
    objects = _git(root, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
    rows = objects.decode("ascii").splitlines()
    if len(rows) > 2 * MAX_FILES + 1 or [r.split()[0] for r in rows if r.endswith(" commit")] != [revision]:
        raise ExportError("candidate object database contains additional history")
    reachable = {r.split()[0] for r in _git(root, "rev-list", "--objects", revision).decode().splitlines()}
    if {r.split()[0] for r in rows} != reachable:
        raise ExportError("candidate object database contains unreviewed objects")
    policy = read_policy(policy_path)
    identity = policy.get("public_identity")
    if not identity:
        raise ExportError("private policy must declare public_identity")
    identity_bytes = f"{identity['name']} <{identity['email']}> ".encode()
    for field in (b"author ", b"committer "):
        headers = [line for line in commit.split(b"\n\n", 1)[0].splitlines() if line.startswith(field)]
        if len(headers) != 1 or not headers[0][len(field):].startswith(identity_bytes):
            raise ExportError("candidate author or committer differs from public identity")
    folded = commit.decode("utf-8", errors="replace").casefold()
    if any(token.casefold() in folded for token in policy["forbidden"]):
        raise ExportError("forbidden identifier remains in commit metadata")
    # One reviewed branch only: a second benign branch on the same commit would add no object and
    # no reachable commit, yet would publish private branch topology and any stash/note/replace ref.
    refs = [line for line in _git(root, "for-each-ref", "--format=%(refname) %(objectname)").decode("utf-8").splitlines() if line]
    if len(refs) != 1:
        raise ExportError("candidate refs must hold exactly one reviewed branch")
    ref_name, _, ref_oid = refs[0].rpartition(" ")
    if not ref_name.startswith("refs/heads/") or ref_oid != revision:
        raise ExportError("candidate refs contain unreviewed metadata")
    if any(token.casefold() in ref_name.casefold() for token in policy["forbidden"]):
        raise ExportError("forbidden identifier remains in ref name")
    if _git(root, "rev-parse", "--symbolic-full-name", "HEAD").decode().strip() != ref_name:
        raise ExportError("candidate HEAD is not the reviewed branch")
    if report_path.stat().st_size > MAX_TOTAL:
        raise ExportError("private report exceeds size limit")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("policy_sha256") != hashlib.sha256(policy_path.read_bytes()).hexdigest():
        raise ExportError("private report does not match reviewed policy")
    if report.get("public_identity") != identity or report.get("history_included") is not False:
        raise ExportError("private report identity or history contract differs")
    if report.get("utf8_approvals", []) != policy.get("utf8_approvals", []):
        raise ExportError("private report UTF-8 approvals differ from reviewed policy")
    approvals = {(a["path"], a["token"].casefold()): a for a in policy.get("utf8_approvals", [])}
    # Binary approvals are keyed by the PRIVATE source path and never by the rewritten output path,
    # because the exporter looks them up before rewriting and does not rewrite binary bytes at all.
    # An approval nobody used is harmless here (it publishes nothing), so unlike UTF-8 approvals it
    # is not required to be consumed; an unapproved committed binary is not.
    binary_approvals = policy["binary_sha256"]
    used = set()
    files = report.get("files")
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise ExportError("private report has no bounded file manifest")
    expected = {}
    rewrite = _rewriter(policy)
    for row in files:
        # The manifest is not trusted wholesale: shape, selection and path content are checked here.
        # Selection is judged on the private source path, exactly as the exporter judged it, so a
        # rewritten output path cannot be blamed for a pattern it was never matched against.
        if not isinstance(row, dict) or not {"source_path", "path", "mode", "bytes", "sha256"} <= set(row):
            raise ExportError("private report rows require source path, path, mode, bytes and SHA-256")
        name, source = row["path"], row["source_path"]
        safe_path(name)
        safe_path(source)
        if type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_FILE:
            raise ExportError("private report file size is out of range")
        if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ExportError("private report file hash is malformed")
        if not any(fnmatch.fnmatchcase(source, p) for p in policy["include"]) or any(
                fnmatch.fnmatchcase(source, p) for p in policy["exclude"]):
            raise ExportError("export manifest path is not selected by the private policy")
        if any(token.casefold() in name.casefold() for token in policy["forbidden"]):
            raise ExportError("forbidden identifier remains in exported path")
        if rewrite(source) != name:
            raise ExportError("export manifest path differs from the policy rewrite of its source path")
        if name in expected:
            raise ExportError("private report repeats a file")
        expected[name] = row
    raw = _git(root, "ls-tree", "-rz", "--full-tree", revision)
    actual = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = path.decode("utf-8")
        if kind != "blob" or mode not in ("100644", "100755") or name not in expected:
            raise ExportError("candidate tree differs from export manifest")
        size = int(_git(root, "cat-file", "-s", oid))
        if size > MAX_FILE:
            raise ExportError("candidate blob exceeds size limit")
        data = _git(root, "cat-file", "blob", oid)
        row = expected[name]
        digest = hashlib.sha256(data).hexdigest()
        if mode != row["mode"] or len(data) != row["bytes"] or digest != row["sha256"]:
            raise ExportError("candidate blob differs from export manifest")
        # Independent re-scan of the committed bytes, not a manifest comparison: a report that
        # faithfully describes a leaking file is still a leak. Same scanner as the exporter.
        binary = b"\x00" in data
        try:
            data.decode("utf-8")
        except UnicodeError:
            binary = True
        if binary and binary_approvals.get(row["source_path"]) != digest:
            # Same rule as the exporter, this time against committed bytes: a report that describes an
            # unreviewed blob faithfully still describes an unreviewed blob.
            raise ExportError("candidate binary content lacks its approved source hash")
        for token, location, _count in _scan(name, data, policy["forbidden"]):
            key = (name, token.casefold())
            approval = approvals.get(key)
            if location == "content" and not binary and approval and approval["sha256"] == digest:
                used.add(key)
            else:
                raise ExportError("forbidden identifier remains in candidate " +
                                  ("filename" if location == "path" else "content or approval"))
        actual[name] = len(data)
    if set(actual) != set(expected) or sum(actual.values()) > MAX_TOTAL:
        raise ExportError("candidate tree differs from export manifest")
    if approvals.keys() - used:
        raise ExportError("candidate does not use every reviewed UTF-8 approval")
    # --ignored=matching: an ignored leftover is never published, but it must not sit in a tree
    # that the operator is about to treat as the reviewed public artifact.
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching").strip():
        raise ExportError("candidate working tree is not clean")
    return {"version": 1, "commit": revision, "files": len(actual), "fresh_root": True,
            "identity_verified": True, "manifest_match": True, "content_rescan_clean": True,
            "publication_authorized": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "revision", "policy", "report"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = check_history(Path(args.candidate), args.revision, Path(args.policy), Path(args.report))
    except (ExportError, OSError, ValueError, KeyError, TypeError):
        print("public history verification refused; inspect the private candidate and report", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
