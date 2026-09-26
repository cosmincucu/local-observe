"""Build a reviewed, history-free tree from pinned Git blobs and a PRIVATE policy.

No network access, worktree copying, Git initialization, publication or deletion.
See docs/units/public-export.md for the policy and remaining release gates.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 10000
MAX_DIAGNOSTICS = 100
MAX_DIAGNOSTIC_BYTES = 128 * 1024
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10))}


class ExportError(ValueError):
    """Invalid input; messages deliberately do not echo policy or source content."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportError("duplicate policy key: " + _label(key))
        result[key] = value
    return result


def _label(value: str, limit: int = 128) -> str:
    """Bounded printable policy/path metadata, never a source-content excerpt."""
    escaped = value[:limit + 1].encode("unicode_escape").decode("ascii")
    return escaped if len(escaped) <= limit else escaped[:limit] + "...[truncated]"


def _keys(value, required: set[str], role: str, optional=frozenset()) -> None:
    if not isinstance(value, dict):
        raise ExportError(role + " must be an object")
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ExportError("missing " + role + " key: " + _label(sorted(missing)[0]))
    if unknown:
        raise ExportError("unknown " + role + " key: " + _label(sorted(unknown)[0]))


def _text(value) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def read_policy(path: Path) -> dict:
    if path.stat().st_size > MAX_FILE:
        raise ExportError("policy exceeds size limit")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExportError("policy must be UTF-8 JSON") from exc
    required = {"version", "include", "exclude", "replacements", "forbidden", "binary_sha256"}
    _keys(policy, required, "policy", {"utf8_approvals", "public_identity"})
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise ExportError("unsupported policy version")
    for key in ("include", "exclude", "forbidden"):
        values = policy[key]
        if not isinstance(values, list) or not all(_text(v) for v in values):
            raise ExportError("policy " + key + " must contain nonempty UTF-8 strings")
    if not policy["include"] or not policy["forbidden"]:
        raise ExportError("explicit selection and forbidden checks are required")
    for pattern in policy["include"] + policy["exclude"]:
        if pattern.startswith("/") or "\\" in pattern or ":" in pattern or ".." in pattern.split("/"):
            raise ExportError("invalid selection pattern")
    replacements = policy["replacements"]
    if not isinstance(replacements, list):
        raise ExportError("replacements must be a list")
    seen = set()
    for entry in replacements:
        _keys(entry, {"from", "to"}, "replacement")
        if not all(_text(entry[k]) for k in ("from", "to")):
            raise ExportError("replacement strings must be nonempty")
        if entry["from"] in seen or entry["from"] == entry["to"]:
            raise ExportError("duplicate or ineffective replacement")
        seen.add(entry["from"])
    hashes = policy["binary_sha256"]
    if not isinstance(hashes, dict) or not all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for k, v in hashes.items()):
        raise ExportError("binary approvals require source path and SHA-256")
    for path in hashes:
        safe_path(path)
    approvals = policy.get("utf8_approvals", [])
    if not isinstance(approvals, list) or len(approvals) > MAX_FILES:
        raise ExportError("utf8_approvals must be a bounded list")
    seen_approvals = set()
    for entry in approvals:
        _keys(entry, {"path", "sha256", "token", "reason"}, "UTF-8 approval")
        if not all(_text(entry[k]) for k in entry):
            raise ExportError("UTF-8 approval fields must be nonempty UTF-8 strings")
        safe_path(entry["path"])
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ExportError("UTF-8 approval requires output SHA-256")
        if entry["token"] not in policy["forbidden"]:
            raise ExportError("UTF-8 approval token must name a forbidden entry")
        if not entry["reason"].strip() or len(entry["reason"].encode("utf-8")) > 1000 or not entry["reason"].isprintable():
            raise ExportError("UTF-8 approval reason must be printable and at most 1000 bytes")
        key = (entry["path"], entry["token"].casefold())
        if key in seen_approvals:
            raise ExportError("duplicate UTF-8 approval path/token")
        seen_approvals.add(key)
    if "public_identity" in policy:
        identity = policy["public_identity"]
        _keys(identity, {"name", "email"}, "public_identity")
        if not all(_text(v) and v == v.strip() and v.isprintable() for v in identity.values()):
            raise ExportError("public_identity fields must be printable nonempty strings")
        if len(identity["name"].encode("utf-8")) > 100 or any(c in identity["name"] for c in "<>"):
            raise ExportError("public_identity name must be at most 100 bytes without angle brackets")
        if len(identity["email"]) > 254 or len(identity["email"].split("@")[0]) > 64 or ".." in identity["email"] or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9_+-])?@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+", identity["email"]):
            raise ExportError("public_identity email must be a plain email address")
        if any(token.casefold() in v.casefold() for token in policy["forbidden"] for v in identity.values()):
            raise ExportError("public_identity contains a forbidden identifier")
    return policy


def safe_path(name: str) -> None:
    if not _text(name):
        raise ExportError("unsafe export path")
    parts = name.split("/")
    if not name or len(name.encode("utf-8")) > 4096 or PurePosixPath(name).is_absolute() or any(
        not p or len(p.encode("utf-8")) > 255 or p in (".", "..") or p[-1:] in (".", " ") or
        any(ord(c) < 32 or c in '\\:<>"|?*' for c in p) or
        p.casefold() == ".git" or p.casefold().split(".")[0] in RESERVED
        for p in parts
    ):
        raise ExportError("unsafe export path")


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _git(source: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-c", f"safe.directory={source.as_posix()}",
                             "-C", str(source), *args], capture_output=True, check=False)
    if result.returncode:
        raise ExportError("source Git read failed")
    return result.stdout


def _rewriter(policy: dict):
    mapping = {v["from"]: v["to"] for v in policy["replacements"]}
    pattern = re.compile("|".join(re.escape(k) for k in sorted(mapping, key=lambda s: (-len(s), s)))) if mapping else None
    def rewrite(text):
        if not pattern:
            return text
        size = len(text.encode("utf-8"))
        for match in pattern.finditer(text):
            size += len(mapping[match[0]].encode("utf-8")) - len(match[0].encode("utf-8"))
            if size > MAX_FILE:
                raise ExportError("rewritten value exceeds byte limit")
        return pattern.sub(lambda m: mapping[m[0]], text)
    return rewrite


def _scan(name: str, data: bytes, forbidden: list[str]):
    """Yield one count per token/location; do not return any matched context."""
    folded = ""
    try:
        folded = data.decode("utf-8").casefold()
    except UnicodeError:
        pass
    path_folded, data_lower = name.casefold(), data.lower()
    for token in forbidden:
        path_count = path_folded.count(token.casefold())
        content_count = max(folded.count(token.casefold()), data_lower.count(token.encode("utf-8").lower()))
        if path_count:
            yield token, "path", path_count
        if content_count:
            yield token, "content", content_count


def _record(diagnostics, kind, path, token, count):
    diagnostics["total_findings"] += 1
    diagnostics["matched_occurrences"] += count
    if len(diagnostics["findings"]) < MAX_DIAGNOSTICS:
        diagnostics["findings"].append({"kind": kind, "path": _label(path, 512),
                                        "token": _label(token), "count": count})
    else:
        diagnostics["truncated"] = True


def _write_report(path: Path, report: dict) -> None:
    # O_EXCL refuses existing files and links; private by default on POSIX.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True)
        stream.write("\n")


def _locations(source, policy_path, destination, report_path):
    if destination.is_symlink() or report_path.is_symlink():
        raise ExportError("output and private report must not be symlinks")
    source, policy_path = source.resolve(strict=True), policy_path.resolve(strict=True)
    destination, report_path = destination.resolve(), report_path.resolve()
    if not source.is_dir() or not policy_path.is_file():
        raise ExportError("source directory and private policy file are required")
    separations = (
        (_inside(destination, source) or _inside(source, destination), "output and source must not contain one another"),
        (_inside(policy_path, source), "private policy must be outside source"),
        (_inside(policy_path, destination), "private policy must be outside output"),
        (_inside(report_path, source), "private report must be outside source"),
        (_inside(report_path, destination) or _inside(destination, report_path), "private report and output must not contain one another"),
        (_inside(destination, policy_path.parent), "output must not live under the private policy directory"),
        (report_path == policy_path, "private report must differ from private policy"),
    )
    for invalid, message in separations:
        if invalid:
            raise ExportError(message)
    if destination.exists() or report_path.exists():
        raise ExportError("output and private report must be new paths")
    if not destination.parent.is_dir() or not report_path.parent.is_dir():
        raise ExportError("output and private report parent directories must exist")
    return source, policy_path, destination, report_path


def export_tree(source: Path, revision: str, policy_path: Path, destination: Path,
                report_path: Path, *, dry_run: bool = False, diagnose: bool = False) -> dict:
    """Write diagnostics only by explicit request, after validating private locations."""
    source, policy_path, destination, report_path = _locations(source, policy_path, destination, report_path)
    diagnostics = {"findings": [], "total_findings": 0, "matched_occurrences": 0,
                   "scanned_files": 0, "truncated": False}
    try:
        result = _export_tree(source, revision, policy_path, destination, report_path,
                              dry_run=dry_run, diagnostics=diagnostics)
    except (ExportError, OSError) as exc:
        if diagnose:
            report = {"version": 1, "status": "refused", "publication_authorized": False,
                      "error": str(exc) if isinstance(exc, ExportError) else "export I/O failed",
                      "diagnostics": diagnostics}
            if len(json.dumps(report, ensure_ascii=True).encode("ascii")) > MAX_DIAGNOSTIC_BYTES:
                raise ExportError("diagnostic report exceeds byte limit") from exc
            _write_report(report_path, report)
        raise
    if dry_run and diagnose:
        _write_report(report_path, {"version": 1, "status": "validated", "publication_authorized": False,
                                    "validated_files": len(result["files"]), "diagnostics": diagnostics})
    return result


def _export_tree(source: Path, revision: str, policy_path: Path, destination: Path,
                 report_path: Path, *, dry_run: bool, diagnostics: dict) -> dict:
    """Validate all selected blobs before creating destination; return private manifest.

    Report and output must not exist. On an I/O failure, preserve partial output for
    inspection; no success report is written and a retry requires a new destination.
    """
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ExportError("revision must be a full lowercase commit ID")
    resolved = _git(source, "rev-parse", "--verify", revision + "^{commit}").decode("ascii").strip()
    if resolved != revision:
        raise ExportError("revision must identify the commit itself")
    policy = read_policy(policy_path)
    approvals = {(a["path"], a["token"].casefold()): a for a in policy.get("utf8_approvals", [])}
    used_approvals = set()
    rewrite = _rewriter(policy)
    entries = _git(source, "ls-tree", "-rz", "--full-tree", revision).split(b"\0")
    if len(entries) > MAX_FILES + 1:
        raise ExportError("source tree exceeds file-count limit")
    outputs, manifest, omitted, seen = [], [], [], set()
    total = 0
    # Mapping names are never product material, even if accidentally selected.
    private_names = {"anonymise.map", "anonymize.map", policy_path.name.casefold()}
    for raw in entries:
        if not raw:
            continue
        metadata, raw_name = raw.split(b"\t", 1)
        try:
            name = raw_name.decode("utf-8")
        except UnicodeError as exc:
            raise ExportError("source filename is not UTF-8") from exc
        mode, kind, oid = metadata.decode("ascii").split()
        selected = any(fnmatch.fnmatchcase(name, p) for p in policy["include"])
        excluded = any(fnmatch.fnmatchcase(name, p) for p in policy["exclude"])
        if not selected or excluded:
            omitted.append(name)
            continue
        safe_path(name)
        if any(p.casefold() in private_names for p in name.split("/")):
            raise ExportError("private mapping selected for export")
        if mode not in ("100644", "100755") or kind != "blob":
            raise ExportError("selected symlinks and submodules are unsupported")
        size = int(_git(source, "cat-file", "-s", oid))
        total += size
        if size > MAX_FILE or total > MAX_TOTAL:
            raise ExportError("selected input exceeds byte limit")
        data = _git(source, "cat-file", "blob", oid)
        if len(data) != size:
            raise ExportError("source blob size mismatch")
        output_name = rewrite(name)
        safe_path(output_name)
        key = output_name.casefold()
        if key in seen or any(key.startswith(old + "/") or old.startswith(key + "/") for old in seen):
            raise ExportError("rewritten paths collide")
        if any(p.casefold() in private_names for p in output_name.split("/")):
            raise ExportError("rewritten path selects private mapping")
        seen.add(key)
        binary = b"\x00" in data
        try:
            decoded = data.decode("utf-8")
        except UnicodeError:
            binary = True
        if binary:
            if policy["binary_sha256"].get(name) != hashlib.sha256(data).hexdigest():
                raise ExportError("unreviewed binary selected")
        else:
            data = rewrite(decoded).encode("utf-8")
        if len(data) > MAX_FILE:
            raise ExportError("rewritten file exceeds byte limit")
        diagnostics["scanned_files"] += 1
        output_hash = hashlib.sha256(data).hexdigest()
        for token, location, count in _scan(output_name, data, policy["forbidden"]):
            approval_key = (output_name, token.casefold())
            approval = approvals.get(approval_key)
            if location == "content" and not binary and approval and approval["sha256"] == output_hash:
                used_approvals.add(approval_key)
            else:
                _record(diagnostics, "forbidden-" + location, output_name, token, count)
        outputs.append((output_name, data, mode))
        manifest.append({"source_path": name, "path": output_name, "mode": mode,
                         "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "binary": binary})
    for key in approvals.keys() - used_approvals:
        _record(diagnostics, "stale-utf8-approval", key[0], approvals[key]["token"], 0)
    if diagnostics["total_findings"]:
        raise ExportError("forbidden identifier remains or UTF-8 approval is stale; use --diagnose for private details")
    if not outputs:
        raise ExportError("selection produced no files")
    output_bytes = sum(len(data) for _, data, _ in outputs)
    if output_bytes > MAX_TOTAL:
        raise ExportError("rewritten output exceeds byte limit")
    manifest.sort(key=lambda row: row["path"])
    public_manifest = [{k: v for k, v in row.items() if k != "source_path"} for row in manifest]
    result = {"version": 1, "source_revision": revision, "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
              "files": manifest, "omitted": sorted(omitted), "total_bytes": output_bytes,
              "tree_sha256": hashlib.sha256(json.dumps(public_manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
              "history_included": False, "publication_authorized": False}
    if "utf8_approvals" in policy:
        result["utf8_approvals"] = policy["utf8_approvals"]
    if "public_identity" in policy:
        result["public_identity"] = policy["public_identity"]
    if dry_run:
        return result
    destination.mkdir()
    for name, data, mode in outputs:
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(data)
        os.chmod(output, 0o755 if mode == "100755" else 0o644)
        if output.read_bytes() != data:
            raise ExportError("output readback failed; inspect incomplete destination")
    _write_report(report_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("source", "revision", "policy", "destination", "report"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--dry-run", action="store_true", help="validate only; write neither output nor report")
    parser.add_argument("--diagnose", action="store_true", help="write private diagnostics on refusal or dry-run; never print matched context")
    args = parser.parse_args()
    try:
        result = export_tree(Path(args.source), args.revision, Path(args.policy), Path(args.destination),
                             Path(args.report), dry_run=args.dry_run, diagnose=args.diagnose)
    except (ExportError, OSError) as exc:
        # OS exception filenames may disclose private paths. Do not print them.
        print(str(exc) if isinstance(exc, ExportError) else "export I/O failed; no success claimed", file=sys.stderr)
        return 1
    print(json.dumps({"validated_files": len(result["files"]), "total_bytes": result["total_bytes"],
                      "tree_sha256": result["tree_sha256"], "dry_run": args.dry_run}))
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
