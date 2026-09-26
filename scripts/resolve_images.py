"""Resolve public Docker Hub candidates to verified linux/amd64 manifest digests.

This downloads manifests only, not images, and makes no runtime compatibility claim.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ", ".join(("application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"))


def get(url, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=30) as response:
        return response.read(), response.headers


def verify_digest(body, expected):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", expected or ""):
        raise ValueError("Missing/unsupported registry digest")
    if "sha256:" + hashlib.sha256(body).hexdigest() != expected:
        raise ValueError("Manifest digest does not match registry bytes")


def resolve(candidate):
    repository, separator, tag = candidate.rpartition(":")
    if not separator or not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository):
        raise ValueError("Expected an explicit Docker Hub repository:tag candidate")
    query = urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
    raw, _ = get("https://auth.docker.io/token?" + query)
    token = json.loads(raw)["token"]
    headers = {"Accept": MEDIA, "Authorization": "Bearer " + token}
    base = f"https://registry-1.docker.io/v2/{repository}/manifests/"
    raw, metadata = get(base + urllib.parse.quote(tag, safe=""), headers)
    source_digest = metadata.get("Docker-Content-Digest")
    verify_digest(raw, source_digest)
    model = json.loads(raw)
    if "manifests" not in model:
        raise ValueError("Candidate has no platform index; platform needs explicit inspection")
    matches = [m for m in model["manifests"] if m.get("platform", {}).get("os") == "linux"
               and m["platform"].get("architecture") == "amd64"
               and m["platform"].get("variant", "") in ("", "v1")]
    if len(matches) != 1:
        raise ValueError("No unique linux/amd64 manifest")
    digest = matches[0]["digest"]
    raw, _ = get(base + digest, headers)
    verify_digest(raw, digest)
    return {"candidate": candidate, "source_index_digest": source_digest,
            "image": repository + "@" + digest, "platform": "linux/amd64"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; retain old resolution evidence")
    versions = json.loads((ROOT / "components/data/store-signoz/versions.json").read_text(encoding="utf-8"))
    report = {"resolved_at": dt.datetime.now(dt.timezone.utc).isoformat(), "images": {}, "errors": {},
              "runtime_conformance": "not-run", "image_downloads": "not-run"}
    for variable, candidate in versions["images"].items():
        try:
            report["images"][variable] = resolve(candidate)
        except urllib.error.HTTPError as exc:
            report["errors"][variable] = f"Registry HTTP {exc.code} for {candidate}"
        except Exception as exc:
            report["errors"][variable] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    report["status"] = "fail" if report["errors"] else "resolved"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps(report, indent=2))
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
