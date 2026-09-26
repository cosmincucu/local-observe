"""Refuse an operator release pin that is not true of the product checkout standing beside it.

The operator side of a release is one small committed file, `local-observe.pin.json`, naming the
product tag the installation runs, the commit that tag points at, and the image digests its
deployment uses (docs/RELEASING.md, "The operator's pin file"). This gate asks one question, offline,
in the operator's CI, and answers with a refusal naming both sides of every disagreement:

* is the pinned commit still the commit that tag resolves to in the checkout on disk (a tag that
  moved, a checkout advanced by hand, or a pin copied from an earlier release all fail here); and
* is every digest the operator pinned one this product checkout actually records in
  `components/**/versions.json` (or, for a third-party image, in its resolved `image-lock.json`)?

What it cannot prove, and does not claim: that the running containers use those digests, that the
checkout's working tree is clean at that tag, or that the images exist in any daemon. Those belong to
`lo-deployment verify-release` and the runtime conformance run
(`docs/OPERATOR-MODEL.md` section 6), never to an offline file check.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

#: The whole key set. A typo (`commmit`) would otherwise drop a promise silently, so an unknown key
#: is a refusal rather than something to ignore.
PIN_KEYS = ("tag", "commit", "images")
TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
#: A key that names an image rather than describing a property of one: `LO_SIGNOZ_IMAGE` yes, `image`
#: no. Used to keep the name a digest belongs to when the reference sits one level deeper in the file.
UPPER_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
#: Product files under `components/` that record an image identity. `versions.json` is the release
#: contract's pin register; `image-lock.json` is where a candidate tag's *resolved* digest lives
#: (components/data/store-signoz/image-lock.json), so a digest-only pin has to be read from both.
PIN_SOURCES = ("versions.json", "image-lock.json")


def load_pin(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Read the operator's pin file as (pin, errors); the errors returned are structural, not semantic.

    A file that cannot be read, parsed or understood is refused outright and the caller runs no further
    check against it, because half a pin is not a promise -- so the mapping returned in that case is
    empty, never a partially valid one that a later check could quietly trust.
    """
    if not path.is_file():
        return {}, [f"{path}: no operator pin file there (this gate has nothing to honour; name the "
                    f"tag, the commit and the images, or say why the file was removed)"]
    try:
        pin = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {}, [f"{path}: is not readable JSON ({exc})"]
    if not isinstance(pin, dict):
        return {}, [f"{path}: must hold one JSON object with the keys {', '.join(PIN_KEYS)}"]
    errors: list[str] = []
    for key in sorted(set(pin) - set(PIN_KEYS)):
        errors.append(f"{path}: unknown pin key {key!r}; this gate reads only {', '.join(PIN_KEYS)}, "
                      f"so a key it cannot check is a promise it cannot keep")
    for key in PIN_KEYS:
        if key not in pin:
            errors.append(f"{path}: missing required key {key!r}")
    if "tag" in pin and (not isinstance(pin["tag"], str) or not TAG_PATTERN.fullmatch(pin["tag"])):
        errors.append(f"{path}: tag must look like vMAJOR.MINOR.PATCH, not {pin['tag']!r}")
    if "commit" in pin and (not isinstance(pin["commit"], str)
                            or not COMMIT_PATTERN.fullmatch(pin["commit"])):
        errors.append(f"{path}: commit must be a full 40-hex-digit commit ID, never an abbreviated one "
                      f"or a tag name ({pin['commit']!r})")
    if "images" in pin and (not isinstance(pin["images"], dict) or not pin["images"]):
        errors.append(f"{path}: images must be a non-empty mapping of image name to digest-pinned "
                      f"reference; a pin that names no image checks nothing")
    return ({}, errors) if errors else (pin, [])


def product_pins(root: Path) -> tuple[dict[str, dict[str, str]], dict[str, str], list[str]]:
    """Return the digests a product checkout records, as (by name, by digest, errors).

    Walks `components/**/versions.json` and `components/**/image-lock.json` for any string value
    holding a `sha256:<64 hex>` digest, keyed by the JSON name beside it (and by the nearest enclosing
    UPPER_SNAKE name, which is how `image-lock.json` nests a reference) and also pooled by digest
    alone. Keyed comparison is what catches two pins swapped, which a bare set test would wave
    through. A pin register that will not parse is itself an error line: an unreadable register must
    not read as an empty one that nothing can disagree with.
    """
    by_name: dict[str, dict[str, str]] = {}
    by_digest: dict[str, str] = {}
    errors: list[str] = []

    def walk(node: Any, name: str | None, upper: str | None, where: str) -> None:
        """Record every digest under its own key and under the Compose-style name enclosing it.

        `image-lock.json` nests the reference one level deeper (`images.LO_SIGNOZ_IMAGE.image`), so the
        innermost key alone would call every third-party digest `image` and lose the name that makes a
        swapped pin detectable. `upper` carries the nearest enclosing UPPER_SNAKE key, which is how the
        product names an image variable.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, str(key), str(key) if UPPER_NAME.fullmatch(str(key)) else upper, where)
        elif isinstance(node, list):
            for value in node:
                walk(value, name, upper, where)
        elif isinstance(node, str):
            match = DIGEST_PATTERN.search(node)
            if match is None:
                return
            by_digest.setdefault(match.group(0), where)
            for key in (name, upper):
                if key:
                    by_name.setdefault(key, {}).setdefault(match.group(0), where)

    components = root / "components"
    if components.is_dir():
        for path in sorted(components.rglob("*.json")):
            if path.name not in PIN_SOURCES:
                continue
            try:
                body = path.read_text(encoding="utf-8")
            except OSError as exc:
                errors.append(f"{path.relative_to(root).as_posix()}: pin register cannot be read ({exc})")
                continue
            try:
                walk(json.loads(body), None, None, path.relative_to(root).as_posix())
            except json.JSONDecodeError as exc:
                errors.append(f"{path.relative_to(root).as_posix()}: pin register is not valid JSON "
                              f"({exc}), so no pin can be honoured against this checkout")
    return by_name, by_digest, errors


def tag_commit(checkout: Path, tag: str) -> str | None:
    """The commit `tag` peels to in `checkout`, or None when the checkout holds no such tag.

    `refs/tags/` is spelled out so a *branch* carrying the release name cannot satisfy a tag pin, and
    nothing here fetches: the promise of a pinned checkout is reviewed bytes, not whatever the remote
    says today.
    """
    result = subprocess.run(
        ["git", "-c", f"safe.directory={checkout.as_posix()}", "-C", str(checkout), "rev-parse",
         "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}"],
        capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        return None
    return result.stdout.strip() or None


def check_commit(tag: str, pinned: str, resolved: str | None, checkout: Path) -> list[str]:
    """Refuse a pin whose commit is not the commit that tag names in this checkout."""
    if resolved is None:
        return [f"tag {tag}: the product checkout at {checkout} resolves no such tag, so these bytes "
                f"cannot honour the pin (fetch the release or re-tag it; never advance the checkout by "
                f"hand and leave the pin behind)"]
    if resolved != pinned:
        return [f"tag {tag}: pin names commit {pinned}, that tag resolves to {resolved} in {checkout}; "
                f"a tag that moved is a different release and must be re-reviewed, not re-pinned by eye"]
    return []


def check_images(images: dict[str, Any], by_name: dict[str, dict[str, str]], by_digest: dict[str, str],
                 checkout: Path) -> list[str]:
    """Refuse any pinned image that is not digest-pinned, or not the digest this release records.

    A name the product records nothing under is judged against the digest pool instead, so an operator
    may key a pin by their own label (`gatus`, say) as long as the digest is one this release names.
    """
    errors: list[str] = []
    for name in sorted(images):
        value = images[name]
        if not isinstance(value, str):
            errors.append(f"{name}: an image pin must be one reference string, not "
                          f"{type(value).__name__}")
            continue
        match = DIGEST_PATTERN.search(value)
        if match is None:
            errors.append(f"{name}: {value} carries no sha256 digest; a floating or tag-only reference "
                          f"is exactly the drift this pin file exists to make impossible")
            continue
        digest = match.group(0)
        recorded = by_name.get(name)
        if recorded and digest not in recorded:
            errors.append(f"{name}: pinned {digest}, which "
                          f"{', '.join(sorted(set(recorded.values())))} does not record for {name} (it "
                          f"records {', '.join(sorted(recorded))}); pull the release first and re-pin "
                          f"after, never the reverse")
        elif not recorded and digest not in by_digest:
            errors.append(f"{name}: pinned {digest}, which no {' or '.join(PIN_SOURCES)} under "
                          f"{(checkout / 'components').as_posix()} records; either that is not this "
                          f"release's image or the product pin register is missing it")
    return errors


def check_pin(pin: dict[str, Any], checkout: Path,
              resolve: Callable[[Path, str], str | None] | None = None,
              pins: Callable[[Path], tuple[dict[str, dict[str, str]], dict[str, str], list[str]]]
              | None = None) -> list[str]:
    """Every refusal against a structurally valid pin: the register lines, the commit line, the images.

    `resolve` and `pins` are parameters so the comparison is testable without a git repository and
    without a product tree; leaving them None binds the real readers at call time (not at definition
    time, which is what makes a module-level patch of either one reach here).
    """
    resolve = resolve or tag_commit
    pins = pins or product_pins
    by_name, by_digest, errors = pins(checkout)
    errors += check_commit(pin["tag"], pin["commit"], resolve(checkout, pin["tag"]), checkout)
    errors += check_images(pin["images"], by_name, by_digest, checkout)
    return errors


def main(argv: list[str] | None = None) -> int:
    """Check one operator pin against one product checkout; exit non-zero on any refusal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, required=True,
                        help="the operator's local-observe.pin.json")
    parser.add_argument("--checkout", type=Path, required=True,
                        help="the pinned product checkout whose tag must resolve to the pinned commit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    pin_path = Path(args.pin)
    checkout = Path(args.checkout).resolve()
    pin, errors = load_pin(pin_path)
    if not errors:
        errors = check_pin(pin, checkout)
    if args.json:
        print(json.dumps({"pin_check": "fail" if errors else "pass", "pin": str(pin_path),
                          "checkout": str(checkout), "tag": (pin or {}).get("tag"),
                          "errors": errors}, indent=2))
    elif errors:
        print("\n".join(errors))
    else:
        print(f"pin OK: {pin['tag']} at {pin['commit']} with {len(pin['images'])} image digest(s) "
              f"matching {checkout}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
