#!/bin/sh
# Operator-side product gates for a pinned local-observe release, run as one command, offline.
#
# Usage:
#   scripts/operator/overlay_gate.sh [--python INTERPRETER] --root CHECKOUT --pin PIN MODEL [MODEL...]
#
#   --root CHECKOUT   the pinned product checkout (a git clone at a detached tag, not a vendored copy)
#   --pin PIN         the operator's local-observe.pin.json (tag, commit, images)
#   MODEL...          one or more operator Compose models: each is the top-level file that `include:`s
#                     the pinned component manifests merged with that operator's own overlays. Paths
#                     resolve as the shell resolves them, against the caller's working directory.
#
# What it runs, and in this order:
#   check_foundation.py --root CHECKOUT --compose MODEL   (once per MODEL)
#   operator/pin_check.py --pin PIN --checkout CHECKOUT   (once)
#
# Every model is gated in its own run, so the output names the file that failed rather than a merged
# list of lines from several. Exit is 0 only when every run passed, 1 when any run refused, and 2 for
# bad arguments -- a missing --pin or an empty model list must never read as a green gate. Nothing
# here starts a container, reads a host, fetches from a remote or writes a file: it is the offline
# pre-merge check docs/OPERATOR-MODEL.md section 6 describes, and CD still runs no part of it.
set -eu

here=$(cd "$(dirname "$0")/../.." && pwd) # the checkout holding these gate scripts (scripts/operator/..)
python=${PYTHON:-python3}              # ${PYTHON} wins, so CI can name an interpreter
root=""
pin=""

usage() {
    echo "usage: overlay_gate.sh [--python INTERPRETER] --root CHECKOUT --pin PIN MODEL [MODEL...]" >&2
}

while [ $# -gt 0 ]; do
    case $1 in
        --python) [ $# -ge 2 ] || { echo "overlay_gate: --python needs a value" >&2; exit 2; }
            python=$2; shift 2 ;;
        --root) [ $# -ge 2 ] || { echo "overlay_gate: --root needs a value" >&2; exit 2; }
            root=$2; shift 2 ;;
        --pin) [ $# -ge 2 ] || { echo "overlay_gate: --pin needs a value" >&2; exit 2; }
            pin=$2; shift 2 ;;
        -h|--help)
            echo "usage: overlay_gate.sh [--python INTERPRETER] --root CHECKOUT --pin PIN MODEL [MODEL...]"
            echo "each MODEL is an operator Compose file that include:s the pinned product manifests;"
            echo "the header of this file says what the two gates run and what their exit codes mean"
            exit 0 ;;
        -*) echo "overlay_gate: unknown option $1 (see --help)" >&2; usage; exit 2 ;;
        *) break ;;
    esac
done

if [ -z "$root" ] || [ -z "$pin" ] || [ $# -eq 0 ]; then
    usage
    exit 2
fi
if [ ! -d "$root/components" ]; then
    echo "overlay_gate: --root $root holds no components/ directory, so it is not a product checkout" >&2
    exit 1
fi
if ! command -v "$python" >/dev/null 2>&1; then
    echo "overlay_gate: no interpreter named $python (set PYTHON or --python)" >&2
    exit 2
fi

status=0
for model in "$@"; do
    echo "--- check_foundation --root $root --compose $model"
    "$python" -B "$here/scripts/check_foundation.py" --root "$root" --compose "$model" || status=1
done
echo "--- pin_check --pin $pin --checkout $root"
"$python" -B "$here/scripts/operator/pin_check.py" --pin "$pin" --checkout "$root" || status=1

if [ "$status" -ne 0 ]; then
    echo "overlay_gate: FAILED ($# model(s) and one pin checked)" >&2
fi
exit "$status"
