#!/bin/sh
# Trains the profile for a profile-guided build (.github/workflows/release.yml). Installs the
# instrumented cp314 wheel in DIR (built with -Cprofile-generate) in a venv of its own
# (UV_PROJECT_ENVIRONMENT, .venv-pgo by default) with the CodSpeed benchmarks' dependencies (the
# codspeed group alone: no cryptography, which has no wheel for every platform trained on), then
# runs the benchmarks (benchmarks/), each process writing its counts to RAW_DIR. Between them they
# use every feature; a feature they leave out can get slower, not faster. On Python 3.14 (UV_PYTHON
# can name a build of it, e.g. an x86_64 one to run under Rosetta): one profile serves every
# Python's wheel. Run from the repo root, with uv:
#   sh .github/scripts/pgo-train.sh DIR RAW_DIR
set -eu

dir=$1
raw=$2

# The one file of the glob it's given; fails unless there's exactly one.
only() {
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        echo "Expected one wheel, got: $*" >&2
        exit 1
    fi
    echo "$1"
}

wheel=$(only "$dir"/ryjwt-*-cp314-cp314-*.whl)
mkdir -p "$raw"
raw=$(cd "$raw" && pwd)
# In Git Bash (Windows), as a path the extension can open: D:/a/..., not /d/a/...
if command -v cygpath >/dev/null 2>&1; then
    raw=$(cygpath -m "$raw")
fi
export UV_PYTHON="${UV_PYTHON:-3.14}" UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-.venv-pgo}"
export LLVM_PROFILE_FILE="$raw/ryjwt-%p-%m.profraw"
set -x
uv sync --locked --only-group codspeed
uv pip install --python "$UV_PROJECT_ENVIRONMENT" --no-deps "$wheel"
uv run --no-sync pytest benchmarks -p no:cacheprovider -q \
    --codspeed --codspeed-mode walltime --codspeed-warmup-time 0.1 --codspeed-max-time 0.5
rm -rf .codspeed
