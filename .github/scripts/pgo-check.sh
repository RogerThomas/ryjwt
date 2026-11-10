#!/bin/sh
# Checks the profile-guided build of the wheel for Python 3.14, the Python the profile was
# trained on, by what rustc said about the profile (LOG, from rustc-pgo.rs). rustc only warns
# when the profile can't be read or doesn't match the code, and builds on without it; it says
# nothing at all about a function it finds no counts for unless built with
# -Cllvm-args=-pgo-warn-missing-function. Fails if the profile couldn't be read, or the build
# found any function changed since the training, or any of ryjwt's own functions (crate `_ryjwt`)
# without counts. (The other Pythons' builds can find some of both, in code that differs between
# Python versions, e.g. PyO3's, and use the rest.) Run from the repo root:
#   sh .github/scripts/pgo-check.sh LOG
set -eu

log=$1

if [ ! -f "$log" ]; then
    echo "::error::$log is missing: the build didn't run rustc through rustc-pgo.rs"
    exit 1
fi
unreadable=$(grep -c '\.profdata' "$log" || true)
changed=$(grep -c 'hash mismatch' "$log" || true)
# The functions without counts, by their (v0) symbol names; ryjwt's own are those whose path
# starts in crate _ryjwt: whose first crate root (C, a disambiguator s..._, then the name's length
# and the name, after a _ when it starts with one) is _ryjwt. Not, say, a hashbrown function
# instantiated in _ryjwt, which only ends there.
missing=$(sed -n 's/.*no profile data available for function \(_R[0-9A-Za-z_]*\).*/\1/p' "$log" \
    | sort -u)
own=$(printf '%s\n' "$missing" | awk '
    match($0, /C(s[0-9A-Za-z]*_)?[0-9]+/) {
        len = substr($0, RSTART, RLENGTH); sub(/^C(s[0-9A-Za-z]*_)?/, "", len)
        name = substr($0, RSTART + RLENGTH); sub(/^_/, "", name)
        if (substr(name, 1, len + 0) == "_ryjwt") print
    }')
# The number of lines in $1, 0 when it's empty.
count() {
    if [ -z "$1" ]; then
        echo 0
    else
        printf '%s\n' "$1" | wc -l | tr -d ' '
    fi
}
echo "Python 3.14's build: $changed functions changed since the training;" \
    "$(count "$missing") without counts, $(count "$own") of them ryjwt's own"
if [ "$unreadable" -ne 0 ] || [ "$changed" -ne 0 ] || [ -n "$own" ]; then
    { grep -E '\.profdata|hash mismatch' "$log" || true; printf '%s\n' "$own"; } \
        | head -5 | cut -c1-400
    echo "::error::The wheel for Python 3.14 doesn't match the profile it was trained for"
    exit 1
fi
