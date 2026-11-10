#!/bin/sh
# Merges the raw counts pgo-train.sh wrote to RAW_DIR into PROFILE, the file a profile-guided
# build takes (-Cprofile-use), with the toolchain's own llvm-profdata (rustup's llvm-tools, the
# same LLVM as the compiler). Fails if there are no counts, or the profile is empty or unreadable:
# rustc only warns about a bad profile and builds without it. Then builds the builds' RUSTC_WRAPPER
# (rustc-pgo.rs) next to PROFILE: rustc_pgo, or rustc_pgo.exe on Windows. Run from the repo root,
# where the builds run (in their container, on Linux):
#   sh .github/scripts/pgo-merge.sh RAW_DIR PROFILE
set -eu

raw=$1
profile=$2

rustup component add llvm-tools
host=$(rustc -vV | sed -n 's/^host: //p')
sysroot=$(rustc --print sysroot)
if command -v cygpath >/dev/null 2>&1; then
    sysroot=$(cygpath -u "$sysroot") # Git Bash (Windows): C:\Users\... as /c/Users/...
fi
profdata="$sysroot/lib/rustlib/$host/bin/llvm-profdata"

set -- "$raw"/*.profraw
if [ ! -f "$1" ]; then
    echo "::error::No profile counts in $raw"
    exit 1
fi
"$profdata" merge --failure-mode=any -o "$profile" "$@"
summary=$("$profdata" show "$profile")
echo "$summary"
total=$(echo "$summary" | sed -n 's/^Total count: //p')
if [ "${total:-0}" -eq 0 ]; then
    echo "::error::$profile has no counts"
    exit 1
fi
echo "$profile: $(wc -c < "$profile") bytes, from $# raw files"

rustc -O --edition 2024 --crate-name rustc_pgo --out-dir "$(dirname "$profile")" \
    .github/scripts/rustc-pgo.rs
