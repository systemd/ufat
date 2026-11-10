#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The line coverage report, see HACKING.md:
#
#     tools/coverage.sh [ARGS...]
#
# It builds everything with coverage instrumentation into target/coverage,
# runs `cargo test --locked ARGS...`, merges the profiles the tests leave
# into target/coverage/ufat.profdata, and reports the line coverage of the
# test binaries and the tool with llvm-cov into target/coverage/report.txt.
# The llvm tools must be at least as new as the LLVM in rustc. Those of
# rustup's llvm-tools component are used when it is installed, otherwise
# the first one found below. LLVM_PROFDATA= and LLVM_COV= override.
set -eu -o pipefail

cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=$PWD/target/coverage
export RUSTFLAGS="-C instrument-coverage"
profiles=$CARGO_TARGET_DIR/profiles
# Set before the build: the build scripts are instrumented as well and
# would leave their profiles in the source tree otherwise.
export LLVM_PROFILE_FILE=$profiles/%p-%m.profraw

if [ -z "${LLVM_PROFDATA:-}" ]; then
    rustup_tools=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin
    for t in "$rustup_tools/llvm-profdata" llvm-profdata-21 llvm-profdata-20 llvm-profdata-19 llvm-profdata; do
        if command -v "$t" > /dev/null; then
            LLVM_PROFDATA=$t
            break
        fi
    done
fi
if [ -z "${LLVM_PROFDATA:-}" ]; then
    echo "llvm-profdata not found, set LLVM_PROFDATA and LLVM_COV" >&2
    exit 1
fi
LLVM_COV=${LLVM_COV:-${LLVM_PROFDATA/profdata/cov}}

rm -rf "$profiles"
cargo test --locked "$@"

objects=()
while read -r b; do
    objects+=(-object "$b")
done < <(cargo test --locked --no-run --message-format=json "$@" | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')

"$LLVM_PROFDATA" merge -sparse -o "$CARGO_TARGET_DIR/ufat.profdata" "$profiles"/*.profraw
# Test code, build scripts and the toolchain's own sources are left out.
"$LLVM_COV" report "${objects[@]}" -instr-profile="$CARGO_TARGET_DIR/ufat.profdata" \
    --ignore-filename-regex='/rustc/|/\.cargo/|/\.rustup/|(^|/)tests/|tests\.rs$|(^|/)build\.rs$' |
    tee "$CARGO_TARGET_DIR/report.txt"
