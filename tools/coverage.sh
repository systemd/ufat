#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The line coverage report, see HACKING.md. In a build directory set up
# with -Db_coverage=true, the tests leave their profiles in OUTDIR and the
# coverage-report target runs
#
#     tools/coverage.sh OUTDIR BINARY...
#
# It merges the profiles into OUTDIR/ufat.profdata, removes them, and
# reports the line coverage of the BINARYs with llvm-cov into
# OUTDIR/report.txt. The llvm tools must be at least as new as the LLVM in
# rustc. The first one found below is used, LLVM_PROFDATA= and LLVM_COV=
# override.
set -eu -o pipefail

out=$1
shift

if [ -z "${LLVM_PROFDATA:-}" ]; then
    for t in llvm-profdata-21 llvm-profdata-20 llvm-profdata-19 llvm-profdata; do
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

profiles=("$out"/*.profraw)
if [ -e "${profiles[0]}" ]; then
    "$LLVM_PROFDATA" merge -sparse -o "$out/ufat.profdata" "${profiles[@]}"
    rm -f "${profiles[@]}"
elif [ ! -e "$out/ufat.profdata" ]; then
    echo "no profiles in $out, run meson test first" >&2
    exit 1
fi

objects=()
for b in "${@:2}"; do
    objects+=(-object "$b")
done
# Test code and the toolchain's own sources are left out.
"$LLVM_COV" report "$1" "${objects[@]}" -instr-profile="$out/ufat.profdata" \
    --ignore-filename-regex='/rustc/|/\.cargo/|/\.rustup/|(^|/)tests/|tests\.rs$' | tee "$out/report.txt"
