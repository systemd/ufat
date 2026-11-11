#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs the Kani proofs, see HACKING.md:
#
#     verify/run.sh [CRATE]
#
# CRATE is the crate root of the proofs, verify/lib.rs by default.
#
# Environment:
#   HARNESS       run this harness only
#   SLOW          add the harnesses that take longer than half an hour
#   DIR           add the harness of the directory index
#   KANI_JOBS     harnesses that run at the same time (default: one per
#                 core, at most four, since each CBMC instance can take
#                 several GB)
#   KANI_VERBOSE  run the harnesses one after the other with the full
#                 output of every check
#   KANI          the kani binary (default: kani)
#   KANI_FLAGS    replaces the default flags
set -eu

crate=${1:-$(dirname "$0")/lib.rs}
rustflags="--edition 2021"
if [ -n "${SLOW:-}" ]; then
    rustflags="$rustflags --cfg slow_proofs"
fi
if [ -n "${DIR:-}" ]; then
    rustflags="$rustflags --cfg dir_proofs"
fi

read -r -a args <<< "${KANI_FLAGS:--Z stubbing -Z unstable-options --harness-timeout 30m}"
if [ -z "${KANI_VERBOSE:-}" ]; then
    jobs=${KANI_JOBS:-$(nproc)}
    if [ -z "${KANI_JOBS:-}" ] && [ "$jobs" -gt 4 ]; then
        jobs=4
    fi
    args+=(-j "$jobs" --output-format terse)
fi
if [ -n "${HARNESS:-}" ]; then
    args+=(--harness "$HARNESS" --exact)
fi

RUSTFLAGS=$rustflags exec "${KANI:-kani}" "${args[@]}" "$crate"
