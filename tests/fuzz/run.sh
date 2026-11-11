#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The fuzzing campaign, see HACKING.md:
#
#     cargo build --locked -p ufat -p fuzz-seeds
#     tests/fuzz/run.sh [UFAT [FUZZ_SEEDS [OUTDIR]]]
#
# It builds the seeds, runs the image, manifest, Varlink and targeted
# campaigns and sums up their reports. It fails when one of them found
# something. UFAT, FUZZ_SEEDS and OUTDIR default to target/debug/ufat,
# target/debug/fuzz-seeds and target/fuzz of this tree.
#
# Environment:
#   FUZZ_OUT     where seeds, reports and findings go (default: OUTDIR)
#   ITERATIONS   variants per campaign (default 200)
#   WORKERS      parallel workers (default 4)
#   UFAT_MTOOLS  directory holding mtools binaries for more seeds
#   PYTHON       the interpreter (default: python3 -I)
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
ufat=${1:-$repo/target/debug/ufat}
seeds=${2:-$repo/target/debug/fuzz-seeds}
out=${FUZZ_OUT:-${3:-$repo/target/fuzz}}
iterations=${ITERATIONS:-200}
workers=${WORKERS:-4}
python=${PYTHON:-python3 -I}

FUZZ_SEEDS=$seeds "$here/seeds.sh" "$out/seeds" "$ufat" || exit 1

args=(--ufat "$ufat" --seeds "$out/seeds" --out "$out/out")
rc=0
$python "$here/mutate.py" images "${args[@]}" --count "$iterations" --workers "$workers" || rc=1
$python "$here/mutate.py" manifests "${args[@]}" --count "$iterations" --workers "$workers" || rc=1
$python "$here/varlink_fuzz.py" "${args[@]}" --count $((iterations / 10 + 1)) || rc=1
$python "$here/targeted.py" --ufat "$ufat" --seeds "$out/seeds" --work "$out/targeted" || rc=1
$python "$here/summarize.py" "$out/out"
exit $rc
