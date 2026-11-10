#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Compares two ufat binaries on a few small workloads, see HACKING.md. What
# every run cost goes to $BENCH_DIR/out/compare.tsv, and bench/compare.py
# turns that into a table and a verdict.
#
# Usage: bench/compare.sh BASE HEAD [CASE-REGEX]
#
# Every workload runs once per binary under cachegrind, which counts the
# instructions executed in user space, and once under strace -c, which
# counts the system calls. Neither count depends on how busy the machine
# is. Then the workload runs PAIRS times per binary, base and head
# alternating, under measure: wall time, peak RSS, and the bytes passed to
# read(2) and write(2).
#
# Environment:
#   BUILD      the directory holding measure and genfile (default:
#              target/release of this tree)
#   BENCH_DIR  scratch directory, put it on tmpfs (default:
#              $TMPDIR/ufat-compare)
#   PAIRS      timed runs per binary (default 9); 0 skips them
#   METHODS    what to run, a subset of "ir sys time" (default: all three)
#   FILES      files in the wide and deep trees (default 10000)
#   UKI        size of each of the four UKIs in the ESP (default 2M)
#   CORE       the CPU the timed runs are pinned to (default: the last
#              CPU; "none" disables pinning)
#   VALGRIND, STRACE  the tools (default: PATH)

set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

[ $# -ge 2 ] || { echo "usage: bench/compare.sh BASE HEAD [CASE-REGEX]" >&2; exit 2; }
BASE=$(realpath "$1")
HEAD=$(realpath "$2")
CASES=${3:-.}
BUILD=${BUILD:-$repo/target/release}
BENCH_DIR=${BENCH_DIR:-${TMPDIR:-/tmp}/ufat-compare}
PAIRS=${PAIRS:-9}
METHODS=${METHODS:-"ir sys time"}
FILES=${FILES:-10000}
UKI=${UKI:-2M}
CORE=${CORE:-$(( $(nproc) - 1 ))}
VALGRIND=${VALGRIND:-valgrind}
STRACE=${STRACE:-strace}
MEASURE=$BUILD/measure
GENFILE=$BUILD/genfile
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1700000000

say() { printf '%s\n' "$*" >&2; }
for b in "$BASE" "$HEAD" "$MEASURE" "$GENFILE"; do
    [ -x "$b" ] || { say "$b is missing, see HACKING.md"; exit 1; }
done
[[ " $METHODS " != *" ir "* ]] || command -v "$VALGRIND" > /dev/null || { say "no valgrind"; exit 1; }
[[ " $METHODS " != *" sys "* ]] || command -v "$STRACE" > /dev/null || { say "no strace"; exit 1; }

IN=$BENCH_DIR/in
IMG=$BENCH_DIR/img
OUT=$BENCH_DIR/out
mkdir -p "$IN" "$IMG" "$OUT"
rm -rf "$OUT/ir" "$OUT/sys" "$OUT/wrap"
mkdir -p "$OUT/ir" "$OUT/sys" "$OUT/wrap"
RAW=$OUT/compare.tsv
: > "$RAW"

# ------------------------------------------------------------------- inputs
# Smaller than the ones of bench/run.sh: every workload runs under
# valgrind. Inputs depend on FILES and UKI only, and are built once.
make_inputs() {
    local stamp=$IN/.ready-$FILES-$UKI
    [ -e "$stamp" ] && return
    say "building inputs under $IN (FILES=$FILES UKI=$UKI)"
    rm -rf "$IN"; mkdir -p "$IN"
    # A subshell that stops at the first failure, so the stamp is only set
    # when every input is there. Its status is checked after it: set -e
    # does not apply inside a command whose status || or if tests.
    (
    set -e -o pipefail
    local e i n d kb
    file() { mkdir -p "$(dirname "$1")" && "$GENFILE" "$1" "$2" "$3"; }
    # The ESP of bench/run.sh with smaller UKIs: 4 UKIs plus 50 small files.
    e=$IN/esp
    for i in 1 2 3 4; do file "$e/EFI/Linux/linux-6.12.$i-300.fc41.x86_64.efi" "$UKI" "$i"; done
    file "$e/EFI/BOOT/BOOTX64.EFI" 96K 10
    file "$e/EFI/BOOT/fbx64.efi" 64K 11
    file "$e/EFI/BOOT/mmx64.efi" 80K 12
    file "$e/EFI/systemd/systemd-bootx64.efi" 96K 13
    file "$e/EFI/fedora/shimx64.efi" 90K 14
    file "$e/EFI/fedora/grubx64.efi" 100K 15
    file "$e/EFI/fedora/mmx64.efi" 80K 16
    file "$e/EFI/fedora/BOOTX64.CSV" 100 17
    file "$e/loader/loader.conf" 60 18
    file "$e/loader/random-seed" 32 19
    file "$e/loader/entries.srel" 5 20
    for i in $(seq 1 19); do file "$e/loader/entries/linux-6.12.$i-300.fc41.x86_64.conf" 300 "$((100 + i))"; done
    for i in $(seq 1 20); do
        file "$e/EFI/Linux/linux-6.12.1-300.fc41.x86_64.efi.extra.d/$(printf '%02d' "$i")-addon.addon.efi" 4K "$((200 + i))"
    done
    # FILES files of 1 KiB: in one directory, with long names that share
    # their 8.3 prefix so every one needs a ~n tail; and spread over 100
    # directories.
    kb=$(head -c 1024 /dev/zero | tr '\0' x)
    d=$IN/wide/entries; mkdir -p "$d"
    for ((n = 0; n < FILES; n++)); do printf '%s' "$kb" > "$d/$(printf 'entry-%05d.conf' "$n")"; done
    for ((i = 0; i < 100; i++)); do mkdir -p "$IN/deep/$(printf 'd%03d' "$i")"; done
    for ((n = 0; n < FILES; n++)); do
        printf '%s' "$kb" > "$IN/deep/$(printf 'd%03d' "$((n % 100))")/$(printf 'entry-%05d.conf' "$n")"
    done
    find "$IN" -exec touch -h -d @1700000000 {} +
    # The manifest of the ESP, and its files back to back in manifest
    # order, the contents the stream mode expects.
    "$HEAD" manifest "$e" > "$IN/esp.manifest"
    tr '\036' '\n' < "$IN/esp.manifest" | grep '"size":' | sed -E 's/.*"name":"([^"]*)".*/\1/' |
        while IFS= read -r n; do cat "$e/$n"; done > "$IN/esp.blob"
    [ -s "$IN/esp.blob" ] || { say "empty blob"; exit 1; }
    # An empty file system of 256 MiB, the target of populate, and one
    # holding the wide tree, the input of check. Both are made once, by
    # the head binary, so that both binaries see the same bytes.
    truncate -s 256M "$IN/empty.img"
    "$HEAD" assemble --sector-size 512 --identifier 1234abcd --label ESP "$IN/empty.img"
    cp --sparse=always "$IN/empty.img" "$IN/wide.img"
    "$HEAD" populate "$IN/wide.img" "$IN/wide"
    )
    if [ $? != 0 ]; then
        say "building the inputs failed"
        exit 1
    fi
    touch "$stamp"
}
make_inputs

# ---------------------------------------------------------------- workloads
# Every workload calls RUN LABEL SETUP MEASURE-ARGUMENTS...: SETUP is a
# function that runs untimed before every run, @UFAT@ stands for the binary
# measured.
fresh_image() { cp --sparse=always "$IN/empty.img" "$IMG/target.img"; }
no_image() { rm -f "$IMG/target.img"; }
empty_image() { rm -f "$IMG/target.img" && : > "$IMG/target.img"; }
nothing() { :; }
ASM=(assemble --create --sector-size 512 --identifier 1234abcd --label ESP)
POPULATE='{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}'
ASSEMBLE='{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2},"options":{"sectorSize":512,"identifier":"1234-ABCD","label":"ESP"}}'
workloads() {
    local r=$1
    $r assemble/esp no_image -- @UFAT@ "${ASM[@]}" "$IMG/target.img" "$IN/esp"
    $r assemble/esp-stream no_image --stdin "$IN/esp.blob" -- @UFAT@ "${ASM[@]}" --manifest "$IN/esp.manifest" "$IMG/target.img" -
    $r assemble/wide no_image -- @UFAT@ "${ASM[@]}" "$IMG/target.img" "$IN/wide"
    $r populate/wide fresh_image -- @UFAT@ populate "$IMG/target.img" "$IN/wide"
    $r populate/deep fresh_image -- @UFAT@ populate "$IMG/target.img" "$IN/deep"
    $r check/wide nothing -- @UFAT@ check "$IN/wide.img"
    $r manifest/esp nothing -- @UFAT@ manifest "$IN/esp"
    $r manifest/wide nothing -- @UFAT@ manifest "$IN/wide"
    $r varlink/Populate-wide fresh_image --ufat @UFAT@ --method org.uapi-group.FileSystem.Populate \
        --fd "rw:$IMG/target.img" --fd "$IN/wide" --params "$POPULATE"
    $r varlink/Assemble-esp-stream empty_image --ufat @UFAT@ --method org.uapi-group.FileSystem.Assemble \
        --fd "rw:$IMG/target.img" --fd "$IN/esp.manifest" --fd "$IN/esp.blob" --params "$ASSEMBLE"
}

want() { [[ "$1" =~ $CASES ]]; }

# The measure arguments with @UFAT@ replaced by $1.
substitute() {
    local bin=$1 a; shift
    for a in "$@"; do
        if [ "$a" = @UFAT@ ]; then printf '%s\0' "$bin"; else printf '%s\0' "$a"; fi
    done
}

# The wrappers measure starts in place of ufat for the counted runs. They
# keep the process ID for the Varlink calls, which pass the socket with
# LISTEN_PID: valgrind runs the program in its own process, and strace
# runs it in a child, where a shell sets LISTEN_PID before it execs ufat.
for side in base head; do
    if [ "$side" = base ]; then bin=$BASE; else bin=$HEAD; fi
    printf '#!/bin/sh\nexec %q --tool=cachegrind --cache-sim=no --cachegrind-out-file="$COUNT_OUT" --log-file="$COUNT_OUT.log" %q "$@"\n' \
        "$VALGRIND" "$bin" > "$OUT/wrap/ir-$side"
    printf '#!/bin/sh\nexec %q -f -c -U name,calls,errors -o "$COUNT_OUT" sh -c %q %q "$@"\n' \
        "$STRACE" 'LISTEN_PID=$$ exec "$0" "$@"' "$bin" > "$OUT/wrap/sys-$side"
    chmod +x "$OUT/wrap/ir-$side" "$OUT/wrap/sys-$side"
done

# count METHOD LABEL SETUP ARGS...: one run per binary under the counter.
count() {
    local method=$1 label=$2 setup=$3 side out n; shift 3
    want "$label" || return 0
    for side in base head; do
        out=$OUT/$method/${label//\//_}.$side
        "$setup" || { say "setup for $label failed"; return 1; }
        local -a argv
        mapfile -d '' argv < <(substitute "$OUT/wrap/$method-$side" "$@")
        if ! COUNT_OUT=$out "$MEASURE" -l "$label" "${argv[@]}" > /dev/null; then
            say "  $label ($side, $method) failed"
            printf '%s\t%s\t%s\t%s\n' "$method" "$label" "$side" "failed" >> "$RAW"
            continue
        fi
        case $method in
        ir) n=$(sed -n 's/^summary: //p' "$out") ;;
        sys) n=$(awk '$1 == "total" { print $2 }' "$out") ;;
        esac
        printf '%s\t%s\t%s\t%s\n' "$method" "$label" "$side" "${n:-failed}" >> "$RAW"
    done
}
count_ir() { count ir "$@"; }
count_sys() { count sys "$@"; }

PIN=()
if [ "$CORE" != none ] && command -v taskset > /dev/null 2>&1; then
    PIN=(taskset -c "$CORE")
fi

# timed LABEL SETUP ARGS...: PAIRS runs per binary, alternating, the order
# within a pair swapped from one pair to the next (base head, head base).
timed() {
    local label=$1 setup=$2 i side bin line order; shift 2
    want "$label" || return 0
    for ((i = 0; i < PAIRS; i++)); do
        order="base head"
        [ $((i % 2)) = 1 ] && order="head base"
        for side in $order; do
            if [ "$side" = base ]; then bin=$BASE; else bin=$HEAD; fi
            "$setup" || { say "setup for $label failed"; return 1; }
            local -a argv
            mapfile -d '' argv < <(substitute "$bin" "$@")
            line=$("${PIN[@]}" "$MEASURE" -l "$label" "${argv[@]}") || say "  $label ($side) failed"
            # measure: label wall user sys maxrss wchar rchar syscw syscr status
            printf 'time\t%s\t%s\t%s\n' "$label" "$side" "$(printf '%s' "$line" | cut -f2-)" >> "$RAW"
        done
    done
}

say "base: $BASE (sha256 $(sha256sum "$BASE" | cut -c1-16))"
say "head: $HEAD (sha256 $(sha256sum "$HEAD" | cut -c1-16))"
for m in $METHODS; do
    started=$(date +%s)
    case $m in
    ir) workloads count_ir ;;
    sys) workloads count_sys ;;
    time) [ "$PAIRS" -gt 0 ] && workloads timed ;;
    *) say "unknown method $m"; exit 2 ;;
    esac
    say "$m: $(( $(date +%s) - started )) s"
done
say "raw data: $RAW"
