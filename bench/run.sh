#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# ufat benchmarks, see HACKING.md. Not part of `cargo test`.
#
# Builds deterministic inputs on tmpfs, then times mkfs, populate, size,
# manifest/assemble (directory and stream source), fsck and the Varlink
# path, against mkfs.fat, mcopy, sha256sum and fsck.fat where a reference
# tool exists. Every measurement runs REPEAT times on a fresh image, rows
# that take under 100 ms REPEAT_FAST times; the summary reports the minimum
# and the median wall time, the median user and system time, the peak RSS
# and the bytes passed to write(2) (wchar from /proc/PID/io, read after the
# process exited and before it is reaped; the kernel adds the counters of
# reaped children to their parent, kernel/exit.c wait_task_zombie(), so
# the figure covers the mcopy and mmd children of the mcopy walk as well).
#
# Usage: bench/run.sh [CASE-REGEX]
#
# `cargo build --release --locked -p ufat -p bench` builds the binary and
# the two helpers. CASE-REGEX defaults to BENCH_CASES, or every case.
#
# Environment:
#   UFAT         the binary to measure (default: BUILD/ufat); any ufat
#                binary works, BUILD only supplies the helpers
#   BUILD        the directory with the helpers (default: target/release of
#                this tree)
#   BENCH_DIR    scratch directory, put it on tmpfs (default: $TMPDIR/ufat-bench)
#   REPEAT       runs per measurement (default 3)
#   REPEAT_FAST  runs for a measurement whose first run took under 100 ms
#                (default 10): one such run is noise
#   CORE         the CPU everything measured is pinned to with taskset
#                (default: the last CPU; "none" disables pinning). Pick one
#                whose SMT sibling is idle, the header names the siblings.
#   TAG          appended to every case name as "@TAG", so that two binaries
#                measured with KEEP_RAW=1 end up side by side in one summary
#   WIDE         files in the wide trees (default 10000)
#   SIZES        mkfs image sizes (default "256M 1G 4G"; 256M is 257M with
#                4096 byte sectors, the FAT32 minimum)
#   ZERO_BIG     1 to run assemble --zero on the largest image too (that pins
#                the whole image in tmpfs)
#   MCOPY_TREES  the trees the mcopy reference walks (default "esp wide-flat83
#                wide-deep"; mcopy does not finish wide-flat, its colliding
#                long names, within 40 minutes)
#   UFAT_MTOOLS  directory holding mcopy and mmd (default: PATH)
#   MKFS_FAT, FSCK_FAT  the dosfstools binaries (default: PATH, /usr/sbin)
#   VLIMIT       ulimit -v for everything measured, KiB (default 6000000)
#   KEEP_RAW     1 to append to out/raw.tsv instead of starting it afresh, so
#                that several invocations with CASE-REGEX end in one summary
#
# The mcopy reference mirrors what systemd does in src/shared/vfat-util.c:
# sorted walk, one `mmd -Ds -DS -i IMG ::/dir` per directory, consecutive
# files of a directory batched into one `mcopy -p -Q -m -i IMG FILES ::/dir/`.
# mkfs.fat runs with -F 32 -S SS --invariant -n LABEL, ufat assemble with the
# matching --mkfs-fat-compat options, and the two images are compared.
#
# Internal: `run.sh --mcopy-tree IMG SRC` performs the systemd style walk;
# the benchmark measures that invocation.

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

BUILD=${BUILD:-$repo/target/release}
UFAT=${UFAT:-$BUILD/ufat}
BENCH_DIR=${BENCH_DIR:-${TMPDIR:-/tmp}/ufat-bench}
REPEAT=${REPEAT:-3}
REPEAT_FAST=${REPEAT_FAST:-10}
CORE=${CORE:-$(( $(nproc) - 1 ))}
SUFFIX=${TAG:+@$TAG}
WIDE=${WIDE:-10000}
SIZES=${SIZES:-"256M 1G 4G"}
ZERO_BIG=${ZERO_BIG:-0}
MCOPY_TREES=${MCOPY_TREES:-"esp wide-flat83 wide-deep"}
VLIMIT=${VLIMIT:-6000000}
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1700000000 MTOOLS_SKIP_CHECK=1

find_tool() { # find_tool NAME [DIR]
    local n=$1 d=${2:-}
    if [ -n "$d" ] && [ -x "$d/$n" ]; then echo "$d/$n"; return; fi
    command -v "$n" 2>/dev/null && return
    for p in /usr/sbin /sbin /usr/local/sbin; do [ -x "$p/$n" ] && { echo "$p/$n"; return; }; done
    return 1
}
MCOPY=$(find_tool mcopy "${UFAT_MTOOLS:-}" || true)
MMD=$(find_tool mmd "${UFAT_MTOOLS:-}" || true)
MKFS_FAT=${MKFS_FAT:-$(find_tool mkfs.fat || true)}
FSCK_FAT=${FSCK_FAT:-$(find_tool fsck.fat || true)}
SHA256SUM=$(command -v sha256sum || true)

# ---------------------------------------------------------------- mcopy walk
mcopy_tree() { # mcopy_tree IMG SRC REL   (systemd's vfat-util.c order)
    local img=$1 src=$2 rel=$3 e name
    local -a batch=()
    for e in "$src"/*; do
        [ -e "$e" ] || continue
        name=$(basename "$e")
        if [ -d "$e" ]; then
            if [ ${#batch[@]} -gt 0 ]; then
                "$MCOPY" -p -Q -m -i "$img" "${batch[@]}" "::/$rel${rel:+/}" || return 1
                batch=()
            fi
            "$MMD" -Ds -DS -i "$img" "::/$rel${rel:+/}$name" 2>/dev/null || true
            mcopy_tree "$img" "$e" "$rel${rel:+/}$name" || return 1
        elif [ -f "$e" ]; then
            batch+=("$e")
        fi
    done
    if [ ${#batch[@]} -gt 0 ]; then
        "$MCOPY" -p -Q -m -i "$img" "${batch[@]}" "::/$rel${rel:+/}" || return 1
    fi
    return 0
}
if [ "${1:-}" = --mcopy-tree ]; then
    ulimit -v "$VLIMIT"
    mcopy_tree "$2" "$3" ""
    exit $?
fi

CASES=${1:-${BENCH_CASES:-.}}
ulimit -v "$VLIMIT"
IN=$BENCH_DIR/in
IMG=$BENCH_DIR/img
OUT=$BENCH_DIR/out
mkdir -p "$IN" "$IMG" "$OUT"
RAW=$OUT/raw.tsv
[ "${KEEP_RAW:-0}" = 1 ] || : > "$RAW"

say() { printf '%s\n' "$*" >&2; }

# ------------------------------------------------------------------ helpers
MEASURE=$BUILD/measure
GENFILE=$BUILD/genfile
if [ ! -x "$MEASURE" ] || [ ! -x "$GENFILE" ]; then
    say "no helpers in $BUILD, run cargo build --release --locked -p ufat -p bench"
    exit 1
fi
[ -x "$UFAT" ] || { say "no ufat binary at $UFAT"; exit 1; }

# ------------------------------------------------------------------ the CPU
# Everything measured runs pinned to one CPU; its SMT sibling should be
# idle. The governor and the boost state go into the header because they
# move the numbers by 15% on a laptop.
PIN=()
if [ "$CORE" != none ] && command -v taskset > /dev/null 2>&1; then
    PIN=(taskset -c "$CORE")
    siblings=$(cat "/sys/devices/system/cpu/cpu$CORE/topology/thread_siblings_list" 2>/dev/null || echo "?")
    pinned="pinned to CPU $CORE (SMT siblings $siblings)"
else
    pinned="not pinned"
fi
cpu_state() {
    local g b
    g=$(cat /sys/devices/system/cpu/cpufreq/policy*/scaling_governor 2>/dev/null | sort -u | paste -sd,)
    b=$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || cat /sys/devices/system/cpu/cpufreq/policy*/boost 2>/dev/null | sort -u | paste -sd,)
    echo "governor=${g:-unknown} boost=${b:-unknown}$([ -r /sys/devices/system/cpu/amd_pstate/status ] && echo " amd_pstate=$(cat /sys/devices/system/cpu/amd_pstate/status)")"
}
ufat_id() {
    local sum tree
    sum=$(sha256sum "$UFAT" | cut -c1-16)
    tree=$(git -C "$repo" describe --always --dirty 2>/dev/null || echo "?")
    echo "ufat=$UFAT (sha256 $sum..., tree at $tree)"
}

# ------------------------------------------------------------------- inputs
small_file() { # small_file PATH SIZE SEED
    mkdir -p "$(dirname "$1")"
    "$GENFILE" "$1" "$2" "$3"
}

make_inputs() {
    local stamp=$IN/.ready-$WIDE
    [ -e "$stamp" ] && return
    say "building inputs under $IN (WIDE=$WIDE)"
    rm -rf "$IN"; mkdir -p "$IN"
    # An ESP: 4 UKIs of 64 MiB plus 50 small files.
    local e=$IN/esp i
    for i in 1 2 3 4; do
        small_file "$e/EFI/Linux/linux-6.12.$i-300.fc41.x86_64.efi" 64M "$i"
    done
    small_file "$e/EFI/BOOT/BOOTX64.EFI" 96K 10
    small_file "$e/EFI/BOOT/fbx64.efi" 64K 11
    small_file "$e/EFI/BOOT/mmx64.efi" 80K 12
    small_file "$e/EFI/systemd/systemd-bootx64.efi" 96K 13
    small_file "$e/EFI/fedora/shimx64.efi" 90K 14
    small_file "$e/EFI/fedora/grubx64.efi" 100K 15
    small_file "$e/EFI/fedora/mmx64.efi" 80K 16
    small_file "$e/EFI/fedora/BOOTX64.CSV" 100 17
    small_file "$e/loader/loader.conf" 60 18
    small_file "$e/loader/random-seed" 32 19
    small_file "$e/loader/entries.srel" 5 20
    for i in $(seq 1 19); do
        small_file "$e/loader/entries/linux-6.12.$i-300.fc41.x86_64.conf" 300 "$((100 + i))"
    done
    for i in $(seq 1 20); do
        small_file "$e/EFI/Linux/linux-6.12.1-300.fc41.x86_64.efi.extra.d/$(printf '%02d' "$i")-addon.addon.efi" 4K "$((200 + i))"
    done
    # Wide trees: WIDE small files in one directory, with long names that
    # share their 8.3 prefix (every one needs a ~n tail), the same with
    # names that fit 8.3, and WIDE files spread over 100 directories.
    local d n
    d=$IN/wide-flat/entries; mkdir -p "$d"
    for ((n = 0; n < WIDE; n++)); do printf 'entry-%05d.conf\n' "$n" > "$d/$(printf 'entry-%05d.conf' "$n")"; done
    d=$IN/wide-flat83/entries; mkdir -p "$d"
    for ((n = 0; n < WIDE; n++)); do printf 'E%05d.CNF\n' "$n" > "$d/$(printf 'E%05d.CNF' "$n")"; done
    d=$IN/wide-deep
    for ((i = 0; i < 100; i++)); do mkdir -p "$d/$(printf 'd%03d' "$i")"; done
    for ((n = 0; n < WIDE; n++)); do printf 'entry-%05d.conf\n' "$n" > "$d/$(printf 'd%03d' "$((n % 100))")/$(printf 'entry-%05d.conf' "$n")"; done
    find "$IN" -exec touch -h -d @1700000000 {} +
    # The manifest of the ESP and the blob the stream mode expects: the
    # regular files back to back in manifest order.
    "$UFAT" manifest "$e" > "$IN/esp.manifest" || exit 1
    tr '\036' '\n' < "$IN/esp.manifest" | grep '"size":' | sed -E 's/.*"name":"([^"]*)".*/\1/' |
        while IFS= read -r name; do cat "$e/$name"; done > "$IN/esp.blob"
    [ "$(stat -c %s "$IN/esp.blob")" -gt 0 ] || { say "empty blob"; exit 1; }
    touch "$stamp"
}
make_inputs

# -------------------------------------------------------------- measuring
want() { [[ "$1" =~ $CASES ]]; }

# One line per case from the raw data: n, min and median wall, median user
# and sys, max RSS, median byte and call counts, and whether a run failed.
summarize() { # summarize RAW
    awk -F'\t' '
        function median(a, n,   i, j, t) {
            for (i = 2; i <= n; i++) { t = a[i]; j = i - 1; while (j >= 1 && a[j] > t) { a[j + 1] = a[j]; j-- } a[j + 1] = t }
            return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
        }
        function med(l, col,   j, c) { c = n[l]; for (j = 1; j <= c; j++) tmp[j] = v[l, col, j]; return median(tmp, c) }
        {
            l = $1
            if (!(l in seen)) { seen[l] = ++k; labels[k] = l; min[l] = $2 }
            n[l]++
            for (c = 2; c <= 9; c++) v[l, c, n[l]] = $c
            if ($2 < min[l]) min[l] = $2
            if ($5 > rss[l]) rss[l] = $5
            if ($10 != 0) bad[l] = 1
        }
        END {
            printf "%-48s %3s %8s %8s %8s %8s %8s %13s %13s %8s %8s %s\n", "case", "n", "wall_min", "wall_med", "user_med", "sys_med", "rss_MiB", "written_B", "read_B", "syscw", "syscr", "status"
            for (i = 1; i <= k; i++) {
                l = labels[i]
                printf "%-48s %3d %8.3f %8.3f %8.3f %8.3f %8.1f %13d %13d %8d %8d %s\n", l, n[l], min[l], med(l, 2), med(l, 3), med(l, 4), rss[l] / 1024, med(l, 6), med(l, 7), med(l, 8), med(l, 9), (l in bad) ? "FAILED" : "ok"
            }
        }' "$1"
}

# bench LABEL SETUP [measure options] -- COMMAND...   (or the Varlink form)
# SETUP is evaluated before every repetition and is not timed. A case whose
# first run takes under 100 ms is repeated REPEAT_FAST times.
bench() {
    local label=$1$SUFFIX setup=$2; shift 2
    want "$label" || return 0
    local i=0 runs=$REPEAT wall
    while [ "$i" -lt "$runs" ]; do
        eval "$setup" || { say "setup for $label failed"; return 1; }
        "${PIN[@]}" "$MEASURE" -l "$label" "$@" >> "$RAW" || say "  $label: run $((i + 1)) failed (see $RAW)"
        i=$((i + 1))
        if [ "$i" -eq 1 ]; then
            wall=$(awk -F'\t' -v l="$label" '$1 == l { w = $2 } END { print w + 0 }' "$RAW")
            if awk -v w="$wall" 'BEGIN { exit !(w < 0.1) }' && [ "$runs" -lt "$REPEAT_FAST" ]; then
                runs=$REPEAT_FAST
            fi
        fi
    done
    awk -F'\t' -v l="$label" '$1 == l' "$RAW" | summarize /dev/stdin | tail -n 1 >&2
}

img_size() { # img_size SS SIZE -> the size to use (257M for 256M at 4096)
    if [ "$1" = 4096 ] && [ "$2" = 256M ]; then echo 257M; else echo "$2"; fi
}

fresh_sparse() { rm -f "$1"; truncate -s "$2" "$1"; }

# A formatted image, byte identical with mkfs.fat's for the same parameters.
fresh_fs() { # fresh_fs PATH SS SIZE
    fresh_sparse "$1" "$3"
    "$UFAT" assemble --sector-size "$2" --mkfs-fat-compat --oem-name mkfs.fat --identifier 1234abcd \
        --timestamp 1426325213 --label ESP "$1" || return 1
}

ufat_mkfs_args() { echo "--sector-size $1 --mkfs-fat-compat --oem-name mkfs.fat --identifier 1234abcd --timestamp 1426325213 --label ESP"; }

say "$(ufat_id)"
say "$(cpu_state), $pinned"

# ------------------------------------------------------------- (a) mkfs
for ss in 512 4096; do
    for size in $SIZES; do
        sz=$(img_size "$ss" "$size")
        W=$IMG/mkfs.img
        bench "mkfs/$ss/$size/ufat" "fresh_sparse $W $sz" -- "$UFAT" assemble $(ufat_mkfs_args "$ss") "$W"
        if [ -n "$MKFS_FAT" ]; then
            R=$IMG/mkfs-ref.img
            bench "mkfs/$ss/$size/mkfs.fat" "fresh_sparse $R $sz" -- "$MKFS_FAT" -F 32 -S "$ss" --invariant -n ESP "$R"
            if want "mkfs/$ss/$size/"; then
                if cmp -s "$W" "$R"; then say "  mkfs/$ss/$size: ufat and mkfs.fat images are byte identical"
                else say "  mkfs/$ss/$size: WARNING ufat and mkfs.fat images differ"; fi
            fi
            rm -f "$R"
        fi
        if [ "$size" != "${SIZES##* }" ] || [ "$ZERO_BIG" = 1 ]; then
            bench "mkfs/$ss/$size/ufat-zero" "fresh_sparse $W $sz" -- "$UFAT" assemble $(ufat_mkfs_args "$ss") --zero "$W"
        fi
        rm -f "$W"
    done
done

# ----------------------------------------------------- (b) populate, (e) fsck
# esp goes to a 1 GiB image (the UKIs need 256 MiB), the wide trees to 256 MiB
# (257 MiB with 4096 byte sectors): the smallest ESP, with 512 byte clusters
# when the sector size is 512, as mkfs.fat lays it out.
for ss in 512 4096; do
    for tree in esp wide-flat wide-flat83 wide-deep; do
        case $tree in esp) size=1G ;; *) size=$(img_size "$ss" 256M) ;; esac
        W=$IMG/pop-$tree-$ss.img
        src=$IN/$tree
        bench "populate/$ss/$tree/ufat" "fresh_fs $W $ss $size" -- "$UFAT" populate "$W" "$src"
        if want "fsck/$ss/$tree/" && [ -e "$W" ]; then
            bench "fsck/$ss/$tree/ufat" ":" -- "$UFAT" check "$W"
            [ -n "$FSCK_FAT" ] && bench "fsck/$ss/$tree/fsck.fat" ":" -- "$FSCK_FAT" -n "$W"
        fi
        if [ -n "$MCOPY" ] && [ -n "$MMD" ] && [[ " $MCOPY_TREES " == *" $tree "* ]]; then
            R=$IMG/pop-$tree-$ss-mcopy.img
            bench "populate/$ss/$tree/mcopy" "fresh_fs $R $ss $size" -- "$here/run.sh" --mcopy-tree "$R" "$src"
            rm -f "$R"
        fi
        # keep $W for the Varlink Check below, removed there
    done
done

# ------------------------------------------------------------- (c) size/plan
for ss in 512 4096; do
    for tree in esp wide-flat wide-flat83 wide-deep; do
        bench "size/$ss/$tree" ":" -- "$UFAT" assemble --plan --sector-size "$ss" "$IN/$tree"
    done
    bench "size/$ss/esp-manifest" ":" -- "$UFAT" assemble --plan --sector-size "$ss" --manifest "$IN/esp.manifest"
done

# ----------------------------------------------- (d) manifest, sha256, assemble
# `ufat manifest` hashes every file; sha256sum over the same files is the
# reference for the SHA-256 implementation.
mapfile -t ESP_FILES < <(find "$IN/esp" -type f | sort)
bench "sha256/esp/ufat-manifest" ":" -- "$UFAT" manifest "$IN/esp"
[ -n "$SHA256SUM" ] && bench "sha256/esp/sha256sum" ":" -- "$SHA256SUM" "${ESP_FILES[@]}"
for ss in 512 4096; do
    W=$IMG/asm-$ss.img
    # --create without --size sizes the image to fit the manifest.
    bench "assemble/$ss/esp/dir-fit" "rm -f $W" -- "$UFAT" assemble --create --sector-size "$ss" --identifier 1234abcd --label ESP \
        --manifest "$IN/esp.manifest" "$W" "$IN/esp"
    bench "assemble/$ss/esp/stream-fit" "rm -f $W" --stdin "$IN/esp.blob" -- "$UFAT" assemble --create --sector-size "$ss" --identifier 1234abcd --label ESP \
        --manifest "$IN/esp.manifest" "$W" -
    # Into a formatted 1 GiB image, like populate above: the difference to
    # populate is the manifest handling and the SHA-256 verification.
    # --force, since the image holds a file system.
    bench "assemble/$ss/esp/dir-1G" "fresh_fs $W $ss 1G" -- "$UFAT" assemble --force --manifest "$IN/esp.manifest" "$W" "$IN/esp"
    bench "assemble/$ss/esp/stream-1G" "fresh_fs $W $ss 1G" --stdin "$IN/esp.blob" -- "$UFAT" assemble --force --manifest "$IN/esp.manifest" "$W" -
    rm -f "$W"
done

# ------------------------------------------------------------- (f) Varlink
# The same operations over the Varlink interface, the binary started with a
# connected socket as fd 3 like sd_varlink_connect_exec() does.
for ss in 512 4096; do
    W=$IMG/vl-$ss.img
    size=1G
    # Everything the service touches is passed as a descriptor: the image
    # read-write, the sources, the manifest and the contents blob read-only.
    bench "varlink/$ss/esp/Populate" "fresh_fs $W $ss $size" --ufat "$UFAT" --method org.uapi-group.FileSystem.Populate \
        --fd "rw:$W" --fd "$IN/esp" \
        --params '{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1,"times":"clamp"},"timestampUSec":1700000000000000}'
    bench "varlink/$ss/esp/Check" ":" --ufat "$UFAT" --method org.uapi-group.FileSystem.Check --fd "$W" --params '{"image":{"fileDescriptor":0}}'
    bench "varlink/$ss/esp/Populate-manifest-stream-1G" "fresh_fs $W $ss $size" --ufat "$UFAT" --method org.uapi-group.FileSystem.Populate \
        --fd "rw:$W" --fd "$IN/esp.manifest" --fd "$IN/esp.blob" \
        --params '{"image":{"fileDescriptor":0},"path":"/","content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2},"timestampUSec":1700000000000000}'
    bench "varlink/$ss/esp/Assemble-manifest-stream-fit" "rm -f $W; : > $W" --ufat "$UFAT" --method org.uapi-group.FileSystem.Assemble \
        --fd "rw:$W" --fd "$IN/esp.manifest" --fd "$IN/esp.blob" \
        --params "{\"image\":{\"fileDescriptor\":0},\"content\":{\"manifest\":{\"fileDescriptor\":1},\"sourceFileDescriptor\":2},\"options\":{\"sectorSize\":$ss,\"identifier\":\"1234-ABCD\",\"label\":\"ESP\",\"timestampUSec\":1700000000000000}}"
    rm -f "$W"
    for tree in esp wide-flat wide-flat83 wide-deep; do rm -f "$IMG/pop-$tree-$ss.img"; done
done

# -------------------------------------------------------------- summary
{
    echo "ufat benchmark: $(date -u +%Y-%m-%dT%H:%MZ), $(uname -sr), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')"
    ufat_id
    echo "$(cpu_state), $pinned"
    echo "REPEAT=$REPEAT REPEAT_FAST=$REPEAT_FAST WIDE=$WIDE BENCH_DIR=$BENCH_DIR"
    echo "wall_min/wall_med = minimum and median wall time over n runs (s); user_med/sys_med = median CPU time (s);"
    echo "rss = peak RSS MiB (max over runs); written/read = median bytes passed to write(2)/read(2); syscw/syscr = their median call counts"
    summarize "$RAW"
} | tee "$OUT/summary.txt"
say "raw data: $RAW"
