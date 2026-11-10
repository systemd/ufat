#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds the seed corpus for the mutation harness: a source tree, FAT32
# images made with ufat's library and with mkfs.fat + mcopy (512 and 4096
# byte sectors), and the manifests (the fixtures plus one from `ufat
# manifest`). The images stay small enough to mutate in memory, below the
# 65525 cluster floor the command line tool enforces, so they are formatted
# by the fuzz-seeds helper (tests/fuzz/seeds.rs) and filled with `ufat
# populate`.
#
#     FUZZ_SEEDS=build/tests/fuzz/fuzz-seeds tests/fuzz/seeds.sh OUTDIR [UFAT] [MTOOLS_BIN_DIR]
set -euo pipefail

OUT=${1:?usage: seeds.sh OUTDIR [UFAT] [MTOOLS_BIN_DIR]}
UFAT=${2:-$(dirname "$0")/../../build/ufat}
MTOOLS=${3:-${UFAT_MTOOLS:-}}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SEEDS=${FUZZ_SEEDS:-$REPO/build/tests/fuzz/fuzz-seeds}
export SOURCE_DATE_EPOCH=1700000000
export MTOOLS_SKIP_CHECK=1
export TZ=UTC

mkdir -p "$OUT/images" "$OUT/manifests" "$OUT/trees"
# mcopy runs from inside the tree; the image path must survive that.
OUT=$(cd "$OUT" && pwd)

# ---------------------------------------------------------------- tree
T=$OUT/trees/seed
rm -rf "$T"
mkdir -p "$T/EFI/BOOT" "$T/EFI/Linux" "$T/EFI/systemd" "$T/loader/entries" \
    "$T/empty dir" "$T/deep/er/and/deeper/still" "$T/Mixed Case Dir"
printf 'MZ' > "$T/EFI/BOOT/BOOTX64.EFI"; head -c 4094 /dev/zero | tr '\0' 'B' >> "$T/EFI/BOOT/BOOTX64.EFI"
cp "$T/EFI/BOOT/BOOTX64.EFI" "$T/EFI/systemd/systemd-bootx64.efi"
printf 'MZ' > "$T/EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi"; seq 1 9000 >> "$T/EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi"
head -c 70000 /dev/urandom > "$T/EFI/Linux/a very long file name with spaces and ünïcödé and 日本語 characters that needs many long name entries.efi"
printf 'timeout 5\nconsole-mode auto\n' > "$T/loader/loader.conf"
printf 'title Fedora\nlinux /EFI/Linux/linux.efi\n' > "$T/loader/entries/fedora.conf"
printf 'type1\n' > "$T/loader/entries.srel"
head -c 32 /dev/urandom > "$T/loader/random-seed"
: > "$T/empty"
printf 'deep\n' > "$T/deep/er/and/deeper/still/leaf.txt"
printf 'mixed\n' > "$T/Mixed Case Dir/Readme.md"
printf 'x\n' > "$T/Mixed Case Dir/readme.txt"
printf 'y\n' > "$T/Mixed Case Dir/README.TXT.bak"
head -c 513 /dev/urandom > "$T/odd513.bin"
head -c 4097 /dev/urandom > "$T/odd4097.bin"
head -c 200000 /dev/urandom > "$T/big200k.bin"
for i in $(seq 1 40); do printf '%d\n' "$i" > "$T/loader/entries/entry-number-$i.conf"; done
find "$T" -exec touch -h -d @1700000000 {} +

# A small tree for `populate` runs against mutated images.
S=$OUT/trees/small
rm -rf "$S"; mkdir -p "$S/sub dir"
printf 'hello\n' > "$S/hello.txt"; head -c 3000 /dev/urandom > "$S/sub dir/Data File.bin"; : > "$S/sub dir/empty"
find "$S" -exec touch -h -d @1700000000 {} +

# ---------------------------------------------------------------- images made by ufat's library
mk_ufat() { # name size sector cluster
    local img=$OUT/images/$1
    rm -f "$img"
    "$SEEDS" "$img" "$2" "$3" "$4" SEED
    "$UFAT" populate "$img" "$T"
    # check exits 0 with warnings only (the small volume is one) and 4 when
    # it found errors; only errors matter here.
    local report; report=$("$UFAT" check "$img" || true)
    grep -q '; 0 errors,' <<< "$report" || { echo "seed $1 has errors" >&2; echo "$report"; exit 1; }
}
mk_ufat ufat-512s-512c-2M.img 2M 512 512
mk_ufat ufat-512s-4096c-8M.img 8M 512 4096
mk_ufat ufat-4096s-4096c-4M.img 4M 4096 4096
mk_ufat ufat-4096s-32768c-8M.img 8M 4096 32768
mk_ufat ufat-512s-512c-1M.img 1M 512 512

# ---------------------------------------------------------------- images made by mkfs.fat and mcopy
if [ -n "$MTOOLS" ] && [ -x "$MTOOLS/mcopy" ]; then
    mk_dos() { # name size-in-KiB sector
        local img=$OUT/images/$1
        rm -f "$img"
        truncate -s "$2K" "$img"
        /usr/sbin/mkfs.fat -F 32 -S "$3" -n DOSSEED --invariant "$img" > /dev/null
        (cd "$T" && "$MTOOLS/mcopy" -i "$img" -s -m -b ./* ::/)
        # fsck.fat exits 1 for the small-volume warning alone; look at its text.
        local dos; dos=$(/usr/sbin/fsck.fat -n "$img" 2>&1 || true)
        grep -q 'files, .*clusters$\|^.*: [0-9]* files' <<< "$dos" || { echo "seed $1 fails fsck.fat" >&2; echo "$dos"; exit 1; }
        # mcopy -s writes "." entries pointing at cluster 0, which ufat's
        # check reports (exit 4); the image is still what a real producer
        # emits, so it only has to be readable.
        local rc=0
        "$UFAT" check "$img" > /dev/null || rc=$?
        case $rc in 0 | 4) ;; *) echo "seed $1 breaks ufat check (exit $rc)" >&2; exit 1 ;; esac
    }
    mk_dos dos-512s-4M.img 4096 512
    mk_dos dos-4096s-8M.img 8192 4096
else
    echo "mtools not found, skipping the mkfs.fat seeds" >&2
fi

# ---------------------------------------------------------------- manifests
cp "$REPO/tests/fixtures/esp/Uapi16Manifest" "$OUT/manifests/esp.Uapi16Manifest"
cp "$REPO/tests/fixtures/esp/size-hash-mtime.Uapi16Manifest" "$OUT/manifests/esp-size-hash-mtime.Uapi16Manifest"
cp "$REPO/tests/fixtures/esp/none.Uapi16Manifest" "$OUT/manifests/esp-none.Uapi16Manifest"
cp "$REPO/tests/fixtures/esp/signed.Uapi16Manifest" "$OUT/manifests/esp-signed.Uapi16Manifest"
cp "$REPO/tests/fixtures/special/Uapi16Manifest" "$OUT/manifests/special.Uapi16Manifest"
cp "$REPO/tests/fixtures/empty/Uapi16Manifest" "$OUT/manifests/empty.Uapi16Manifest"
"$UFAT" manifest "$T" > "$OUT/manifests/seed-tree.Uapi16Manifest"
# Source trees the manifests refer to.
rm -rf "$OUT/trees/esp" "$OUT/trees/special"
cp -r "$REPO/tests/fixtures/esp/tree" "$OUT/trees/esp"
cp -r "$REPO/tests/fixtures/special/tree" "$OUT/trees/special"

ls -la "$OUT/images" "$OUT/manifests"
