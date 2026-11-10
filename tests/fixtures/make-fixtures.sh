#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Regenerates the manifest fixtures with systemd's own tool:
#
#     tests/fixtures/make-fixtures.sh /path/to/systemd-manifest
#
# Every case gets a directory with the manifest(s) systemd-manifest wrote
# and, where git can hold it, a copy of the tree they describe. FIFOs are
# left out of the copies, hardlinks become separate files and mtimes are
# whatever the checkout sets; the tests take times from the manifests.
set -euo pipefail

MANIFEST=${1:?usage: make-fixtures.sh SYSTEMD-MANIFEST}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

stamp() {
    # Fixed, even-second mtimes so FAT can hold them exactly.
    local t=$1
    shift
    touch -h -d "@$t" "$@"
}

copy_tree() {
    # Regular files, directories and symlinks only.
    rm -rf "$2"
    mkdir -p "$2"
    (cd "$1" && find . -type d -exec mkdir -p "$2/{}" \; \
        -o -type f -exec cp -p "{}" "$2/{}" \; \
        -o -type l -exec cp -P "{}" "$2/{}" \;)
}

# ---------------------------------------------------------------- esp
# What an ESP of a systemd system looks like.
T=$WORK/esp
mkdir -p "$T/EFI/BOOT" "$T/EFI/Linux" "$T/EFI/systemd" "$T/loader/entries"
printf 'MZ' > "$T/EFI/BOOT/BOOTX64.EFI"
head -c 4094 /dev/zero | tr '\0' 'B' >> "$T/EFI/BOOT/BOOTX64.EFI"
cp "$T/EFI/BOOT/BOOTX64.EFI" "$T/EFI/systemd/systemd-bootx64.efi"
printf 'MZ' > "$T/EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi"
seq 1 1500 >> "$T/EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi"
printf 'timeout 5\nconsole-mode auto\n' > "$T/loader/loader.conf"
printf 'title Fedora\nlinux /EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi\n' > "$T/loader/entries/fedora.conf"
printf 'seedseedseedseedseedseedseedseed' > "$T/loader/random-seed"
: > "$T/loader/entries.srel"
printf 'type1\n' > "$T/loader/entries.srel"
stamp 1700000000 "$T/EFI/BOOT/BOOTX64.EFI" "$T/EFI/systemd/systemd-bootx64.efi"
stamp 1700000002 "$T/EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi"
stamp 1700000004 "$T/loader/loader.conf" "$T/loader/entries/fedora.conf" "$T/loader/entries.srel"
stamp 1700000006 "$T/loader/random-seed"
stamp 1699999000 "$T/EFI/BOOT" "$T/EFI/Linux" "$T/EFI/systemd" "$T/EFI" "$T/loader/entries" "$T/loader" "$T"
mkdir -p "$HERE/esp"
"$MANIFEST" make --field=default,+mtime "$T" "$HERE/esp/Uapi16Manifest"
"$MANIFEST" make --field=size,hash,mtime "$T" "$HERE/esp/size-hash-mtime.Uapi16Manifest"
"$MANIFEST" make --field=none "$T" "$HERE/esp/none.Uapi16Manifest"
copy_tree "$T" "$HERE/esp/tree"

# A signed copy of the same manifest, with a throwaway key.
openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=ufat test' -days 3650 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
"$MANIFEST" make --field=default,+mtime --private-key="$WORK/key.pem" --certificate="$WORK/cert.pem" \
    "$T" "$HERE/esp/signed.Uapi16Manifest"

# ---------------------------------------------------------------- special
# Everything a manifest can describe that FAT cannot hold, next to things
# it can: a symlink, a FIFO, a hardlink pair, extended attributes, an empty
# directory, a read-only file, names FAT needs long entries for.
T=$WORK/special
mkdir -p "$T/sub/nested" "$T/empty dir"
printf 'first\n' > "$T/a.txt"
printf 'second\n' > "$T/Mixed Case.TXT"
printf 'third\n' > "$T/sub/nested/deep.conf"
printf 'read only\n' > "$T/sub/readonly.bin"
chmod 0444 "$T/sub/readonly.bin"
printf 'hardlinked\n' > "$T/sub/hl_a"
ln "$T/sub/hl_a" "$T/sub/hl_b"
ln -s a.txt "$T/link"
mkfifo "$T/sub/fifo"
printf 'umlaut\n' > "$T/sub/ümlaut ∞.txt"
: > "$T/empty"
if ! setfattr -n user.comment -v 'set by make-fixtures' "$T/a.txt" 2>/dev/null; then
    echo "warning: user xattrs not supported here, the special fixture has none" >&2
fi
stamp 1700000100 "$T/a.txt" "$T/Mixed Case.TXT" "$T/sub/nested/deep.conf" "$T/sub/readonly.bin"
stamp 1700000102 "$T/sub/hl_a" "$T/link" "$T/sub/fifo" "$T/sub/ümlaut ∞.txt" "$T/empty"
stamp 1699999100 "$T/sub/nested" "$T/sub" "$T/empty dir" "$T"
mkdir -p "$HERE/special"
"$MANIFEST" make --field=default,+mtime,+user-name,+group-name "$T" "$HERE/special/Uapi16Manifest"
copy_tree "$T" "$HERE/special/tree"

# ---------------------------------------------------------------- empty
T=$WORK/empty
mkdir -p "$T"
stamp 1700000200 "$T"
mkdir -p "$HERE/empty"
"$MANIFEST" make --field=default,+mtime "$T" "$HERE/empty/Uapi16Manifest"

# The version that made them, for the record.
"$MANIFEST" --version | head -1 > "$HERE/VERSION"
echo "fixtures written to $HERE"
