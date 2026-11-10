#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# The SystemTime overflow panics the first campaign found: a --timestamp or
# a $SOURCE_DATE_EPOCH above i64::MAX seconds panicked (exit 101, "overflow
# when adding duration to `SystemTime`") instead of failing. ufat refuses
# timestamps a SystemTime cannot hold now; this is kept as the regression
# check: every command must exit 1 with a message, the script exits 1 when
# one of them still panics.
set -u
UFAT=${1:-build/ufat}
IMG=$(mktemp)
"$UFAT" assemble --create --size 40M "$IMG" > /dev/null 2>&1
rc=0
for cmd in "populate --timestamp 18446744073709551615 --path /d $IMG" \
           "populate --timestamp 9223372036854775808 --path /d $IMG" \
           "assemble --timestamp 18446744073709551615 $IMG"; do
    # shellcheck disable=SC2086
    "$UFAT" $cmd; s=$?
    echo "ufat $cmd -> exit $s"
    [ $s -eq 1 ] || rc=1
done
SOURCE_DATE_EPOCH=18446744073709551615 "$UFAT" populate --path /e "$IMG"; s=$?
echo "SOURCE_DATE_EPOCH=18446744073709551615 ufat populate -> exit $s"
[ $s -eq 1 ] || rc=1
rm -f "$IMG"
exit $rc
