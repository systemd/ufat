#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# The manifest reader panic the campaign re-found: a gptUuid, gptTypeUuid or
# gptDiskUuid string whose byte 9 lies inside a multibyte character was
# sliced at that byte. The reader no longer slices UUID strings at a byte
# offset; this is kept as the regression check: `ufat assemble --plan`
# must exit 1 with "is not a UUID", the script exits 1 otherwise.
UFAT=${1:-target/debug/ufat}
M=$(mktemp)
printf '\036{"mediaType":"application/vnd.uapi.16.manifest"}\n\036{"name":"x","size":0,"gptUuid":"urn:uuid\303\251\303\251\303\251\303\251"}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n' > "$M"
"$UFAT" assemble --plan --manifest "$M"; s=$?
echo "exit $s"
rm -f "$M"
[ $s -eq 1 ]
