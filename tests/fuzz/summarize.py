#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Sums up the reports mutate.py and varlink_fuzz.py wrote under one or more
output directories: variants and runs per command and outcome, machine time,
and the findings by signature.

    tests/fuzz/summarize.py OUT...
"""

import collections
import glob
import json
import os
import sys


def main():
    runs = collections.Counter()      # (campaign, command, outcome) -> runs
    variants = collections.Counter()  # (campaign, strategy) -> variants
    seconds = collections.Counter()
    findings = collections.Counter()
    for out in sys.argv[1:]:
        for path in glob.glob(os.path.join(out, "report-*.json")):
            r = json.load(open(path))
            label = r.get("campaign", "varlink")
            seconds[label] += r["seconds"]
            if label == "varlink":
                for k, v in r["stats"].items():
                    group, kind = k.split("/")
                    runs[("varlink", group, kind)] += v
                    variants[("varlink", group)] += v
            else:
                for s in r["stats"]:
                    k, v = s.rsplit("=", 1)
                    strat, cmd, kind = k.split("/")
                    runs[(label, cmd, kind)] += int(v)
                    # One variant runs several commands; count it once, on the
                    # command every variant runs.
                    if cmd in ("list", "plan"):
                        variants[(label, strat)] += int(v)
            for f in r["findings"]:
                findings[(label, f["sig"])] += 1
    print("machine time: %s" % ", ".join("%s %.0fs" % (k, v) for k, v in sorted(seconds.items())))
    print()
    print("variants per campaign and strategy:")
    for (label, strat), n in sorted(variants.items()):
        print("  %-10s %-12s %7d" % (label, strat, n))
    print("  total variants: %d" % sum(variants.values()))
    print()
    print("runs per command and outcome (ok0 = exit 0, ok1 = exit 1 with a message; fsck: ok4 = problems found, ok8 = not checkable):")
    by_cmd = collections.defaultdict(dict)
    for (label, cmd, kind), n in runs.items():
        by_cmd[(label, cmd)][kind] = n
    for (label, cmd), kinds in sorted(by_cmd.items()):
        total = sum(kinds.values())
        print("  %-10s %-16s %7d  %s" % (label, cmd, total, "  ".join("%s=%d" % kv for kv in sorted(kinds.items()))))
    print("  total runs: %d" % sum(runs.values()))
    print()
    print("findings by signature:")
    for (label, sig), n in sorted(findings.items(), key=lambda x: -x[1]):
        print("  %6d  %-10s %s" % (n, label, sig))


if __name__ == "__main__":
    main()
