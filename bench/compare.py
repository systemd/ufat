#!/usr/bin/python3 -I
# SPDX-License-Identifier: LGPL-2.1-or-later
"""compare: the verdict of the performance gate, see HACKING.md.

  bench/compare.py [--accept FILE] [--summary FILE] OUT

OUT is the out directory of bench/compare.sh. Prints a Markdown table of
what every workload cost with the base and the head binary, appends it to
--summary (the job summary in CI), and exits 1 when the head binary
regressed beyond a limit on a workload that --accept does not name.

--accept FILE holds the values of the Perf-regression: trailers of the
commits between base and head, one per line: glob patterns of workload
names, such as populate/* varlink/Populate-wide. A regression of a
workload one of them names is reported and does not fail.
"""

import argparse
import fnmatch
import os
import re
import shutil
import statistics
import subprocess
import sys

# metric: (title, relative limit, absolute floor). The head fails when it
# exceeds the base by more than the relative limit and by more than the
# floor. The instruction count moves by up to 0.5% between runs (the
# random keys of the hash maps), the system calls by a dozen, the bytes
# not at all. Peak RSS is the smallest of the timed runs, which moves by
# up to 3%; wall time, the median of the ratios of the pairs, moves by
# several percent and only fails on a gross regression. See HACKING.md.
LIMITS = {
    'ir': ('instructions', 0.03, 1000000),
    'sys': ('syscalls', 0.02, 20),
    'written': ('written', 0.01, 4096),
    'read': ('read', 0.01, 4096),
    'rss': ('peak RSS', 0.10, 1024),
    'wall': ('wall', 0.50, 0.020),
}
ORDER = ['ir', 'sys', 'written', 'read', 'rss', 'wall']


def load(path):
    """compare.tsv: per workload and side, a list of values per metric."""
    data = {}
    labels = []
    with open(path) as f:
        for line in f:
            field = line.rstrip('\n').split('\t')
            method, label, side = field[:3]
            if label not in data:
                data[label] = {'base': {}, 'head': {}}
                labels.append(label)
            d = data[label][side]
            if method in ('ir', 'sys'):
                if field[3] == 'failed':
                    d['failed'] = True
                else:
                    d.setdefault(method, []).append(int(field[3]))
                continue
            # time: wall user sys maxrss wchar rchar syscw syscr status
            if len(field) < 12 or field[11] != '0':
                d['failed'] = True
                continue
            d.setdefault('wall', []).append(float(field[3]))
            d.setdefault('rss', []).append(int(field[6]))
            d.setdefault('written', []).append(int(field[7]))
            d.setdefault('read', []).append(int(field[8]))
    return labels, data


def accepted_patterns(path):
    if not path or not os.path.exists(path):
        return []
    patterns = []
    with open(path) as f:
        for line in f:
            patterns += [p for p in re.split(r'[\s,]+', line.strip()) if p]
    return patterns


def human(metric, v):
    if metric == 'wall':
        return '%.1f ms' % (v * 1000)
    if metric == 'rss':
        return '%.1f MiB' % (v / 1024)
    if metric in ('written', 'read'):
        return '%.2f MB' % (v / 1e6)
    if metric == 'ir':
        return '%.1fM' % (v / 1e6)
    return '%d' % v


def compare(base, head, metric):
    """(base value, head value, relative change, regressed) for a metric."""
    b, h = base.get(metric), head.get(metric)
    if not b or not h:
        return None
    if metric == 'wall':
        # Interleaved runs: the median of the per-pair ratios, which
        # cancels drift common to both, and the medians for the table.
        ratios = [y / x for x, y in zip(b, h) if x > 0]
        bv, hv = statistics.median(b), statistics.median(h)
        change = statistics.median(ratios) - 1 if ratios else 0.0
    elif metric == 'rss':
        # Noise only ever adds pages: the smallest is the most stable.
        bv, hv = min(b), min(h)
        change = (hv - bv) / bv if bv else 0.0
    else:
        bv, hv = statistics.median(b), statistics.median(h)
        change = (hv - bv) / bv if bv else 0.0
    _, rel, floor = LIMITS[metric]
    regressed = change > rel and hv - bv > floor
    return bv, hv, change, regressed


def details(out, label, regressed_metrics):
    """Where it went: system calls by name, functions by instructions."""
    lines = []
    name = label.replace('/', '_')
    if 'sys' in regressed_metrics:
        counts = {}
        for side in ('base', 'head'):
            try:
                with open(os.path.join(out, 'sys', name + '.' + side)) as f:
                    for line in f:
                        p = line.split()
                        if len(p) >= 2 and p[1].isdigit() and p[0] != 'total':
                            counts.setdefault(p[0], {})[side] = int(p[1])
            except OSError:
                pass
        rows = [(c.get('head', 0) - c.get('base', 0), s, c.get('base', 0), c.get('head', 0))
                for s, c in counts.items()]
        rows = [r for r in sorted(rows, reverse=True) if r[0] != 0][:8]
        if rows:
            lines.append('System calls that changed:')
            lines.append('')
            lines += ['    %-20s %8d -> %8d (%+d)' % (s, b, h, d) for d, s, b, h in rows]
            lines.append('')
    if 'ir' in regressed_metrics and shutil.which('cg_annotate'):
        b = os.path.join(out, 'ir', name + '.base')
        h = os.path.join(out, 'ir', name + '.head')
        try:
            # Function names only: base and head were built from different
            # directories.
            text = subprocess.run(['cg_annotate', '--diff', '--no-annotate',
                                   '--mod-filename', 's/.*//', b, h],
                                  capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            text = ''
        # The lines of the file:function summary, the biggest changes first.
        funcs, section = [], False
        for line in text.splitlines():
            if line.startswith('-- '):
                section = line.startswith('-- File:function')
                continue
            m = re.match(r'^\s+(-?[\d,]+)\s+\(\s*-?[\d.]+%\)\s+(\S.*)$', line)
            if section and m:
                funcs.append((int(m.group(1).replace(',', '')), m.group(2).strip()))
        funcs = sorted(funcs, key=lambda t: -abs(t[0]))[:10]
        if funcs:
            lines.append('Functions with the largest change in instructions:')
            lines.append('')
            lines += ['    %+14d  %s' % (n, f[:100]) for n, f in funcs]
            lines.append('')
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--accept', help='file with Perf-regression: patterns')
    ap.add_argument('--summary', help='append the Markdown report here')
    ap.add_argument('--no-wall-gate', action='store_true', help='report wall time only')
    ap.add_argument('out')
    a = ap.parse_args()
    labels, data = load(os.path.join(a.out, 'compare.tsv'))
    patterns = accepted_patterns(a.accept)
    report = ['## Performance: base against head', '',
              '| workload | ' + ' | '.join(LIMITS[m][0] for m in ORDER) + ' |',
              '|---' * (len(ORDER) + 1) + '|']
    failed, accepted, broken, more = [], [], [], []
    for label in labels:
        base, head = data[label]['base'], data[label]['head']
        cells, bad = [], []
        for m in ORDER:
            r = compare(base, head, m)
            if r is None:
                cells.append('n/a')
                continue
            bv, hv, change, regressed = r
            if m == 'wall' and a.no_wall_gate:
                regressed = False
            cell = '%s (%+.1f%%)' % (human(m, hv), change * 100)
            if regressed:
                bad.append(m)
                cell = '**%s**' % cell
            cells.append(cell)
        if head.get('failed'):
            broken.append(label)
            cells = ['head failed'] + cells[1:]
        elif base.get('failed'):
            cells = ['base failed'] + cells[1:]
        report.append('| %s | %s |' % (label, ' | '.join(cells)))
        if bad:
            ok = any(fnmatch.fnmatchcase(label, p) for p in patterns)
            (accepted if ok else failed).append((label, bad))
            more += ['### %s: %s%s' % (label, ', '.join(LIMITS[m][0] for m in bad),
                                       ' (accepted by a Perf-regression: trailer)' if ok else ''), '']
            for m in bad:
                bv, hv, change, _ = compare(base, head, m)
                more.append('- %s: %s -> %s, %+.1f%% (limit %+.0f%%)' %
                            (LIMITS[m][0], human(m, bv), human(m, hv), change * 100, LIMITS[m][1] * 100))
            more.append('')
            more += details(a.out, label, bad)
    report.append('')
    report.append('Each cell is the head and its change from the base. Limits: ' +
                  ', '.join('%s %+.0f%%' % (LIMITS[m][0], LIMITS[m][1] * 100) for m in ORDER) + '.')
    report.append('')
    report += more
    text = '\n'.join(report) + '\n'
    print(text)
    if a.summary:
        with open(a.summary, 'a') as f:
            f.write(text)
    for label, bad in accepted:
        print('::warning title=Accepted performance regression::%s: %s' %
              (label, ', '.join(LIMITS[m][0] for m in bad)))
    for label, bad in failed:
        print('::error title=Performance regression::%s: %s, see the job summary; '
              'a Perf-regression: trailer naming the workload accepts it' %
              (label, ', '.join(LIMITS[m][0] for m in bad)))
    for label in broken:
        print('::error title=Workload failed::%s failed with the head binary' % label)
    return 1 if failed or broken else 0


if __name__ == '__main__':
    sys.exit(main())
