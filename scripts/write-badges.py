#!/usr/bin/env python3
"""Write shields.io endpoint JSON badges from the committed baseline.

usage: write-badges.py BASELINE_JSON OUT_DIR RATCHET_RESULT   (RATCHET_RESULT: pass|fail)
Colors follow the plain thresholds documented in COVERAGE.md and never flatter.
The proof-to-code ratio badge is informational: it is never red.
"""
import json
from pathlib import Path
import sys

RATIO_RANGE = (5.0, 15.0)


def proven_color(percent):
    for floor, color in [(90, 'brightgreen'), (75, 'green'), (50, 'yellow'), (25, 'orange')]:
        if percent >= floor:
            return color
    return 'red'


def unverified_color(percent):
    for ceiling, color in [(10, 'brightgreen'), (25, 'green'), (50, 'yellow'), (75, 'orange')]:
        if percent < ceiling:
            return color
    return 'red'


def ratio_badge(ratio):
    if ratio is None:
        return 'n/a', 'lightgrey'
    low, high = RATIO_RANGE
    return f'{ratio:.1f}', 'brightgreen' if low <= ratio <= high else 'yellow'


def badge(label, message, color):
    return dict(schemaVersion=1, label=label, message=message, color=color)


def build(baseline, ratchet_result):
    total = baseline['total']
    percent = lambda lines: 100 * lines / total
    ratio_message, ratio_color = ratio_badge(baseline['proof_ratio'])
    passed = ratchet_result == 'pass'
    return {
        'proven': badge('proven', f"{percent(baseline['proven']):.1f}%", proven_color(percent(baseline['proven']))),
        'tested': badge('tested', f"{percent(baseline['tested']):.1f}%", 'blue'),
        'unverified': badge('unverified', f"{baseline['unverified']} lines",
                            unverified_color(percent(baseline['unverified']))),
        'proof-ratio': badge('proof/code', ratio_message, ratio_color),
        'ratchet': badge('ratchet', 'pass' if passed else 'fail', 'brightgreen' if passed else 'red'),
    }


def main(argv):
    baseline_path, out_dir, ratchet_result = argv
    if ratchet_result not in ('pass', 'fail'):
        raise SystemExit('RATCHET_RESULT must be pass or fail')
    badges = build(json.loads(Path(baseline_path).read_text()), ratchet_result)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for name, content in badges.items():
        (Path(out_dir) / f'{name}.json').write_text(json.dumps(content, sort_keys=True) + '\n')


if __name__ == '__main__':
    main(sys.argv[1:])
