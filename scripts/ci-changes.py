#!/usr/bin/env python3
"""Decide whether a change touches anything the hax/F* (or ProVerif) jobs read.

Fails closed: a path is ignorable only if it matches IGNORABLE; everything else
(src/**, Cargo.*, hax-driver.py, proofs/**, formal-coverage.toml, scripts/verify-fstar.py,
the hax/proverif workflows, .github/actions/**, ...) counts as relevant.

Usage: ci-changes.py [BASE_REF]   writes `relevant=true|false` to $GITHUB_OUTPUT (or stdout).
Without BASE_REF (push, schedule, dispatch) the answer is always true.
"""
from fnmatch import fnmatchcase
import os
import subprocess
import sys

# Not read by extraction or F*. coverage.yml has its own checks and is never skipped.
IGNORABLE = ('*.md', 'docs/*', 'LICENSE*', 'CODEOWNERS', 'coverage/*', '.github/ISSUE_TEMPLATE/*',
             '.github/dependabot.yml', '.github/workflows/ci.yml', '.github/workflows/coverage.yml',
             'scripts/test-features', 'deny.toml')


def is_relevant(paths):
    return any(not any(fnmatchcase(p, pattern) for pattern in IGNORABLE) for p in paths if p)


def changed_paths(base_ref):
    out = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', base_ref, 'HEAD'], text=True)
    return out.splitlines()


def main(argv):
    relevant = True if len(argv) < 2 else is_relevant(changed_paths(argv[1]))
    line = f'relevant={str(relevant).lower()}'
    print(line)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(line + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
