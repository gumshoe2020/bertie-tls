#!/usr/bin/env python3
"""Skip proof jobs only when all changed paths are known unrelated inputs.

Usage: ci-changes.py [--job hax|proverif] [BASE_REF]. Without BASE_REF
(push, schedule, dispatch), always run. Unknown paths always run either job.
"""
import argparse
from fnmatch import fnmatchcase
import os
import subprocess
import sys

# Not read by extraction or F*. coverage.yml has its own checks and is never skipped.
IGNORABLE = ('*.md', 'docs/*', 'LICENSE*', 'CODEOWNERS', 'coverage/*', '.github/ISSUE_TEMPLATE/*',
             '.github/dependabot.yml', '.github/workflows/ci.yml', '.github/workflows/coverage.yml',
             'scripts/test-features', 'deny.toml')


# Derived from hax-driver.py extract-proverif, setup-hax, setup-proverif,
# install-proverif and check-proverif. Workspace manifests affect Cargo resolution.
PROVERIF_INPUTS = ('src/*', 'Cargo.toml', 'Cargo.lock', '*/Cargo.toml',
                   '.cargo/*', 'rust-toolchain*', 'build.rs', '*/build.rs',
                   'hax-driver.py', 'proofs/proverif/*', 'scripts/check-proverif',
                   'scripts/install-proverif', '.github/workflows/proverif.yml',
                   '.github/actions/setup-hax/*', '.github/actions/setup-proverif/*',
                   'scripts/ci-changes.py', 'scripts/tests/test_ci_changes.py')
# Only these additional paths are known to belong exclusively to the F* job.
PROVERIF_IGNORABLE = ('proofs/fstar/*', 'scripts/verify-fstar.py',
                      'scripts/tests/test_verify_fstar.py', 'formal-coverage.toml',
                      '.github/workflows/hax.yml')


def is_relevant(paths, job='hax'):
    for path in filter(None, paths):
        if job == 'proverif' and any(fnmatchcase(path, p) for p in PROVERIF_INPUTS):
            return True
        ignored = IGNORABLE + (PROVERIF_IGNORABLE if job == 'proverif' else ())
        if not any(fnmatchcase(path, p) for p in ignored):
            return True
    return False


def changed_paths(base_ref):
    base_ref = subprocess.check_output(['git', 'merge-base', base_ref, 'HEAD'], text=True).strip()
    out = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', base_ref, 'HEAD'], text=True)
    return out.splitlines()


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', choices=('hax', 'proverif'), default='hax')
    parser.add_argument('base_ref', nargs='?')
    args = parser.parse_args(argv[1:])
    relevant = args.base_ref is None or is_relevant(changed_paths(args.base_ref), args.job)
    line = f'relevant={str(relevant).lower()}'
    print(line)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(line + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
