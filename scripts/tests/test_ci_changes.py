import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import tempfile

spec = importlib.util.spec_from_file_location('ci_changes', Path(__file__).parents[1] / 'ci-changes.py')
ci_changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci_changes)
relevant = ci_changes.is_relevant


class ChangesDetection(unittest.TestCase):
    def test_docs_only_is_skipped(self):
        self.assertFalse(relevant(['README.md', 'docs/a.txt', 'COVERAGE.md', 'coverage/baseline.json']))

    def test_no_changes_is_skipped(self):
        self.assertFalse(relevant([]))

    def test_source_change_runs(self):
        self.assertTrue(relevant(['README.md', 'src/server.rs']))

    def test_lockfile_and_manifest_run(self):
        self.assertTrue(relevant(['Cargo.lock']))
        self.assertTrue(relevant(['Cargo.toml']))

    def test_workflow_changes(self):
        self.assertTrue(relevant(['.github/workflows/hax.yml']))
        self.assertTrue(relevant(['.github/actions/setup-hax/action.yml']))
        self.assertFalse(relevant(['.github/workflows/ci.yml']))

    def test_proof_and_script_inputs_run(self):
        for path in ['proofs/fstar/extraction/Bertie_tls.Der.fst', 'hax-driver.py',
                     'scripts/verify-fstar.py', 'formal-coverage.toml']:
            self.assertTrue(relevant([path]), path)

    def test_the_detector_itself_is_never_ignored(self):
        self.assertTrue(relevant(['scripts/ci-changes.py']))
        self.assertTrue(relevant(['scripts/tests/test_ci_changes.py']))

    def test_unknown_files_fail_closed(self):
        self.assertTrue(relevant(['something/new.bin']))



class ProVerifChanges(unittest.TestCase):
    def test_all_proverif_inputs_run(self):
        for path in ('src/server.rs', 'src/new/fragment.md', 'Cargo.toml', 'Cargo.lock',
                     'record/Cargo.toml', '.cargo/config.toml', 'rust-toolchain.toml',
                     'build.rs', 'hax-driver.py', 'proofs/proverif/handwritten_lib.pvl',
                     'proofs/proverif/extraction/lib.pvl', 'proofs/proverif/extraction/analysis.pv',
                     'proofs/proverif/expected-results.txt', 'scripts/install-proverif',
                     'scripts/check-proverif', '.github/actions/setup-hax/action.yml',
                     '.github/actions/setup-proverif/action.yml', '.github/workflows/proverif.yml',
                     'scripts/ci-changes.py', 'scripts/tests/test_ci_changes.py'):
            with self.subTest(path=path):
                self.assertTrue(relevant([path], 'proverif'))

    def test_unrelated_inputs_skip(self):
        self.assertFalse(relevant(['README.md', 'docs/a.txt', 'coverage/baseline.json',
                                  '.github/workflows/ci.yml', '.github/workflows/coverage.yml',
                                  '.github/workflows/hax.yml', 'proofs/fstar/extraction/A.fst',
                                  'scripts/verify-fstar.py', 'formal-coverage.toml'], 'proverif'))
        self.assertFalse(relevant([], 'proverif'))

    def test_unknown_or_mixed_changes_run(self):
        self.assertTrue(relevant(['new-input.bin'], 'proverif'))
        self.assertTrue(relevant(['README.md', 'proofs/proverif/expected-results.txt'], 'proverif'))

    def test_non_pr_events_always_run(self):
        for job in ('hax', 'proverif'):
            with patch.object(ci_changes, 'changed_paths') as changed, patch.dict(os.environ, {'GITHUB_OUTPUT': ''}):
                self.assertEqual(ci_changes.main(['ci-changes.py', '--job', job]), 0)
                changed.assert_not_called()

    def test_pr_output_is_written_for_both_decisions(self):
        for paths, expected in ((['README.md'], 'false'), (['Cargo.lock'], 'true')):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'output'
                with patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), patch.object(ci_changes, 'changed_paths', return_value=paths):
                    self.assertEqual(ci_changes.main(['ci-changes.py', '--job', 'proverif', 'base']), 0)
                self.assertEqual(output.read_text(), f'relevant={expected}\n')

    def test_diff_uses_merge_base_and_sees_deletions_and_renames(self):
        with patch.object(ci_changes.subprocess, 'check_output', side_effect=['merge-base\n', 'old.rs\nnew.rs\n']) as call:
            self.assertEqual(ci_changes.changed_paths('base'), ['old.rs', 'new.rs'])
        self.assertEqual(call.call_args_list[1].args[0],
                         ['git', 'diff', '--name-only', '--no-renames', 'merge-base', 'HEAD'])

    def test_git_failure_does_not_emit_a_skip(self):
        with patch.object(ci_changes, 'changed_paths', side_effect=ci_changes.subprocess.CalledProcessError(128, 'git')):
            with self.assertRaises(ci_changes.subprocess.CalledProcessError):
                ci_changes.main(['ci-changes.py', '--job', 'proverif', 'missing'])


if __name__ == '__main__':
    unittest.main()
