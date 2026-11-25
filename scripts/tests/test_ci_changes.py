import importlib.util
from pathlib import Path
import unittest

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


if __name__ == '__main__':
    unittest.main()
