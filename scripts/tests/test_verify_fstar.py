import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('verify_fstar', Path(__file__).parents[1] / 'verify-fstar.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class CacheDependencies(unittest.TestCase):
    def test_dependencies_precede_consumers(self):
        deps = '/cache/B.checked: B.fst /cache/A.checked\n/cache/A.checked: A.fst\n'
        self.assertEqual(verify.dependency_levels(deps, Path('/cache')), [['A.fst'], ['B.fst']])

    def test_cycle_or_missing_dependency_fails_closed(self):
        for deps in ('/cache/A.checked: A.fst /cache/A.checked',
                     '/cache/A.checked: A.fst /cache/missing.checked'):
            with self.assertRaises(RuntimeError):
                verify.dependency_levels(deps, Path('/cache'))

    def test_dependency_analysis_failure_blocks_cache(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(verify, 'OUT', Path(directory)):
            with self.assertRaises(RuntimeError):
                verify.warm_cache(lambda args, log: 1, ['fresh'], Path('/cache'))

    def test_warmup_uses_digest_checked_cache_in_dependency_order(self):
        calls = []
        def launch(args, log):
            calls.append(args)
            if '--dep' in args:
                log.write_text('/cache/B.checked: B.fst /cache/A.checked\n/cache/A.checked: A.fst\n')
            return 0
        with tempfile.TemporaryDirectory() as directory, patch.object(verify, 'OUT', Path(directory)), patch.dict(verify.os.environ, {'FSTAR_JOBS': '1'}):
            verify.warm_cache(launch, ['fresh'], Path('/cache'))
        self.assertEqual([args[-1] for args in calls[1:]], ['A.fst', 'B.fst'])
        for args in calls:
            self.assertIn('--cache_checked_modules', args)
            self.assertIn('--cache_dir', args)
            self.assertNotIn('--lax', args)
