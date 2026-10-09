"""Native finalization-worker behavior at the modeled transport boundary."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))


class FinalizationTests(unittest.TestCase):
    def test_native_completion_retries_and_no_readback(self):
        binary = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not binary.exists() or not all(importlib.util.find_spec(m) for m in ('unicorn', 'pefile')):
            self.skipTest('Pinned utility or native-emulation dependencies unavailable')
        from verify_finalization import verify
        result = verify(binary.read_bytes())
        self.assertTrue(result['offline_host_finalization_audit_passed'])
        self.assertEqual(len(result['cases']), 5)
        self.assertEqual([len(case['calls']) for case in result['cases']], [1, 1, 2, 2, 2])
        self.assertEqual([case['native_result_field'] for case in result['cases']], [2, 2, 2, 1, 1])
        self.assertFalse(result['physical_flash_verified'])
        self.assertFalse(result['flash_ready'])


if __name__ == '__main__':
    unittest.main()
