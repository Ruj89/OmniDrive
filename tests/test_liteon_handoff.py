"""Execute the continuous modeled firmware handoff with expected/faulted NOR."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class HandoffTests(unittest.TestCase):
    def test_native_copy_writer_return_and_persistent_failure(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        report = ROOT / 'dump/report.json'
        binary = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, report, binary)) or not all(
                importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Pinned native research inputs unavailable')
        from verify_handoff import verify
        from audit_integrity import build
        inquiry = bytes.fromhex(json.loads(report.read_text())['extended_inquiry_hex'])
        result = verify(original.read_bytes(), build(original.read_bytes())[0], inquiry, binary.read_bytes())
        self.assertTrue(result['offline_native_handoff_audit_passed'])
        self.assertEqual(len(result['cases']), 6)
        self.assertTrue(all(c['final_array_matches_expected'] for c in result['cases'][:-1]))
        faulty = result['cases'][-1]
        self.assertFalse(faulty['final_array_matches_expected'])
        self.assertEqual(faulty['native_readback_mismatches'], 4)
        self.assertEqual(faulty['handler_invalid_field'], 0)
        self.assertEqual(faulty['handler_auth_failure'], 0)
        self.assertEqual(faulty['native_returns'], [0x1baf48, 0x9ef7e])
        self.assertFalse(result['flash_ready'])


if __name__ == '__main__':
    unittest.main()
