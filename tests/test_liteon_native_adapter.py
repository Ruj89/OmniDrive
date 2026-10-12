"""Assemble and execute native MT1939 adapter instructions; no device access."""
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from native_adapter import assemble


class NativeAdapterTests(unittest.TestCase):
    def test_unknown_specimen_is_rejected_before_assembly(self):
        for image in (b'', bytes(0x200000)):
            with self.assertRaisesRegex(ValueError, 'exact original'):
                assemble(image)

    def test_adapter_instructions_with_native_dispatch_and_reader_prologues(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned local specimen and armips are required')
        from verify_native_adapter import verify
        result = verify(path.read_bytes())
        self.assertTrue(result['adapter_abi_verified'])
        self.assertEqual(result['passthrough_dispatch_cases'], 255 * 6)
        self.assertEqual(len(result['native_mode_prologues']), 2)
        self.assertEqual(result['accepted_cases'] + len(result['rejected_cases']), 5 * 32 * 3)
        self.assertTrue(result['callee_saved_registers_and_stack_preserved'])
        self.assertEqual(result['overlay_size'], 0x200000)
        self.assertFalse(result['flash_ready'])
        self.assertFalse(result['full_omnidrive_port'])


if __name__ == '__main__':
    unittest.main()
