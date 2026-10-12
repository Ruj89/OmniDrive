"""Optional integration evidence uses locally retained, pinned research inputs."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import verify_loader as loader


class LoaderAcceptanceTests(unittest.TestCase):
    def test_rejects_unknown_firmware_before_execution(self):
        with self.assertRaisesRegex(ValueError, 'pinned original'):
            loader.verify(bytes(0x200000), b'', b'', b'')

    def test_inquiry_rejects_incompatible_or_changed_capture(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        report = ROOT / 'dump/report.json'
        if not original.exists() or not report.exists():
            self.skipTest('Local captured specimen unavailable')
        firmware = original.read_bytes()
        inquiry = bytes.fromhex(json.loads(report.read_text())['extended_inquiry_hex'])
        baseline = loader.validate_inquiry(firmware, inquiry)
        self.assertEqual(baseline['valid_sha256'], loader.INQUIRY_VALID_SHA256)
        self.assertEqual(loader.validate_inquiry(firmware, inquiry[:164])['valid_sha256'],
                         baseline['valid_sha256'])
        # Host protocol selection, identity, flash size, profile and session material.
        for offset in (4, 8, 16, 32, 0x60, 0x6a, 0x6f, 0x70, 0x72, 148):
            with self.subTest(offset=hex(offset)):
                changed = bytearray(inquiry)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    loader.validate_inquiry(firmware, bytes(changed))
        changed = bytearray(inquiry)
        changed[0x70] = 0x1f  # Regression: review's unsupported writer type passed before.
        with self.assertRaisesRegex(ValueError, 'writer type'):
            loader.validate_inquiry(firmware, changed)

    def test_native_read_failure_aborts_after_retry_limit(self):
        class Utility:
            def cdb(self, *args, **kwargs):
                return b''

        class Reader:
            attempts = 0

            def command(self, *args):
                return {'invalid_field': 0, 'auth_failure': 0}

            def read_buffer(self, cdb):
                self.attempts += 1
                raise loader.ReadbackTransferError('Controller transfer failed')

        reader = Reader()
        with self.assertRaisesRegex(loader.ReadbackError, 'after 3 attempts'):
            loader.transfer_block(Utility(), reader, 0, bytes(4096))
        self.assertEqual(reader.attempts, 3)

    def test_native_acceptance_and_corruption_rejection(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        inquiry = ROOT / 'dump/report.json'
        utility = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, inquiry, utility)):
            self.skipTest('Pinned local firmware/utility inputs are not distributed')
        if not all(importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Optional native-emulation dependencies unavailable')
        image = original.read_bytes()
        patch = loader.build(image)[0]
        report = loader.verify(image, patch, bytes.fromhex(
            json.loads(inquiry.read_text())['extended_inquiry_hex']), utility.read_bytes())
        self.assertEqual([c['accepted'] for c in report['profile_cases']], [True, False, False, False])
        self.assertEqual([c['accepted'] for c in report['image_cases']], [True] * 4 + [False] * 7)
        for case in report['image_cases'][:8]:
            self.assertEqual(case['commands'], 1026)
            self.assertEqual(case['readback_comparisons'], 512)
            self.assertEqual(len(case['readbacks']), 512)
            # Native handler remaps the final 128 KiB into scratch while profile is installed.
            for read in case['readbacks']:
                self.assertEqual(read['dma_offset'], min(read['requested_offset'], 0x1e0000))
        for case, attempts in zip(report['image_cases'][8:], (2, 3, 3)):
            self.assertFalse(case['final_command_sent'])
            self.assertEqual(case['readback_attempts'], attempts)
            self.assertFalse(any(e['address'] == 0x1baeb4 for e in case['events']))
        self.assertTrue(report['block_readback_verified'])
        self.assertEqual(report['inquiry']['valid_sha256'], loader.INQUIRY_VALID_SHA256)
        self.assertEqual([c['accepted'] for c in report['imported_profile_chip_cases']], [True, True, False])
        self.assertEqual(len(report['imported_programmer_entry_cases']), 4)
        self.assertFalse(report['flash_ready'])
        self.assertFalse(report['hardware_tested'])


if __name__ == '__main__':
    unittest.main()
