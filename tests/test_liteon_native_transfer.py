"""Run native transfer setup, reparse and cleanup, including FUA/cancellation."""
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class NativeTransferTests(unittest.TestCase):
    def original(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        return original.read_bytes()

    def test_cd_native_dma_and_return(self):
        from verify_native_transfer import verify
        report = verify(self.original())
        self.assertEqual(len(report['cd_native_transfer_cases']), 144)
        self.assertFalse(report['optical_transfer_verified'])

    def test_zero_length_returns_without_dma_or_read_state_changes(self):
        from verify_native_transfer import verify_zero_length
        report = verify_zero_length(self.original())
        self.assertEqual(len(report['zero_length_cases']), 44)
        self.assertFalse(report['optical_transfer_verified'])

    def test_psn_internal_packet_reparse(self):
        from verify_native_transfer import verify_packet_reparse
        report = verify_packet_reparse(self.original())
        self.assertEqual(len(report['native_packet_reparse_cases']), 90)
        self.assertFalse(report['optical_transfer_verified'])

    def test_dvd_ram_bd_native_dma_and_return(self):
        from verify_native_transfer import verify_data_transfer
        report = verify_data_transfer(self.original())
        self.assertEqual(len(report['data_native_transfer_cases']), 216)
        self.assertFalse(report['optical_transfer_verified'])

    def test_queued_ordinary_read_returns_to_dispatcher_after_raw_cleanup(self):
        from verify_native_transfer import verify_queued_commands
        report = verify_queued_commands(self.original())
        self.assertEqual(len(report['queued_command_cases']), 24)
        self.assertTrue(all(not c['inherits_raw_format'] for c in report['queued_command_cases']))
        self.assertEqual(len(report['continuation_gate_cases']), 252)
        self.assertFalse(report['optical_transfer_verified'])

    def test_queued_c0_and_nonreads_return_without_idle_timer_ticks(self):
        from verify_native_transfer import verify_queued_nonreads
        report = verify_queued_nonreads(self.original())
        self.assertEqual(len(report['queued_nonread_cases']), 36)
        self.assertTrue(all(c['idle_wait_visits'] == 0 for c in report['queued_nonread_cases']))
        self.assertFalse(report['physical_throughput_verified'])

    def test_raw_dvd_r_bypasses_native_rejection_and_ram_uses_requested_descrambling(self):
        from verify_native_transfer import verify_raw_state_and_recordable
        report = verify_raw_state_and_recordable(self.original())
        self.assertEqual(len(report['raw_state_and_recordable_cases']), 16)
        self.assertFalse(report['optical_transfer_verified'])


if __name__ == '__main__':
    unittest.main()
