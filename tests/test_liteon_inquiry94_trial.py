"""Pinned patch/rollback targets, source checks and physical-write abort behavior."""
import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import inquiry94_trial as trial


class TrialTests(unittest.TestCase):
    def test_wrong_target_and_direction_rejected_before_open(self):
        with patch.object(trial.SgDevice, '__init__') as initialize:
            for direction in ('apply', 'rollback', 'arbitrary'):
                with self.subTest(direction=direction), self.assertRaises(trial.ReadError):
                    trial.TrialDevice('/dev/never-open', bytes(3968), bytes(0x200000), bytes(16), None, direction)
            initialize.assert_not_called()

    def test_inquiry_marker_is_required_despite_transport_padding(self):
        path = ROOT / 'dump/report.json'
        if not path.exists():
            self.skipTest('Pinned INQUIRY capture unavailable')
        live = json.loads(path.read_text())
        original = bytes.fromhex(live['standard_inquiry_hex'])
        trial.restore.check_live(live)
        for length in (94, 96):
            patched = bytearray(original[:length])
            patched[4] = 89
            live['standard_inquiry_hex'] = patched.hex()
            trial.restore.check_live(live, standard_length=94)
            with self.assertRaises(trial.ReadError):
                trial.restore.check_live(live)  # original-only defaults still reject patch
            patched[4] = 91
            live['standard_inquiry_hex'] = patched.hex()
            with self.assertRaises(trial.ReadError):
                trial.restore.check_live(live, standard_length=94)

    def run_fake(self, direction, fault=None):
        class Device:
            def __init__(self):
                self.commands = 0
                self.finalization_attempted = self.finalization_transport_accepted = False
                self.closed = False

            def stage_target(self, progress):
                self.commands = 1
                if fault == 'stage':
                    raise trial.ReadError('Staging failed')
                self.commands = 1025
                return {'all_blocks_matched': True, 'blocks_matched': 512, 'read_attempts': 512,
                        'finalization_sent': False, 'physical_flash_verified': False, 'flash_ready': False}

            def finalize(self):
                self.commands += 1
                self.finalization_attempted = True
                if fault == 'final':
                    raise trial.ReadError('Ambiguous finalization failure')
                self.finalization_transport_accepted = True

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            (package / 'trial.json').write_text('{}')
            device = Device()
            source = trial.restore.RAW_SHA256 if direction == 'apply' else trial.PATCH_RAW_SHA256
            with patch.object(trial, 'load_package', return_value=(b'', b'', b'', {})), \
                 patch.object(trial, 'check_baseline'), \
                 patch.object(trial, 'TrialDevice', return_value=device), \
                 patch.object(trial, 'probe', return_value={'identity': trial.restore.IDENTITY}), \
                 patch.object(trial.restore, 'check_live') as live_check, \
                 patch.object(trial, 'read_dump', return_value='wrong' if fault == 'source' else source):
                if fault:
                    with self.assertRaises(trial.ReadError):
                        trial.run_trial(package, package, '/dev/not-opened', package / 'output', direction)
                else:
                    trial.run_trial(package, package, '/dev/not-opened', package / 'output', direction)
                self.assertEqual(live_check.call_args.kwargs['standard_length'], 96 if direction == 'apply' else 94)
            self.assertTrue(device.closed)
            return json.loads((package / 'output/trial-result.json').read_text())

    def test_both_directions_require_exact_current_source_before_data_out(self):
        for direction in ('apply', 'rollback'):
            with self.subTest(direction=direction):
                result = self.run_fake(direction, 'source')
                self.assertEqual(result['update_commands_issued'], 0)
                self.assertFalse(result['finalization_attempted'])
                self.assertEqual(result['outcome'], 'aborted_before_finalization')

    def test_staging_failure_prevents_finalization_in_both_directions(self):
        for direction in ('apply', 'rollback'):
            with self.subTest(direction=direction):
                result = self.run_fake(direction, 'stage')
                self.assertFalse(result['finalization_sent'])
                self.assertEqual(result['update_commands_issued'], 1)

    def test_ambiguous_finalization_is_unknown_and_not_retried(self):
        for direction in ('apply', 'rollback'):
            with self.subTest(direction=direction):
                result = self.run_fake(direction, 'final')
                self.assertIsNone(result['finalization_sent'])
                self.assertEqual(result['update_commands_issued'], 1026)
                self.assertEqual(result['outcome'], 'finalization_outcome_unknown_do_not_retry')

    def test_success_binds_target_without_claiming_readback(self):
        for direction, target in (('apply', trial.PATCH_SHA256), ('rollback', trial.staging.IMAGE_SHA256)):
            with self.subTest(direction=direction):
                result = self.run_fake(direction)
                self.assertEqual(result['target_decoded_sha256'], target)
                self.assertEqual(result['outcome'], 'transport_accepted_requires_cold_readback')
                self.assertTrue(result['finalization_sent'])
                self.assertFalse(result['physical_flash_verified'])


class NativeTrialTests(unittest.TestCase):
    def test_payload_derivation_and_both_guarded_transports(self):
        if importlib.util.find_spec('Crypto') is None:
            self.skipTest('Optional cryptography dependency unavailable')
        from Crypto.Cipher import AES
        original_package = ROOT / 'dump/bw12b1lt-original-restore-package'
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        baseline = ROOT / 'dump'
        if not all(p.exists() for p in (original_package, original, baseline / 'report.json')):
            self.skipTest('Pinned preparation inputs unavailable')
        with tempfile.TemporaryDirectory() as directory:
            from audit_integrity import build
            patched = Path(directory) / 'inquiry94.bin'
            patched.write_bytes(build(original.read_bytes())[0])
            package = Path(directory) / 'package'
            trial.prepare(original_package, original, patched, baseline, package)
            for direction in ('apply', 'rollback'):
                profile, staged, tag, manifest = trial.load_package(package, direction)
                with tempfile.NamedTemporaryFile(mode='w+') as journal, patch.object(trial.SgDevice, '__init__'):
                    device = trial.TrialDevice('/dev/not-opened', profile, staged, tag, journal, direction)
                    device.fd = 123
                    calls, stored = [], {}

                    class Libc:
                        def ioctl(self, fd, operation, pointer):
                            hdr = C.cast(pointer, C.POINTER(trial.restore.SgIoHdr)).contents
                            cdb = C.string_at(hdr.cmdp, hdr.cmd_len)
                            calls.append(cdb)
                            if cdb == trial.restore.FINAL_CDB:
                                assert hdr.timeout == 300000 and C.string_at(hdr.dxferp, 16) == tag
                            elif cdb == trial.staging.PROFILE_CDB:
                                assert C.string_at(hdr.dxferp, hdr.dxfer_len) == profile
                            else:
                                offset = int.from_bytes(cdb[3:6], 'big')
                                if hdr.dxfer_direction == -2:
                                    stored[offset] = C.string_at(hdr.dxferp, hdr.dxfer_len)
                                else:
                                    C.memmove(hdr.dxferp, stored[offset], hdr.dxfer_len)
                            return 0

                    device.libc = Libc()
                    result = device.stage_target()
                    self.assertEqual(result['blocks_matched'], 512)
                    self.assertEqual(b''.join(stored[i] for i in sorted(stored)), staged)
                    device.finalize()
                    with self.assertRaises(trial.ReadError):
                        device.finalize()
                    self.assertEqual(len(calls), 1026)
                    self.assertTrue(device.finalization_transport_accepted)
            profile, staged, tag, unused = trial.load_package(package, 'apply')
            with patch.object(trial.SgDevice, '__init__') as initialize:
                # Original-only runner still refuses the patched target.
                with self.assertRaises(trial.ReadError):
                    trial.restore.RestoreDevice('/dev/not-opened', profile, staged, tag, None)
                with self.assertRaises(trial.ReadError):
                    trial.TrialDevice('/dev/not-opened', profile, staged, tag, None, 'rollback')
                initialize.assert_not_called()
            # Editing both payload and manifest cannot authorize another image.
            damaged = bytearray(staged)
            damaged[0x9cb76] ^= 1
            (package / 'inquiry94.staged.bin').write_bytes(damaged)
            manifest['patched_staged_sha256'] = trial.sha(damaged)
            (package / 'trial.json').write_text(json.dumps(manifest))
            with self.assertRaises(trial.ReadError):
                trial.load_package(package, 'apply')
            # A correctly encrypted patched baseline is required for rollback.
            report = json.loads((baseline / 'report.json').read_text())
            inquiry = bytes.fromhex(report['extended_inquiry_hex'])
            image = patched.read_bytes()
            raw = b''.join(AES.new(inquiry[148:164], AES.MODE_CBC, inquiry[16:32]).encrypt(image[i:i + 128])
                           for i in range(0, len(image), 128))
            self.assertEqual(trial.sha(raw), trial.PATCH_RAW_SHA256)
            patch_baseline = Path(directory) / 'patched-baseline'
            patch_baseline.mkdir()
            standard = bytearray.fromhex(report['standard_inquiry_hex'])
            standard[4] = 89
            report.update(standard_inquiry_hex=standard[:94].hex(), hashes=[trial.PATCH_RAW_SHA256] * 2)
            (patch_baseline / 'report.json').write_text(json.dumps(report))
            for name in ('flash1.raw.bin', 'flash2.raw.bin'):
                (patch_baseline / name).write_bytes(raw)
            trial.check_baseline(patch_baseline, 'rollback')
            with self.assertRaises(trial.ReadError):
                trial.check_baseline(patch_baseline, 'apply')
            (patch_baseline / 'flash2.raw.bin').write_bytes(bytes(len(raw)))
            with self.assertRaises(trial.ReadError):
                trial.check_baseline(patch_baseline, 'rollback')

    def test_native_rollback_from_patched_firmware(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        report = ROOT / 'dump/report.json'
        binary = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, report, binary)) or not all(
                importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Pinned native research inputs unavailable')
        from verify_loader import Utility
        from verify_handoff import run
        from audit_integrity import build
        patched = bytes(build(original.read_bytes())[0])
        inquiry = bytes.fromhex(json.loads(report.read_text())['extended_inquiry_hex'])
        utility = Utility(binary.read_bytes())
        for jedec in (0xc22015, 0xc22415):
            with self.subTest(jedec=jedec):
                result = run(patched, original.read_bytes(), inquiry, utility, jedec)
                self.assertTrue(result['final_array_matches_expected'])
                self.assertEqual(result['final_array_sha256'], trial.staging.IMAGE_SHA256)
                self.assertEqual(result['handler_invalid_field'], 0)
                self.assertEqual(result['handler_auth_failure'], 0)
                self.assertEqual(result['native_returns'], [0x1baf48, 0x9ef7e])


if __name__ == '__main__':
    unittest.main()
