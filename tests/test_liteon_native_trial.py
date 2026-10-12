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
import native_trial as trial

# Legacy test discovery reloads read_flash. Assert the exception from the
# shared transport/require helper rather than a second read_flash module copy.


class TrialTests(unittest.TestCase):
    def test_wrong_target_and_direction_rejected_before_open(self):
        with patch.object(trial.SgDevice, '__init__') as initialize:
            for direction in ('apply', 'rollback', 'arbitrary'):
                with self.subTest(direction=direction), self.assertRaises(trial.staging.ReadError):
                    trial.TrialDevice('/dev/never-open', bytes(3968), bytes(0x200000), bytes(16), None, direction)
            initialize.assert_not_called()

    def test_native_inquiry_checks_both_signatures_and_session(self):
        live = json.loads((ROOT / 'dump/report.json').read_text())
        trial.check_live(live, 'apply')
        for field in ('standard_inquiry_hex', 'extended_inquiry_hex'):
            data = bytearray.fromhex(live[field])
            data[74:86] = trial.MARKER
            live[field] = data.hex()
        trial.check_live(live, 'rollback')
        for field, offset in (('standard_inquiry_hex', 74), ('standard_inquiry_hex', 4),
                              ('extended_inquiry_hex', 74), ('extended_inquiry_hex', 148)):
            changed = dict(live)
            data = bytearray.fromhex(changed[field])
            data[offset] ^= 1
            changed[field] = data.hex()
            with self.subTest(field=field, offset=offset), self.assertRaises(trial.staging.ReadError):
                trial.check_live(changed, 'rollback')

    def run_fake(self, direction, fault=None):
        class Device:
            def __init__(self):
                self.commands = 0
                self.finalization_attempted = self.finalization_transport_accepted = False
                self.closed = False

            def stage_target(self, progress):
                self.commands = 1
                if fault == 'stage':
                    raise trial.staging.ReadError('Staging failed')
                self.commands = 1025
                return {'all_blocks_matched': True, 'blocks_matched': 512, 'read_attempts': 512,
                        'finalization_sent': False, 'physical_flash_verified': False, 'flash_ready': False}

            def finalize(self):
                self.commands += 1
                self.finalization_attempted = True
                if fault == 'final':
                    raise trial.staging.ReadError('Ambiguous finalization failure')
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
                 patch.object(trial, 'check_live') as live_check, \
                 patch.object(trial, 'read_dump', return_value='wrong' if fault == 'source' else source):
                if fault:
                    with self.assertRaises(trial.staging.ReadError):
                        trial.run_trial(package, package, '/dev/not-opened', package / 'output', direction)
                else:
                    trial.run_trial(package, package, '/dev/not-opened', package / 'output', direction)
                self.assertEqual(live_check.call_args.args[1], direction)
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
            from native_adapter import assemble as build
            patched = Path(directory) / 'inquiry94.bin'
            patched.write_bytes(build(original.read_bytes())[0])
            package = Path(directory) / 'package'
            # Evidence validation has its own stale-source/hash tests below.
            with patch('verify_native_port.validate_evidence'):
                trial.prepare(original_package, original, patched, baseline, package, Path('unused.json'))
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
                    with self.assertRaises(trial.staging.ReadError):
                        device.finalize()
                    self.assertEqual(len(calls), 1026)
                    self.assertTrue(device.finalization_transport_accepted)
            profile, staged, tag, unused = trial.load_package(package, 'apply')
            with patch.object(trial.SgDevice, '__init__') as initialize:
                # Original-only runner still refuses the patched target.
                with self.assertRaises(trial.staging.ReadError):
                    trial.restore.RestoreDevice('/dev/not-opened', profile, staged, tag, None)
                with self.assertRaises(trial.staging.ReadError):
                    trial.TrialDevice('/dev/not-opened', profile, staged, tag, None, 'rollback')
                initialize.assert_not_called()
            # Editing both payload and manifest cannot authorize another image.
            damaged = bytearray(staged)
            damaged[0x1dea00] ^= 1
            (package / 'native.staged.bin').write_bytes(damaged)
            manifest['patched_staged_sha256'] = trial.sha(damaged)
            (package / 'trial.json').write_text(json.dumps(manifest))
            with self.assertRaises(trial.staging.ReadError):
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
            standard[74:86] = trial.MARKER
            extended = bytearray(inquiry)
            extended[74:86] = trial.MARKER
            report.update(standard_inquiry_hex=standard.hex(), extended_inquiry_hex=extended.hex(),
                          hashes=[trial.PATCH_RAW_SHA256] * 2)
            (patch_baseline / 'report.json').write_text(json.dumps(report))
            for name in ('flash1.raw.bin', 'flash2.raw.bin'):
                (patch_baseline / name).write_bytes(raw)
            trial.check_baseline(patch_baseline, 'rollback')
            with self.assertRaises(trial.staging.ReadError):
                trial.check_baseline(patch_baseline, 'apply')
            (patch_baseline / 'flash2.raw.bin').write_bytes(bytes(len(raw)))
            with self.assertRaises(trial.staging.ReadError):
                trial.check_baseline(patch_baseline, 'rollback')

    def test_native_handoff_in_both_directions(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        report = ROOT / 'dump/report.json'
        binary = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, report, binary)) or not all(
                importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Pinned native research inputs unavailable')
        from verify_loader import Utility
        from verify_handoff import run
        from native_adapter import assemble as build
        patched = bytes(build(original.read_bytes())[0])
        original_inquiry = bytes.fromhex(json.loads(report.read_text())['extended_inquiry_hex'])
        patched_inquiry = bytearray(original_inquiry)
        patched_inquiry[74:86] = trial.MARKER
        utility = Utility(binary.read_bytes())
        for source, target, inquiry in ((original.read_bytes(), patched, original_inquiry),
                                        (patched, original.read_bytes(), bytes(patched_inquiry))):
            for jedec in (0xc22015, 0xc22415):
                with self.subTest(target=trial.sha(target), jedec=jedec):
                    result = run(source, target, inquiry, utility, jedec)
                    self.assertTrue(result['final_array_matches_expected'])
                    self.assertEqual(result['final_array_sha256'], trial.sha(target))
                    self.assertEqual(result['handler_invalid_field'], 0)
                    self.assertEqual(result['handler_auth_failure'], 0)
                    self.assertEqual(result['native_returns'], [0x1baf48, 0x9ef7e])


if __name__ == '__main__':
    unittest.main()
