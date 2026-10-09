"""Original-only restore guards, once-only physical finalization and error evidence."""
import ctypes as C
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import restore_original as restore


class RestoreTests(unittest.TestCase):
    def device(self, journal, *, result=0, residual=0, status=0, host=0):
        device = restore.RestoreDevice.__new__(restore.RestoreDevice)
        device.tag = bytes(range(16))
        device.fd, device.commands, device.journal = 123, 1025, journal
        device.staging_verified = True
        device.finalization_attempted = device.finalization_transport_accepted = False
        calls = []

        class Libc:
            def ioctl(self, fd, operation, pointer):
                hdr = C.cast(pointer, C.POINTER(restore.SgIoHdr)).contents
                assert fd == 123 and operation == restore.SG_IO
                assert hdr.cmd_len == 12 and C.string_at(hdr.cmdp, 12) == restore.FINAL_CDB
                assert hdr.dxfer_direction == -2 and hdr.dxfer_len == 16
                assert C.string_at(hdr.dxferp, 16) == bytes(range(16))
                assert hdr.timeout == 300000
                # Intent must be durably journaled BEFORE the actual syscall.
                assert json.loads(Path(journal.name).read_text().splitlines()[-1])['event'] == 'finalization_intent'
                calls.append(hdr.timeout)
                hdr.resid, hdr.status, hdr.host_status = residual, status, host
                return result

        device.libc = Libc()
        return device, calls

    def test_finalization_once_exact_cdb_timeout_and_durable_intent(self):
        with tempfile.NamedTemporaryFile(mode='w+') as journal:
            device, calls = self.device(journal)
            device.staging_verified = False
            with self.assertRaises(restore.ReadError):
                device.finalize()
            self.assertEqual(calls, [])
            device.staging_verified = True
            device.finalize()
            self.assertTrue(device.finalization_transport_accepted)
            with self.assertRaises(restore.ReadError):
                device.finalize()
            with self.assertRaises(restore.ReadError):
                device.transfer(restore.staging.block_cdb(0), bytes(4096))
            self.assertEqual(calls, [300000])
            self.assertEqual(device.commands, 1026)
            journal.seek(0)
            records = [json.loads(line) for line in journal]
            self.assertEqual([r['event'] for r in records], ['finalization_intent', 'finalization_result'])

    def test_transport_failure_is_never_retried(self):
        for fields in ({'result': -1}, {'residual': 1}, {'status': 2}, {'host': 3}):
            with self.subTest(fields=fields), tempfile.NamedTemporaryFile(mode='w+') as journal:
                device, calls = self.device(journal, **fields)
                with self.assertRaises(restore.ReadError):
                    device.finalize()
                self.assertTrue(device.finalization_attempted)
                self.assertFalse(device.finalization_transport_accepted)
                with self.assertRaises(restore.ReadError):
                    device.finalize()
                self.assertEqual(len(calls), 1)

    def test_wrong_tag_rejected_before_open(self):
        with patch.object(restore.staging.StagingDevice, '__init__') as initialize:
            with self.assertRaises(restore.ReadError):
                restore.RestoreDevice('/dev/never-open', bytes(3968), bytes(0x200000), bytes(16), io.StringIO())
            initialize.assert_not_called()

    def exercise_runner(self, *, live_failure=False, wrong_flash=False, staging_failure=False, final_failure=False):
        class Device:
            def __init__(self):
                self.commands = 0
                self.finalization_attempted = self.finalization_transport_accepted = False
                self.closed = False

            def stage_original(self, progress):
                self.commands = 1
                if staging_failure:
                    raise restore.ReadError('Staging failure')
                self.commands = 1025
                return {'all_blocks_matched': True, 'blocks_matched': 512, 'read_attempts': 512,
                        'finalization_sent': False, 'physical_flash_verified': False, 'flash_ready': False}

            def finalize(self):
                self.finalization_attempted = True
                self.commands += 1
                if final_failure:
                    raise restore.ReadError('Ambiguous finalization failure')
                self.finalization_transport_accepted = True

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'restore.json').write_text('{}')
            output = base / 'result'
            device = Device()
            with patch.object(restore, 'load_package', return_value=(b'', b'', b'', {})), \
                 patch.object(restore, 'check_baseline'), \
                 patch.object(restore, 'RestoreDevice', return_value=device), \
                 patch.object(restore, 'probe', return_value={'identity': restore.IDENTITY}), \
                 patch.object(restore, 'check_live', side_effect=restore.ReadError('Live mismatch') if live_failure else None), \
                 patch.object(restore, 'read_dump', return_value='wrong' if wrong_flash else restore.RAW_SHA256):
                if any((live_failure, wrong_flash, staging_failure, final_failure)):
                    with self.assertRaises(restore.ReadError):
                        restore.restore(base, base, '/dev/not-opened', output)
                else:
                    result = restore.restore(base, base, '/dev/not-opened', output)
                    self.assertTrue(result['finalization_transport_accepted'])
            self.assertTrue(device.closed)
            return json.loads((output / 'restore-result.json').read_text())

    def test_runner_preflight_and_staging_failures_never_finalize(self):
        for fields, count in (({'live_failure': True}, 0), ({'wrong_flash': True}, 0),
                              ({'staging_failure': True}, 1)):
            with self.subTest(fields=fields):
                report = self.exercise_runner(**fields)
                self.assertFalse(report['finalization_attempted'])
                self.assertIs(report['finalization_sent'], False)
                self.assertEqual(report['update_commands_issued'], count)
                self.assertEqual(report['outcome'], 'aborted_before_finalization')

    def test_runner_ambiguous_finalization_preserves_unknown_outcome(self):
        report = self.exercise_runner(final_failure=True)
        self.assertTrue(report['finalization_attempted'])
        self.assertIsNone(report['finalization_sent'])
        self.assertEqual(report['update_commands_issued'], 1026)
        self.assertEqual(report['outcome'], 'finalization_outcome_unknown_do_not_retry')
        self.assertFalse(report['physical_flash_verified'])

    def test_accepted_transport_still_requires_physical_readback(self):
        report = self.exercise_runner()
        self.assertEqual(report['outcome'], 'transport_accepted_requires_cold_readback')
        self.assertTrue(report['finalization_sent'])
        self.assertFalse(report['physical_flash_verified'])
        self.assertFalse(report['flash_ready'])

    def test_native_package_and_baseline_tampering(self):
        binary = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        image, report = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin', ROOT / 'dump/report.json'
        if not all(p.exists() for p in (binary, image, report)) or not all(
                importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Pinned native research inputs unavailable')
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'package'
            restore.prepare(image, report, binary, package)
            profile, staged, tag, manifest = restore.load_package(package)
            self.assertEqual(len(profile), 3968)
            self.assertEqual(len(staged), 0x200000)
            self.assertEqual(restore.sha(tag), restore.FINAL_TAG_SHA256)
            self.assertFalse(manifest['boot_update'])
            (package / 'original.final-tag.bin').write_bytes(bytes(16))
            manifest['finalization_tag_sha256'] = restore.sha(bytes(16))
            (package / 'restore.json').write_text(json.dumps(manifest))
            with self.assertRaises(restore.ReadError):
                restore.load_package(package)
            manifest['finalization_tag_sha256'] = restore.FINAL_TAG_SHA256
            (package / 'restore.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(restore.ReadError, 'tag'):
                restore.load_package(package)
            baseline = Path(directory) / 'baseline'
            baseline.mkdir()
            baseline_report = json.loads(report.read_text())
            baseline_report['complete'] = False
            (baseline / 'report.json').write_text(json.dumps(baseline_report))
            with self.assertRaisesRegex(restore.ReadError, 'complete'):
                restore.check_baseline(baseline)


if __name__ == '__main__':
    unittest.main()
