"""Staging transport bounds, abort behavior and native RAM round trips."""
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
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import stage_update as stage


class FakeDevice:
    def __init__(self, faults=(), write_failure=False):
        self.calls, self.faults = [], list(faults)
        self.payload = b''
        self.write_failure = write_failure

    def transfer(self, cdb, payload=None):
        self.calls.append(cdb)
        if payload is not None:
            if cdb != stage.PROFILE_CDB and self.write_failure:
                raise stage.ReadError('Write transport failed')
            self.payload = payload
            return b''
        fault = self.faults.pop(0) if self.faults else None
        if fault == 'failed':
            raise stage.ReadError('Read transport failed')
        if fault == 'short':
            return self.payload[:-1]
        if fault == 'mismatch':
            return bytes([self.payload[0] ^ 1]) + self.payload[1:]
        return self.payload


class StagingTests(unittest.TestCase):
    profile = bytes(3968)
    image = bytes(range(256)) * (stage.SIZE // 256)

    def test_complete_transfer_omits_finalization(self):
        device = FakeDevice()
        result = stage.transfer_image(device, self.profile, self.image)
        self.assertEqual(len(device.calls), 1025)
        self.assertEqual(result['blocks_matched'], 512)
        self.assertEqual(device.calls[-1], bytes.fromhex('3c01011ff000001000000000'))
        self.assertFalse(result['finalization_sent'])
        self.assertFalse(result['physical_flash_verified'])
        self.assertFalse(result['flash_ready'])

    def test_read_errors_and_mismatches_abort_without_advancing(self):
        for faults, count in ((['failed'] * 3, 5), (['short'] * 3, 5), (['mismatch'] * 2, 4)):
            with self.subTest(faults=faults):
                device = FakeDevice(faults)
                with self.assertRaises(stage.ReadError):
                    stage.transfer_image(device, self.profile, self.image)
                self.assertEqual(len(device.calls), count)
                self.assertTrue(all(cdb[9] in (0, 0x7f) for cdb in device.calls))
                self.assertTrue(all(cdb[3:6] == bytes(3) for cdb in device.calls))
        device = FakeDevice(write_failure=True)
        with self.assertRaises(stage.ReadError):
            stage.transfer_image(device, self.profile, self.image)
        self.assertEqual(len(device.calls), 2)

    def test_mixed_transient_read_faults_recover(self):
        device = FakeDevice(['failed', 'short', 'mismatch', 'failed', 'short'])
        result = stage.transfer_image(device, self.profile, self.image)
        self.assertEqual(result['read_attempts'], 517)
        self.assertTrue(result['all_blocks_matched'])

    def test_allowlist_rejects_finalization_arbitrary_writes_and_reads(self):
        for control in (0x80, 0xa0):
            cdb = bytes.fromhex('3b0501000000000010000000')
            cdb = cdb[:9] + bytes([control]) + cdb[10:]
            for payload in (None, bytes(16)):
                self.assertFalse(stage.allowed_command(cdb, payload, self.profile, self.image))
        self.assertFalse(stage.allowed_command(stage.PROFILE_CDB, b'X' * 3968, self.profile, self.image))
        self.assertFalse(stage.allowed_command(stage.block_cdb(0), b'X' * stage.BLOCK, self.profile, self.image))
        self.assertFalse(stage.allowed_command(bytes.fromhex('3c01f0000000000080000000'),
                                             None, self.profile, self.image))
        for offset in (-1, 1, stage.SIZE):
            with self.assertRaises(stage.ReadError):
                stage.block_cdb(offset)

    def test_sg_io_directions_residual_and_journal(self):
        device = stage.StagingDevice.__new__(stage.StagingDevice)
        device.profile, device.staged = self.profile, self.image
        device.fd, device.commands, device.journal = 123, 0, io.StringIO()

        class Libc:
            residual = 0

            def ioctl(self, fd, operation, pointer):
                hdr = C.cast(pointer, C.POINTER(stage.SgIoHdr)).contents
                assert fd == 123 and operation == stage.SG_IO
                assert hdr.cmd_len == 12 and hdr.dxfer_len == stage.BLOCK
                if hdr.dxfer_direction == -3:
                    C.memmove(hdr.dxferp, StagingTests.image[:stage.BLOCK], stage.BLOCK)
                else:
                    assert hdr.dxfer_direction == -2
                    assert C.string_at(hdr.dxferp, hdr.dxfer_len) == StagingTests.image[:stage.BLOCK]
                hdr.resid = self.residual
                return 0

        device.libc = Libc()
        device.transfer(stage.block_cdb(0), self.image[:stage.BLOCK])
        self.assertEqual(device.transfer(stage.block_cdb(0, read=True)), self.image[:stage.BLOCK])
        device.libc.residual = 1
        with self.assertRaisesRegex(stage.ReadError, 'Short'):
            device.transfer(stage.block_cdb(0, read=True))
        for control in (0x80, 0xa0):
            cdb = bytes.fromhex('3b0501000000000010') + bytes([control, 0, 0])
            with self.assertRaisesRegex(stage.ReadError, 'allowlist'):
                device.transfer(cdb, bytes(16))
        self.assertEqual(device.commands, 3)
        records = [json.loads(line) for line in device.journal.getvalue().splitlines()]
        self.assertEqual([r['direction'] for r in records], ['out', 'in', 'in'])
        self.assertEqual(records[-1]['residual'], 1)

    def test_payload_rejection_precedes_device_open(self):
        with patch.object(stage.SgDevice, '__init__') as initialize:
            with self.assertRaises(stage.ReadError):
                stage.StagingDevice('/dev/never-open', self.profile, self.image, io.StringIO())
            initialize.assert_not_called()

    def test_live_inquiry_mismatch_aborts_before_any_write(self):
        # Some transports pad a 94-byte response to 96: check advertised size too.
        for length, additional in ((94, 89), (96, 89), (96, 91)):
            with self.subTest(standard_length=length, additional=additional), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                package = base / 'package'
                package.mkdir()
                (package / 'package.json').write_text('{}')
                output = base / 'result'
                device = FakeDevice()
                device.commands = 0
                device.close = lambda: None
                inquiry = bytearray(164)
                inquiry[4] = 159
                standard = bytearray(length)
                standard[4] = additional
                response = {'standard_inquiry_hex': standard.hex(),
                            'extended_inquiry_hex': inquiry.hex()}
                with patch.object(stage, 'load_package', return_value=(self.profile, self.image, {})), \
                     patch.object(stage, 'StagingDevice', return_value=device), \
                     patch.object(stage, 'probe', return_value=response):
                    with self.assertRaises(stage.ReadError):
                        stage.stage(package, '/dev/not-opened', output)
                self.assertEqual(device.calls, [])
                summary = json.loads((output / 'staging-result.json').read_text())
                self.assertEqual(summary['update_commands_issued'], 0)
                self.assertFalse(summary['finalization_sent'])
                self.assertIn('error', summary)


class NativeStagingTests(unittest.TestCase):
    def test_package_derivation_tampering_and_native_roundtrip(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        report_path = ROOT / 'dump/report.json'
        utility = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, report_path, utility)):
            self.skipTest('Pinned research inputs unavailable')
        if not all(importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Native-emulation dependencies unavailable')
        from verify_loader import ReaderGates
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'package'
            stage.prepare(original, report_path, utility, package)
            profile, staged, manifest = stage.load_package(package)
            inquiry = bytes.fromhex(json.loads(report_path.read_text())['extended_inquiry_hex'])
            reader = ReaderGates(original.read_bytes(), inquiry)

            class NativeDevice:
                def transfer(self, cdb, payload=None):
                    assert stage.allowed_command(cdb, payload, profile, staged)
                    if payload is None:
                        return reader.read_buffer(cdb)
                    status = reader.command(cdb, payload)
                    assert not status['invalid_field'] and not status['auth_failure']
                    return b''

            result = stage.transfer_image(NativeDevice(), profile, staged)
            self.assertTrue(result['all_blocks_matched'])
            self.assertFalse(any(e['address'] == 0x1baeb4 for e in reader.events))
            self.assertEqual(len(reader.command_hashes), 1025)
            self.assertEqual(len(reader.readbacks), 512)
            damaged = bytearray(staged)
            damaged[0x1fffff] ^= 1
            (package / 'original.staged.bin').write_bytes(damaged)
            manifest['staged_sha256'] = stage.sha(damaged)
            (package / 'package.json').write_text(json.dumps(manifest))
            with self.assertRaises(stage.ReadError):
                stage.load_package(package)
            manifest['staged_sha256'] = stage.STAGED_SHA256
            (package / 'package.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(stage.ReadError, 'staging image'):
                stage.load_package(package)


if __name__ == '__main__':
    unittest.main()
