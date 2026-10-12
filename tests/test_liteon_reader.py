import importlib.util
import ctypes as C
import hashlib
import json
from pathlib import Path
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reader", ROOT / "tools/liteon/device/read_flash.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
sys.modules["read_flash"] = reader
decoder_spec = importlib.util.spec_from_file_location("decoder", ROOT / "tools/liteon/dump_analysis/decode_flash.py")
decoder = importlib.util.module_from_spec(decoder_spec)
decoder_spec.loader.exec_module(decoder)


class ReaderTests(unittest.TestCase):
    def test_decoder_matches_original_and_resets_each_transfer(self):
        try:
            import Crypto.Cipher.AES
        except ImportError:
            self.skipTest("Optional pycryptodome dependency not installed")
        vector = json.loads((ROOT / "tests/liteon_read_vectors.json").read_text())["decode_vector"]
        raw = bytes.fromhex(vector["raw"])
        key = bytes.fromhex(vector["key"])
        iv = bytes.fromhex(vector["iv"])
        expected = bytes.fromhex(vector["decoded"])
        self.assertEqual(decoder.decode(raw + raw, key, iv), expected + expected)

    def test_decoder_uses_valid_inquiry_tail_and_rejects_wrong_dump(self):
        inquiry = bytearray(240)
        inquiry[4] = 159  # 164 valid bytes, despite 240 transferred.
        inquiry[16:32] = bytes(range(32, 48))
        inquiry[0x60:0x68] = b"EXTRAINQ"
        inquiry[0x6f] = 1
        inquiry[0x72] = 0xc2
        inquiry[148:164] = bytes(range(16))
        raw = bytes(65536)
        digest = hashlib.sha256(raw).hexdigest()
        report = {"identity": {"vendor": "ASUS", "model": "BW-12B1LT", "revision": "1.03"},
                  "extended_inquiry_hex": inquiry.hex(), "reads_match": True,
                  "hashes": [digest, digest]}
        key, iv, valid_length = decoder.parameters(report, raw)
        self.assertEqual(key, bytes(range(16)))
        self.assertEqual(iv, bytes(range(32, 48)))
        self.assertEqual(valid_length, 164)
        with self.assertRaises(reader.ReadError):
            decoder.parameters(report, b"x" + raw[1:])
        with self.assertRaises(reader.ReadError):
            decoder.parameters(report, raw[:-128])
        inquiry[4] = 255
        report["extended_inquiry_hex"] = inquiry.hex()
        with self.assertRaises(reader.ReadError):
            decoder.parameters(report, raw)

    def test_transport_checks_status_and_short_reads(self):
        class FakeLibc:
            status = 0
            residual = 0
            def ioctl(self, fd, request, pointer):
                hdr = C.cast(pointer, C.POINTER(reader.SgIoHdr)).contents
                self.assert_direction = hdr.dxfer_direction
                hdr.status = self.status
                hdr.resid = self.residual
                C.memset(hdr.dxferp, 0x42, hdr.dxfer_len)
                return 0
        device = reader.SgDevice.__new__(reader.SgDevice)
        device.fd = 123
        device.libc = FakeLibc()
        cdb = reader.flash_cdb("df83", 0)
        self.assertEqual(device.read(cdb, 128), b"B" * 128)
        self.assertEqual(device.libc.assert_direction, -3)
        device.libc.status = 2
        with self.assertRaises(reader.ReadError):
            device.read(cdb, 128)
        device.libc.status = 0
        for residual in (-1, 1, 129):
            device.libc.residual = residual
            with self.assertRaises(reader.ReadError):
                device.read(cdb, 128)

    def test_cdbs_match_original_utility(self):
        evidence = json.loads((ROOT / "tests/liteon_read_vectors.json").read_text())
        for vector in evidence["vectors"]:
            cdb = reader.flash_cdb(vector["protocol"], vector["offset"])
            self.assertEqual(cdb.hex(), vector["cdb"])
            self.assertEqual(vector["length"], 128)
            self.assertEqual(vector["direction"], 1)
            self.assertTrue(reader.allowed_read(cdb, 128))

    def test_write_and_malformed_commands_rejected(self):
        for cdb in (bytes.fromhex("3b 05 01 00 00 00 00 00 80 00 00 00"),
                    bytes.fromhex("df 84 00 00 ff 00 00 00 00 00 00 00"),
                    reader.flash_cdb("df83", 0)[:-1] + b"\x01",
                    reader.flash_cdb("df83", 0x80)[:8] + b"\x01" + bytes(3)):
            self.assertFalse(reader.allowed_read(cdb, 128))
        self.assertFalse(reader.allowed_read(reader.flash_cdb("df83", 0), 129))

    def test_bad_offsets(self):
        for offset in (-128, 1, reader.MAX_SIZE):
            with self.assertRaises(ValueError):
                reader.flash_cdb("df83", offset)

    def test_metadata(self):
        data = bytearray(240)
        data[0x60:0x68] = b"EXTRAINQ"
        data[0x6f] = 32
        self.assertEqual(reader.flash_metadata(data)["reported_size"], 2 * 1024 * 1024)
        self.assertEqual(reader.flash_metadata(data)["protocol"], "df83")
        data[0x72] = 0x80
        self.assertEqual(reader.flash_metadata(data)["protocol"], "buffer-f0")
        for invalid in (b"", bytes(240), data[:0x72]):
            with self.assertRaises(reader.ReadError):
                reader.flash_metadata(invalid)
        data[0x6f] = 0
        with self.assertRaises(reader.ReadError):
            reader.flash_metadata(data)

    def test_wrong_target_gets_no_extended_command(self):
        class WrongDevice:
            calls = 0
            def read(self, cdb, length, exact):
                self.calls += 1
                data = bytearray(96)
                data[0] = 5
                data[8:16] = b"OTHER   "
                return bytes(data)
        device = WrongDevice()
        with self.assertRaises(reader.ReadError):
            reader.probe(device)
        self.assertEqual(device.calls, 1)

    def test_dump_blocks_and_preserves_partial_on_failure(self):
        class FakeDevice:
            calls = []
            fail_at = None
            def read(self, cdb, length):
                offset = int.from_bytes(cdb[6:9], "big")
                self.calls.append(offset)
                if offset == self.fail_at:
                    raise reader.ReadError("Injected transport error")
                return bytes([offset // 128]) * length
        meta = {"flash": {"reported_size": 256, "protocol": "df83"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flash.bin"
            device = FakeDevice()
            reader.dump(device, meta, path)
            self.assertEqual(device.calls, [0, 128])
            self.assertEqual(path.read_bytes(), bytes(128) + bytes([1]) * 128)
            with self.assertRaises(FileExistsError):
                reader.dump(device, meta, path)
            device.fail_at = 128
            partial = Path(directory) / "partial.bin"
            with self.assertRaises(reader.ReadError):
                reader.dump(device, meta, partial)
            self.assertEqual(partial.stat().st_size, 128)


if __name__ == "__main__":
    unittest.main()
