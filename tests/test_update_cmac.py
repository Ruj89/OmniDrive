import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import audit_integrity


class UpdateCmacTests(unittest.TestCase):
    def run_update(self, image):
        with tempfile.TemporaryDirectory() as directory:
            # A LiteOn filename alone must never bypass CMAC processing.
            path = Path(directory) / 'ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin'
            path.write_bytes(image)
            subprocess.run([sys.executable, str(ROOT / 'scripts/update_cmac.py'), str(path)],
                           check=True, capture_output=True)
            return path.read_bytes()

    def test_liteon_armips_output_is_preserved(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists():
            self.skipTest('Local research specimen is not distributed')
        image, _ = audit_integrity.build(original.read_bytes())
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '46be83575f28161ff3a851604d476070220a4a4970c7b5343622bf31b55ddc6b')
        self.assertEqual(self.run_update(image), image)

    def test_mt1959_updates_only_enabled_tag(self):
        image = bytearray(0x10600)
        image[0x10400:0x10400 + 16 * 28] = b'\xff' * (16 * 28)
        data = bytes(range(32))
        image[0x10000:0x10020] = data
        struct.pack_into('<3L16s', image, 0x10400, 1, 0x10000, 0x1001f, bytes(16))
        expected = bytearray(image)
        key = bytes.fromhex('BD209408E35E526A36235234434FE8AB')
        tag = CMAC.new(key, data[:16][::-1] + data[16:][::-1], ciphermod=AES).digest()
        expected[0x1040c:0x1041c] = tag[::-1]
        self.assertEqual(self.run_update(image), expected)


if __name__ == '__main__':
    unittest.main()
