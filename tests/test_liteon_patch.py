import importlib.util
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch as mock_patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/liteon"))
spec = importlib.util.spec_from_file_location("audit_integrity", ROOT / "tools/liteon/audit_integrity.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class InquiryPatchTests(unittest.TestCase):
    def test_missing_armips_is_reported(self):
        with mock_patch.object(patch.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(ValueError, "armips is required"):
                patch.assemble(bytes(0x200000))

    def test_rejects_unknown_images(self):
        for image in (b"", bytes(0x200000)):
            with self.assertRaises(ValueError):
                patch.build(image)

    def test_checksum_wraparound(self):
        image = bytearray(0x200000)
        struct.pack_into("<II", image, patch.MAIN_START, 0xffffffff, 2)
        struct.pack_into("<I", image, patch.CHECKSUM_OFFSET, 123)
        self.assertEqual(patch.word_sum(image), 1)

    def test_native_checksum_excludes_padding_and_wraps(self):
        image = bytearray(0x200000)
        struct.pack_into('<II', image, patch.MAIN_START, 0xffffffff, 2)
        self.assertEqual(patch.native_word_sum(image), 1)
        image[patch.MAIN_SUM_END:patch.CHECKSUM_OFFSET] = b'\xff' * 512
        self.assertEqual(patch.native_word_sum(image), 1)
        self.assertEqual(patch.word_sum(image), (1 - 128) & 0xffffffff)

    def test_exact_specimen_patch_and_preservation(self):
        path = ROOT / "firmware/ASUS_BW-12B1LT_1.03.bin"
        if not path.exists():
            self.skipTest("Local research specimen is not distributed with the repository")
        original = path.read_bytes()
        modified, report = patch.build(original)
        # Pin the previous Python-generated image independently of the assembler.
        self.assertEqual(hashlib.sha256(modified).hexdigest(),
                         "46be83575f28161ff3a851604d476070220a4a4970c7b5343622bf31b55ddc6b")
        self.assertEqual(len(modified), len(original))
        self.assertEqual(modified[patch.PATCH_OFFSET:patch.PATCH_OFFSET + 4], bytes.fromhex("5e203080"))
        self.assertEqual(modified[:patch.MAIN_START], original[:patch.MAIN_START])
        self.assertEqual(modified[patch.MAIN_END:], original[patch.MAIN_END:])
        self.assertEqual(modified[0x10400:0x1048c], original[0x10400:0x1048c])
        self.assertFalse(report['flash_ready'])
        self.assertEqual(patch.native_word_sum(modified),
                         struct.unpack_from('<I', modified, patch.CHECKSUM_OFFSET)[0])
        self.assertEqual((struct.unpack_from('<I', modified, patch.CHECKSUM_OFFSET)[0]
                          - patch.word_sum(modified)) & 0xffffffff, 0x80)
        self.assertEqual({int(c['offset'], 16) for c in report['changes']},
                         {patch.PATCH_OFFSET, patch.CHECKSUM_OFFSET + 2})
        with self.assertRaises(ValueError):
            patch.build(modified)


if __name__ == "__main__":
    unittest.main()
