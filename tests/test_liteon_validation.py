import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/liteon"))
import liteon_paths
for name in ("read_flash", "decode_flash", "validate_flash"):
    spec = importlib.util.spec_from_file_location(name, liteon_paths.tool(name))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
validator = sys.modules["validate_flash"]
ReadError = sys.modules["read_flash"].ReadError


class ValidationTests(unittest.TestCase):
    def test_checksum_wraparound_and_corruption(self):
        image = struct.pack("<4I", 0xffffffff, 2, 1, 0xffffffff)
        self.assertEqual(validator.checksum(image, 0, 16)["delta"], 0)
        damaged = bytearray(image)
        damaged[4] ^= 1
        self.assertNotEqual(validator.checksum(damaged, 0, 16)["delta"], 0)
        with self.assertRaises(ReadError):
            validator.checksum(image, 0, 20)

    def test_descriptor_endianness_and_bounds(self):
        inquiry = bytearray(164)
        inquiry[0x73] = 4
        for i, (tag, start, end) in enumerate(((0, 0, 0xffff), (1, 0x1e0000, 0x1effff),
                                             (2, 0x1f0000, 0x1fffff), (3, 0x1d0000, 0x1dffff))):
            inquiry[0x74 + i * 8:0x7c + i * 8] = (tag.to_bytes(2, "little") +
                                                 start.to_bytes(3, "big") + end.to_bytes(3, "big"))
        regions = validator.partition_table(inquiry, 0x200000)
        self.assertEqual(regions[1], {"id": 3, "start": 0x1d0000, "end_exclusive": 0x1e0000})
        with self.assertRaises(ReadError):
            validator.partition_table(inquiry, 0x1fffff)
        inquiry[0x7c:0x84] = inquiry[0x74:0x7c]
        with self.assertRaises(ReadError):
            validator.partition_table(inquiry, 0x200000)


if __name__ == "__main__":
    unittest.main()
