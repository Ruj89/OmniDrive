"""Set the native MT1939 word sums of a BW-12B1LT 1.03 image instead of a CMAC.

The image is recognized by its identification string, not by its filename.
The main sum covers [0x10000, 0x1cfdf8) and is stored at 0x1cfff8; the profile
sum covers [0x1d0000, 0x1dfff8) and is stored at 0x1dfff8. Both are verified by
the native update loader (see LOADER_ACCEPTANCE.md).
"""
from pathlib import Path
import struct

IDENTITY = b'ASUS    BW-12B1LT       1.032011/04/18 21:15    '
IDENTITY_OFFSET = 0x1c6f40
SUMS = ((0x10000, 0x1cfdf8, 0x1cfff8), (0x1d0000, 0x1dfff8, 0x1dfff8))


def word_sum(image, start, end):
    return sum(w[0] for w in struct.iter_unpack('<I', image[start:end])) & 0xffffffff


def finalize(image):
    image = bytearray(image)
    for start, end, offset in SUMS:
        struct.pack_into('<I', image, offset, word_sum(image, start, end))
    return bytes(image)


def finalize_if_native(path):
    path = Path(path)
    image = path.read_bytes()
    if len(image) != 0x200000 or image[IDENTITY_OFFSET:IDENTITY_OFFSET + len(IDENTITY)] != IDENTITY:
        return False
    path.write_bytes(finalize(image))
    print('MT1939 image: native word sums set; MT1959 CMAC skipped')
    return True
