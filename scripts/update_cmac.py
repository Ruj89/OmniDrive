import argparse
import hashlib
from pathlib import Path
import struct
import sys

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

MT1959_CMAC_KEY = bytes.fromhex('BD209408E35E526A36235234434FE8AB')
cmac_range_fmt = '<3L16s'
cmac_range_size = struct.calcsize(cmac_range_fmt)

parser = argparse.ArgumentParser()
parser.add_argument("firmware_file")
args = parser.parse_args()

# This exact LiteOn INQUIRY-94 image already has its native checksum set by
# armips. Its header must not be interpreted as an MT1959 CMAC table.
LITEON_INQUIRY94_SHA256 = '46be83575f28161ff3a851604d476070220a4a4970c7b5343622bf31b55ddc6b'
if hashlib.sha256(Path(args.firmware_file).read_bytes()).hexdigest() == LITEON_INQUIRY94_SHA256:
    print('LiteOn INQUIRY-94 image: native checksum already set; skipping MT1959 CMAC')
    sys.exit(0)

def calc_cmac(cmac_struct):
    enabled, start, end, original_cmac = struct.unpack(cmac_range_fmt, cmac_struct)

    if enabled == 0xFFFFFFFF:
        return None

    firmware_file.seek(start)
    cmac_range = bytearray(firmware_file.read(end - start + 1))
    
    # Reverse
    for i in range(0, len(cmac_range), 16):
        cmac_block = cmac_range[i:i+16]
        cmac_range[i:i+16] = cmac_block[::-1]

    cmac = CMAC.new(MT1959_CMAC_KEY, cmac_range, ciphermod=AES)
    print("CMAC for block starting at 0x{:X} ending at 0x{:X}: {}".format(start, end, cmac.hexdigest()))
    return cmac.digest()


with open(args.firmware_file, 'r+b') as firmware_file:
    firmware_file.seek(0x10400)
    cmac_ranges = firmware_file.read(cmac_range_size * 16)

    for i in range(0, 16):
        cmac_struct = cmac_ranges[i*cmac_range_size:i*cmac_range_size+cmac_range_size]
        cmac = calc_cmac(cmac_struct)
        if cmac is not None:
            cmac = bytearray(cmac)
            cmac.reverse()
            firmware_file.seek(0x10400 + i*cmac_range_size + 12)
            firmware_file.write(cmac)
    

        
    firmware_file.close()
