#!/usr/bin/env python3
"""Offline extraction of read CDBs from one known Flash Utility binary.

Optional research dependencies: pefile, unicorn. Never invokes Windows APIs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SHA256 = "34dd3c6a21be113fc30bfd0514647d1e2c6fe192263e49dea9c70410cf19f9f3"


def analyze(path):
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP

    binary = path.read_bytes()
    if hashlib.sha256(binary).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Unexpected binary: addresses apply only to the documented SHA-256")
    pe = pefile.PE(data=binary)
    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    emulator.mem_map(0x400000, 0x200000)
    emulator.mem_write(0x400000, pe.get_memory_mapped_image())
    emulator.mem_map(0x800000, 0x100000)
    emulator.reg_write(UC_X86_REG_ESP, 0x8ff000)
    # Stop after decompression and branch relocation, before import resolution.
    emulator.emu_start(0x54e790, 0x54e8be, timeout=20000000, count=20000000)
    if emulator.reg_read(UC_X86_REG_EIP) != 0x54e8be:
        raise ValueError("Decompression did not reach the expected boundary")
    vectors = []

    def capture(uc, address, size, unused):
        if address != 0x40afe4:
            return
        stack = uc.reg_read(UC_X86_REG_ESP)
        _, drive, cdb, cdb_length, buffer, length, direction = struct.unpack(
            "<7I", uc.mem_read(stack, 28))
        vectors.append({"cdb": bytes(uc.mem_read(cdb, cdb_length)).hex(),
                        "length": length, "direction": direction})
        uc.emu_stop()

    hook = emulator.hook_add(UC_HOOK_CODE, capture, begin=0x40afe4, end=0x40afe4)
    for name, function in (("df83", 0x40259c), ("buffer-f0", 0x402618)):
        for offset in (0, 0x80, 0x123400, 0x1fff80):
            emulator.reg_write(UC_X86_REG_ESP, 0x8ff000)
            emulator.mem_write(0x8ff000, struct.pack("<4I", 0, 0x880000, 0x881000, offset))
            before = len(vectors)
            emulator.emu_start(function, 0x40b043, timeout=1000000, count=1000)
            if len(vectors) != before + 1:
                raise ValueError("Read routine did not reach transport boundary")
            vectors[-1].update(protocol=name, offset=offset)
    emulator.hook_del(hook)
    # Synthetic data only: this captures the original decoder's result without
    # embedding any user's drive serial or firmware in the test evidence.
    raw = bytes(range(128))
    key = bytes(range(16))
    iv = bytes(range(32, 48))
    emulator.mem_write(0x880000, raw)
    emulator.mem_write(0x881000, key)
    emulator.mem_write(0x882000, iv)
    emulator.mem_write(0x8ff000, struct.pack("<6I", 0x890000, 0x880000,
                                           0x883000, 128, 0x881000, 0x882000))
    emulator.reg_write(UC_X86_REG_ESP, 0x8ff000)
    emulator.emu_start(0x403eb4, 0x890000, timeout=10000000, count=5000000)
    if emulator.reg_read(UC_X86_REG_EIP) != 0x890000:
        raise ValueError("Decoder did not return within the emulation limit")
    decoded = bytes(emulator.mem_read(0x883000, 128))
    return {"binary_sha256": EXPECTED_SHA256, "vectors": vectors,
            "decode_vector": {"raw": raw.hex(), "key": key.hex(), "iv": iv.hex(),
                              "decoded": decoded.hex()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.binary), indent=2))
