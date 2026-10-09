#!/usr/bin/env python3
# Purpose: Map firmware signatures, functions, and references for offline reverse engineering.
"""Reproducible, offline reconnaissance of the known BW-12B1LT image.

Signature matches and linear-sweep references are leads, not patch addresses.
Capstone and Unicorn are needed only in the research Python environment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_SP)

IMAGE_SHA256 = "c0a5d073ccfce917712a459b73bff51bcf42bf41ee0703575c0408a59828f84d"
SIGNATURES = {
    # Selected comments in asm/ASUS_BW-16D1HT_3.02.asm. Short patterns are
    # inherently ambiguous even when they happen to match only once.
    "ChangeDiscRWMode": "10 b5 04 00 00 20",
    "ReadDiscData": "f3 b5 c8 20",
    "ReadCDDA": "f0 b5 ?? 48 8d b0",
    "SetCDType": "03 00 07 22 17 48 12 02 00 b5",
    "ReadDVDRAMData": "f1 b5 00 26 00 22",
    "ReadDiscStructMemDWORD": "09 68 12 68 89 18",
    "ReturnSense": "00 04 00 23 18 43 09 02 08 43 ?? 49 10 43 08 60 70 47",
}


def signature_hits(image, pattern):
    regex = b"".join(b"." if token == "??" else re.escape(bytes.fromhex(token))
                     for token in pattern.split())
    return [m.start() for m in re.finditer(regex, image, re.S) if m.start() % 2 == 0]


def disassemble(image, start, end, thumb=True):
    engine = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    return [f"{i.address:08x}: {i.bytes.hex():10} {i.mnemonic} {i.op_str}"
            for i in engine.disasm(image[start:end], start)]


def emulate_cd_type(image):
    """Execute the original candidate with synthetic registers and MMIO.

    Nothing accesses real hardware. Keep the switch helper and inline table
    intact; mapping instructions as executable is not a whole-drive model.
    """
    observations = []
    for initial in (0, 0xffffffff, 0xa5a5a5a5):
        for kind in range(8):
            for subq in (0, 1, 2):
                cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
                cpu.mem_map(0, 0x200000)
                cpu.mem_write(0, image)
                cpu.mem_map(0x02000000, 0x10000)  # synthetic stack
                cpu.mem_map(0x04050000, 0x1000)  # synthetic MMIO
                cpu.mem_map(0x03000000, 0x1000)  # return sentinel
                cpu.mem_write(0x04050060, struct.pack("<I", initial))
                cpu.reg_write(UC_ARM_REG_SP, 0x0200fff0)
                cpu.reg_write(UC_ARM_REG_LR, 0x03000001)
                cpu.reg_write(UC_ARM_REG_R0, kind)
                cpu.reg_write(UC_ARM_REG_R1, subq)
                writes = []

                def track_write(uc, access, address, size, value, data):
                    if not 0x02000000 <= address < 0x02010000:
                        writes.append({"address": address, "size": size, "value": value})

                cpu.hook_add(UC_HOOK_MEM_WRITE, track_write)
                cpu.emu_start(0x1bd8d9, 0x03000000, count=300)
                final = struct.unpack("<I", cpu.mem_read(0x04050060, 4))[0]
                if cpu.reg_read(UC_ARM_REG_PC) != 0x03000000:
                    raise ValueError("SetCDType candidate failed to return within 300 instructions")
                if any(w["address"] != 0x04050060 or w["size"] != 4 for w in writes):
                    raise ValueError("Unexpected non-stack write in SetCDType candidate")
                if (initial ^ final) & ~0xf00:
                    raise ValueError("Unexpected register bits modified")
                observations.append({"type_argument": kind, "subq_argument": subq,
                                     "initial": initial, "final": final, "writes": writes})
    return {"cases": len(observations), "all_returned": True,
            "non_stack_write_address": 0x04050060,
            "only_bits_8_to_11_changed": True, "observations": observations,
            "limitation": "Synthetic MMIO only; optical behavior and MT1959 equivalence unverified."}


def analyze(image):
    digest = hashlib.sha256(image).hexdigest()
    if len(image) != 0x200000 or digest != IMAGE_SHA256:
        raise ValueError("This map is scoped to the validated BW-12B1LT 1.03 specimen")
    signatures = {name: {"pattern": pattern, "hits": signature_hits(image, pattern),
                         "status": "candidate only"}
                  for name, pattern in SIGNATURES.items()}
    # This compatibility-looking header must NOT be passed to update_cmac.py:
    # interpreting a non-FFFFFFFF flag as 'enabled' produces an invalid range.
    descriptors = []
    for index in range(16):
        offset = 0x10400 + 28 * index
        flag, start, end, tag = struct.unpack_from("<III16s", image, offset)
        descriptors.append({"index": index, "offset": offset, "flag": flag,
                            "start": start, "end_inclusive": end, "tag_hex": tag.hex(),
                            "range_inside_image": 0 <= start <= end < len(image),
                            "interpretation": "CMAC-like layout; semantics not established"})

    references = {"ChangeDiscRWMode": [], "SetCDType": [], "cdb_candidate": []}
    targets = {0x45b8a: "ChangeDiscRWMode", 0x1bd8d8: "SetCDType"}
    engine = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    engine.skipdata = True
    for address, size, mnemonic, operands in engine.disasm_lite(image[0x19000:0x1d0000], 0x19000):
        if mnemonic in ("bl", "blx") and operands.startswith("#0x"):
            name = targets.get(int(operands[1:], 16))
            if name:
                references[name].append(address)
        if size == 2:
            word = int.from_bytes(image[address:address + 2], "little")
            if word & 0xf800 == 0x4800:
                literal = ((address + 4) & ~3) + (word & 255) * 4
                if literal + 4 <= len(image) and struct.unpack_from("<I", image, literal)[0] == 0x02000d20:
                    references["cdb_candidate"].append(address)
    # Linear sweep deliberately includes data; reference counts are search
    # aids, not confirmed call-graph edges.
    runs = {}
    for value in (0, 255):
        found = [(m.start() + 0x10000, m.end() - m.start())
                 for m in re.finditer(bytes([value]) + b"{256,}", image[0x10000:0x1d0000])]
        runs[f"0x{value:02x}"] = [{"offset": a, "size": n}
                                   for a, n in sorted(found, key=lambda r: r[1], reverse=True)[:8]]
    return {"image_sha256": digest, "image_size": len(image),
            "patch_ready": False, "signature_source": "asm/ASUS_BW-16D1HT_3.02.asm comments",
            "signatures": signatures, "linear_sweep_references": references,
            "references_warning": "May include decoded data; confirm each reference with control flow.",
            "cdb_candidate": {"address": 0x02000d20,
                              "evidence": [0x17e086, 0x17e094, 0x18a7f2, 0x1da1e],
                              "status": "strong static evidence; runtime ABI unverified"},
            "media_type_candidate": {"address": 0x01ffabf0, "evidence": [0x17e0ee, 0x17e124],
                                     "status": "static candidate; all disc-type encodings unverified"},
            "header_descriptors": descriptors, "uniform_runs_not_proven_free": runs,
            "cd_type_emulation": emulate_cd_type(image)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory; never overwritten")
    args = parser.parse_args()
    image = args.image.read_bytes()
    report = analyze(image)
    sections = [
        ("Main vectors (ARM; targets follow as data)", 0x10000, 0x10020, False),
        ("Reset entry (ARM)", 0x1bb8e0, 0x1bba50, False),
        ("Switch helper (ARM)", 0x1b9b0c, 0x1b9b24, False),
        ("ChangeDiscRWMode candidate, before inline table", 0x45b8a, 0x45b9a, True),
        ("ChangeDiscRWMode candidate, switch arms", 0x45ba8, 0x45bde, True),
        ("SetCDType candidate, before inline table", 0x1bd8d8, 0x1bd8e6, True),
        ("SetCDType candidate, switch arms", 0x1bd8ee, 0x1bd93c, True),
        ("Read CDB validation candidate", 0x17e084, 0x17e15c, True),
        ("CD selection caller", 0x18a7f2, 0x18a846, True),
    ]
    listing = ["OFFLINE RESEARCH: addresses are file offsets under identity mapping.",
               "These excerpts do not constitute a verified patch profile.\n"]
    for title, start, end, thumb in sections:
        listing.append(title)
        listing.extend(disassemble(image, start, end, thumb))
        listing.append("")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "map.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output_dir / "disassembly.txt").write_text("\n".join(listing) + "\n")
    print(f"Research map: {args.output_dir / 'map.json'}")
    print(f"Original SetCDType candidate: {report['cd_type_emulation']['cases']} emulated cases returned")
    print("patch_ready: false")


if __name__ == "__main__":
    main()
