#!/usr/bin/env python3
# Purpose: Emulate integrity-record selection paths in the firmware within bounded offline runs.
"""Bounded offline execution of the specimen's integrity-record selector."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import build, IMAGE_SHA256


def run(image, selector, synthetic=False):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emulator.mem_map(0, 0x200000)
    emulator.mem_write(0, image)
    if synthetic:
        # Navigation experiment only: remove the FIRST terminator in emulated RAM.
        emulator.mem_write(0x10400, b"\0" * 4)
    emulator.mem_map(0x02000000, 0x10000)
    emulator.reg_write(UC_ARM_REG_SP, 0x0200f000)
    emulator.reg_write(UC_ARM_REG_LR, 0x02000001)
    emulator.reg_write(UC_ARM_REG_R0, selector)
    calls, logs = [], []
    instructions = 0

    def hook(uc, address, size, unused):
        nonlocal instructions
        instructions += 1
        if address in (0x26476, 0x400c0):
            # Peripheral preparation and debug output, no real hardware.
            if address == 0x400c0:
                logs.append([uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)])
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0xa18f0:
            args = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            calls.append({"start": args[0], "end_inclusive": args[1], "tag_address": args[2]})
            if not (synthetic and selector == 1):
                # Map selection without pretending to reproduce the MMIO tag engine.
                uc.reg_write(UC_ARM_REG_R0, 1)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            # Selector 1's empty range is rejected by native instructions before MMIO.

    emulator.hook_add(UC_HOOK_CODE, hook)
    emulator.emu_start(0xa19d7, 0x02000000, timeout=1000000, count=5000)
    if emulator.reg_read(UC_ARM_REG_PC) != 0x02000000:
        raise ValueError("Integrity selector did not return within the bound")
    returned = emulator.reg_read(UC_ARM_REG_R0)
    if not synthetic and (returned != 1 or calls):
        raise ValueError("Expected the original first record to terminate selection")
    if synthetic:
        expected_counts = {0: 4, 1: 1, 2: 0, 0xffffffff: 0}
        if len(calls) != expected_counts[selector] or returned != (0 if selector == 1 else 1):
            raise ValueError("Unexpected synthetic record selection")
        expected = {0: [(0x11000, 0x18fff, 0x1040c),
                        (0x1d0000, 0x1dffef, 0x10428),
                        (0x19000, 0x1cfdef, 0x10444),
                        (0x10400, 0x1046f, 0x1047c)],
                    1: [(0xffffffff, 0xffffffff, 0x10460)], 2: [], 0xffffffff: []}
        actual = [(call["start"], call["end_inclusive"], call["tag_address"]) for call in calls]
        if actual != expected[selector]:
            raise ValueError("Unexpected selected ranges or tag pointers")
        if selector == 1 and logs != [[0xf6, 0xa9], [0x5e, 3]]:
            raise ValueError("Expected native empty-range failure diagnostic")
    return {"selector": selector, "synthetic_first_flag_zero": synthetic,
            "returned": returned, "verifier_calls": calls, "debug_calls": logs,
            "instructions": instructions}


def trace(image):
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Expected the pinned unmodified decoded specimen")
    patched, _ = build(image)
    # Pin the observed call and the caller's next instruction: result overwritten.
    if image[0x1c756:0x1c75e] != bytes.fromhex("012085f03dF9" + "5948"):
        raise ValueError("Unexpected startup selector call")
    runs = []
    for name, data in (("original", image), ("experimental", patched)):
        for selector in (0, 1, 2, 0xffffffff):
            result = run(data, selector)
            result["image"] = name
            runs.append(result)
    for selector in (0, 1, 2, 0xffffffff):
        result = run(image, selector, synthetic=True)
        result["image"] = "synthetic navigation only"
        runs.append(result)
    return {"input_sha256": IMAGE_SHA256, "runs": runs,
            "selector_address": 0xa19d6, "range_verifier_address": 0xa18f0,
            "startup_call_address": 0x1c756, "startup_selector": 1,
            "first_flag_ffffffff_terminates": True,
            "observed_startup_call_checks_no_tags": True,
            "flash_ready": False,
            "limitations": ["Peripheral setup and diagnostics are stubbed.",
                            "Synthetic navigation stubs successful tag verification for selector 0.",
                            "No AES key, additive checker, other caller or loader acceptance is established."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = trace(args.image.read_bytes())
        with args.output.open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(f"12 bounded selector runs passed; report: {args.output}; flash_ready=false")
        return 0
    except (OSError, ValueError, ImportError) as error:
        print(f"Trace stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
