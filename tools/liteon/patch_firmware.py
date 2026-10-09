#!/usr/bin/env python3
"""Build the specimen-specific ASUS BW-12B1LT 1.03 OmniDrive firmware."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

IMAGE_SHA256 = "c0a5d073ccfce917712a459b73bff51bcf42bf41ee0703575c0408a59828f84d"
PATCH_OFFSET = 0x9cb76
MAIN_START = 0x10000
MAIN_END = 0x1d0000
CHECKSUM_OFFSET = MAIN_END - 8
MAIN_SUM_END = CHECKSUM_OFFSET - 0x200
ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_NAME = "ASUS_BW-12B1LT_1.03"
PATCH_ASM = ROOT / "asm" / (FIRMWARE_NAME + ".asm")
VERSION_ASM = ROOT / "asm/version.asm"


def output_name():
    version = VERSION_ASM.read_text()
    components = []
    for part in ("Major", "Minor", "Patch"):
        match = re.search(rf"^Version{part}\s+equ\s+(\d+)\s*$", version, re.MULTILINE)
        if match is None:
            raise ValueError(f"Missing Version{part} in {VERSION_ASM}")
        components.append(match.group(1))
    return FIRMWARE_NAME + "_OmniDrive-" + ".".join(components) + ".bin"


def assemble(image):
    """Run armips in isolation; never expose the user's input file for writing."""
    with tempfile.TemporaryDirectory(prefix="omnidrive-") as directory:
        work = Path(directory)
        for name in ("asm", "firmware", "patched_firmware"):
            (work / name).mkdir()
        (work / "firmware" / (FIRMWARE_NAME + ".bin")).write_bytes(image)
        (work / "asm" / PATCH_ASM.name).write_bytes(PATCH_ASM.read_bytes())
        (work / "asm/version.asm").write_bytes(VERSION_ASM.read_bytes())
        try:
            result = subprocess.run(["armips", PATCH_ASM.name], cwd=work / "asm",
                                    capture_output=True, text=True, check=False)
        except FileNotFoundError as error:
            raise ValueError("armips is required; install it and add it to PATH") from error
        if result.returncode:
            raise ValueError(f"armips failed: {result.stdout}{result.stderr}")
        patched = (work / "patched_firmware" / output_name()).read_bytes()
    if (len(patched) != len(image)
            or patched[PATCH_OFFSET:PATCH_OFFSET + 2] != bytes.fromhex("5e20")
            or patched[:PATCH_OFFSET] != image[:PATCH_OFFSET]
            or patched[PATCH_OFFSET + 2:] != image[PATCH_OFFSET + 2:]):
        raise ValueError("Unexpected armips output; expected only Thumb movs r0, #94")
    return bytearray(patched)


def native_word_sum(image):
    """WRITE BUFFER sums LE32 words up to 0x1cfdf8, excluding 512-byte padding."""
    return sum(w[0] for w in struct.iter_unpack(
        "<I", image[MAIN_START:MAIN_SUM_END])) & 0xffffffff


def word_sum(image):
    return sum(w[0] for w in struct.iter_unpack(
        "<I", image[MAIN_START:CHECKSUM_OFFSET])) & 0xffffffff


def build(image):
    if len(image) != 0x200000 or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Expected the exact, unmodified decoded BW-12B1LT 1.03 specimen")
    if image[PATCH_OFFSET:PATCH_OFFSET + 4] != bytes.fromhex("60203080"):
        raise ValueError("Unexpected INQUIRY instructions")
    stored = struct.unpack_from("<I", image, CHECKSUM_OFFSET)[0]
    if stored != native_word_sum(image) or image[MAIN_SUM_END:CHECKSUM_OFFSET] != b'\xff' * 512:
        raise ValueError("Main checksum or excluded padding differs from the native layout")
    patched = assemble(image)
    struct.pack_into("<I", patched, CHECKSUM_OFFSET, native_word_sum(patched))
    changes = [{"offset": f"0x{i:06x}", "before": f"{a:02x}", "after": f"{b:02x}"}
               for i, (a, b) in enumerate(zip(image, patched)) if a != b]
    if any(int(c["offset"], 16) not in {PATCH_OFFSET, *range(CHECKSUM_OFFSET, CHECKSUM_OFFSET + 4)}
           for c in changes):
        raise ValueError("Unexpected bytes changed")
    return bytes(patched), {
        "experiment": "Standard INQUIRY maximum length 96 -> 94 bytes",
        "assembler": "armips",
        "assembly_source": "asm/" + PATCH_ASM.name,
        "output_file": output_name(),
        "input_sha256": IMAGE_SHA256,
        "output_sha256": hashlib.sha256(patched).hexdigest(),
        "size": len(patched), "changes": changes,
        "instruction_before": "movs r0, #0x60",
        "instruction_after": "movs r0, #0x5e",
        "main_checksum_before": f"0x{stored:08x}",
        "main_checksum_after": f"0x{struct.unpack_from('<I', patched, CHECKSUM_OFFSET)[0]:08x}",
        "main_checksum_algorithm": "LE32 sum modulo 2^32, [0x10000,0x1cfdf8), stored at 0x1cfff8",
        "flash_ready": False,
        "unresolved": ["This build manifest alone does not validate hardware flashing or recovery.",
                       "Hardware acceptance evidence must be reviewed separately for this exact specimen/image."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, nargs="?",
                        default=ROOT / "firmware" / (FIRMWARE_NAME + ".bin"),
                        help="Original decoded image, never a raw/encrypted dump")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "patched_firmware",
                        help="Output directory (default: patched_firmware)")
    args = parser.parse_args()
    try:
        patched, report = build(args.image.read_bytes())
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = args.output_dir / output_name()
        if output.resolve() == args.image.resolve():
            raise ValueError("Output must not overwrite the original firmware")
        output.write_bytes(patched)
        output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"OmniDrive firmware: {output}; flash_ready=false")
        return 0
    except (OSError, ValueError) as error:
        print(f"Patch stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
