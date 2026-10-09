#!/usr/bin/env python3
# Purpose: Compare the pinned firmware images and audit decoded flash readbacks offline.
"""Audit original/experimental files and an optional restored readback offline."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import re
import subprocess
import tempfile
import sys

from read_flash import ReadError
from validate_flash import checksum, validate

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
    return validate_assembly(image, patched)


def validate_assembly(image, patched):
    if (len(patched) != len(image)
            or patched[PATCH_OFFSET:PATCH_OFFSET + 2] != bytes.fromhex("5e20")
            or patched[:PATCH_OFFSET] != image[:PATCH_OFFSET]
            or patched[PATCH_OFFSET + 2:CHECKSUM_OFFSET] != image[PATCH_OFFSET + 2:CHECKSUM_OFFSET]
            or patched[CHECKSUM_OFFSET + 4:] != image[CHECKSUM_OFFSET + 4:]
            or struct.unpack_from("<I", patched, CHECKSUM_OFFSET)[0] != native_word_sum(patched)):
        raise ValueError("Unexpected armips output; expected INQUIRY-94 and its LiteOn checksum")
    return bytearray(patched)


def native_word_sum(image):
    """WRITE BUFFER sums LE32 words up to 0x1cfdf8, excluding 512-byte padding."""
    return sum(w[0] for w in struct.iter_unpack(
        "<I", image[MAIN_START:MAIN_SUM_END])) & 0xffffffff


def word_sum(image):
    return sum(w[0] for w in struct.iter_unpack(
        "<I", image[MAIN_START:CHECKSUM_OFFSET])) & 0xffffffff


def build(image, assembled_image=None):
    if len(image) != 0x200000 or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Expected the exact, unmodified decoded BW-12B1LT 1.03 specimen")
    if image[PATCH_OFFSET:PATCH_OFFSET + 4] != bytes.fromhex("60203080"):
        raise ValueError("Unexpected INQUIRY instructions")
    stored = struct.unpack_from("<I", image, CHECKSUM_OFFSET)[0]
    if stored != native_word_sum(image) or image[MAIN_SUM_END:CHECKSUM_OFFSET] != b'\xff' * 512:
        raise ValueError("Main checksum or excluded padding differs from the native layout")
    patched = (assemble(image) if assembled_image is None
               else validate_assembly(image, assembled_image))
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
        "unresolved": ["This build manifest alone does not validate hardware flashing.",
                       "Hardware acceptance evidence must be reviewed separately for this exact specimen/image."],
    }


REGIONS = (("boot", 0, 0x10000), ("main", 0x10000, 0x1d0000),
           ("profile", 0x1d0000, 0x1e0000), ("reserved_1", 0x1e0000, 0x1f0000),
           ("reserved_2", 0x1f0000, 0x200000))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compare_readback(original, readback):
    if len(readback) != len(original):
        raise ReadError("Restored decoded readback has a different size")
    regions = {name: original[start:end] == readback[start:end]
               for name, start, end in REGIONS}
    return {"sha256": digest(readback), "byte_identical_to_original": readback == original,
            "regions_identical": regions,
            "changed_byte_count": sum(a != b for a, b in zip(original, readback))}


def audit(directory, original, experimental, readback_directory=None, readback_image=None):
    if digest(original) != IMAGE_SHA256:
        raise ReadError("Integrity baseline is not the pinned original specimen")
    report_bytes = (directory / "report.json").read_bytes()
    raw1 = (directory / "flash1.raw.bin").read_bytes()
    raw2 = (directory / "flash2.raw.bin").read_bytes()
    baseline = validate(raw1, raw2, original, json.loads(report_bytes))
    if not baseline["offline_structure_consistent"]:
        raise ReadError("Original backup failed structural validation")
    expected, manifest = build(original)
    if experimental != expected:
        raise ReadError("Experimental image differs from the exact OmniDrive build")
    regions = []
    for name, start, end in REGIONS:
        regions.append({"name": name, "start": start, "end_exclusive": end,
                        "original_sha256": digest(original[start:end]),
                        "experimental_sha256": digest(experimental[start:end]),
                        "unchanged": original[start:end] == experimental[start:end]})
    records = []
    for index in range(16):
        offset = 0x10400 + index * 28
        flag, start, end = struct.unpack_from("<III", original, offset)
        records.append({"offset": offset, "flag": flag, "start": start,
                        "end_inclusive": end, "tag_hex": original[offset + 12:offset + 28].hex()})
    result = {
        "original_validation": baseline,
        "backup_files": {"flash1.raw.bin": digest(raw1), "flash2.raw.bin": digest(raw2),
                         "report.json": digest(report_bytes), "decoded_original": digest(original)},
        "experimental_sha256": digest(experimental), "exact_patch_matches": True,
        "changes": manifest["changes"], "regions": regions,
        "integrity_header_unchanged": original[0x10400:0x105c0] == experimental[0x10400:0x105c0],
        "integrity_records": records,
        "experimental_checksums": {name: checksum(experimental, start, end)
                                   for name, start, end in REGIONS[:3]},
        "offline_integrity_consistent": True,
        "restore_readback_verified": False,
        "flash_ready": False,
        "unresolved": [
            "Run verify_loader.py separately for native update-input acceptance evidence.",
            "This offline file audit alone does not establish physical write/erase completion or preservation.",
            "Hardware trial evidence requires separate review.",
        ],
    }
    if (readback_directory is None) != (readback_image is None):
        raise ReadError("Supply both a restored dump directory and its decoded image")
    if readback_directory is not None:
        restored = readback_image.read_bytes()
        validation = validate((readback_directory / "flash1.raw.bin").read_bytes(),
                              (readback_directory / "flash2.raw.bin").read_bytes(), restored,
                              json.loads((readback_directory / "report.json").read_text()))
        comparison = compare_readback(original, restored)
        comparison["validation"] = validation
        result["restored_readback"] = comparison
        result["restore_readback_verified"] = (
            validation["offline_structure_consistent"] and comparison["byte_identical_to_original"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Original two raw reads and report.json")
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--experimental", type=Path, required=True)
    parser.add_argument("--readback-directory", type=Path)
    parser.add_argument("--readback-image", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New JSON report; never overwritten")
    args = parser.parse_args()
    try:
        result = audit(args.directory, args.original.read_bytes(), args.experimental.read_bytes(),
                       args.readback_directory, args.readback_image)
        with args.output.open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(f"Offline integrity consistent; report: {args.output}")
        if args.readback_directory is not None:
            print(f"Restored readback identical: {result['restore_readback_verified']}")
            return 0 if result["restore_readback_verified"] else 1
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError) as error:
        print(f"Audit stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
