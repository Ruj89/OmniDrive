#!/usr/bin/env python3
"""Audit original/experimental files and an optional restored readback offline."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from patch_firmware import build, IMAGE_SHA256
from read_flash import ReadError
from validate_flash import checksum, validate

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
        raise ReadError("Recovery baseline is not the pinned original specimen")
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
        "recovery_ready": False, "flash_ready": False,
        "unresolved": [
            "Run verify_loader.py separately for native update-input acceptance evidence.",
            "This offline file audit alone does not establish physical write/erase completion or preservation.",
            "Hardware trial evidence and recovery when normal firmware stops responding require separate review.",
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
        print(f"Offline integrity consistent; recovery_ready=false; report: {args.output}")
        if args.readback_directory is not None:
            print(f"Restored readback identical: {result['restore_readback_verified']}")
            return 0 if result["restore_readback_verified"] else 1
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError) as error:
        print(f"Audit stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
