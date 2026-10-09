#!/usr/bin/env python3
# Purpose: Check decoded flash structure, checksums, partition layout, and read consistency.
"""Validate a decoded dump offline, without changing images or accessing SATA."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from decode_flash import decode, parameters
from read_flash import ReadError


def checksum(image, start, end):
    """Observed trailer layout: additive LE32 sum, then a four-byte marker."""
    if start % 4 or end % 4 or end - start < 8 or end > len(image):
        raise ReadError("Invalid checksum region")
    calculated = sum(word[0] for word in struct.iter_unpack("<I", image[start:end - 8])) & 0xffffffff
    stored = struct.unpack_from("<I", image, end - 8)[0]
    return {"start": start, "end_exclusive": end,
            "calculated_le32_sum": calculated, "stored": stored,
            "delta": (stored - calculated) & 0xffffffff,
            "trailer_hex": image[end - 8:end].hex()}


def partition_table(inquiry, size):
    if len(inquiry) < 0x74:
        raise ReadError("No partition descriptor table")
    count = inquiry[0x73]
    if count != 4 or 0x74 + count * 8 > len(inquiry):
        raise ReadError("Unsupported partition descriptor table")
    regions = []
    for index in range(count):
        entry = inquiry[0x74 + index * 8:0x7c + index * 8]
        # Two-byte LE id, three-byte BE start, three-byte BE inclusive end.
        identifier = int.from_bytes(entry[:2], "little")
        start = int.from_bytes(entry[2:5], "big")
        end = int.from_bytes(entry[5:8], "big") + 1
        if not 0 <= start < end <= size:
            raise ReadError("Partition descriptor outside the flash")
        regions.append({"id": identifier, "start": start, "end_exclusive": end})
    ordered = sorted(regions, key=lambda r: r["start"])
    if len({r["id"] for r in ordered}) != count:
        raise ReadError("Duplicate partition identifiers")
    if any(a["end_exclusive"] > b["start"] for a, b in zip(ordered, ordered[1:])):
        raise ReadError("Overlapping partition descriptors")
    # This validation profile is intentionally limited to the observed target.
    expected = [(0, 0, 0x10000), (3, 0x1d0000, 0x1e0000),
                (1, 0x1e0000, 0x1f0000), (2, 0x1f0000, 0x200000)]
    if [(r["id"], r["start"], r["end_exclusive"]) for r in ordered] != expected:
        raise ReadError("Partition layout differs from the researched ASUS profile")
    return ordered


def validate(raw1, raw2, image, report, reference=None):
    key, iv, valid_length = parameters(report, raw1)
    if raw1 != raw2:
        raise ReadError("Raw reads differ")
    if decode(raw1, key, iv) != image:
        raise ReadError("Decoded image differs from a fresh decode of the raw read")
    inquiry = bytes.fromhex(report["extended_inquiry_hex"])[:valid_length]
    regions = partition_table(inquiry, len(image))
    if len(image) != 0x200000:
        raise ReadError("This validation profile requires a 2 MiB image")
    checksums = {"boot": checksum(image, 0, 0x10000),
                 "main": checksum(image, 0x10000, 0x1d0000),
                 "profile_data": checksum(image, 0x1d0000, 0x1e0000)}
    native_main_sum = sum(word[0] for word in struct.iter_unpack(
        '<I', image[0x10000:0x1cfdf8])) & 0xffffffff
    vectors = list(struct.unpack_from("<8I", image, 0x10000))
    expected_vectors = [0xe59ff018] * 5 + [0xe1a00000, 0xe59ff014, 0xe59ff014]
    literals = list(struct.unpack_from("<7I", image, 0x10020))
    boot_id = image[0x3000:0x3014].decode("ascii", errors="replace")
    main_id = image[0x1c6f40:0x1c6f78].decode("ascii", errors="replace")
    checks = {
        "raw_reads_identical": True,
        "fresh_decode_matches_file": True,
        "partition_layout_consistent": True,
        "boot_additive_checksum_matches": checksums["boot"]["delta"] == 0,
        "profile_additive_checksum_matches": checksums["profile_data"]["delta"] == 0,
        "main_native_checksum_matches": native_main_sum == checksums["main"]["stored"],
        "arm_exception_vectors_match": vectors == expected_vectors,
        "vector_targets_inside_flash": all(0 <= v < len(image) for v in literals),
        "boot_identifier_matches": boot_id == "12B2S  Boot Code0A24",
        "main_identifier_matches_inquiry": image[0x1c6f40:0x1c6f78] == inquiry[8:64],
        "mt1939_boot_markers_present": all(image.find(b"MT1939 Boot Code", start, end) >= 0
                                          for start, end in ((0, 0x10000), (0x10000, 0x1d0000))),
        "profile_model_matches": image[0x1d0000:0x1d0010] == inquiry[16:32],
        "profile_trailer_marker_matches": image[0x1dfffc:0x1e0000] == b"PLDS",
        "unused_tail_erased": image[0x1e0000:] == b"\xff" * 0x20000,
    }
    result = {"size": len(image), "decoded_sha256": hashlib.sha256(image).hexdigest(),
              "checks": checks, "partition_descriptors": regions, "checksums": checksums,
              "native_main_checksum": {"start": 0x10000, "end_exclusive": 0x1cfdf8,
                                       "stored_at": 0x1cfff8, "calculated": native_main_sum},
              "boot_identifier": boot_id, "main_identifier": main_id,
              "arm_vectors": vectors, "vector_targets": literals,
              "offline_structure_consistent": all(checks.values()),
              "flash_ready": False,
              "unresolved": [
                  "Structure checks alone do not validate restoration or physical preservation of drive-specific regions.",
                  "No byte-identical official ASUS image is available for comparison.",
              ]}
    if reference is not None:
        if len(reference) != len(image):
            raise ReadError("Reference has a different size; incomplete downloads are rejected")
        reference_sums = {name: checksum(reference, region["start"], region["end_exclusive"])
                          for name, region in checksums.items()}
        result["reference"] = {
            "identity": "Lite-On iHBS112 2 PL06 (different model; structural comparison only)",
            "sha256": hashlib.sha256(reference).hexdigest(),
            "checksums": reference_sums,
            "first_0x3000_equal_bytes": sum(a == b for a, b in zip(image[:0x3000], reference[:0x3000])),
            "main_checksum_convention_matches": reference_sums["main"]["delta"] == checksums["main"]["delta"] == 0x80,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory containing both raw files and report.json")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate((args.directory / "flash1.raw.bin").read_bytes(),
                          (args.directory / "flash2.raw.bin").read_bytes(), args.image.read_bytes(),
                          json.loads((args.directory / "report.json").read_text()),
                          args.reference.read_bytes() if args.reference else None)
        with args.output.open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0 if result["offline_structure_consistent"] else 1
    except (OSError, ValueError, KeyError, ReadError, ImportError) as error:
        print(f"Validation stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
