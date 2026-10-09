#!/usr/bin/env python3
# Purpose: Decode saved Lite-On flash reads into a firmware image using captured INQUIRY data.
"""Decode a saved Lite-On raw flash stream offline; never accesses a drive."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from read_flash import BLOCK_SIZE, ReadError, flash_metadata


def parameters(report, raw):
    if report.get("identity") != {"vendor": "ASUS", "model": "BW-12B1LT", "revision": "1.03"}:
        raise ReadError("Report is not for the expected ASUS target")
    inquiry = bytes.fromhex(report["extended_inquiry_hex"])
    if len(inquiry) < 5:
        raise ReadError("Truncated extended INQUIRY")
    # Some Linux transports return the allocation size without an accurate
    # residual. Bytes past Additional Length are padding, not the key.
    valid_length = inquiry[4] + 5
    if valid_length > len(inquiry) or valid_length < 0x83:
        raise ReadError("Invalid extended INQUIRY Additional Length")
    valid = inquiry[:valid_length]
    flash = flash_metadata(valid)
    if not flash["encoded_response"]:
        raise ReadError("This report does not select the encoded read protocol")
    if len(raw) != flash["reported_size"] or len(raw) % BLOCK_SIZE:
        raise ReadError("Raw image size disagrees with the report")
    digest = hashlib.sha256(raw).hexdigest()
    hashes = report.get("hashes", [])
    if not report.get("reads_match") or len(hashes) != 2 or any(h != digest for h in hashes):
        raise ReadError("Raw image does not match both successful read hashes")
    return valid[-16:], valid[16:32], valid_length


def decode(raw, key, iv):
    from Crypto.Cipher import AES
    if len(key) != 16 or len(iv) != 16 or len(raw) % BLOCK_SIZE:
        raise ValueError("Expected AES-128 key/IV and complete 128-byte transfer blocks")
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray(len(raw))
    # CBC resets for each 128-byte SATA response, rather than chaining across
    # the entire firmware. Decrypt first, then XOR with IV/preceding ciphertext.
    for offset in range(0, len(raw), BLOCK_SIZE):
        block = raw[offset:offset + BLOCK_SIZE]
        decrypted = cipher.decrypt(block)
        chain = iv + block[:-16]
        result[offset:offset + BLOCK_SIZE] = bytes(a ^ b for a, b in zip(decrypted, chain))
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.raw.read_bytes()
        report = json.loads(args.report.read_text())
        key, iv, valid_length = parameters(report, raw)
        decoded = decode(raw, key, iv)
        with args.output.open("xb") as output:
            output.write(decoded)
        print(json.dumps({"output": str(args.output), "size": len(decoded),
                          "sha256": hashlib.sha256(decoded).hexdigest(),
                          "inquiry_valid_length": valid_length,
                          "decoding": "AES-128-CBC, IV reset every 128 bytes",
                          "mt1939_boot_marker_present": b"MT1939 Boot Code" in decoded,
                          "asus_model_present": b"BW-12B1LT" in decoded,
                          "flash_write_validated": False}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError) as error:
        print(f"Stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
