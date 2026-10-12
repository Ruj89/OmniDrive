#!/usr/bin/env python3
# Purpose: Read and save flash data from a compatible Lite-On drive over Linux SG_IO.
"""Experimental Linux Lite-On flash reader. No data-out or write commands."""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SG_IO = 0x2285
BLOCK_SIZE = 128
MAX_SIZE = 8 * 1024 * 1024  # Protocol/tool limit, not this drive's flash capacity.


class SgIoHdr(C.Structure):
    _fields_ = [
        ("interface_id", C.c_int), ("dxfer_direction", C.c_int),
        ("cmd_len", C.c_ubyte), ("mx_sb_len", C.c_ubyte),
        ("iovec_count", C.c_ushort), ("dxfer_len", C.c_uint),
        ("dxferp", C.c_void_p), ("cmdp", C.c_void_p), ("sbp", C.c_void_p),
        ("timeout", C.c_uint), ("flags", C.c_uint), ("pack_id", C.c_int),
        ("usr_ptr", C.c_void_p), ("status", C.c_ubyte),
        ("masked_status", C.c_ubyte), ("msg_status", C.c_ubyte),
        ("sb_len_wr", C.c_ubyte), ("host_status", C.c_ushort),
        ("driver_status", C.c_ushort), ("resid", C.c_int),
        ("duration", C.c_uint), ("info", C.c_uint),
    ]


class ReadError(RuntimeError):
    pass


def flash_cdb(protocol, offset):
    if offset < 0 or offset % BLOCK_SIZE or offset + BLOCK_SIZE > MAX_SIZE:
        raise ValueError("Flash offset must be aligned to 128 bytes and below 8 MiB")
    address = offset.to_bytes(3, "big")
    if protocol == "df83":
        return bytes.fromhex("df 83 00 00 ff 00") + address + bytes(3)
    if protocol == "buffer-f0":
        return bytes.fromhex("3c 01 f0") + address + bytes.fromhex("00 00 80 00 00 00")
    raise ValueError("Unknown read protocol")


def allowed_read(cdb, length):
    if cdb == bytes.fromhex("12 00 00 00 60 00") and length == 96:
        return True
    if cdb == bytes.fromhex("12 00 00 00 f0 40 00 00 00 00 00 00") and length == 240:
        return True
    if length == BLOCK_SIZE and len(cdb) == 12:
        for protocol, start in (("df83", 6), ("buffer-f0", 3)):
            offset = int.from_bytes(cdb[start:start + 3], "big")
            try:
                if cdb == flash_cdb(protocol, offset):
                    return True
            except ValueError:
                pass
    return False


class SgDevice:
    def __init__(self, path):
        # SG_IO vendor CDBs may need O_RDWR even when all transfers are data-in.
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        if not (stat.S_ISBLK(os.fstat(self.fd).st_mode) or
                stat.S_ISCHR(os.fstat(self.fd).st_mode)):
            os.close(self.fd)
            raise ReadError("Expected a /dev/srN or /dev/sgN device")
        self.libc = C.CDLL(None, use_errno=True)
        self.libc.ioctl.argtypes = [C.c_int, C.c_ulong, C.c_void_p]
        self.libc.ioctl.restype = C.c_int

    def close(self):
        os.close(self.fd)

    def read(self, cdb, length, exact=True):
        if not allowed_read(cdb, length):
            raise ReadError("Command rejected by read-only allowlist")
        cmd = (C.c_ubyte * len(cdb)).from_buffer_copy(cdb)
        data = (C.c_ubyte * length)()
        sense = (C.c_ubyte * 64)()
        hdr = SgIoHdr(interface_id=ord("S"), dxfer_direction=-3,
                      cmd_len=len(cdb), mx_sb_len=len(sense), dxfer_len=length,
                      dxferp=C.addressof(data), cmdp=C.addressof(cmd),
                      sbp=C.addressof(sense), timeout=10000)
        if self.libc.ioctl(self.fd, SG_IO, C.byref(hdr)) < 0:
            error = C.get_errno()
            raise OSError(error, os.strerror(error))
        if hdr.status or hdr.host_status or hdr.driver_status or hdr.info & 1:
            raise ReadError(f"CDB={cdb.hex(' ')} status={hdr.status:#x} "
                            f"host={hdr.host_status:#x} driver={hdr.driver_status:#x} "
                            f"sense={bytes(sense[:hdr.sb_len_wr]).hex(' ')}")
        if not 0 <= hdr.resid <= length:
            raise ReadError(f"Invalid residual byte count: {hdr.resid}")
        actual = length - hdr.resid
        if exact and actual != length:
            raise ReadError(f"Short read: requested {length}, received {actual}")
        return bytes(data[:actual])


def identity(data):
    if len(data) < 36 or (data[0] & 0x1f) != 5:
        raise ReadError("INQUIRY did not identify an optical device")
    return {name: data[start:end].decode("ascii", errors="replace").strip()
            for name, start, end in (("vendor", 8, 16), ("model", 16, 32),
                                     ("revision", 32, 36))}


def flash_metadata(data):
    # Recovered from Flash Utility 7.2.0, VA 0x402c58..0x402d32.
    if len(data) < 0x73 or data[0x60:0x68] not in (b"EXTRAINQ", b"LITEONIT"):
        raise ReadError("Extended INQUIRY has no recognized Lite-On signature")
    size = data[0x6f] << 16
    if size < BLOCK_SIZE or size > MAX_SIZE:
        raise ReadError(f"Unusable reported flash size: {size}; no guessed size used")
    flags = data[0x72]
    encoded = (flags & 0x83) == 1 or bool(flags & 0x80)
    return {"reported_size": size, "flags": flags,
            "protocol": "buffer-f0" if encoded else "df83",
            "encoded_response": encoded, "profile": data[0x70] & 0x1f,
            "size_source": "experimental interpretation of extended INQUIRY byte 0x6f"}


def probe(device):
    standard = device.read(bytes.fromhex("12 00 00 00 60 00"), 96, exact=False)
    ident = identity(standard)
    result = {"identity": ident, "standard_inquiry_hex": standard.hex(),
              "experimental": True, "hardware_validated": False}
    # Only this exact target is authorized for proprietary inquiry/flash reads.
    if ident != {"vendor": "ASUS", "model": "BW-12B1LT", "revision": "1.03"}:
        raise ReadError(f"Target mismatch: {ident}; expected ASUS BW-12B1LT 1.03")
    extended = device.read(bytes.fromhex("12 00 00 00 f0 40 00 00 00 00 00 00"),
                           240, exact=False)
    result["extended_inquiry_hex"] = extended.hex()
    if len(extended) >= 5:
        result["extended_inquiry_advertised_length"] = extended[4] + 5
        result["extended_inquiry_transferred_length"] = len(extended)
    try:
        result["flash"] = flash_metadata(extended)
    except ReadError as error:
        result["flash_metadata_error"] = str(error)
    return result


def dump(device, metadata, path):
    if "flash" not in metadata:
        raise ReadError("No recognized flash metadata; cannot dump")
    flash = metadata["flash"]
    digest = hashlib.sha256()
    with open(path, "xb") as output:
        for offset in range(0, flash["reported_size"], BLOCK_SIZE):
            block = device.read(flash_cdb(flash["protocol"], offset), BLOCK_SIZE)
            if len(block) != BLOCK_SIZE:
                raise ReadError(f"Short flash block at {offset:#x}")
            output.write(block)
            digest.update(block)
            if offset % 65536 == 0:
                print(f"Reading {offset:#x}/{flash['reported_size']:#x}", file=sys.stderr)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device", help="Optical device, e.g. /dev/sr0")
    parser.add_argument("--output", required=True, type=Path,
                        help="New directory for report and optional dump")
    parser.add_argument("--dump", action="store_true",
                        help="Experimentally read flash twice and compare hashes")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"device": args.device, "complete": False}
    device = None
    try:
        device = SgDevice(args.device)
        report.update(probe(device))
        if args.dump:
            report["hashes"] = []
            for number in (1, 2):
                report["hashes"].append(dump(device, report,
                                               args.output / f"flash{number}.raw.bin"))
            report["reads_match"] = report["hashes"][0] == report["hashes"][1]
            if not report["reads_match"]:
                raise ReadError("The two reads differ; files preserved for analysis")
            report["complete"] = True
            report["image_verified"] = False
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ReadError, ValueError) as error:
        report["error"] = str(error)
        print(f"Stopped: {error}", file=sys.stderr)
        return 1
    finally:
        if device is not None:
            device.close()
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
