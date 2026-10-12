#!/usr/bin/env python3
# Purpose: Prepare a pinned update package and optionally stage it in drive RAM for validation.
"""Prepare or test the pinned BW-12B1LT original update in staging RAM only.

The Linux transport excludes finalization (80/a0), erase, reset and unlock.
Preparing a package is offline; `stage` explicitly performs data-out to RAM.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from read_flash import SgDevice, SgIoHdr, SG_IO, ReadError, probe
from audit_integrity import IMAGE_SHA256
from analyze_utility import EXPECTED_SHA256

SIZE = 0x200000
BLOCK = 0x1000
INQUIRY_SHA256 = '6d1dc11d8918d4745ef6edfe0eb3cef8e7b28fb4841bf7834c7dcf28f8a6972b'
# Original x86 encoder output for the pinned original and captured session.
# Preparation recomputes these from the pinned utility; live transport requires
# these exact bytes independently of editable package metadata.
PROFILE_SHA256 = '704f9b091c57cc40e6fc22e02de0a19090d4eb7c8740bff332b2844494623d34'
STAGED_SHA256 = 'c3cc614f28c307df7b799b038830d5dfda972035d3e600042b9bfd9a40bf2e6a'
PROFILE_CDB = bytes.fromhex('3b0501000000000f807f0000')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ReadError(message)


def block_cdb(offset, *, read=False):
    require(0 <= offset <= SIZE - BLOCK and offset % BLOCK == 0, 'Invalid staging block offset')
    return (bytes.fromhex('3c0101' if read else '3b0501') + offset.to_bytes(3, 'big') +
            BLOCK.to_bytes(3, 'big') + bytes(3))


def check_payloads(profile, staged):
    require(len(profile) == 3968 and sha(profile) == PROFILE_SHA256, 'Unrecognized profile payload')
    require(len(staged) == SIZE and sha(staged) == STAGED_SHA256, 'Unrecognized original staging image')


def prepare(image_path, report_path, utility_path, output):
    from verify_loader import Utility, validate_inquiry
    require(not output.exists(), 'Package directory already exists')
    original = image_path.read_bytes()
    require(sha(original) == IMAGE_SHA256, 'Expected the pinned original decoded image')
    report = json.loads(report_path.read_text())
    # Require the acquired preflash baseline, not a standalone guessed INQUIRY.
    from validate_flash import validate
    baseline = validate((report_path.parent / 'flash1.raw.bin').read_bytes(),
                        (report_path.parent / 'flash2.raw.bin').read_bytes(), original, report)
    require(report.get('complete') and baseline['offline_structure_consistent'], 'Incomplete baseline')
    inquiry = bytes.fromhex(report['extended_inquiry_hex'])
    validate_inquiry(original, inquiry)
    utility = Utility(utility_path.read_bytes())
    profile, descriptor = utility.profile(inquiry)
    key, iv = inquiry[148:164], inquiry[16:32]
    cipher, tag = utility.encode(profile, key, iv)
    profile_payload = cipher + tag
    staged = bytearray(original)
    cipher, unused_tag = utility.encode(bytes(staged[0x70000:0x80000]), key, iv, window=True)
    staged[0x70000:0x80000] = cipher
    staged = bytes(staged)
    check_payloads(profile_payload, staged)
    require(utility.cdb(len(profile_payload), control=0x7f) == PROFILE_CDB, 'Native profile CDB differs')
    for offset in range(0, SIZE, BLOCK):
        for read in (False, True):
            require(utility.cdb(BLOCK, offset, read=read) == block_cdb(offset, read=read),
                    'Native block CDB differs')
    manifest = {'format': 'bw12b1lt-original-staging-v1', 'original_sha256': IMAGE_SHA256,
                'inquiry_valid_sha256': INQUIRY_SHA256, 'utility_sha256': EXPECTED_SHA256,
                'profile_sha256': PROFILE_SHA256, 'staged_sha256': STAGED_SHA256,
                'profile': descriptor, 'blocks': SIZE // BLOCK, 'block_size': BLOCK,
                'normal_update_commands': 1 + 2 * (SIZE // BLOCK),
                'finalization_included': False, 'flash_ready': False}
    output.mkdir(parents=True, exist_ok=False)
    (output / 'profile.enc.bin').write_bytes(profile_payload)
    (output / 'original.staged.bin').write_bytes(staged)
    (output / 'package.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def load_package(directory):
    manifest = json.loads((directory / 'package.json').read_text())
    require(manifest.get('format') == 'bw12b1lt-original-staging-v1', 'Unsupported staging package')
    for key, value in (('original_sha256', IMAGE_SHA256), ('inquiry_valid_sha256', INQUIRY_SHA256),
                       ('utility_sha256', EXPECTED_SHA256), ('profile_sha256', PROFILE_SHA256),
                       ('staged_sha256', STAGED_SHA256), ('blocks', 512), ('block_size', BLOCK),
                       ('normal_update_commands', 1025), ('finalization_included', False),
                       ('flash_ready', False)):
        require(manifest.get(key) == value, f'Unexpected package field: {key}')
    profile = (directory / 'profile.enc.bin').read_bytes()
    staged = (directory / 'original.staged.bin').read_bytes()
    check_payloads(profile, staged)
    return profile, staged, manifest


def allowed_command(cdb, payload, profile, staged):
    """Allow only exact prepared RAM payloads or a 4096-byte staging read."""
    if payload is not None and cdb == PROFILE_CDB:
        return payload == profile
    if len(cdb) != 12:
        return False
    offset = int.from_bytes(cdb[3:6], 'big')
    if offset % BLOCK or offset > SIZE - BLOCK:
        return False
    if payload is None:
        return cdb == block_cdb(offset, read=True)
    return cdb == block_cdb(offset) and payload == staged[offset:offset + BLOCK]


class StagingDevice(SgDevice):
    def __init__(self, path, profile, staged, journal):
        check_payloads(profile, staged)  # reject before opening the device
        self.profile, self.staged, self.journal = profile, staged, journal
        self.commands = 0
        super().__init__(path)

    def transfer(self, cdb, payload=None):
        require(allowed_command(cdb, payload, self.profile, self.staged),
                'Command rejected by staging-only allowlist')
        length = BLOCK if payload is None else len(payload)
        cmd = (C.c_ubyte * len(cdb)).from_buffer_copy(cdb)
        data = (C.c_ubyte * length)() if payload is None else (C.c_ubyte * length).from_buffer_copy(payload)
        sense = (C.c_ubyte * 64)()
        hdr = SgIoHdr(interface_id=ord('S'), dxfer_direction=-3 if payload is None else -2,
                      cmd_len=len(cdb), mx_sb_len=len(sense), dxfer_len=length,
                      dxferp=C.addressof(data), cmdp=C.addressof(cmd), sbp=C.addressof(sense), timeout=10000)
        self.commands += 1
        result = self.libc.ioctl(self.fd, SG_IO, C.byref(hdr))
        actual = length - hdr.resid if 0 <= hdr.resid <= length else 0
        record = {'sequence': self.commands, 'cdb_hex': cdb.hex(),
                  'direction': 'in' if payload is None else 'out', 'requested_length': length,
                  'residual': hdr.resid, 'status': hdr.status, 'host_status': hdr.host_status,
                  'driver_status': hdr.driver_status, 'info': hdr.info,
                  'sense_hex': bytes(sense[:hdr.sb_len_wr]).hex(), 'duration_ms': hdr.duration}
        if result < 0:
            record['errno'] = C.get_errno()
        else:
            record['data_sha256'] = sha(bytes(data[:actual]))
        self.journal.write(json.dumps(record) + '\n')
        self.journal.flush()
        require(result >= 0, f'SG_IO failed: errno={record.get("errno")}')
        require(not (hdr.status or hdr.host_status or hdr.driver_status or hdr.info & 1),
                f'Staging transfer failed: CDB={cdb.hex()} sense={record["sense_hex"]}')
        require(0 <= hdr.resid <= length and actual == length, 'Short staging transfer')
        return bytes(data) if payload is None else b''


def transfer_image(device, profile, staged, progress=None):
    """1025 commands normally; no finalization is constructed or sent."""
    device.transfer(PROFILE_CDB, profile)
    matched, read_attempts = 0, 0
    for offset in range(0, SIZE, BLOCK):
        payload = staged[offset:offset + BLOCK]
        device.transfer(block_cdb(offset), payload)
        for comparison in range(2):
            for attempt in range(3):
                read_attempts += 1
                try:
                    response = device.transfer(block_cdb(offset, read=True))
                except ReadError:
                    continue
                if len(response) == BLOCK:
                    break
            else:
                raise ReadError(f'Staging read failed at {offset:#x} after three attempts')
            if response == payload:
                break
        else:
            raise ReadError(f'Staging comparison failed twice at {offset:#x}')
        matched += 1
        if progress and matched % 64 == 0:
            progress(matched)
    return {'blocks_matched': matched, 'read_attempts': read_attempts,
            'all_blocks_matched': matched == SIZE // BLOCK, 'finalization_sent': False,
            'physical_flash_verified': False, 'flash_ready': False}


def stage(directory, device_path, output):
    profile, staged, manifest = load_package(directory)
    output.mkdir(parents=True, exist_ok=False)
    device = None
    summary = {'stage': 'original_update_staging_ram', 'device': device_path,
               'package_sha256': sha((directory / 'package.json').read_bytes()),
               'all_blocks_matched': False, 'finalization_sent': False,
               'physical_flash_verified': False, 'flash_ready': False}
    try:
        with (output / 'transport.jsonl').open('x') as journal:
            device = StagingDevice(device_path, profile, staged, journal)
            live = probe(device)  # existing strict identity checks, data-in only
            standard = bytes.fromhex(live['standard_inquiry_hex'])
            require(len(standard) == 96 and standard[4] + 5 == 96,
                    'Expected unmodified 96-byte standard INQUIRY')
            inquiry = bytes.fromhex(live['extended_inquiry_hex'])
            require(len(inquiry) >= 164 and inquiry[4] + 5 == 164 and sha(inquiry[:164]) == INQUIRY_SHA256,
                    'Live INQUIRY differs from package session; no staging writes sent')
            summary.update(identity=live['identity'], inquiry_valid_sha256=sha(inquiry[:164]))
            summary.update(transfer_image(device, profile, staged,
                           lambda count: print(f'RAM blocks compared: {count}/512', flush=True)))
        return summary
    except (OSError, ValueError, KeyError, ReadError) as error:
        summary['error'] = str(error)
        raise
    finally:
        if device is not None:
            summary['update_commands_issued'] = device.commands
            device.close()
        (output / 'staging-result.json').write_text(json.dumps(summary, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare_args = sub.add_parser('prepare', help='Offline package using the pinned original and utility')
    prepare_args.add_argument('--image', type=Path, required=True)
    prepare_args.add_argument('--report', type=Path, required=True)
    prepare_args.add_argument('--utility', type=Path, required=True)
    prepare_args.add_argument('--output', type=Path, required=True)
    inspect_args = sub.add_parser('inspect', help='Verify a package without opening a device')
    inspect_args.add_argument('--package', type=Path, required=True)
    stage_args = sub.add_parser('stage', help='Linux live test: write and compare staging RAM; never finalize')
    stage_args.add_argument('--package', type=Path, required=True)
    stage_args.add_argument('--device', required=True)
    stage_args.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.image, args.report, args.utility, args.output)
        elif args.action == 'inspect':
            result = load_package(args.package)[2]
        else:
            result = stage(args.package, args.device, args.output)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError) as error:
        print(f'Staging stopped: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
