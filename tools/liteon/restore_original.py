#!/usr/bin/env python3
# Purpose: Prepare and execute the pinned original-firmware rewrite on the target drive.
"""Experimental Linux physical rewrite of the pinned BW-12B1LT original only.

This trial preserves boot in the native mode-80 writer, but erases main/profile.
It never accepts an arbitrary image or retries finalization. A successful SG_IO
return does not prove physical write completion; cold-start readback is required.
"""
import argparse
import ctypes as C
import json
import os
from pathlib import Path
import sys

from read_flash import ReadError, SgIoHdr, SG_IO, probe, dump as read_dump
import stage_update as staging

FINAL_CDB = bytes.fromhex('3b0501000000000010800000')
FINAL_TAG_SHA256 = '6af0e7e35ee4dcf863ea511b95737287a76a40db7b9bfe68c076b2cb22d0c29b'
RAW_SHA256 = '47e8882c0d0f983df709186142ba81ca91d62661dd4352531c54c8ac1dd6a379'
FINAL_TIMEOUT_MS = 300000
IDENTITY = {'vendor': 'ASUS', 'model': 'BW-12B1LT', 'revision': '1.03'}
sha, require = staging.sha, staging.require


def check_live(report, *, standard_length=96):
    require(report.get('identity') == IDENTITY, 'Unexpected drive identity')
    require(standard_length in (94, 96), 'Unsupported expected INQUIRY length')
    standard = bytes.fromhex(report['standard_inquiry_hex'])
    received_lengths = (94, 96) if standard_length == 94 else (96,)
    require(len(standard) in received_lengths and standard[4] + 5 == standard_length,
            f'Expected {standard_length}-byte standard INQUIRY')
    inquiry = bytes.fromhex(report['extended_inquiry_hex'])
    require(len(inquiry) >= 164 and inquiry[4] + 5 == 164 and
            sha(inquiry[:164]) == staging.INQUIRY_SHA256, 'Live INQUIRY differs from pinned specimen')
    flash = report.get('flash', {})
    require(flash.get('reported_size') == staging.SIZE and flash.get('protocol') == 'buffer-f0' and
            flash.get('flags') == 0xc2 and flash.get('encoded_response') is True,
            'Unexpected flash read protocol')


def check_baseline(directory):
    report = json.loads((directory / 'report.json').read_text())
    check_live(report)
    require(report.get('complete') is True and report.get('reads_match') is True and
            report.get('hashes') == [RAW_SHA256, RAW_SHA256], 'Expected two complete original baseline reads')
    for name in ('flash1.raw.bin', 'flash2.raw.bin'):
        raw = (directory / name).read_bytes()
        require(len(raw) == staging.SIZE and sha(raw) == RAW_SHA256, f'Baseline differs: {name}')


def prepare(image, report, utility, output):
    from verify_loader import Utility, validate_inquiry
    require(not output.exists(), 'Restore package directory already exists')
    original = image.read_bytes()
    require(sha(original) == staging.IMAGE_SHA256, 'Expected pinned original decoded image')
    check_baseline(report.parent)
    inquiry = bytes.fromhex(json.loads(report.read_text())['extended_inquiry_hex'])
    validate_inquiry(original, inquiry)
    native = Utility(utility.read_bytes())
    unused_cipher, tag = native.encode(original[0x70000:0x80000], inquiry[148:164], inquiry[16:32], window=True)
    require(len(tag) == 16 and sha(tag) == FINAL_TAG_SHA256, 'Native original tag differs')
    require(native.cdb(16, control=0x80) == FINAL_CDB, 'Native original finalization CDB differs')
    output.mkdir(parents=True, exist_ok=False)
    staging.prepare(image, report, utility, output / 'staging')
    manifest = {'format': 'bw12b1lt-original-restore-trial-v1',
                'original_sha256': staging.IMAGE_SHA256, 'inquiry_valid_sha256': staging.INQUIRY_SHA256,
                'baseline_raw_sha256': RAW_SHA256, 'finalization_cdb_hex': FINAL_CDB.hex(),
                'finalization_tag_sha256': FINAL_TAG_SHA256, 'physical_write': True,
                'boot_update': False, 'main_and_profile_rewritten': True,
                'finalization_max_attempts': 1, 'finalization_timeout_ms': FINAL_TIMEOUT_MS,
                'hardware_write_validated': False, 'flash_ready': False}
    (output / 'original.final-tag.bin').write_bytes(tag)
    (output / 'restore.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def load_package(directory):
    manifest = json.loads((directory / 'restore.json').read_text())
    expected = {'format': 'bw12b1lt-original-restore-trial-v1',
                'original_sha256': staging.IMAGE_SHA256, 'inquiry_valid_sha256': staging.INQUIRY_SHA256,
                'baseline_raw_sha256': RAW_SHA256, 'finalization_cdb_hex': FINAL_CDB.hex(),
                'finalization_tag_sha256': FINAL_TAG_SHA256, 'physical_write': True,
                'boot_update': False, 'main_and_profile_rewritten': True,
                'finalization_max_attempts': 1, 'finalization_timeout_ms': FINAL_TIMEOUT_MS,
                'hardware_write_validated': False, 'flash_ready': False}
    for key, value in expected.items():
        require(manifest.get(key) == value, f'Unexpected restore package field: {key}')
    profile, staged, unused = staging.load_package(directory / 'staging')
    tag = (directory / 'original.final-tag.bin').read_bytes()
    require(len(tag) == 16 and sha(tag) == FINAL_TAG_SHA256, 'Unrecognized original finalization tag')
    return profile, staged, tag, manifest


def durable_json(path, value):
    with path.open('w') as output:
        output.write(json.dumps(value, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())


class RestoreDevice(staging.StagingDevice):
    def __init__(self, path, profile, staged, tag, journal):
        require(len(tag) == 16 and sha(tag) == FINAL_TAG_SHA256, 'Unrecognized original finalization tag')
        self.tag = tag
        self.staging_verified = False
        self.finalization_attempted = False
        self.finalization_transport_accepted = False
        super().__init__(path, profile, staged, journal)

    def stage_original(self, progress=None):
        require(not self.finalization_attempted and not self.staging_verified, 'Restore stage already used')
        result = staging.transfer_image(self, self.profile, self.staged, progress)
        self.staging_verified = result['all_blocks_matched'] is True and result['blocks_matched'] == 512
        require(self.staging_verified, 'Original staging verification incomplete')
        return result

    def transfer(self, cdb, payload=None):
        require(not self.finalization_attempted and not self.staging_verified,
                'Staging transport is closed after verification or finalization')
        return super().transfer(cdb, payload)

    def finalize(self):
        require(self.staging_verified and not self.finalization_attempted,
                'Finalization requires verified staging and is never retried')
        cmd = (C.c_ubyte * 12).from_buffer_copy(FINAL_CDB)
        data = (C.c_ubyte * 16).from_buffer_copy(self.tag)
        sense = (C.c_ubyte * 64)()
        hdr = SgIoHdr(interface_id=ord('S'), dxfer_direction=-2, cmd_len=12,
                      mx_sb_len=len(sense), dxfer_len=16, dxferp=C.addressof(data),
                      cmdp=C.addressof(cmd), sbp=C.addressof(sense), timeout=FINAL_TIMEOUT_MS)
        intent = {'event': 'finalization_intent', 'sequence': self.commands + 1,
                  'cdb_hex': FINAL_CDB.hex(), 'direction': 'out', 'requested_length': 16,
                  'data_sha256': sha(self.tag), 'timeout_ms': FINAL_TIMEOUT_MS,
                  'physical_flash_verified': False}
        self.journal.write(json.dumps(intent) + '\n')
        self.journal.flush()
        os.fsync(self.journal.fileno())
        self.finalization_attempted = True
        self.commands += 1
        result = self.libc.ioctl(self.fd, SG_IO, C.byref(hdr))  # EXACTLY ONE invocation
        record = dict(intent, event='finalization_result', ioctl_return=result,
                      residual=hdr.resid, status=hdr.status, host_status=hdr.host_status,
                      driver_status=hdr.driver_status, info=hdr.info,
                      sense_hex=bytes(sense[:hdr.sb_len_wr]).hex(), duration_ms=hdr.duration)
        if result < 0:
            record['errno'] = C.get_errno()
        self.journal.write(json.dumps(record) + '\n')
        self.journal.flush()
        os.fsync(self.journal.fileno())
        require(result >= 0, f'Finalization SG_IO failed: errno={record.get("errno")}; do not retry')
        require(not (hdr.status or hdr.host_status or hdr.driver_status or hdr.info & 1),
                f'Finalization transport error: sense={record["sense_hex"]}; do not retry')
        require(hdr.resid == 0, 'Short finalization transfer; physical outcome unknown; do not retry')
        self.finalization_transport_accepted = True


def restore(directory, baseline, device_path, output):
    profile, staged, tag, manifest = load_package(directory)
    check_baseline(baseline)  # verify retained raw backup before opening hardware
    output.mkdir(parents=True, exist_ok=False)
    device = None
    summary = {'stage': 'original_physical_restore_trial', 'device': device_path,
               'package_sha256': sha((directory / 'restore.json').read_bytes()),
               'original_sha256': staging.IMAGE_SHA256, 'boot_update': False,
               'live_preflight_matches_original': False, 'all_blocks_matched': False,
               'finalization_attempted': False, 'finalization_sent': False,
               'finalization_transport_accepted': False, 'physical_flash_verified': False,
               'flash_ready': False, 'outcome': 'preflight'}
    result_path = output / 'restore-result.json'
    durable_json(result_path, summary)
    try:
        with (output / 'transport.jsonl').open('x') as journal:
            device = RestoreDevice(device_path, profile, staged, tag, journal)
            live = probe(device)
            check_live(live)
            durable_json(output / 'preflight-probe.json', live)
            print('Read-only preflight: comparing current physical flash with original...', flush=True)
            raw_sha = read_dump(device, live, output / 'live-preflight.raw.bin')
            require(raw_sha == RAW_SHA256, 'Current flash differs from original; no update commands sent')
            summary.update(live_preflight_matches_original=True, preflight_raw_sha256=raw_sha,
                           identity=live['identity'], outcome='staging')
            summary.update(device.stage_original(
                lambda count: print(f'Original RAM blocks compared: {count}/512', flush=True)))
            summary['outcome'] = 'ready_to_finalize_original'
            durable_json(result_path, summary)
            print('PHYSICAL WRITE: original main/profile; boot skipped. Keep power connected; do not interrupt.', flush=True)
            device.finalize()
            summary['outcome'] = 'transport_accepted_requires_cold_readback'
        return summary
    except BaseException as error:
        summary['error'] = str(error) or type(error).__name__
        summary['outcome'] = ('finalization_outcome_unknown_do_not_retry' if
                              device is not None and device.finalization_attempted else 'aborted_before_finalization')
        raise
    finally:
        if device is not None:
            summary.update(update_commands_issued=device.commands,
                           finalization_attempted=device.finalization_attempted,
                           finalization_transport_accepted=device.finalization_transport_accepted,
                           finalization_sent=(True if device.finalization_transport_accepted else
                                              None if device.finalization_attempted else False))
        durable_json(result_path, summary)
        if device is not None:
            device.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='Offline: derive the original-only physical-write package')
    for name in ('image', 'report', 'utility', 'output'):
        prep.add_argument('--' + name, type=Path, required=True)
    inspect = sub.add_parser('inspect', help='Check package and backup without accessing hardware')
    inspect.add_argument('--package', type=Path, required=True)
    inspect.add_argument('--baseline', type=Path, required=True)
    run = sub.add_parser('run', help='PHYSICAL FLASH WRITE of original; cold-start readback required')
    run.add_argument('--package', type=Path, required=True)
    run.add_argument('--baseline', type=Path, required=True)
    run.add_argument('--device', required=True)
    run.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.image, args.report, args.utility, args.output)
        elif args.action == 'inspect':
            result = load_package(args.package)[3]
            check_baseline(args.baseline)
        else:
            result = restore(args.package, args.baseline, args.device, args.output)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError, KeyboardInterrupt) as error:
        print(f'Restore stopped: {error or type(error).__name__}. If finalization was attempted, keep power connected and do not retry.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
