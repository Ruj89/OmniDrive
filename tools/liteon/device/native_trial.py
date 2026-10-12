#!/usr/bin/env python3
# Purpose: Prepare and run the pinned MT1939 OmniDrive patch or original-firmware rollback trial.
"""Pinned BW-12B1LT MT1939 OmniDrive physical trial and working-drive rollback.

apply: known original -> pinned full MT1939 OmniDrive candidate.
rollback: verified MT1939 OmniDrive patch -> known original.
Both use the once-only, boot-skipping finalization from restore_original.
No arbitrary images or unknown source flash.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import restore_original as restore
import stage_update as staging
from read_flash import SgDevice, ReadError, probe, dump as read_dump

PATCH_SHA256 = '5eac461d23ebcd42ed80c53705822619d245d14a322396c1cb43983b65f9906d'
PATCH_STAGED_SHA256 = 'd9498e416cc453e8b2d60a34bae43d7b54ea1e7b8c9e4af51915262fd8a2b909'
PATCH_RAW_SHA256 = '1a304a8379612a5e813d862b33fcf9bf2eeb959a8b253d1f2935388889016a94'
sha, require = staging.sha, staging.require
MANIFEST = {'format': 'bw12b1lt-native-trial-v1',
            'original_sha256': staging.IMAGE_SHA256, 'patched_sha256': PATCH_SHA256,
            'original_staged_sha256': staging.STAGED_SHA256, 'patched_staged_sha256': PATCH_STAGED_SHA256,
            'original_raw_sha256': restore.RAW_SHA256, 'patched_raw_sha256': PATCH_RAW_SHA256,
            'profile_sha256': staging.PROFILE_SHA256, 'inquiry_valid_sha256': staging.INQUIRY_SHA256,
            'finalization_tag_sha256': restore.FINAL_TAG_SHA256,
            'finalization_cdb_hex': restore.FINAL_CDB.hex(), 'boot_update': False,
            'finalization_max_attempts': 1, 'finalization_timeout_ms': restore.FINAL_TIMEOUT_MS,
            'expected_patch_inquiry_length': 96, 'full_omnidrive_hooks': True,
            'patch_hardware_validated': False, 'flash_ready': False}


PATCH_INQUIRY_SHA256 = '662f6cc177ad834239a1d8371f463090177f5fdcf271b1572b19e7d7fe852ca9'
MARKER = b'OmniDrive\x01\x00\x04'
MANIFEST['patched_inquiry_valid_sha256'] = PATCH_INQUIRY_SHA256


def check_live(report, direction):
    require(direction in ('apply', 'rollback'), 'Unsupported trial direction')
    if direction == 'apply':
        return restore.check_live(report)
    standard = bytes.fromhex(report['standard_inquiry_hex'])
    inquiry = bytes.fromhex(report['extended_inquiry_hex'])
    require(len(standard) == 96 and standard[74:86] == MARKER,
            'Expected native OmniDrive 1.0.4 standard INQUIRY')
    require(len(inquiry) >= 164 and sha(inquiry[:164]) == PATCH_INQUIRY_SHA256,
            'Expected pinned native OmniDrive extended INQUIRY')
    # Only the reviewed template marker differs. Preserve all original checks
    # on identity, session key/IV, protocol and advertised response lengths.
    normalized = dict(report)
    extended = bytearray(inquiry)
    extended[74:86] = bytes(12)
    normalized['extended_inquiry_hex'] = extended.hex()
    restore.check_live(normalized)


def check_payloads(profile, staged, tag, direction):
    require(direction in ('apply', 'rollback'), 'Unsupported trial direction')
    require(len(profile) == 3968 and sha(profile) == staging.PROFILE_SHA256, 'Unrecognized profile')
    expected = PATCH_STAGED_SHA256 if direction == 'apply' else staging.STAGED_SHA256
    require(len(staged) == staging.SIZE and sha(staged) == expected, 'Unrecognized target staging image')
    require(len(tag) == 16 and sha(tag) == restore.FINAL_TAG_SHA256, 'Unrecognized original window tag')


def check_baseline(directory, direction):
    require(direction in ('apply', 'rollback'), 'Unsupported trial direction')
    if direction == 'apply':
        return restore.check_baseline(directory)
    report = json.loads((directory / 'report.json').read_text())
    check_live(report, 'rollback')
    require(report.get('complete') is True and report.get('reads_match') is True and
            report.get('hashes') == [PATCH_RAW_SHA256, PATCH_RAW_SHA256],
            'Expected two complete pinned patched-image reads before rollback')
    for name in ('flash1.raw.bin', 'flash2.raw.bin'):
        raw = (directory / name).read_bytes()
        require(len(raw) == staging.SIZE and sha(raw) == PATCH_RAW_SHA256, f'Patched baseline differs: {name}')


def prepare(original_package, original_path, patched_path, baseline, output, evidence):
    from native_adapter import assemble
    from verify_native_port import validate_evidence
    from Crypto.Cipher import AES
    require(not output.exists(), 'Trial package directory already exists')
    profile, original_staged, tag, unused_manifest = restore.load_package(original_package)
    check_baseline(baseline, 'apply')
    original, patched = original_path.read_bytes(), patched_path.read_bytes()
    require(sha(original) == staging.IMAGE_SHA256 and sha(patched) == PATCH_SHA256,
            'Expected exact original and MT1939 OmniDrive images')
    require(patched == assemble(original)[0], 'Patch differs from native assembly/checksum build')
    validate_evidence(evidence, original_path, patched_path)
    offsets = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    require(patched[:0x10000] == original[:0x10000] and patched[0x1e0000:] == original[0x1e0000:],
            'Candidate changes boot or reserved tails')
    patched_staged = bytearray(original_staged)
    for offset in offsets:
        require(not 0x70000 <= offset < 0x80000, 'Patch changes authenticated window')
        patched_staged[offset] = patched[offset]
    patched_staged = bytes(patched_staged)
    check_payloads(profile, patched_staged, tag, 'apply')
    check_payloads(profile, original_staged, tag, 'rollback')
    # Independently derive both expected read-stream hashes. This matches the
    # established reader's AES-CBC reset for every 128-byte response.
    inquiry = bytes.fromhex(json.loads((baseline / 'report.json').read_text())['extended_inquiry_hex'])
    candidate_inquiry = bytearray(inquiry)
    candidate_inquiry[74:86] = MARKER
    require(sha(candidate_inquiry[:164]) == PATCH_INQUIRY_SHA256,
            'Predicted candidate extended INQUIRY differs')
    for image, expected in ((original, restore.RAW_SHA256), (patched, PATCH_RAW_SHA256)):
        digest = hashlib.sha256()
        for offset in range(0, len(image), 128):
            digest.update(AES.new(inquiry[148:164], AES.MODE_CBC, inquiry[16:32]).encrypt(image[offset:offset + 128]))
        require(digest.hexdigest() == expected, 'Predicted physical read stream differs')
    output.mkdir(parents=True, exist_ok=False)
    for name, data in (('profile.enc.bin', profile), ('original.staged.bin', original_staged),
                       ('native.staged.bin', patched_staged), ('window.final-tag.bin', tag)):
        (output / name).write_bytes(data)
    (output / 'trial.json').write_text(json.dumps(MANIFEST, indent=2) + '\n')
    return dict(MANIFEST)


def load_package(directory, direction):
    require(direction in ('apply', 'rollback'), 'Unsupported trial direction')
    manifest = json.loads((directory / 'trial.json').read_text())
    for key, value in MANIFEST.items():
        require(manifest.get(key) == value, f'Unexpected trial package field: {key}')
    profile = (directory / 'profile.enc.bin').read_bytes()
    original = (directory / 'original.staged.bin').read_bytes()
    patched = (directory / 'native.staged.bin').read_bytes()
    tag = (directory / 'window.final-tag.bin').read_bytes()
    check_payloads(profile, original, tag, 'rollback')
    check_payloads(profile, patched, tag, 'apply')
    return profile, patched if direction == 'apply' else original, tag, manifest


class TrialDevice(restore.RestoreDevice):
    def __init__(self, path, profile, staged, tag, journal, direction):
        # Separate fixed-image constructor: the original-only runner's payload
        # checks/constructor remain intact and cannot accept this patched target.
        check_payloads(profile, staged, tag, direction)
        self.profile, self.staged, self.tag, self.journal = profile, staged, tag, journal
        self.commands = 0
        self.staging_verified = False
        self.finalization_attempted = self.finalization_transport_accepted = False
        SgDevice.__init__(self, path)

    def stage_target(self, progress=None):
        # Inherited comparison/finalization gates operate on constructor-pinned
        # self.staged; the algorithm and once-only final command are unchanged.
        return super().stage_original(progress)


def run_trial(directory, baseline, device_path, output, direction):
    profile, staged, tag, manifest = load_package(directory, direction)
    check_baseline(baseline, direction)
    output.mkdir(parents=True, exist_ok=False)
    applying = direction == 'apply'
    source_raw = restore.RAW_SHA256 if applying else PATCH_RAW_SHA256
    target_sha = PATCH_SHA256 if applying else staging.IMAGE_SHA256
    summary = {'stage': 'native_physical_trial', 'direction': direction, 'device': device_path,
               'package_sha256': sha((directory / 'trial.json').read_bytes()),
               'source_raw_sha256': source_raw, 'target_decoded_sha256': target_sha,
               'boot_update': False, 'live_preflight_matches_source': False, 'all_blocks_matched': False,
               'finalization_attempted': False, 'finalization_sent': False,
               'finalization_transport_accepted': False, 'physical_flash_verified': False,
               'flash_ready': False, 'outcome': 'preflight'}
    result_path = output / 'trial-result.json'
    restore.durable_json(result_path, summary)
    device = None
    try:
        with (output / 'transport.jsonl').open('x') as journal:
            device = TrialDevice(device_path, profile, staged, tag, journal, direction)
            live = probe(device)
            check_live(live, direction)
            restore.durable_json(output / 'preflight-probe.json', live)
            print(f'Read-only preflight: require {"original" if applying else "MT1939 OmniDrive"} flash...', flush=True)
            raw_sha = read_dump(device, live, output / 'live-preflight.raw.bin')
            require(raw_sha == source_raw, 'Current flash differs from expected source; no update commands sent')
            summary.update(live_preflight_matches_source=True, preflight_raw_sha256=raw_sha,
                           identity=live['identity'], outcome='staging')
            summary.update(device.stage_target(
                lambda count: print(f'Target RAM blocks compared: {count}/512', flush=True)))
            summary['outcome'] = 'ready_to_finalize_native' if applying else 'ready_to_finalize_original_rollback'
            restore.durable_json(result_path, summary)
            print(f'PHYSICAL WRITE: {"MT1939 OmniDrive patch" if applying else "original rollback"}; boot skipped. Keep power connected; do not interrupt.', flush=True)
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
        restore.durable_json(result_path, summary)
        if device is not None:
            device.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='Offline: build exact patch and rollback payloads')
    for name in ('original-package', 'original', 'patched', 'baseline', 'output', 'evidence'):
        prep.add_argument('--' + name, type=Path, required=True)
    inspect = sub.add_parser('inspect', help='Validate both package targets and the original baseline offline')
    inspect.add_argument('--package', type=Path, required=True)
    inspect.add_argument('--baseline', type=Path, required=True)
    readback = sub.add_parser('verify-readback', help='Offline: validate two full cold-start reads')
    readback.add_argument('--baseline', type=Path, required=True)
    readback.add_argument('--state', choices=('original', 'candidate'), required=True)
    for action in ('apply', 'rollback'):
        run = sub.add_parser(action, help=f'PHYSICAL WRITE: {action}; requires a responding drive')
        run.add_argument('--package', type=Path, required=True)
        run.add_argument('--baseline', type=Path, required=True)
        run.add_argument('--device', required=True)
        run.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.original_package, args.original, args.patched, args.baseline, args.output, args.evidence)
        elif args.action == 'verify-readback':
            check_baseline(args.baseline, 'apply' if args.state == 'original' else 'rollback')
            result = {'state': args.state, 'full_image_matches_expected': True, 'flash_ready': False}
        elif args.action == 'inspect':
            result = load_package(args.package, 'apply')[3]
            check_baseline(args.baseline, 'apply')
        else:
            result = run_trial(args.package, args.baseline, args.device, args.output, args.action)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, ReadError, ImportError, KeyboardInterrupt) as error:
        print(f'Trial stopped: {error or type(error).__name__}. If finalization was attempted, keep power connected and do not retry.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
