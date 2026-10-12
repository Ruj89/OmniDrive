#!/usr/bin/env python3
"""Collect offline native-port evidence bound to one exact generated firmware.

All verifiers assemble the same pinned specimen. No device is opened. Existing
images and reports are never overwritten; --generated checks the CMake output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import require
from native_adapter import assemble, ROOT, SOURCES


def evidence_sources():
    return sorted({ROOT / name for name in SOURCES} | {
        ROOT / 'CMakeLists.txt', ROOT / 'arm-toolchain.cmake',
        *(ROOT / 'tools/liteon').rglob('*.py')})


def validate_evidence(path, original, generated):
    """Reject stale reports before preparing a fixed physical-test package."""
    report = json.loads(Path(path).read_text())
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    require(report.get('image_kind') == 'mt1939-native-adapter' and
            report.get('image_size') == 0x200000, 'Unexpected evidence kind/size')
    require(report.get('original_sha256') == digest(original) and
            report.get('output_sha256') == digest(generated), 'Evidence image hash mismatch')
    expected = {str(p.relative_to(ROOT)): digest(p) for p in evidence_sources()}
    require(report.get('source_sha256') == expected, 'Evidence sources are stale or incomplete')
    for name in ('startup', 'adapter', 'error_and_cache_hooks', 'addressing_and_controls',
                 'transfer_modes', 'media', 'identification', 'bd_rom_di', 'read_timer',
                 'cd_transfer', 'packet_reparse', 'data_transfer', 'queued_commands',
                 'queued_nonreads', 'raw_state_and_recordable', 'zero_length', 'loader', 'programmer'):
        require(isinstance(report.get(name), dict) and bool(report[name]),
                f'Evidence missing audit: {name}')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New report path')
    parser.add_argument('--utility', type=Path)
    parser.add_argument('--capture', type=Path, help='Pinned original INQUIRY capture JSON')
    args = parser.parse_args()
    require(not args.output.exists(), 'Report destination must be new')
    require(bool(args.utility) == bool(args.capture), 'Loader audit needs both utility and capture')
    original = args.original.read_bytes()
    candidate, _ = assemble(original)
    require(args.generated.read_bytes() == candidate, 'Generated image differs from reviewed native build')

    from verify_adapter_placement import verify as startup
    from verify_native_adapter import verify as adapter
    from verify_native_hooks import verify as errors, verify_addressing_and_controls, verify_transfer_modes
    from verify_native_media import verify as media, verify_identification
    from verify_native_recognition import verify as recognition
    from verify_native_speed import verify as speed
    from verify_native_transfer import (verify as transfer, verify_packet_reparse,
                                        verify_data_transfer, verify_queued_commands,
                                        verify_raw_state_and_recordable, verify_queued_nonreads,
                                        verify_zero_length)
    report = dict(image_kind='mt1939-native-adapter',
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  output_sha256=hashlib.sha256(candidate).hexdigest(),
                  generated_image=str(args.generated), image_size=len(candidate),
                  full_omnidrive_port=False, flash_ready=False)
    # Bind evidence to sources as well as binary bytes. A report cannot silently
    # describe an older set of checks after the firmware source is unchanged.
    sources = evidence_sources()
    report['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sources}
    for name, verifier in (
            ('startup', lambda b: startup(b)[1]),
            ('adapter', adapter),
            ('error_and_cache_hooks', errors),
            ('addressing_and_controls', verify_addressing_and_controls),
            ('transfer_modes', verify_transfer_modes), ('media', media),
            ('identification', verify_identification), ('bd_rom_di', recognition),
            ('read_timer', speed), ('cd_transfer', transfer),
            ('packet_reparse', verify_packet_reparse), ('data_transfer', verify_data_transfer),
            ('queued_commands', verify_queued_commands),
            ('queued_nonreads', verify_queued_nonreads),
            ('raw_state_and_recordable', verify_raw_state_and_recordable),
            ('zero_length', verify_zero_length)):
        print(f'Verifying {name}...', flush=True)
        report[name] = verifier(original)
    if args.utility:
        from verify_loader import verify as loader
        capture = json.loads(args.capture.read_text())
        print('Verifying native loader...', flush=True)
        report['loader'] = loader(original, candidate,
                                  bytes.fromhex(capture['extended_inquiry_hex']),
                                  args.utility.read_bytes(), native_adapter=True)
        from verify_native_programmer import verify as programmer
        print('Verifying native C payload programmer...', flush=True)
        report['programmer'] = programmer(original, candidate,
            bytes.fromhex(capture['extended_inquiry_hex']), args.utility.read_bytes())
    report['limitations'] = [
        'Optical acquisition, physical data delivery and real interrupts are unverified.',
        'MT1959 read-speed and CD data-speed patches have no MT1939 counterpart; speed needs a physical test.',
        'MT1939 isolates raw request state and validates before shared main.c (see NATIVE_ADAPTER.md).',
        'Historical physical INQUIRY-94 trials do not validate this native payload.',
    ]
    # Catch an input changing while the potentially long verification runs.
    require(args.generated.read_bytes() == candidate, 'Generated firmware changed during verification')
    require(all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == digest
                for p, digest in report['source_sha256'].items()), 'Sources changed during verification')
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(f'Offline evidence saved: {args.output}; full_omnidrive_port=false; flash_ready=false')


if __name__ == '__main__':
    main()
