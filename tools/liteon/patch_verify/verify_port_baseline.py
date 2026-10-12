#!/usr/bin/env python3
"""Measure the missing OmniDrive command and read-mode hooks in the INQUIRY-94 baseline.

This is an offline negative-control audit, not a port or a hardware emulator.
It accepts only the pinned original and INQUIRY-94 images. A future port needs
new acceptance tests rather than reusing this baseline as proof of support.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import IMAGE_SHA256, validate_assembly
from map_scsi import CDB, MEDIA, Experiment

INQUIRY94_SHA256 = '46be83575f28161ff3a851604d476070220a4a4970c7b5343622bf31b55ddc6b'
SECTOR_FORMAT = 0x04050064


def verify(original, modified):
    for image, expected in ((original, IMAGE_SHA256), (modified, INQUIRY94_SHA256)):
        if len(image) != 0x200000 or hashlib.sha256(image).hexdigest() != expected:
            raise ValueError('Expected the pinned original and INQUIRY-94 baseline; this audit cannot certify a new port')
    validate_assembly(original, modified)

    dispatch_cases = []
    mode_cases = []
    for name, image in (('original', original), ('inquiry94', modified)):
        for media in (0, 4, 0x40, 0x50, 0x60, 0xc0):
            ex = Experiment(image, [(0x1b14e, 0x1bdea)], stubs={0x1afb4: 1})
            ex.put(CDB, 0xc0)
            ex.put(MEDIA, media)
            ex.put(0x02000611, 1)
            result = ex.run(0x1b14e)
            if result['termination'] != 'returned' or result['sense'] != [5, 0x20, 0]:
                raise ValueError('Unexpected C0 baseline behavior')
            dispatch_cases.append({'image': name, 'media': media, **result})

        for family, entry, media, helper, target, raw_format in (
                ('dvd', 0xc8404, 0x40, 0x1bbc1c, 0x1bf38c, 0x98),
                ('dvd_ram', 0xc8404, 0x50, 0x1bbc1c, 0xe3370, 0x98),
                ('bd', 0xace90, 0xc0, None, 0xb5828, 0xf8)):
            for fua in (0, 8):
                for initial_upper in (0, 0xa5a50000, 0xffffff00):
                    packet = bytearray(12)
                    packet[0] = 0xa8
                    packet[1] = 0x80 | fua  # OmniDrive's internal raw marker
                    packet[2:6] = (0x123456).to_bytes(4, 'big')
                    packet[6:10] = (0x234).to_bytes(4, 'big')
                    ex = Experiment(image, [(entry, entry + 0x500), (0xc83e0, 0xc8404)],
                                    stubs={} if helper is None else {helper: 0}, stops=[target])
                    ex.cpu.mem_write(CDB, bytes(packet))
                    ex.put(MEDIA, media)
                    ex.put(0x020006b8, 0x7fffffff, 4)  # synthetic last sector
                    ex.put(SECTOR_FORMAT, initial_upper | raw_format, 4)
                    result = ex.run(entry)
                    final_format = ex.get(SECTOR_FORMAT, 4)
                    if (result['pc'] != target or result['calls'][-1]['args'][0] != fua
                            or final_format != initial_upper | 0x10):
                        raise ValueError('Unexpected native read-mode baseline behavior')
                    mode_cases.append({'image': name, 'family': family, 'fua': fua,
                                       'initial_format': initial_upper | raw_format,
                                       'final_format': final_format, **result})

    return {
        'original_sha256': IMAGE_SHA256,
        'modified_sha256': INQUIRY94_SHA256,
        'full_omnidrive_port': False,
        'changed_offsets': [i for i, (a, b) in enumerate(zip(original, modified)) if a != b],
        'c0_dispatch': dispatch_cases,
        'native_read_mode': mode_cases,
        'blockers': [
            'C0 is rejected with sense 05/20/00 for every tested media classification.',
            'Native DVD/DVD-RAM/BD handlers overwrite raw sector-format bits before calling the data reader.',
            'Payload allocation, native function ABI and alternate dispatch paths still need a verified port.',
            'Descrambling, EDC, lead-in/out, XGD and Nintendo hooks are not implemented in this baseline.',
        ],
        'limitations': [
            'Synthetic RAM/MMIO; readiness and DVD layer lookup are explicit stubs.',
            'Execution stops at the native data reader; no optical reads or transport delivery are simulated.',
            'Hardware media capabilities are not inferred from the MT1959 feature table.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('modified', type=Path)
    parser.add_argument('--report', type=Path, required=True, help='New JSON report; never overwritten')
    args = parser.parse_args()
    report = verify(args.original.read_bytes(), args.modified.read_bytes())
    with args.report.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(f"Verified {len(report['c0_dispatch'])} C0 dispatch and {len(report['native_read_mode'])} native read-mode cases.")
    print('Full OmniDrive port: absent. See ' + str(args.report))
    return 1  # The requested complete feature set is absent, even though the audit ran successfully.


if __name__ == '__main__':
    sys.exit(main())
