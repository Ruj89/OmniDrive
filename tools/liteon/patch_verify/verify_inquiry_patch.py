#!/usr/bin/env python3
# Purpose: Compare original and patched INQUIRY behavior through bounded firmware emulation.
"""Compare original and patched INQUIRY instructions in bounded emulation."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import CDB, Experiment, require
from audit_integrity import build


def exercise(image, allocation, field=None):
    # The template writer and control-state helper are explicit substitutions,
    # as in map_scsi.responses(). No actual buffer or DMA ownership is modelled.
    ex = Experiment(image, [(0x9cab0, 0x9cba8), (0x9b8c0, 0x9b8e6)],
                    stubs={0xa6646: 0, 0x9ca70: 0})
    packet = bytearray([0x12, 0, 0, 0, allocation, 0] + [0] * 6)
    if field is not None:
        packet[field] = 1
    ex.cpu.mem_write(CDB, bytes(packet))
    ex.put(0x02000648, 0x01000000, 4)
    result = ex.run(0x9cab0)
    result.update(allocation=allocation, invalid_field=field,
                  response_length=ex.get(0x02000636, 2),
                  data_pending=ex.get(0x02000613),
                  deferred_error=ex.get(0x02000616),
                  transfer_pointer=ex.get(0x040300e8, 4),
                  transfer_length=ex.get(0x04042154, 4))
    return result


def verify(original, patched):
    expected, manifest = build(original)
    require(patched == expected, "Image differs from the exact OmniDrive patch")
    rows = []
    for allocation in (0, 1, 36, 93, 94, 95, 96, 255):
        before = exercise(original, allocation)
        after = exercise(patched, allocation)
        for row, cap in ((before, 96), (after, 94)):
            length = (min(allocation, cap) + 1) & ~1
            require(row['response_length'] == length, "Unexpected padded response length")
            require(row['data_pending'] == bool(allocation), "Unexpected pending flag")
            require(row['deferred_error'] == 0, "Unexpected error")
            if allocation:
                require(row['transfer_pointer'] == 0x0101c780, "Response pointer changed")
                require(row['transfer_length'] == length, "Unexpected MMIO length")
                writes = [c for c in row['calls'] if c['target'] == 0xa6646]
                require(len(writes) == 1 and writes[0]['args'][:2] == [0x1c784, cap - 5],
                        "INQUIRY additional-length byte mismatch")
        rows.append({'before': before, 'after': after})
    for field in (1, 2):
        before = exercise(original, 96, field)
        after = exercise(patched, 96, field)
        require(before == after, "Invalid-field behavior changed")
        require(after['deferred_error'] == 1 and after['data_pending'] == 0,
                "Invalid field was not rejected")
        rows.append({'before': before, 'after': after})
    return {'experiment': manifest['experiment'], 'comparisons': len(rows),
            'executions': 2 * len(rows), 'passed': True, 'flash_ready': False,
            'scope': 'Standard INQUIRY length/data-in setup and invalid fields only; '
                     'template writer and control-state helper stubbed; synthetic RAM/MMIO; '
                     'extended INQUIRY, transport delivery and hardware untested.',
            'results': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("patched", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.original.read_bytes(), args.patched.read_bytes())
        with args.output.open("x") as output:
            output.write(json.dumps(report, indent=2) + "\n")
        print(f"Passed {report['comparisons']} comparisons / {report['executions']} executions; hardware untested")
        return 0
    except (OSError, ValueError) as error:
        print(f"Verification stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
