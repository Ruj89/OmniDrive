#!/usr/bin/env python3
"""Build a physical MT1939 research candidate and execute its native startup.

This establishes size, checksum, scatter initialization and bounded hook ABI.
It does not establish exclusive runtime ownership or optical functionality.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_SP

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import CHECKSUM_OFFSET, native_word_sum
from map_scsi import require
from native_adapter import (assemble, reviewed_offsets, FLASH_PAYLOAD_BASE,
                            FLASH_PAYLOAD_LIMIT)

RAM_BASE, RAM_SIZE = 0x01ff0000, 0x20000
SCATTER_BEGIN, SCATTER_END = 0x1ce2e0, 0x1ce370
STARTUP_END = 0x1b9de4


def startup(image, poison):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(RAM_BASE, RAM_SIZE)
    cpu.mem_write(RAM_BASE, bytes([poison]) * RAM_SIZE)
    reads, stack_at_scatter = [], []

    def code(cpu, address, size, _):
        require(0x1bba20 <= address < 0x1bba50 or 0x1ac00 <= address < 0x1ac94,
                f'Unexpected startup execution at {address:#x}')
        if address == 0x1ac00:
            stack_at_scatter.append(cpu.reg_read(UC_ARM_REG_SP))

    def read(cpu, access, address, size, value, _):
        require(address + size <= FLASH_PAYLOAD_BASE or address >= FLASH_PAYLOAD_LIMIT,
                'Native startup reads from the payload allocation')
        reads.append((address, size))

    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.hook_add(UC_HOOK_MEM_READ, read)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xd3)
    cpu.emu_start(0x1bba20, STARTUP_END, count=20000)
    require(cpu.reg_read(UC_ARM_REG_PC) == STARTUP_END, 'Startup instruction limit reached')
    require(stack_at_scatter == [0x01ffff00], 'Unexpected native SVC stack')
    stacks = {}
    for name, mode in [('fiq', 0x11), ('irq', 0x12), ('abort', 0x17),
                       ('undefined', 0x1b), ('supervisor', 0x13)]:
        cpu.reg_write(UC_ARM_REG_CPSR, 0xc0 | mode)
        stacks[name] = cpu.reg_read(UC_ARM_REG_SP)
    require(stacks == {'fiq': 0x2000400, 'irq': 0x2000200, 'abort': 0x2000000,
                       'undefined': 0x2000000, 'supervisor': 0x1ffff00},
            'Banked native stacks changed')
    return bytes(cpu.mem_read(RAM_BASE, RAM_SIZE)), {
        'poison_byte': poison, 'termination_pc': STARTUP_END,
        'native_stacks': stacks, 'data_read_count': len(reads),
        'payload_data_reads': 0,
    }


def verify(original):
    candidate, symbols = assemble(original)
    records = []
    copied_end = 0
    for address in range(SCATTER_BEGIN, SCATTER_END, 16):
        source, destination, size, handler = struct.unpack_from('<IIII', candidate, address)
        require(handler in (0x1ac40, 0x1ac68), 'Unknown scatter handler')
        require(RAM_BASE <= destination < destination + size <= RAM_BASE + RAM_SIZE,
                'Scatter writes outside mapped native RAM')
        if handler == 0x1ac40:
            copied_end = max(copied_end, source + size)
        records.append({'record': address, 'source': source, 'destination': destination,
                        'size': size, 'operation': 'copy' if handler == 0x1ac40 else 'zero'})
    require(copied_end == 0x1cf750 and copied_end <= FLASH_PAYLOAD_BASE, 'Payload overlaps initialized ROM data')
    require(candidate[0x1ce2e0:0x1ce370] == original[0x1ce2e0:0x1ce370], 'Scatter records changed')
    startup_cases = []
    for poison in (0xa5, 0x5a):
        before, _ = startup(original, poison)
        after, evidence = startup(candidate, poison)
        # The adapter allocates no RAM: initialization must be byte-identical.
        require(after == before, 'Native RAM initialization changed')
        for record in records:
            start = record['destination'] - RAM_BASE
            expected = (candidate[record['source']:record['source'] + record['size']]
                        if record['operation'] == 'copy' else bytes(record['size']))
            require(after[start:start + record['size']] == expected,
                    'Native scatter result differs from its record')
        startup_cases.append(evidence)
    allowed = reviewed_offsets()
    changes = [i for i, (a, b) in enumerate(zip(original, candidate)) if a != b]
    require(set(changes) <= allowed, 'Unreviewed bytes changed')
    checksum = struct.unpack_from('<I', candidate, CHECKSUM_OFFSET)[0]
    require(checksum == native_word_sum(candidate), 'Native checksum mismatch')
    report = {
        'physical_startup_verified': True, 'full_omnidrive_port': False, 'flash_ready': False,
        'original_sha256': hashlib.sha256(original).hexdigest(),
        'candidate_sha256': hashlib.sha256(candidate).hexdigest(),
        'image_size': len(candidate), 'payload_base': FLASH_PAYLOAD_BASE,
        'payload_limit': FLASH_PAYLOAD_LIMIT, 'adapter_ram_bytes': 0,
        'symbols': {k: v for k, v in symbols.items() if k.startswith('Mt')}, 'scatter_records': records, 'startup_cases': startup_cases,
        'native_checksum': checksum, 'changed_byte_count': len(changes),
        'limitations': [
            'The adapter allocates no RAM; startup RAM is byte-identical to the original.',
            'Hook, transfer and loader behavior require their separate verifiers.',
            'This startup experiment establishes neither complete optical transfer nor device flashing.',
        ],
    }
    return candidate, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New research image path')
    parser.add_argument('--report', required=True, type=Path, help='New JSON manifest path')
    args = parser.parse_args()
    # Check both names before creating either artifact.
    require(not args.output.exists() and not args.report.exists(), 'Outputs must be new')
    candidate, report = verify(args.original.read_bytes())
    with args.output.open('xb') as output:
        output.write(candidate)
    with args.report.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(f'Physical startup verified; {len(candidate)} bytes; flash_ready: false')


if __name__ == '__main__':
    main()
