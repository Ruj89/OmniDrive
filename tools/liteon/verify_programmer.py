#!/usr/bin/env python3
# Purpose: Emulate the pinned flash programmer and audit its erase and program operations.
"""Audit the pinned imported flash programmer offline, through its native return.

Unicorn executes the original Thumb code. SPI/controller responses and a NOR
array are modeled in memory. No device, ioctl, Windows API or flasher is opened.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

from audit_integrity import REGIONS
from verify_loader import Utility, IMAGE_SHA256, build, require, sha, validate_inquiry

FLASH_SIZE = 0x200000
PROGRAMMER_SHA256 = '25341b2fc683c3b8bd0796c698f398d015565a0c71ef94de76ced9f8a6fdb666'


class Nor:
    """Only the serial operations actually used by this pinned programmer.

    Macronix PM1290 rev 1.5 / PM1374 rev 2.2: D8 erases the addressed 64 KiB
    block, 20 a 4 KiB sector, and 02 programs within a 256-byte page. Ready
    status is immediate. Protection writes are recorded, not hardware evidence.
    """
    def __init__(self, original, jedec, fault=None):
        require(len(original) == FLASH_SIZE, 'Expected a 2 MiB NOR array')
        require(jedec in (0xc22015, 0xc22415), 'Unsupported modeled JEDEC ID')
        require(fault in (None, 'drop_once', 'drop_always', 'read_once'), 'Unknown fault')
        self.data = bytearray(original)
        self.jedec, self.fault, self.fault_count = jedec, fault, 0
        self.wel, self.status = False, 0
        self.counts = Counter()
        self.erases, self.programs, self.status_writes = [], [], []
        self.erased = bytearray(FLASH_SIZE)
        self.programmed = bytearray(FLASH_SIZE)
        self.trace = hashlib.sha256()

    def range(self, start, length):
        require(0 <= start < FLASH_SIZE and 0 < length <= FLASH_SIZE - start,
                'SPI operation outside modeled flash')

    def transact(self, tx, rx_length, pc):
        require(bool(tx), 'Empty SPI command')
        op = tx[0]
        self.counts[op] += 1
        response = b''
        if op == 0x9f:
            require(len(tx) == 1 and rx_length == 3, 'Unexpected RDID lengths')
            response = self.jedec.to_bytes(3, 'big')
        elif op == 5:
            require(len(tx) == 1 and rx_length == 1, 'Unexpected RDSR lengths')
            response = bytes([self.status | (2 if self.wel else 0)])
        elif op in (6, 4):
            require(len(tx) == 1 and rx_length == 0, 'Unexpected WREN/WRDI lengths')
            self.wel = op == 6
        elif op == 1:
            require(len(tx) == 2 and rx_length == 0 and self.wel, 'Unexpected WRSR')
            self.status = tx[1] & 0xfc
            self.status_writes.append({'pc': pc, 'value': tx[1]})
            self.wel = False
        elif op in (0xd8, 0x20, 2):
            require(self.wel and not self.status & 0x3c, 'Write without WREN or while protected')
            require(len(tx) >= 4 and rx_length == 0, 'Unexpected mutation lengths')
            address = int.from_bytes(tx[1:4], 'big')
            if op in (0xd8, 0x20):
                require(len(tx) == 4, 'Unexpected erase payload')
                length = 0x10000 if op == 0xd8 else 0x1000
                start = address & ~(length - 1)
                self.range(start, length)
                self.data[start:start + length] = b'\xff' * length
                self.erased[start:start + length] = b'\x01' * length
                self.erases.append({'pc': pc, 'opcode': op, 'command_address': address,
                                    'start': start, 'end_exclusive': start + length})
            else:
                payload = tx[4:]
                self.range(address, len(payload))
                require(len(payload) <= 256 and address // 256 == (address + len(payload) - 1) // 256,
                        'Program crosses a NOR page')
                dropped = address == 0x10000 and (self.fault == 'drop_always' or
                          self.fault == 'drop_once' and self.fault_count == 0)
                if dropped:
                    self.fault_count += 1
                else:
                    self.data[address:address + len(payload)] = bytes(
                        a & b for a, b in zip(self.data[address:address + len(payload)], payload))
                self.programmed[address:address + len(payload)] = b'\x01' * len(payload)
                self.programs.append((address, len(payload)))
            self.wel = False
        elif op == 0x0b:
            require(len(tx) == 5, 'Unexpected FAST READ command')  # fifth byte is dummy
            address = int.from_bytes(tx[1:4], 'big')
            self.range(address, rx_length)
            response = bytes(self.data[address:address + rx_length])
            if address == 0x10000 and self.fault == 'read_once' and not self.fault_count:
                response = bytes([response[0] ^ 1]) + response[1:]
                self.fault_count += 1
        else:
            raise ValueError(f'Unmodeled SPI opcode {op:#x} at {pc:#x}')
        require(len(response) == rx_length, 'SPI response length differs')
        self.trace.update(struct.pack('<III', pc, len(tx), rx_length) + tx + response)
        return response


def run(code, original, incoming, jedec, control, *, fault=None, interrupt=None):
    require(sha(code) == PROGRAMMER_SHA256, 'Unexpected imported programmer')
    require(len(incoming) == FLASH_SIZE, 'Unexpected staged image size')
    require(control in (0x80, 0xa0), 'Unsupported final control')
    require(interrupt in (None, 'first_erase', 'first_program'), 'Unknown interruption')
    nor = Nor(original, jedec, fault)
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for address, length in ((0x19000, 0x2000), (0x2000000, 0x10000),
                            (0x3000000, 0x1000), (0x4000000, 0x100000),
                            (0x1000000, FLASH_SIZE), (0x800000, 0x1000)):
        u.mem_map(address, length)
    u.mem_write(0x19000, code)
    u.mem_write(0x1000000, incoming)
    u.mem_write(0x2000f20, b'\xff' * 12)
    u.mem_write(0x40d000c, struct.pack('<I', 0x100))  # synthetic staging base
    u.mem_write(0x11e600b, bytes([control]))
    start = 0x10000 if control == 0x80 else 0
    u.mem_write(0x11e600c, struct.pack('<III', start, start, 0x1e0000 - start))
    interrupted, mismatches = [], []

    def get(address):
        return int.from_bytes(u.mem_read(address, 4), 'little')

    def ready(uc, access, address, size, value, unused):
        if address == 0x4010008:
            uc.mem_write(address, struct.pack('<I', get(address) & ~0x100))
        elif address == 0x4011010:
            uc.mem_write(address, b'\x02')  # completed, not busy

    def serial(uc, access, address, size, value, unused):
        if not value & 2:
            return
        require(size == 4, 'Unexpected SPI trigger access size')
        tx_length, rx_length = get(0x4011008) & 0x3ff, get(0x4011004) & 0x3ff
        require(tx_length + rx_length <= 0x1000, 'SPI buffer overflow')
        tx = bytes(uc.mem_read(0x800000, tx_length))
        response = nor.transact(tx, rx_length, uc.reg_read(UC_ARM_REG_PC))
        if response:
            uc.mem_write(0x800000 + tx_length, response)
        if (interrupt == 'first_erase' and tx[0] in (0xd8, 0x20) or
                interrupt == 'first_program' and tx[0] == 2):
            interrupted.append(uc.reg_read(UC_ARM_REG_PC))
            uc.emu_stop()

    def mismatch(uc, address, size, unused):
        # Reached only when the native byte comparison at 0x19a98 fails.
        mismatches.append(address)

    for address in (0x4010008, 0x4011010):
        u.hook_add(UC_HOOK_MEM_READ, ready, begin=address, end=address)
    u.hook_add(UC_HOOK_MEM_WRITE, serial, begin=0x401100c, end=0x401100c)
    u.hook_add(UC_HOOK_CODE, mismatch, begin=0x19a9c, end=0x19a9c)
    u.reg_write(UC_ARM_REG_SP, 0x200f000)
    u.reg_write(UC_ARM_REG_LR, 0x3000001)
    u.emu_start(0x19001, 0x3000000, count=100000000, timeout=20000000)
    pc = u.reg_read(UC_ARM_REG_PC)
    require(bool(interrupted) or pc == 0x3000000, f'Programmer execution limit at {pc:#x}')
    expected = original[:start] + incoming[start:0x1e0000] + original[0x1e0000:]
    regions = []
    for name, begin, end in REGIONS:
        regions.append({'name': name, 'start': begin, 'end_exclusive': end,
                        'erase_touched_bytes': sum(nor.erased[begin:end]),
                        'program_touched_bytes': sum(nor.programmed[begin:end]),
                        'matches_original': nor.data[begin:end] == original[begin:end],
                        'matches_expected': nor.data[begin:end] == expected[begin:end],
                        'result_sha256': sha(nor.data[begin:end])})
    return {'jedec': f'{jedec:06x}', 'control': control, 'fault': fault,
            'interruption': interrupt, 'interrupted': bool(interrupted), 'stop_pc': pc,
            'native_return_reached': pc == 0x3000000,
            'selected_parameters_hex': bytes(u.mem_read(0x2000f20, 12)).hex(),
            'spi_counts': {f'{op:02x}': count for op, count in sorted(nor.counts.items())},
            'spi_trace_sha256': nor.trace.hexdigest(), 'erases': nor.erases,
            'program_commands': len(nor.programs), 'status_writes': nor.status_writes,
            'native_readback_mismatches': len(mismatches), 'injected_fault_count': nor.fault_count,
            'final_array_matches_expected': nor.data == expected,
            'changed_bytes_from_expected': sum(a != b for a, b in zip(nor.data, expected)),
            'final_array_sha256': sha(nor.data), 'regions': regions}


def verify(original, experimental, inquiry, binary):
    require(sha(original) == IMAGE_SHA256, 'Expected pinned original firmware')
    require(experimental == build(original)[0], 'Unexpected experimental image')
    inquiry_report = validate_inquiry(original, inquiry)
    profile, descriptor = Utility(binary).profile(inquiry)
    code = profile[6:6 + descriptor['code_size']]
    cases = []
    for name, image in (('original', original), ('experimental', experimental)):
        for jedec in (0xc22015, 0xc22415):
            for control in (0x80, 0xa0):
                case = run(code, original, image, jedec, control)
                case['image'] = name
                require(case['final_array_matches_expected'], 'Successful case differs from expected flash')
                require(case['native_readback_mismatches'] == 0, 'Unexpected native mismatch')
                require(case['erases'][0]['command_address'] == 0x1df000 and
                        case['erases'][0]['start'] == 0x1d0000, 'Unexpected initialization erase')
                pages = (0x1e0000 - (0x10000 if control == 0x80 else 0)) // 256
                require(case['program_commands'] == pages and case['spi_counts']['0b'] == pages,
                        'Unexpected page program/verify coverage')
                require(case['spi_counts']['d8'] == (30 if control == 0x80 else 31),
                        'Unexpected erase count')
                for region in case['regions']:
                    touched = region['name'] in ('main', 'profile') or control == 0xa0 and region['name'] == 'boot'
                    length = region['end_exclusive'] - region['start'] if touched else 0
                    require(region['erase_touched_bytes'] == length and region['program_touched_bytes'] == length,
                            'Unexpected erase/program region coverage')
                cases.append(case)
    for fault in ('drop_once', 'drop_always', 'read_once'):
        case = run(code, original, experimental, 0xc22015, 0x80, fault=fault)
        case['image'] = 'experimental'
        require(case['injected_fault_count'] == (4 if fault == 'drop_always' else 1),
                'Unexpected native retry count')
        require(case['native_readback_mismatches'] == case['injected_fault_count'],
                'Native comparison did not detect injected faults')
        require(case['final_array_matches_expected'] == (fault != 'drop_always'),
                'Unexpected fault outcome')
        cases.append(case)
    for interrupt in ('first_erase', 'first_program'):
        case = run(code, original, experimental, 0xc22015, 0x80, interrupt=interrupt)
        case['image'] = 'experimental'
        require(case['interrupted'] and not case['final_array_matches_expected'],
                'Interruption did not expose an incomplete image')
        require(case['regions'][0]['matches_original'] and not case['regions'][2]['matches_original'],
                'Unexpected boot/profile state after interruption')
        cases.append(case)
    return {'original_sha256': sha(original), 'experimental_sha256': sha(experimental),
            'inquiry': inquiry_report, 'utility_sha256': sha(binary), 'profile': descriptor,
            'cases': cases, 'offline_programmer_audit_passed': True,
            'hardware_tested': False, 'flash_ready': False,
            'models': ['SPI lengths/commands taken from original MMIO writes; synthetic JEDEC responses.',
                       'Immediate SPI/controller completion and unprotected NOR; NOR programs by bitwise AND.',
                       'Original programmer runs from 0x19000 to return; native comparisons and retries are executed.',
                       'Peripheral command port 0x4010000 is not interpreted; its busy bit is modeled ready.',
                       'Staging/controller bases initialized separately from the firmware handoff.'],
            'limits': ['Separate entry execution does not prove controller remapping or handoff continuity.',
                       'No physical chip identity, protection/timing behavior or EEPROM/OTP preservation evidence.',
                       'Interrupted cases show in-memory damage only.',
                       'Native return alone is insufficient: the persistent dropped-page case returns with damaged data.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('experimental', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--utility', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Output already exists; choose a new report')
        inquiry = bytes.fromhex(json.loads(args.report.read_text())['extended_inquiry_hex'])
        result = verify(args.original.read_bytes(), args.experimental.read_bytes(), inquiry, args.utility.read_bytes())
        with args.output.open('x') as output:
            output.write(json.dumps(result, indent=2) + '\n')
        print(f"Offline programmer verified: {len(result['cases'])} scenarios; report: {args.output}; flash_ready=false")
        return 0
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(f'Programmer audit stopped: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
