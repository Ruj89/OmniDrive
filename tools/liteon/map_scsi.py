#!/usr/bin/env python3
# Purpose: Trace SCSI command handling in the pinned firmware using bounded emulation.
"""Offline SCSI dispatch map for the exact BW-12B1LT 1.03 specimen.

Executes original instructions in synthetic RAM/MMIO. Calls outside each
experiment's scope must be explicitly stopped or stubbed. No device access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from importlib.metadata import version

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from map_firmware import IMAGE_SHA256

CDB = 0x02000d20
MEDIA = 0x01ffabf0
START = 0x020006bc
LENGTH = 0x020006c4
SENSE = 0x02000602
SENTINEL = 0x03000000
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Experiment:
    def __init__(self, image, ranges, *, stubs=None, stops=(), fifo=()):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cpu.mem_map(0, 0x200000)
        self.cpu.mem_write(0, image)
        # A local alias supported by BL 0x40 callers and matching outbound
        # calls; the hardware mechanism establishing it is still unresolved.
        self.cpu.mem_write(0, image[0x10000:0x10400])
        self.cpu.mem_map(0x01ff0000, 0x20000)
        self.cpu.mem_map(SENTINEL, 0x1000)
        self.cpu.mem_map(0x04000000, 0x100000)
        self.ranges = ranges
        self.stubs = stubs or {}
        self.stops = set(stops)
        self.fifo = list(fifo)
        self.fifo_reads = 0
        self.calls, self.writes, self.trace = [], [], []
        self.finished = None
        self.cpu.hook_add(UC_HOOK_CODE, self.code)
        self.cpu.hook_add(UC_HOOK_MEM_READ, self.read)
        self.cpu.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def put(self, address, value, size=1):
        self.cpu.mem_write(address, value.to_bytes(size, 'little'))

    def get(self, address, size=1):
        return int.from_bytes(self.cpu.mem_read(address, size), 'little')

    def code(self, cpu, address, size, _):
        self.trace.append(address)
        if address == SENTINEL:
            self.finished = 'returned'
            cpu.emu_stop()
        elif address in self.stops:
            self.calls.append({'target': address, 'args': [cpu.reg_read(r) for r in REGS]})
            self.finished = 'boundary'
            cpu.emu_stop()
        elif address in self.stubs:
            result = self.stubs[address]
            self.calls.append({'target': address, 'args': [cpu.reg_read(r) for r in REGS],
                               'stub_return': result})
            cpu.reg_write(UC_ARM_REG_R0, result)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif not any(start <= address < end for start, end in self.ranges):
            raise ValueError(f'Unmodelled execution at {address:#x}')

    def read(self, cpu, access, address, size, value, _):
        if address == 0x040400a8 and self.fifo:
            require(size == 4 and self.fifo_reads < len(self.fifo), 'Unexpected FIFO read')
            self.put(address, self.fifo[self.fifo_reads], 4)
            self.fifo_reads += 1

    def write(self, cpu, access, address, size, value, _):
        if not 0x0200e000 <= address < 0x02010000:
            self.writes.append({'pc': cpu.reg_read(UC_ARM_REG_PC), 'address': address,
                                'size': size, 'value': value})

    def run(self, entry, count=4000):
        self.cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        self.cpu.reg_write(UC_ARM_REG_SP, 0x0200fff0)
        self.cpu.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
        self.cpu.emu_start(entry | 1, SENTINEL, count=count)
        if self.cpu.reg_read(UC_ARM_REG_PC) == SENTINEL:
            self.finished = 'returned'
        require(self.finished is not None, f'Instruction limit at {entry:#x}')
        return {'entry': entry, 'termination': self.finished,
                'pc': self.cpu.reg_read(UC_ARM_REG_PC), 'calls': self.calls,
                'sense': list(self.cpu.mem_read(SENSE, 3)),
                'start': self.get(START, 4), 'length': self.get(LENGTH, 4),
                'cdb_after': bytes(self.cpu.mem_read(CDB, 12)).hex(),
                'writes': self.writes, 'trace': self.trace,
                'stubs': {f'{a:#x}': v for a, v in self.stubs.items()}}


def dispatch(image):
    """All opcodes for six representative media bytes, stopping at handlers.

    Only readiness helper 0x1afb4 is replaced (returns success). This verifies
    routing, not readiness, handler success, or real media classification.
    """
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    targets = set()
    # Decode potential BL/BLX at every halfword; only reached targets count
    # as evidence. This avoids losing alignment across inline switch data.
    for a in range(0x1b14e, 0x1bdea, 2):
        h = int.from_bytes(image[a:a+2], 'little')
        if h & 0xf800 == 0xf000:
            for i in cs.disasm(image[a:a+4], a, count=1):
                if i.mnemonic in ('bl', 'blx') and i.op_str.startswith('#'):
                    targets.add(int(i.op_str[1:], 0))
    targets.discard(0x1afb4)
    rows = []
    for media in (0, 4, 0x40, 0x50, 0x60, 0xc0):
        for opcode in range(256):
            ex = Experiment(image, [(0x1b14e, 0x1bdea)], stubs={0x1afb4: 1})
            ex.put(CDB, opcode)
            ex.put(MEDIA, media)
            ex.put(0x02000611, 1)  # packet branch
            ex.stops.update(targets)
            result = ex.run(0x1b14e)
            if result['termination'] == 'boundary':
                caller = result['trace'][-2]
                ins = next(cs.disasm(image[caller:caller + 4], caller))
                require(ins.mnemonic in ('bl', 'blx') and
                        int(ins.op_str[1:], 0) == result['pc'],
                        'Dispatcher boundary is not an executed direct call')
            result.update(opcode=opcode, media=media)
            rows.append(result)
    by_key = {(r['opcode'], r['media']): r for r in rows}
    for media in (0, 4, 0x40, 0x50, 0x60, 0xc0):
        require(by_key[0x12, media]['pc'] == 0x9cab0, 'INQUIRY routing mismatch')
        require(by_key[3, media]['pc'] == 0x9dbf2, 'REQUEST SENSE routing mismatch')
        require(by_key[0xc0, media]['sense'] == [5, 0x20, 0], 'C0 rejection mismatch')
    for opcode in (0x28, 0xa8):
        for media, target in ((4, 0xe468c), (0x40, 0xc8404), (0x50, 0xc8404),
                              (0x60, 0xc8404), (0xc0, 0xace90)):
            require(by_key[opcode, media]['pc'] == target, 'READ routing mismatch')
    for media, target in ((4, 0xe48e8), (0x40, 0xc8404), (0xc0, 0xad130)):
        require(by_key[0xbe, media]['pc'] == target, 'READ CD routing mismatch')
    require(by_key[0xb9, 4]['pc'] == 0xe4b78, 'READ CD MSF routing mismatch')
    ex = Experiment(image, [(0x1b14e, 0x1bdea)], stubs={0x1afb4: 0})
    ex.put(CDB, 0x28); ex.put(MEDIA, 4); ex.put(0x02000611, 1)
    refused = ex.run(0x1b14e)
    require(refused['termination'] == 'returned', 'Readiness failure did not return')
    return {'cases': rows, 'readiness_failure': refused}


def receive(image):
    rows = []
    for packet in (bytes(range(12)), bytes.fromhex('280012345678001234aabbcc'),
                   bytes.fromhex('a80800123456000002000000'), b'\xff' * 12):
        ex = Experiment(image, [(0x40, 0xae)], stops=[0xae],
                        fifo=struct.unpack('<III', packet))
        ex.cpu.mem_write(CDB - 1, b'\xa5' * 14)
        result = ex.run(0x40)
        require(bytes(ex.cpu.mem_read(CDB, 12)) == packet, 'CDB copy mismatch')
        require(ex.get(CDB - 1) == ex.get(CDB + 12) == 0xa5, 'CDB bounds violated')
        require(ex.fifo_reads == 3, 'FIFO word count mismatch')
        result.update(packet=packet.hex(), fifo_reads=ex.fifo_reads)
        rows.append(result)
    ex = Experiment(image, [(0x40, 0xae)], stubs={0x3fe3c: 0}, fifo=[1, 2, 3])
    ex.put(0x0200060f, 1)
    ex.cpu.mem_write(CDB, b'\xa5' * 12)
    result = ex.run(0x40)
    require(ex.fifo_reads == 0 and result['cdb_after'] == 'a5' * 12, 'Busy path consumed CDB')
    rows.append(result)
    packet = bytes.fromhex('120000002400000000000000')
    ex = Experiment(image, [(0x40, 0x282)],
                    stubs={0x400c0: 0, 0x1ca48: 0, 0x4057e: 0,
                           0x1bc376: 0, 0x1c9c8: 0},
                    fifo=struct.unpack('<III', packet))
    result = ex.run(0x40)
    require(ex.get(0x02000611) == 1 and result['cdb_after'] == packet.hex(),
            'Receive did not publish packet flag')
    result.update(packet=packet.hex(), packet_pending=ex.get(0x02000611))
    rows.append(result)
    return rows


def parsers(image):
    rows = []
    for entry, media, bias, helper, stop in (
            (0xe468c, 4, 150, 0x1bd77e, 0x18a060),
            (0xc8404, 0x40, 0x30000, 0x1bbc1c, 0x1bf38c),
            (0xc8404, 0x50, 0x31000, 0x1bbc1c, 0xe3370),
            (0xace90, 0xc0, 0x100000, None, 0xb5828)):
        for opcode in (0x28, 0xa8):
            for fua in (0, 8):
                packet = bytearray(12)
                packet[0:2] = bytes([opcode, fua])
                packet[2:6] = (0x123456).to_bytes(4, 'big')
                if opcode == 0x28:
                    packet[7:9] = (0x234).to_bytes(2, 'big')
                else:
                    packet[6:10] = (0x234).to_bytes(4, 'big')
                # CD type lookup returns synthetic data-sector selector 2;
                # DVD lookup returns synthetic success 0.
                stubs = {} if helper is None else {helper: 2 if media == 4 else 0}
                if media == 4:
                    stubs[0xe4668] = 0
                ex = Experiment(image, [(entry, entry + 0x500), (0xc83e0, 0xc8404)], stubs=stubs, stops=[stop])
                ex.cpu.mem_write(CDB, bytes(packet)); ex.put(MEDIA, media)
                ex.put(0x020006b8, 0x7fffffff, 4)
                result = ex.run(entry)
                require(result['pc'] == stop, 'Read parser did not reach data function')
                require(result['start'] == 0x123456 + bias and result['length'] == 0x234,
                        'Read address/length mismatch')
                require(result['calls'][-1]['args'][0] == fua, 'FUA argument mismatch')
                result.update(packet=packet.hex(), media=media, bias=bias, fua=fua)
                rows.append(result)
    # READ CD: inspect before the optical helper, after LBA/24-bit length parsing.
    packet = bytes.fromhex('be0000123456000234100000')
    ex = Experiment(image, [(0xe48e8, 0xe4958)], stops=[0xe4958])
    ex.cpu.mem_write(CDB, packet); ex.put(MEDIA, 4)
    result = ex.run(0xe48e8)
    require(result['start'] == 0x123456 + 150 and result['length'] == 0x234, 'READ CD fields')
    result['packet'] = packet.hex(); rows.append(result)
    # READ CD MSF executes the original MSF converter twice.
    packet = bytes.fromhex('b90000000200000300100000')
    ex = Experiment(image, [(0xe4b78, 0xe4c2c), (0xe8ba0, 0xe8bbc)], stops=[0xe4c2c])
    ex.cpu.mem_write(CDB, packet); ex.put(MEDIA, 4)
    result = ex.run(0xe4b78)
    require(result['start'] == 150 and result['length'] == 75, 'MSF conversion mismatch')
    result['packet'] = packet.hex(); rows.append(result)
    return rows


def responses(image):
    rows = []
    for allocation in (0, 1, 36, 95, 96, 255):
        ex = Experiment(image, [(0x9cab0, 0x9cba8), (0x9b8c0, 0x9b8e6)],
                        stubs={0xa6646: 0, 0x9ca70: 0})
        ex.cpu.mem_write(CDB, bytes([0x12, 0, 0, 0, allocation, 0]) + b'\0' * 6)
        ex.put(0x02000648, 0x01000000, 4)  # synthetic buffer base
        result = ex.run(0x9cab0)
        logical = min(allocation, 96)
        padded = (logical + 1) & ~1
        require(ex.get(0x02000636, 2) == padded, 'INQUIRY transfer length')
        require(ex.get(0x02000613) == bool(allocation), 'INQUIRY data-ready flag')
        if allocation:
            require(ex.get(0x040300e8, 4) == 0x0101c780, 'INQUIRY data pointer')
            require(ex.get(0x04042154, 4) == padded, 'INQUIRY MMIO length')
        result.update(allocation=allocation, logical_length=logical, padded_length=padded)
        rows.append(result)
    # Invalid standard inquiry: EVPD bit or nonzero page sets deferred error.
    for field, value in ((1, 1), (2, 1)):
        ex = Experiment(image, [(0x9cab0, 0x9cba8)])
        ex.put(CDB, 0x12); ex.put(CDB + field, value); ex.put(CDB + 4, 36)
        result = ex.run(0x9cab0)
        require(ex.get(0x02000616) == 1, 'INQUIRY invalid-field flag')
        rows.append(result)
    # Execute REQUEST SENSE including original ARM test-and-clear helper.
    ex = Experiment(image, [(0x9dbf2, 0x9de9c), (0x9df80, 0x9dfe8), (0x9b89c, 0x9b8c0)])
    ex.put(CDB, 3); ex.put(CDB + 4, 18)
    ex.cpu.mem_write(SENSE, bytes([5, 0x24, 0]))
    result = ex.run(0x9dbf2)
    fifo = [w['value'] for w in ex.writes if w['address'] == 0x040400a8]
    require(len(fifo) == 18 and fifo[0] == 0x70 and fifo[2] == 5 and fifo[12:14] == [0x24, 0],
            'REQUEST SENSE payload mismatch')
    result['fifo_bytes'] = fifo; rows.append(result)
    return rows


# Reviewed code spans: exclude embedded switch data and literal pools.
SECTIONS = [
    ('Receive routine (low alias)', 0x10040, 0x10282, 0x40, True),
    ('Receive callers', 0x1d002, 0x1d036, 0x1d002, True),
    ('Second receive call', 0x1d4c8, 0x1d4e0, 0x1d4c8, True),
    ('Dispatcher entry / comparisons', 0x1b14e, 0x1b2e6, 0x1b14e, True),
    ('Dispatcher comparisons', 0x1b302, 0x1b378, 0x1b302, True),
    ('Dispatcher comparisons', 0x1b3b4, 0x1b40c, 0x1b3b4, True),
    ('Read dispatch', 0x1b41e, 0x1b4c4, 0x1b41e, True),
    ('Unsupported opcode', 0x1bba4, 0x1bbac, 0x1bba4, True),
    ('INQUIRY call', 0x1bbfa, 0x1bc06, 0x1bbfa, True),
    ('Sense return tail', 0x1bd0e, 0x1bd14, 0x1bd0e, True),
    ('Command wrapper', 0x1bdea, 0x1be48, 0x1bdea, True),
    ('Main loop dispatch call', 0x1c0f8, 0x1c116, 0x1c0f8, True),
    ('INQUIRY', 0x9cab0, 0x9cba8, 0x9cab0, True),
    ('Data-in setup', 0x9b8c0, 0x9b8e6, 0x9b8c0, True),
    ('REQUEST SENSE payload', 0x9dce0, 0x9de98, 0x9dce0, True),
    ('REQUEST SENSE tail', 0x9df80, 0x9dfe8, 0x9df80, True),
    ('Completion / deferred errors', 0x40148, 0x40236, 0x40148, True),
    ('Status register helper', 0x3fcec, 0x3fd62, 0x3fcec, True),
    ('CD READ parser', 0xe468c, 0xe4748, 0xe468c, True),
    ('DVD READ parser', 0xc8404, 0xc85ea, 0xc8404, True),
    ('BD READ parser', 0xace90, 0xacf6a, 0xace90, True),
    ('READ CD parser', 0xe48e8, 0xe4a60, 0xe48e8, True),
    ('READ CD MSF parser', 0xe4b78, 0xe4c2c, 0xe4b78, True),
    ('MSF conversion', 0xe8ba0, 0xe8bbc, 0xe8ba0, True),
    ('Startup scatter loader', 0x1ac00, 0x1ac38, 0x1ac00, False),
    ('Startup copy/zero helpers', 0x1ac40, 0x1ac94, 0x1ac40, False),
]


def listing(image):
    lines = ['Original instructions; file offsets and execution addresses are distinct.',
             'Low alias is a local mapping hypothesis supported by callers, not a boot emulation.']
    for title, start, end, runtime, thumb in SECTIONS:
        lines.append(f'\n{title}: file {start:#x}, execution {runtime:#x}')
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        for i in cs.disasm(image[start:end], runtime):
            file_offset = start + i.address - runtime
            note = ''
            h = int.from_bytes(i.bytes[:2], 'little')
            if thumb and i.size == 2 and h & 0xf800 == 0x4800:
                literal = ((i.address + 4) & ~3) + (h & 255) * 4
                p = start + literal - runtime
                note = f' ; literal file {p:#x} = {struct.unpack_from("<I", image, p)[0]:#010x}'
            lines.append(f'{file_offset:08x} / {i.address:08x}: {i.bytes.hex():10} {i.mnemonic} {i.op_str}{note}')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    image = args.image.read_bytes()
    require(len(image) == 0x200000 and hashlib.sha256(image).hexdigest() == IMAGE_SHA256,
            'Unsupported specimen: expected validated decoded BW-12B1LT 1.03 image')
    require(not args.output_dir.exists(), 'Output directory must be new')
    report = {'image_sha256': IMAGE_SHA256, 'patch_ready': False,
              'dependencies': {name: version(name) for name in ('capstone', 'unicorn')},
              'limitations': ['Synthetic RAM/MMIO, no optical or transport emulation',
                              'Explicit stubs and stopping boundaries recorded per case',
                              'Local file 0x10000 -> runtime 0 alias; boot mechanism unresolved'],
              'receive': receive(image), 'dispatch': dispatch(image),
              'parsers': parsers(image), 'responses': responses(image)}
    report['switch_tables'] = [
        {'file_offset': a, 'opcode': first + n,
         'target': base + 2 * struct.unpack_from('<H', image, a)[0]}
        for start, count, first, base in ((0x1b2e6, 14, 0x45, 0x1b2e8),
                                         (0x1b378, 30, 0xa1, 0x1b37a),
                                         (0x1b40c, 9, 0xf7, 0x1b40e))
        for n in range(count) for a in [start + n * 2]]
    args.output_dir.mkdir(parents=True)
    (args.output_dir / 'scsi-map.json').write_text(json.dumps(report, indent=2) + '\n')
    (args.output_dir / 'scsi-disassembly.txt').write_text(listing(image))
    print(f'Verified: {len(report["receive"])} reception, '
          f'{len(report["dispatch"]["cases"])} dispatch + 1 readiness, '
          f'{len(report["parsers"])} parser, {len(report["responses"])} response cases')
    print(f'Reports: {args.output_dir}; patch_ready: false')


if __name__ == '__main__':
    main()
