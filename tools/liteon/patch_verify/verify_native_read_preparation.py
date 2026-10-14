#!/usr/bin/env python3
"""Compare real native READ preparation with the MT1939 C0 adapter.

Readiness flag tests have an explicit model. Native readiness branches,
interrupt masking/restoration and transfer stores execute original instructions.
"""
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_CPSR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401
from map_scsi import Experiment, CDB, require
from native_adapter import assemble
from verify_native_adapter import AdapterExperiment, READERS, prepare, packet

READY = 0x1afb4
PREPARE = 0x398
CONTROL = 0x04041050
PACKET = 0x04040098
STUBS = {0x1acc8: 0}
RANGES = [(READY, 0x1b14e), (PREPARE, 0x3be), (0x28c28, 0x28c44)]
RECEIVE_CONTROL = 0x040400c4
RECEIVE_RANGES = [(0x40, 0x282), (0x1ca48, 0x1ca68)]
RECEIVE_STUBS = {0x400c0: 0, 0x4057e: 0,
                 0x1bc376: 0, 0x1c9c8: 0, 0xa7952: 0}


def verify_receive(original, image):
    """Execute packet reception, including its low alias, before dispatch.

    MMIO is modeled storage: this tests instruction effects, not optical recovery.
    """
    cases = []
    for seed in (0, 0xffffffff, 0xa5a51234):
        for opcode in range(256):
            cdb = bytes([opcode, 9]) + bytes(7) + bytes([1, 0, 0])
            runs = []
            for firmware in (original, image):
                ex = Experiment(firmware, RECEIVE_RANGES, stubs=RECEIVE_STUBS,
                                fifo=struct.unpack('<III', cdb))
                ex.put(RECEIVE_CONTROL, seed, 4)
                result = ex.run(0x40)
                require(result['termination'] == 'returned' and
                        bytes(ex.cpu.mem_read(CDB, 12)) == cdb and ex.fifo_reads == 3,
                        'Receive path did not preserve the incoming packet')
                runs.append((ex, result))
            before, after = runs
            expected = seed & 0xffff0000 if opcode in (0x28, 0xa8, 0xbe, 0xc0) else seed
            require(after[0].get(RECEIVE_CONTROL, 4) == expected,
                    f'Receive setup missing or unexpected for opcode {opcode:#x}')
            effects = lambda result: [(w['address'], w['size'], w['value'])
                                     for w in result['writes']]
            if opcode != 0xc0:
                require(effects(before[1]) == effects(after[1]) and
                        before[1]['calls'] == after[1]['calls'],
                        f'Non-C0 receive effects changed for opcode {opcode:#x}')
            else:
                require(before[0].get(RECEIVE_CONTROL, 4) == seed,
                        'Original C0 fixture no longer exposes the omission')
                old = effects(before[1])
                new = effects(after[1])
                require([w for w in new if w[0] != RECEIVE_CONTROL] == old and
                        [w for w in new if w[0] == RECEIVE_CONTROL] ==
                        [(RECEIVE_CONTROL, 4, expected)],
                        'C0 reception changed effects beyond its native setup store')
            cases.append(dict(opcode=opcode, seed=seed, control=expected))

    repeated = []
    for media, kind in ((4, 0), (0x40, 1), (0x50, 1), (0xc0, 2)):
        ex = AdapterExperiment(image, ranges=RANGES + RECEIVE_RANGES,
                               stubs=STUBS | RECEIVE_STUBS, stops=READERS.values())
        for address in (READY, 0x28c30, 0x28c28):
            del ex.stubs[address]
        for attempt in range(3):
            cdb = packet(kind | (8 if attempt % 2 else 0), address=attempt, count=1)
            prepare(ex, bytes(12), media)
            state(ex, 0)
            ex.put(RECEIVE_CONTROL, 0xa5a51234, 4)
            ex.fifo = list(struct.unpack('<III', cdb))
            ex.fifo_reads = 0
            ex.finished = None
            require(ex.run(0x40)['termination'] == 'returned', 'Receive did not return')
            require(ex.get(RECEIVE_CONTROL, 4) == 0xa5a50000,
                    'C0 reception retained stale low control bits')
            ex.finished = None
            trace_start = len(ex.trace)
            result = ex.run(0x1b14e)
            require(result['pc'] == READERS[media] and
                    ex.trace[trace_start:].count(PREPARE) == 1 and
                    (ex.get(CONTROL, 4), ex.get(PACKET, 4)) == (0xb0000, 0x100),
                    'Receive-to-reader C0 preparation failed')
            repeated.append(dict(media=media, attempt=attempt, native_read_priming=False))
    return dict(opcode_cases=cases, receive_to_reader_cases=repeated,
                optical_transfer_verified=False)


def state(ex, seed):
    ex.put(0x02000601, 1)  # Ready, no pending write or absent-medium flags.
    ex.put(CONTROL, seed, 4)
    ex.put(PACKET, seed, 4)


def native_ready(original, opcode, seed):
    ex = Experiment(original, RANGES, stubs=STUBS)
    state(ex, seed)
    ex.put(CDB, opcode)
    ex.cpu.reg_write(UC_ARM_REG_R0, 1)
    result = ex.run(READY)
    require(result['termination'] == 'returned' and ex.cpu.reg_read(UC_ARM_REG_R0) == 1,
            'Native readiness fixture did not accept the command')
    return ex


def verify(original):
    image, _ = assemble(original)
    native_cases, cases = [], []
    for seed in (0, 0xffffffff, 0xa5a55a5a):
        expected = (seed | 0xb0000, seed | 0x100)
        # The omission is in native opcode classification: C0 is ready but
        # does not run the preparation used by all four native READ opcodes.
        before = native_ready(original, 0xc0, seed)
        require(PREPARE not in before.trace, 'Native C0 unexpectedly prepares reads')
        for opcode in (0x28, 0xa8, 0xbe, 0xb9):
            ex = native_ready(original, opcode, seed)
            require(PREPARE in ex.trace and
                    (ex.get(CONTROL, 4), ex.get(PACKET, 4)) == expected,
                    'Native READ preparation changed')
            native_cases.append(dict(opcode=opcode, seed=seed,
                                     native_control=ex.get(CONTROL, 4),
                                     native_packet=ex.get(PACKET, 4)))
        for media, kind in ((4, 0), (0x40, 1), (0x50, 1), (0xc0, 2)):
            ex = AdapterExperiment(image, stubs=STUBS,
                                   ranges=RANGES, stops=READERS.values())
            del ex.stubs[READY]  # Execute real readiness, not the usual success stub.
            del ex.stubs[0x28c30]
            del ex.stubs[0x28c28]
            prepare(ex, packet(kind, address=0, count=1), media)
            state(ex, seed)
            result = ex.run(0x1b14e)
            require(result['pc'] == READERS[media] and PREPARE in ex.trace,
                    'C0 reached a reader without native read preparation')
            require((ex.get(CONTROL, 4), ex.get(PACKET, 4)) == expected,
                    'C0 read preparation differs from ordinary READ')
            require(0x28c28 in ex.trace and ex.cpu.reg_read(UC_ARM_REG_CPSR) & 0xc0 == 0,
                    'Read preparation did not restore the interrupt state')
            cases.append(dict(media=media, seed=seed,
                              before_control=before.get(CONTROL, 4),
                              before_packet=before.get(PACKET, 4),
                              after_control=ex.get(CONTROL, 4),
                              after_packet=ex.get(PACKET, 4)))
    require(any(c['before_control'] != c['after_control'] or
                c['before_packet'] != c['after_packet'] for c in cases),
            'Fixtures failed to expose the omitted register setup')
    repeated = []
    for media, kind in ((4, 0), (0x40, 1), (0x50, 1), (0xc0, 2)):
        ex = AdapterExperiment(image, stubs=STUBS,
                               ranges=RANGES, stops=READERS.values())
        for address in (READY, 0x28c30, 0x28c28):
            del ex.stubs[address]
        for attempt, flags in enumerate((kind, kind | 8, kind)):
            # Model setup bits lost between independent requests. No native
            # READ or host priming is allowed to run before the next C0.
            prepare(ex, packet(flags, address=attempt, count=1), media)
            state(ex, 0)
            ex.finished = None
            trace_start = len(ex.trace)
            result = ex.run(0x1b14e)
            trace = ex.trace[trace_start:]
            require(result['pc'] == READERS[media] and trace.count(PREPARE) == 1,
                    'Repeated C0 did not prepare exactly once before its reader')
            require((ex.get(CONTROL, 4), ex.get(PACKET, 4)) == (0xb0000, 0x100),
                    'Repeated C0 depended on preparation retained from an earlier read')
            repeated.append(dict(media=media, attempt=attempt, flags=flags,
                                 native_read_priming=False))
    return dict(receive_preparation=verify_receive(original, image),
                native_read_cases=native_cases, c0_preparation_cases=cases,
                repeated_c0_preparation_cases=repeated,
                optical_transfer_verified=False,
                limitations=['Readiness flag tests are modeled; native interrupt instructions execute.',
                             'This proves register parity with native READ, not the cause of the physical Wii error.'])
