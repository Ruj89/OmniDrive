#!/usr/bin/env python3
"""Reproduce the native 03/11/05 timeout with a stale READ timestamp.

Executes receipt accounting, the assembled adapter and the watchdog's actual
instructions. Stops before error cleanup; optical progress is explicitly zero.
"""
from pathlib import Path
import sys

from unicorn.arm_const import UC_ARM_REG_R5

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401
from map_scsi import CDB, SENSE, Experiment, require
from verify_native_adapter import AdapterExperiment, READERS, packet, prepare

ACCOUNT = 0x1ca56
TICK = 0x020007b2
READ_TICK = 0x020007ba
READ_COUNT = 0x020007d4
WATCHDOG = 0x1bb670
TIMEOUT = 0x1bb726
CONTINUE = 0x1bb7ea


def watchdog(image, now, stamp):
    ex = Experiment(image, [(WATCHDOG, CONTINUE)], stubs={0x40390: 0},
                    stops=(TIMEOUT, CONTINUE))
    ex.put(CDB, 0xa8)  # Shared DVD/BD raw handler's real opcode marker.
    ex.put(TICK, now, 2)
    ex.put(READ_TICK, stamp, 2)
    ex.cpu.reg_write(UC_ARM_REG_R5, TICK)
    result = ex.run(WATCHDOG)
    return result['pc'], result['sense']


def verify(image):
    accounting = []
    for opcode in range(256):
        ex = Experiment(image, [(0x1ca48, 0x1ca68)])
        ex.put(CDB, opcode)
        ex.put(TICK, 0x4321, 2)
        ex.put(READ_TICK, 0x1234, 2)
        ex.put(READ_COUNT, 255)
        ex.run(0x1ca48)
        native_read = opcode in (0x28, 0xa8)
        require(ex.get(READ_TICK, 2) == (0x4321 if native_read else 0x1234)
                and ex.get(READ_COUNT) == (0 if native_read else 255),
                'Native receive accounting classification changed')
        accounting.append(opcode)

    cases = []
    # Include 16-bit tick wrap and the native strict >350 timeout boundary.
    for now in (1000, 10, 65535):
        for age in (350, 351, 1000):
            old = (now - age) & 0xffff
            pc, sense = watchdog(image, now, old)
            expired = age > 350
            require(pc == (TIMEOUT if expired else CONTINUE)
                    and sense == ([3, 0x11, 5] if expired else [0, 0, 0]),
                    'Stale timestamp no longer reproduces native timeout boundary')
            for media, kind in ((0x40, 1), (0x50, 1), (0xc0, 2)):
                ex = AdapterExperiment(image, stops=READERS.values())
                for attempt in range(3):
                    prepare(ex, packet(kind | 8, address=0, count=1), media)
                    ex.put(TICK, now, 2)
                    ex.put(READ_TICK, old, 2)
                    ex.put(READ_COUNT, 255)
                    ex.finished = None
                    trace_start = len(ex.trace)
                    result = ex.run(0x1b14e)
                    require(result['pc'] == READERS[media] and
                            ex.trace[trace_start:].count(ACCOUNT) == 1 and
                            ex.get(READ_TICK, 2) == now and ex.get(READ_COUNT) == 0,
                            'Raw request did not renew native accounting exactly once')
                    require(watchdog(image, now, ex.get(READ_TICK, 2)) ==
                            (CONTINUE, [0, 0, 0]), 'Prepared request timed out immediately')
                    # Real lack of progress must still time out, not be masked.
                    require(watchdog(image, (now + 351) & 0xffff, now) ==
                            (TIMEOUT, [3, 0x11, 5]), 'Real watchdog timeout was suppressed')
                    cases.append(dict(media=media, now=now, age=age, attempt=attempt))

    skipped = []
    for media, cdb in ((4, packet(0, count=1)),
                       (0x40, packet(1, count=0)),
                       (0x40, packet(2, count=1)),
                       (0x40, packet(1, count=1, extras=1))):
        ex = AdapterExperiment(image, stops=READERS.values())
        prepare(ex, cdb, media)
        ex.put(READ_TICK, 0x1234, 2)
        ex.put(READ_COUNT, 42)
        ex.run(0x1b14e)
        require(ACCOUNT not in ex.trace and ex.get(READ_TICK, 2) == 0x1234
                and ex.get(READ_COUNT) == 42,
                'CD, empty or rejected request changed READ accounting')
        skipped.append(cdb.hex())
    return dict(receive_opcode_cases=len(accounting), raw_cases=cases,
                skipped_cases=skipped, optical_transfer_verified=False,
                limitations=['No-progress helper 0x40390 returns zero; no optical model.',
                             'Watchdog execution stops before error cleanup.',
                             'Tick units and real interrupt scheduling are not modeled.'])
