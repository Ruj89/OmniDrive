#!/usr/bin/env python3
"""Verify C0 timer initialization against native IRQ and idle-speed decisions.

The native decision code executes up to its speed-setting boundary. This does
not verify spindle speeds, the other read classifiers or CD data-speed policy.
"""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import Experiment, REGS, MEDIA, require
from native_adapter import assemble
from verify_native_adapter import AdapterExperiment, READERS, prepare, packet
from unicorn.arm_const import UC_ARM_REG_R6

READ_TIMER = 0x02000634


def idle_decision(image, media, timer, speed):
    ex = Experiment(image, [(0x1c478, 0x1c584), (0xa8208, 0xa820e)],
                    stops=(0x1c5ba, 0xa879a))
    ex.put(MEDIA, media)
    ex.put(READ_TIMER, timer, 2)
    ex.put(0x01ffafcc, speed)
    ex.cpu.reg_write(UC_ARM_REG_R6, 0x01ffafcc)
    result = ex.run(0x1c47a)
    return ex.cpu.reg_read(REGS[0]) if result['pc'] == 0xa879a else speed


def verify(original):
    image, symbols = assemble(original)
    # Disable the reached timer store in the compiled shared C handler, not
    # a compiler-specific instruction pattern or a mocked timer operation.
    probe = AdapterExperiment(image, stops=READERS.values())
    prepare(probe, packet(0, count=32), 4)
    probe.put(READ_TIMER, 0xfedc, 2)
    probe.run(0x1b14e)
    reset_sites = [w['pc'] for w in probe.writes if w['address'] == READ_TIMER and
                   w['size'] == 2 and w['value'] == 0]
    require(len(reset_sites) == 1, 'C0 timer reset is missing or ambiguous')
    before = bytearray(image)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    instruction = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(image[reset_sites[0]:], reset_sites[0]))
    require(instruction.mnemonic == 'strh' and instruction.size == 2, 'Timer store instruction changed')
    before[reset_sites[0]:reset_sites[0] + 2] = b'\xc0\x46'
    before = bytes(before)
    cases = []
    for media, flags, speed in ((4, 0, 48), (0x40, 0x11, 16), (0x50, 0x11, 12), (0xc0, 0x12, 8)):
        for elapsed in (0, 251, 501, 1001, 1501, 2001, 0xffff):
            timers = []
            for candidate in (before, image):
                ex = AdapterExperiment(candidate, stops=READERS.values())
                prepare(ex, packet(flags, address=0, count=32), media)
                ex.put(READ_TIMER, elapsed, 2)
                ex.put(READ_TIMER + 2, 0xa5d3, 2)
                ex.put(0x020006b4, 0x4321, 2)
                ex.put(0x020006b6, 0x6543, 2)
                ex.put(0x02000770, 0x8765, 2)
                result = ex.run(0x1b14e)
                require(result['pc'] == READERS[media], 'Timer fixture missed the native reader')
                require(ex.get(READ_TIMER + 2, 2) == 0xa5d3 and
                        ex.get(0x020006b4, 2) == 0x4321 and ex.get(0x020006b6, 2) == 0x6543 and
                        ex.get(0x02000770, 2) == 0x8765, 'C0 reset changed unrelated timers or state')
                timers.append(ex.get(READ_TIMER, 2))
            require(timers == [elapsed, 0], 'C0 did not reset only the mapped elapsed-idle counter')
            old_speed = idle_decision(image, media, timers[0], speed)
            new_speed = idle_decision(image, media, timers[1], speed)
            require(new_speed == speed, 'Fresh C0 retained a native idle-speed reduction')
            cases.append(dict(media=media, elapsed=elapsed, timer_before=timers[0], timer_after=timers[1],
                              requested_speed=speed, native_idle_before=old_speed, native_idle_after=new_speed))
    require(sum(c['native_idle_before'] != c['native_idle_after'] for c in cases) == 20,
            'Native idle-speed counterexamples changed')
    # MT1939 rejects invalid C0 requests before main.c resets the timer.
    preserved = []
    for media, flags in ((4, 0), (0x40, 0x11), (0x50, 0x11), (0xc0, 0x12)):
        for reason, cdb, ready, kept in (
                ('not_ready', packet(flags, count=1), 0, True),
                ('invalid_count', packet(flags, count=0x1000000), 1, True),
                ('invalid_type', packet(3), 1, True)):
            ex = AdapterExperiment(image, stubs={0x1afb4: ready}, stops=READERS.values())
            prepare(ex, cdb, media)
            ex.put(READ_TIMER, 0xfedc, 2)
            result = ex.run(0x1b14e)
            require(result['termination'] == 'returned' and
                    ex.get(READ_TIMER, 2) == (0xfedc if kept else 0),
                    'Non-reading C0 elapsed-idle counter differs from main.c')
            preserved.append(dict(media=media, reason=reason, preserved=kept))
    ticks = []
    for timer in (0, 1, 250, 2000, 0xfffe, 0xffff):
        ex = Experiment(original, [(0x1bb078, 0x1bb08e)], stops=(0x1bb08e,))
        ex.put(READ_TIMER, timer, 2)
        ex.put(READ_TIMER + 2, 0xa5d3, 2)
        ex.run(0x1bb078)
        expected = timer + 1 if timer < 0xffff else 0xffe0
        require(ex.get(READ_TIMER, 2) == expected and ex.get(READ_TIMER + 2, 2) == 0xa5d3,
                'Native IRQ elapsed-idle counter mapping changed')
        ticks.append(dict(before=timer, after=expected))
    return dict(c0_idle_timer_cases=cases, nonreading_timer_preserved=preserved, native_irq_ticks=ticks,
                physical_speed_verified=False,
                limitations=['Native idle-speed decisions stop before the speed-setting function.',
                             'Read-speed classifiers and CD data-speed policy are not certified by this check.'])
