#!/usr/bin/env python3
"""Trace native BD-ROM DI acquisition, copies and empty-header adaptation.

Optical sectors, servo helpers and the copy-engine completion are explicit
fixtures. The metadata reader, retry policy, DI-valid decision, copy setup and
geometry parser execute the specimen's actual instructions. This is not a
physical disc-recognition test.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import REGS, MEDIA, START, require
from native_adapter import assemble
from verify_native_adapter import MODE_CALLEES
from verify_native_media import MediaExperiment, MEMORY, STRUCT
from unicorn.arm_const import UC_ARM_REG_SP

DI_OFFSET = 0x2000
DI_VALID = 0x01ffabc5


class RecognitionExperiment(MediaExperiment):
    def __init__(self, image, sectors, *, failed_attempts=0):
        peripherals = (*MODE_CALLEES, 0xa70e0, 0x400c0, 0x440da, 0x4416e,
                       0x447e4, 0x44088, 0x440a0, 0x44070, 0x441b4,
                       0x432e2, 0x44216, 0x441de, 0x441b0, 0x4290c,
                       0x43bfc, 0x43b00, 0x43c32, 0x43c4a, 0x468b4,
                       0x43140, 0x685d8, 0xa8bf4, 0xa895c, 0xa89fc, 0xa63a8, 0xa63b0,
                       0x4375c, 0x438f2, 0x43c96, 0x42b86, 0x43c6c, 0x43344,
                       0x2904e, 0x4366e, 0x68d5c, 0x67650, 0x68d74, 0x4301e,
                       0xb0164, 0xb015c, 0x44054, 0x4404c)
        super().__init__(image, stubs={a: 0 for a in peripherals}, ranges=[
            (0xb1504, 0xb1790), (0xb6c4a, 0xb7444),
            (0xb5804, 0xb5828), (0xa8d9c, 0xa9000), (0x46918, 0x46a04),
            (0xb0e26, 0xb0eba), (0x443ce, 0x44442), (0x44474, 0x44660),
            (0xb0fe6, 0xb1134), (0xa6758, 0xa6798),
            (0xa6850, 0xa687c), (0xa6bce, 0xa6c00)])
        self.sectors = sectors
        self.failed_attempts = failed_attempts
        self.attempts = []
        self.poll_events = []
        self.engine_copies = []
        self.put(MEDIA, 0xc0)
        self.put(0x01ffafdc, DI_OFFSET, 4)
        # Nonzero sentinels expose accidental copies on failure or an already
        # valid DI; gaps between the two native copies must remain intact.
        self.cpu.mem_write(MEMORY + DI_OFFSET, b'\xa5' * 0xb0)

    def code(self, cpu, address, size, data):
        if address == 0xb6c4e:
            self.attempts.append(dict(start=self.get(START, 4),
                                      args=[cpu.reg_read(r) for r in REGS[:3]]))
            self.put(0x04042000, 0, 4)
            self.put(0x040300a4, 0, 4)
        if address == 0x68d74 and len(self.poll_events) < len(self.attempts):
            require(0x67650 in self.trace and 0x46918 in self.trace,
                    'DI completion arrived before native seek/error setup')
            success = len(self.attempts) > self.failed_attempts
            self.poll_events.append('complete' if success else 'timeout')
            if success:
                # Two ECC blocks (64 sectors) available in the optical cache.
                # The reader's original count check decides success.
                self.put(0x040300a4, 64, 4)
                self.put(0x04042000, 1, 4)
            else:
                # Metadata timer exceeds the native 320-tick threshold. The
                # original timeout/recovery loop must return failure itself.
                self.put(0x02000614, 1)
                self.put(0x020006b6, 321, 2)
        super().code(cpu, address, size, data)

    def write(self, cpu, access, address, size, value, data):
        super().write(cpu, access, address, size, value, data)
        if address != 0x04032044:
            return
        require(size == 4 and value in (2, 4), 'Unexpected DI copy-engine trigger')
        count = self.get(0x0403201c, 4)
        destination = self.get(0x04032014, 4)
        mode = self.get(0x04032048, 4)
        require(count > 0, 'Empty DI copy-engine transfer')
        if value == 2:
            sector = self.get(0x0403204c, 4) & 0xfff
            offset = self.get(0x04032050, 4) & 0xfff
            require(mode == 10 and sector in self.sectors and offset + count <= 2048,
                    'Unmodelled optical DI sector copy')
            payload = self.sectors[sector][offset:offset + count]
            self.cpu.mem_write(MEMORY + destination, payload)
            self.engine_copies.append(dict(kind='optical_cache', sector=sector,
                                            offset=offset, destination=destination, count=count))
        else:
            source = self.get(0x04032010, 4)
            require(mode in (0, 0x20), 'Unmodelled DI memory-copy mode')
            if mode == 0x20:
                source -= count - 1
                destination -= count - 1
            payload = bytes(self.cpu.mem_read(MEMORY + source, count))
            self.cpu.mem_write(MEMORY + destination, payload)
            self.engine_copies.append(dict(kind='memory', source=source,
                                            destination=destination, count=count))


def di_sectors(header):
    """Distinct optical fixtures, including valid BD-ROM and empty Wii U DI."""
    first = bytearray((i * 7 + 3) & 255 for i in range(2048))
    first[:4] = header
    # Single-layer geometry; ordinary nonempty DI uses its actual supplied end.
    first[0xc] = 0x10
    first[0x14:0x20] = bytes.fromhex('00ca73ff0010000000ca73fe')
    if header == bytes(4):
        first[0x14:0x20] = bytes(12)
    second = bytes((i * 11 + 9) & 255 for i in range(2048))
    return {0: bytes(first), 30: second}


def verify(original):
    image, symbols = assemble(original)
    cases = []
    for header in (bytes(4), b'DI\x01\x00', b'BAD!'):
        for failed_attempts in (0, 1, 3, 4):
            sectors = di_sectors(header)
            ex = RecognitionExperiment(image, sectors, failed_attempts=failed_attempts)
            ex.put(DI_VALID, 0xa1)  # Preserve unrelated native validity bits.
            result = ex.run(0xb1626, count=150000)
            success = failed_attempts < 4
            attempts = min(failed_attempts + 1, 4)
            require(ex.attempts == [dict(start=0xd3a00 - 0x6a00 * i, args=[0, 0, 2])
                                    for i in range(attempts)], 'DI retry address/ABI mismatch')
            require(ex.poll_events == ['timeout'] * failed_attempts + (['complete'] if success else []),
                    'DI native retry/completion sequence mismatch')
            require(ex.get(DI_VALID) == (0xa3 if success else 0xa1), 'DI-valid state or unrelated bits changed')
            require(result['termination'] == 'returned' and
                    ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0, 'DI acquisition stack imbalance')
            if success:
                require([c['kind'] for c in ex.engine_copies] ==
                        ['optical_cache', 'optical_cache', 'memory', 'memory'], 'DI copy sequence mismatch')
                expected = bytearray(b'\xa5' * 0xb0)
                expected[:0x40] = sectors[0][:0x40]
                expected[0x70:0xb0] = sectors[0][0x40:0x80]
                require(bytes(ex.cpu.mem_read(MEMORY + DI_OFFSET, 0xb0)) == expected,
                        'Native DI copies changed bytes or the intervening gap')
                require(bytes(ex.cpu.mem_read(STRUCT + 0x2400, 2048)) == sectors[0] and
                        bytes(ex.cpu.mem_read(STRUCT + 0x2c00, 2048)) == sectors[30],
                        'Native optical-cache copy setup lost sector contents')
                # Execute the unpatched parser on the same acquired bytes.
                # Empty DI must expose its real unusable geometry before the
                # adapter replaces only the seven required PSN bytes.
                baseline = RecognitionExperiment(original, sectors)
                baseline.put(DI_VALID, 0xa3)
                baseline.cpu.mem_write(MEMORY + DI_OFFSET, bytes(expected))
                baseline.run(0xb0fe6, count=12000)
                before_end = baseline.get(0x02000400, 4)
                require(before_end == (31 if header == bytes(4) else 0xca73ff),
                        'Native pre-adaptation geometry counterexample changed')
                ex.finished = None
                ex.run(symbols['Mt1939SetBDCharacteristicsHook'], count=12000)
                require(ex.get(0x02000400, 4) == 0xca73ff and
                        ex.get(0x020006b8, 4) == 0xca7400 and
                        ex.get(0x02000484, 4) == 0x100000 and ex.cpu.reg_read(REGS[0]) == 1,
                        'Acquired DI did not reach the native geometry parser')
                adapted = bytearray(expected)
                if header == bytes(4):
                    for offset, value in ((0x15, 0xca), (0x16, 0x73), (0x17, 0xff),
                                          (0x19, 0x10), (0x1d, 0xca), (0x1e, 0x73), (0x1f, 0xfe)):
                        adapted[offset] = value
                require(bytes(ex.cpu.mem_read(MEMORY + DI_OFFSET, 0xb0)) == adapted,
                        'Geometry adaptation modified unrelated acquired DI bytes')
            else:
                require(not ex.engine_copies and
                        bytes(ex.cpu.mem_read(MEMORY + DI_OFFSET, 0xb0)) == b'\xa5' * 0xb0,
                        'Failed DI acquisition copied or adapted stale data')
            cases.append(dict(header=header.hex(), failed_attempts=failed_attempts,
                              accepted=success, attempts=ex.attempts, events=ex.poll_events,
                              copies=ex.engine_copies))
    # An already-valid DI must retain the native early return and its bytes.
    ex = RecognitionExperiment(image, di_sectors(bytes(4)))
    ex.put(DI_VALID, 0xa3)
    ex.run(0xb1626)
    require(not ex.attempts and not ex.engine_copies and
            bytes(ex.cpu.mem_read(MEMORY + DI_OFFSET, 0xb0)) == b'\xa5' * 0xb0,
            'Already-valid DI was reacquired or overwritten')
    return dict(bd_rom_di_cases=cases, already_valid_di_preserved=True,
                native_reader_and_copy_setup=True, physical_recognition_verified=False,
                limitations=[
                    'Optical sectors and completion/timeout events are supplied fixtures.',
                    'Servo, speed-adaptation and peripheral helpers are explicit substitutions.',
                    'Copy-engine memory effects are modeled at native MMIO triggers.',
                    'This covers the BD-ROM DI path after media classification, not the servo classifier.',
                    'No software ASCII header rejection occurs on this executed path; hardware filtering is unverified.',
                ])
