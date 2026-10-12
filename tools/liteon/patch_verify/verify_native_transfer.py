#!/usr/bin/env python3
"""Execute native DMA setup and reader return with explicit event models.

No optical sector data is synthesized. The scheduler boundary supplies either
completion flags or cancellation after the native host DMA has been armed.
"""
from pathlib import Path
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R7, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import CDB, require
from native_adapter import assemble, FORCE_UNIT_ACCESS
from verify_native_adapter import AdapterExperiment, MODE_CALLEES, packet, prepare, SECTOR_FORMAT


class CDTransferExperiment(AdapterExperiment):
    def __init__(self, image, *, cache_available, cancel):
        # Only mode/peripheral/servo helpers are substituted. Native unsigned
        # division, sector-to-MSF, atomic flags, error configuration and host
        # DMA setup execute their original instructions.
        stubs = {a: 0 for a in (*MODE_CALLEES, 0xa70e0, 0x43440, 0x43de6,
            0xa7600, 0x3fcec, 0x189e3c, 0x43ffe, 0x432e2, 0x468b4,
            0x447b0, 0x43554, 0x441b0, 0x44070, 0x42fa4, 0x438f2,
            0x189c0c)}
        super().__init__(image, stubs=stubs, ranges=[
            (0x18ae2c, 0x18b5de), (0x40014, 0x40072), (0x46918, 0x46a04),
            (0xe8c9c, 0xe8cd2), (0x189be8, 0x189c0c),
            (0x1ba99c, 0x1ba9b8), (0x1b9880, 0x1b9b0c)])
        self.cancel = cancel
        self.cache_available = cache_available
        self.events = []
        self.dma_formats = []

    def code(self, cpu, address, size, data):
        if address == 0x40014:
            self.dma_formats.append(self.get(SECTOR_FORMAT, 4))
        if address == 0x1be960:
            # Cache check model: the native comparison of forceUnitAccess with
            # the cached mode (executed in verify_native_hooks) never matches 0xFF.
            hit = self.cache_available and self.get(FORCE_UNIT_ACCESS) != 0xff
            self.calls.append({'target': address, 'stub_return': int(hit)})
            cpu.reg_write(UC_ARM_REG_R0, int(hit))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
            return
        if address == 0x189c0c:
            require(cpu.reg_read(UC_ARM_REG_R0) == 1, 'Unexpected scheduler argument')
            require(self.get(0x04042130, 4) & 3 == 1, 'Event before native DMA start')
            require(self.get(0x02000d20) == 0xc0, 'Raw CD command lost during native transfer')
            self.events.append('cancel' if self.cancel else 'complete')
            if self.cancel:
                self.put(0x02000615, 1)
            else:
                self.put(0x020006ff, 1)
                self.put(0x02000612, 0)
        super().code(cpu, address, size, data)


def verify(original):
    image, _ = assemble(original)
    cases = []
    for fua, available in ((0, 1), (0, 0), (8, 1)):
        for cancel in (False, True):
            for extras in range(8):
                for count in (1, 32, 0xffffff):
                    ex = CDTransferExperiment(image, cache_available=available, cancel=cancel)
                    prepare(ex, packet(fua, address=0, count=count, extras=extras), 4)
                    ex.put(0x02000697, 90)  # Real division in the CD reader.
                    ex.put(0x04042138, 0xa5000000, 4)
                    ex.put(FORCE_UNIT_ACCESS, 0)
                    result = ex.run(0x1b14e, count=12000)
                    require(result['termination'] == 'returned', 'Native CD reader failed to return')
                    require(ex.events == ['cancel' if cancel else 'complete'], 'Unexpected event sequence')
                    require(ex.get(0x02000612) == 0, 'Transfer-pending state leaked after native return')
                    require(ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0, 'Native reader stack imbalance')
                    require(ex.get(0x04042138, 4) == 0xa5000000 | count, 'DMA count truncated')
                    require(ex.get(0x0405006c, 4) & 0x7f == 1, 'CD DMA burst changed')
                    require(ex.get(0x02000697) == 9, 'Native unsigned division did not execute')
                    expected_format = 0x10 | bool(extras & 3) | (2 if extras & 4 else 0)
                    require(ex.dma_formats == [expected_format], 'Native transfer lost raw format')
                    require(ex.get(SECTOR_FORMAT, 4) == 0xa5a50010, 'CD raw format leaked after return')
                    require(ex.get(0x04050060, 4) & 0xf00 == (0x800 if extras & 3 == 2 else 0),
                            'DMA setup lost sub-Q selector')
                    require(result['sense'] == [0, 0, 0], 'Transfer introduced an unexpected sense error')
                    miss = bool(fua or not available)
                    require((0x18afac in result['trace']) == miss, 'Wrong native cache branch')
                    require(result['start'] == (0x000148 if miss else 150),
                            'Native cache miss did not prepare MSF for seek')
                    require(0x40014 in result['trace'] and 0x18b588 in result['trace'],
                            'Native DMA setup or cleanup skipped')
                    if not cancel:
                        require(ex.get(0x0200077f) == min(count, 32), 'Native completion count changed')
                    cases.append(dict(fua=bool(fua), cache_available=bool(available),
                                      event=ex.events[0], extras=extras, count=count))
    return dict(cd_native_transfer_cases=cases, optical_transfer_verified=False,
                full_omnidrive_port=False,
                limitations=['Completion/cancellation flags are injected at the scheduler boundary.',
                             'Mode, cache availability, servo and peripheral helper effects use explicit models.',
                             'Optical bytes, DMA interrupts and physical host delivery are not emulated.'])


def verify_packet_reparse(original):
    """Execute the original readers' READ(12) address decoders after C0 PSN.

    These are bounded parser contracts, not a claim that a particular interrupt
    sequence reaches each continuation. They ensure the internally spoofed CDB
    cannot disagree with START if native code parses it again.
    """
    from map_scsi import CDB, START, LENGTH, REGS
    from verify_native_adapter import READERS
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R7

    class ParserExperiment(AdapterExperiment):
        def __init__(self, image, entry, stop):
            super().__init__(image, ranges=[(entry, stop)], stops=(stop,))
            self.parser_entry = entry

        def code(self, cpu, address, size, data):
            if address == self.parser_entry:
                # Native DVD/RAM snippets are inside their reader stack frames.
                # Supply only their saved remaining-count limit and zero register.
                if address in (0x1c0600, 0xe3d32):
                    cpu.reg_write(UC_ARM_REG_SP, 0x0200ff40)
                    self.put(0x0200ff54 if address == 0x1c0600 else 0x0200ff50,
                             0xffffff, 4)
                    cpu.reg_write(UC_ARM_REG_R4, 0)
                    cpu.reg_write(UC_ARM_REG_R7, LENGTH)
            super().code(cpu, address, size, data)

    image, _ = assemble(original)
    cases = []
    for media in (0x40, 0x44, 0x60, 0x50, 0xc0, 0xc4):
        family = 2 if media >> 6 == 3 else 1
        bias = 0x100000 if family == 2 else (0x31000 if media == 0x50 else 0x30000)
        for psn in (0, bias - 1, bias, 0x800000, 0xffffff):
            for count in (1, 0x234, 0xffffff):
                cdb = packet(0x14 | family, address=psn, count=count)
                ex = AdapterExperiment(image, stops=READERS.values())
                prepare(ex, cdb, media)
                ex.put(0x02000400, 0x208000, 4)
                ex.put(0x0200072a, int(media in (0x44, 0x60)))
                result = ex.run(0x1b14e)
                require(result['termination'] == 'boundary', 'PSN did not reach native reader')
                expected = result['start']
                internal = bytes(ex.cpu.mem_read(CDB, 12))
                require(internal[:2] == bytes((0xa8, cdb[1] | 0x80)) and
                        internal[6:] == cdb[6:], 'PSN rewrite changed flags/count/extras')
                entry, stop = ((0x1bc04e, 0x1bc0da) if family == 2 else
                               ((0xe3d32, 0xe3da2) if media == 0x50 else (0x1c0600, 0x1c06a0)))
                # First execute with the historical direct spoof: this must
                # expose a real wrong address in original instructions.
                before_cdb = bytes((0xa8, cdb[1] | 0x80)) + cdb[2:]
                observed = []
                for candidate in (before_cdb, internal):
                    parser = ParserExperiment(image, entry, stop)
                    prepare(parser, candidate, media)
                    parser.put(LENGTH, count, 4)
                    parser.put(START, expected, 4)
                    parser.run(entry)
                    observed.append(parser.get(START, 4))
                    require(parser.get(LENGTH, 4) == count, 'Native reparse lost transfer count')
                require(observed[0] != expected, 'Regression fixture did not expose the original error')
                require(observed[1] == expected, 'Native reparse applied an extra address bias')
                cases.append(dict(media=media, psn=psn, count=count, start=expected,
                                  before_reparse=observed[0], after_reparse=observed[1]))
    return dict(native_packet_reparse_cases=cases, optical_transfer_verified=False)


class DataTransferExperiment(AdapterExperiment):
    """Run DVD/RAM/BD reader instructions; model peripheral and IRQ boundaries.

    Cache availability is a fixture. A native cache-invalidation request makes
    it unavailable, including when FUA initially encounters a populated cache.
    Completion supplies the same shared flags the readers poll. The BD idle
    wait additionally observes advancing hardware time after completion.
    """
    def __init__(self, image, *, cache_available, cancel, advance_idle_time=True):
        peripheral = (
            *MODE_CALLEES, 0xa70e0, 0x43440, 0x43de6, 0x189e3c, 0x43ffe,
            0x432e2, 0x44250, 0x441b4, 0x1789ac, 0xcd18c, 0xe310a,
            0x400c0, 0x468a0, 0x42c74, 0x42ef8, 0x4290c, 0x441b0,
            0x44070, 0x447b0, 0x269be, 0x440a0, 0x4416e, 0x447e4,
            0x44068, 0x435e0, 0x441de, 0x44102, 0x4410a, 0x43fa8,
            0x47044, 0x43d02, 0x46a1c, 0x43d98, 0x43b00, 0x40378,
            0x40780, 0xa6632, 0x43554, 0x43c32, 0x43c4a, 0x468b4,
            0x43140, 0x3fe3c, 0x3ff62, 0x4054c, 0x189e58, 0x440da,
            0x438f2, 0x43836, 0x46ffc)
        stubs = {a: 0 for a in peripheral}
        stubs.update({0x1be960: cache_available, 0x1bbda4: cache_available})
        super().__init__(image, stubs=stubs, ranges=[
            (0xe3370, 0xe3e78), (0x1bf38c, 0x1c0950), (0xb5828, 0xb6c4e),
            (0x40014, 0x40072), (0x46918, 0x46a04), (0x3fcec, 0x3fd62),
            (0x406e0, 0x40706), (0xa7600, 0xa7688),
            (0xccca4, 0xcccc8), (0xe2694, 0xe26b8), (0xb5804, 0xb5828),
            (0xa8d9c, 0xa8dcc), (0x2c864, 0x2c8cc), (0xcd3d4, 0xcd454)])
        self.cancel = cancel
        self.advance_idle_time = advance_idle_time
        self.events = []
        self.invalidations = []
        self.dma_formats = []
        self.dma_controls = []

    def write(self, cpu, access, address, size, value, data):
        # BD arms host DMA inline, whereas DVD/RAM call 0x40014. Observe the
        # actual start-register store so every media family has the same check.
        if address == 0x04042130 and size == 4 and value & 3 == 1:
            self.dma_formats.append(self.get(SECTOR_FORMAT, 4))
            self.dma_controls.append((self.get(0x04032048, 4) & 8,
                                      self.get(0x04050010, 4) & 4))
        super().write(cpu, access, address, size, value, data)

    def code(self, cpu, address, size, data):
        if address == 0x432e2 and cpu.reg_read(UC_ARM_REG_R1) == 1:
            self.invalidations.append(cpu.reg_read(UC_ARM_REG_R0))
            self.stubs[0x1be960] = self.stubs[0x1bbda4] = 0
        if address in (0x1bf922, 0xe3630, 0xb5d92) and not self.events:
            require(self.get(0x04042130, 4) & 3 == 1, 'Event before native DMA start')
            require(self.raw_marked(), 'Raw marker lost during native transfer')
            self.events.append('cancel' if self.cancel else 'complete')
            if self.cancel:
                self.put(0x02000615, 1)
            else:
                self.put(0x02000610, 1)  # Command finished, no following packet.
                self.put(0x02000612, 0)  # Host transfer no longer pending.
                self.put(0x02000611, 0)
                self.put(0x02000614, 1)
                self.put(0x04042000, 0x40, 4)
        if address == 0xb6b80 and self.advance_idle_time:
            # Native BD code waits for the next command until this timer
            # advances 20 ticks. No branch or reader state is overridden.
            timer = cpu.reg_read(UC_ARM_REG_R7) + 0x38
            self.put(timer, (self.get(timer, 4) + 32) & 0xffffffff, 4)
        super().code(cpu, address, size, data)


def verify_zero_length(original):
    """A zero-sector C0 must return without entering readers or arming DMA."""
    image, _ = assemble(original)
    cases = []
    for media, family in ((4, 0), (0x40, 1), (0x50, 1), (0xc0, 2)):
        for fua in (0, 8):
            for psn in (0, 4):
                for extras in (range(8) if media == 4 else (0,)):
                    experiment = CDTransferExperiment if media == 4 else DataTransferExperiment
                    ex = experiment(image, cache_available=0, cancel=False)
                    cdb = packet(family | fua | psn, address=0, count=0, extras=extras)
                    prepare(ex, cdb, media)
                    # A previous request left a nonzero host DMA count. Native
                    # CD/DVD/RAM DMA setup skips the count store when count=0.
                    preserved = {0x04042138: (0xa5000007, 4),
                                 0x04042130: (0xa5000000, 4),
                                 SECTOR_FORMAT: (0xa5a50010, 4),
                                 0x04032048: (0x12345678, 4),
                                 0x04050010: (0x87654324, 4),
                                 0x02000634: (0x4321, 2),
                                 0x020006bc: (0x123456, 4),
                                 0x020006c4: (7, 4),
                                 FORCE_UNIT_ACCESS: (0xff, 1)}
                    for address, (value, size) in preserved.items():
                        ex.put(address, value, size)
                    # Also supply the native reader fixtures: removing the
                    # zero-count guard must expose actual DMA execution.
                    ex.put(0x02000697, 64)
                    ex.put(0x020006b8, 0x2000000, 4)
                    ex.put(0x02000400, 0x2000000, 4)
                    ex.put(0x020005fc, 1)
                    result = ex.run(0x1b14e, count=12000)
                    require(not ex.dma_formats and not ex.events,
                            'Zero-sector C0 starts host DMA')
                    require(result['termination'] == 'returned' and result['sense'] == [0, 0, 0],
                            'Zero-sector C0 did not complete successfully')
                    require(not any(pc in ex.trace for pc in (0x18ae2c, 0x1bf38c, 0xe3370, 0xb5828)),
                            'Zero-sector C0 entered a native reader')
                    require(bytes(ex.cpu.mem_read(CDB, 12)) == cdb,
                            'Zero-sector C0 changed the packet')
                    require(all(ex.get(address, size) == value
                                for address, (value, size) in preserved.items()),
                            'Zero-sector C0 changed transfer controls or read state')
                    require(not any(w['address'] < 0x04100000 and
                                    w['address'] + w['size'] > 0x04000000
                                    for w in ex.writes), 'Zero-sector C0 wrote MMIO')
                    require(ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
                            'Zero-sector C0 stack imbalance')
                    cases.append(dict(media=media, fua=bool(fua), psn=bool(psn), extras=extras))
    return dict(zero_length_cases=cases, optical_transfer_verified=False)


def verify_data_transfer(original):
    image, _ = assemble(original)
    cases = []
    for media, family, bias, raw_format, miss_pc, cleanup in (
            (0x40, 1, 0x30000, 0x98, 0x1bf434, 0x1c08c0),
            (0x50, 1, 0x31000, 0x98, 0xe33dc, 0xe3e46),
            (0xc0, 2, 0x100000, 0xf8, 0xb58ea, 0xb6c1c)):
        for fua, available in ((0, 1), (0, 0), (8, 1)):
            for descramble in (0, 0x10):
                for psn in (0, 4):
                    for cancel in (False, True):
                        for count in (1, 32, 0xffffff):
                            ex = DataTransferExperiment(image, cache_available=available, cancel=cancel)
                            flags = family | fua | descramble | psn
                            prepare(ex, packet(flags, address=bias if psn else 0, count=count), media)
                            ex.put(0x02000697, 64)
                            ex.put(0x020006b8, 0x2000000, 4)
                            ex.put(0x02000400, 0x2000000, 4)
                            ex.put(0x020005fc, 1)  # Already configured media.
                            ex.put(0x04042138, 0xa5000000, 4)
                            result = ex.run(0x1b14e, count=12000)
                            require(result['termination'] == 'returned', 'Native data reader failed to return')
                            require(ex.events == ['cancel' if cancel else 'complete'], 'Unexpected event sequence')
                            require(ex.get(0x02000612) == 0, 'Transfer-pending state leaked after return')
                            require(ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0, 'Reader stack imbalance')
                            require(ex.get(0x04042138, 4) == 0xa5000000 | count, 'DMA count changed')
                            require(ex.dma_formats == [raw_format], 'Raw format lost during DMA')
                            require(ex.dma_controls == [(8, 4) if descramble else (0, 0)],
                                    'Descrambling request not applied during DMA')
                            require(ex.get(SECTOR_FORMAT, 4) == 0xa5a50010 and
                                    ex.get(0x04032048, 4) & 8 == 0 and
                                    ex.get(0x04050010, 4) & 4 == 0,
                                    'Raw controls leaked after return')
                            require(result['sense'] == [0, 0, 0] and result['start'] == bias,
                                    'Native transfer changed sense or sector address')
                            require((miss_pc in result['trace']) == bool(fua or not available),
                                    'Wrong native cache branch')
                            require(cleanup in result['trace'], 'Native reader cleanup skipped')
                            if fua:
                                require(ex.invalidations and ex.invalidations[0] == (3 if family == 2 else 2),
                                        'FUA did not invalidate the correct native cache')
                            if not cancel:
                                require(ex.get(0x0200077f) == min(count, 32), 'Completion count changed')
                            cases.append(dict(media=media, fua=bool(fua), cache_available=bool(available),
                                              descramble=bool(descramble), psn=bool(psn),
                                              event=ex.events[0], count=count))
    return dict(data_native_transfer_cases=cases, optical_transfer_verified=False,
                full_omnidrive_port=False, limitations=[
                    'Peripheral, servo, cache availability and hardware timer effects use explicit models.',
                    'Completion/cancellation flags are injected after the native host DMA starts.',
                    'Reader, error-mode, atomic flags, DMA setup and cleanup execute original instructions.',
                    'Optical bytes, real interrupts and physical host delivery are not emulated.'])


class QueuedTransferExperiment(DataTransferExperiment):
    def __init__(self, image, queued, *, forbid_idle_wait=False, format_high=0):
        super().__init__(image, cache_available=1, cancel=False,
                         advance_idle_time=not forbid_idle_wait)
        self.queued = queued
        self.forbid_idle_wait = forbid_idle_wait
        self.format_high = format_high
        self.idle_waits = []
        self.initial_idle_checks = 0
        self.packet_checks = 0
        self.ranges.append((0xa644a, 0xa648c))
        self.cpu.mem_map(0x01000000, 0x200000)
        self.put(0x02000644, 0x01000000, 4)
        self.put(0x02000648, 0x100000, 4)
        self.put(0x01ffafdc, 0x2000, 4)
        self.put(0x01002000, 0x4944, 4)
        self.put(0x01105000, 1)

    def code(self, cpu, address, size, data):
        first = not self.events
        if self.events and address in (0x1c05f8, 0xe3d2a, 0xb6b3a):
            self.packet_checks += 1
        if self.events and address in (0x1c08b6, 0xe3e3c, 0xb6b80):
            # DVD/RAM perform one initial timer check before examining packets.
            # Reentering here after a packet check is the added idle-wait path.
            if self.packet_checks:
                self.idle_waits.append(address)
                require(not self.forbid_idle_wait, 'Queued non-READ entered an idle wait')
            else:
                self.initial_idle_checks += 1
        if not self.forbid_idle_wait and address in (0x1c08b6, 0xe3e3c):
            self.put(0x02000634, self.get(0x02000634, 2) + 1, 2)
        super().code(cpu, address, size, data)
        if first and self.events:
            self.put(0x02000610, 0)  # A following packet is available.
            self.put(0x02000611, 1)
            self.put(0x02000614, 0)
            self.cpu.mem_write(CDB, self.queued)
            # Model unrelated format-register fields reading back nonzero.
            self.put(SECTOR_FORMAT, self.get(SECTOR_FORMAT, 4) | self.format_high, 4)


def verify_queued_commands(original):
    """Require raw cleanup before a queued packet returns to the dispatcher.

    Run through native reader cleanup; reaching a second DMA or the native
    continuation parser is a failure. The queued CDB and ready flag must be
    preserved, and raw controls must be restored without adapter RAM.
    """
    from map_scsi import CDB
    image, _ = assemble(original)

    cases = []
    for media, family, gate, parser, raw_format in (
            (0x40, 1, 0x1c05f8, 0x1c0600, 0x98),
            (0x50, 1, 0xe3d2a, 0xe3d32, 0x98),
            (0xc0, 2, 0xb6b3a, 0xb6b42, 0xf8)):
        for opcode in (0x28, 0xa8):
            for descramble, high in ((0, 0), (0x10, 0), (0, 0xa5a50000), (0x10, 0xa5a50000)):
                queued = bytearray(packet(0, address=32, count=32))
                queued[0] = opcode
                if opcode == 0x28:
                    queued[6:10] = bytes((0, 0, 32, 0))
                ex = QueuedTransferExperiment(image, bytes(queued), format_high=high)
                prepare(ex, packet(family | descramble, address=0, count=32), media)
                ex.put(0x02000697, 64)
                ex.put(0x020006b8, 0x2000000, 4)
                ex.put(0x02000400, 0x2000000, 4)
                ex.put(0x020005fc, 1)
                # A sequential cache hit must not hide a leaked raw format.
                ex.stubs[0x40390] = (0x100000 if family == 2 else
                                     (0x31000 if media == 0x50 else 0x30000)) + 32
                ex.stops.add(parser)
                result = ex.run(0x1b14e, count=12000)
                require(result['termination'] == 'returned', 'Queued READ entered the raw fast path')
                require(ex.dma_formats == [raw_format], 'Queued READ started another raw DMA')
                require(bytes(ex.cpu.mem_read(CDB, 12)) == bytes(queued) and
                        ex.get(0x02000611) == 1 and ex.get(0x02000610) == 0,
                        'Native cleanup consumed or changed the queued packet')
                require(ex.get(SECTOR_FORMAT, 4) == 0xa5a50010 and
                        ex.get(0x04032048, 4) & 8 == 0 and ex.get(0x04050010, 4) & 4 == 0,
                        'Raw format or descrambling leaked to the queued READ')
                ex.stops.add(0xace90 if family == 2 else 0xc8404)
                following = ex.run(0x1b14e)
                require(following['termination'] == 'boundary' and
                        following['pc'] == (0xace90 if family == 2 else 0xc8404) and
                        ex.dma_formats == [raw_format],
                        'Queued READ did not pass through the ordinary command guard')
                cases.append(dict(media=media, next_opcode=opcode, descramble=bool(descramble),
                                  format_high=high,
                                  sector_format=ex.get(SECTOR_FORMAT, 4),
                                  descrambling_on=bool(ex.get(0x04032048, 4) & 8),
                                  inherits_raw_format=ex.get(SECTOR_FORMAT, 4) == raw_format))
    gates = []
    for gate in (0x1c05f8, 0xe3d2a, 0xb6b3a):
        for format in (0x10, 0x11, 0xa5a50010, 0x98, 0xf8, 0xa5a50098, 0xa5a500f8):
            for opcode in (0x28, 0xa8, 0xc0, 0x12, 0, 0x2b):
                for pending in (0, 1):
                    ex = AdapterExperiment(image, ranges=[(gate, gate + 4)], stops=(gate + 4,))
                    ex.put(SECTOR_FORMAT, format, 4)
                    ex.put(CDB, opcode)
                    ex.put(0x02000611, pending)
                    result = ex.run(gate)
                    blocked = (format & 0xff) in (0x98, 0xf8) and opcode in (0x28, 0xa8)
                    require(ex.cpu.reg_read(UC_ARM_REG_R0) == (0 if blocked else pending),
                            'Continuation gate changed a non-READ or ordinary fast path')
                    require(ex.get(0x02000611) == pending and ex.get(SECTOR_FORMAT, 4) == format and
                            ex.get(CDB) == opcode and ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
                            'Continuation gate changed native state or stack')
                    gates.append(dict(site=gate, format=format, opcode=opcode, pending=pending))
    return dict(queued_command_cases=cases, continuation_gate_cases=gates,
                optical_transfer_verified=False, limitations=[
        'Queued packets, cache position, completion events and idle time use explicit models.'])


def verify_queued_nonreads(original):
    """A queued C0/INQUIRY/TUR must leave raw readers without any idle tick.

    Run native opcode rejection and cleanup after injecting the next packet.
    Fail at the FIRST idle-wait instruction after packet inspection, before any
    time model can hide it. DVD/RAM's initial timer check runs with time frozen.
    This proves branch behavior, not physical C0 commands/second or tick duration.
    """
    image, _ = assemble(original)
    cases = []
    for media, family, raw_format in ((0x40, 1, 0x98), (0x50, 1, 0x98), (0xc0, 2, 0xf8)):
        for opcode in (0xc0, 0x12, 0):
            for descramble in (0, 0x10):
                for high in (0, 0xa5a50000):
                    queued = bytearray(packet(family | descramble, address=32, count=32))
                    queued[0] = opcode
                    ex = QueuedTransferExperiment(image, bytes(queued),
                                                  forbid_idle_wait=True, format_high=high)
                    prepare(ex, packet(family | descramble, address=0, count=32), media)
                    ex.put(0x02000697, 64)
                    ex.put(0x020006b8, 0x2000000, 4)
                    ex.put(0x02000400, 0x2000000, 4)
                    ex.put(0x020005fc, 1)
                    result = ex.run(0x1b14e, count=12000)
                    require(result['termination'] == 'returned' and not ex.idle_waits and
                            ex.packet_checks == 1,
                            'Queued non-READ did not return immediately to dispatch')
                    require(ex.dma_formats == [raw_format] and ex.get(0x02000612) == 0 and
                            result['sense'] == [0, 0, 0], 'Queued non-READ changed raw completion')
                    require(bytes(ex.cpu.mem_read(CDB, 12)) == bytes(queued) and
                            ex.get(0x02000611) == 1 and ex.get(0x02000610) == 0,
                            'Raw cleanup consumed or changed the queued non-READ')
                    require(ex.get(SECTOR_FORMAT, 4) == 0xa5a50010 and
                            ex.get(0x04032048, 4) & 8 == 0 and ex.get(0x04050010, 4) & 4 == 0 and
                            ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
                            'Queued non-READ leaked raw controls or corrupted the stack')
                    cases.append(dict(media=media, next_opcode=opcode, descramble=bool(descramble),
                                      format_high=high, idle_wait_visits=len(ex.idle_waits),
                                      initial_idle_checks=ex.initial_idle_checks,
                                      packet_checks=ex.packet_checks))
    return dict(queued_nonread_cases=cases, optical_transfer_verified=False,
                physical_throughput_verified=False, limitations=[
                    'Queued packets and completion events use explicit models.',
                    'No idle tick is advanced after a non-READ is queued.',
                    'Tick duration and physical commands/second are not measured.'])


def verify_raw_state_and_recordable(original):
    """Vary previous descrambling state and run rejected DVD-R checks end to end."""
    image, _ = assemble(original)
    cases = []
    for media in (0x50, 0x60):
        for initial in (0, 1):
            for requested in (0, 1):
                for cancel in (False, True):
                    ex = DataTransferExperiment(image, cache_available=1, cancel=cancel)
                    ex.ranges.append((0x17d57c, 0x17d826))
                    bias = 0x31000 if media == 0x50 else 0x30000
                    # DVD-R status 1 rejects a request beyond lastSector before
                    # the raw hook; DVD-RAM uses the same full reader fixture.
                    address = 0x100001 - bias if media == 0x60 else 0
                    prepare(ex, packet(1 | (0x10 if requested else 0), address=address, count=1), media)
                    ex.put(0x02000697, 64)
                    ex.put(0x020006b8, 0x100000, 4)
                    ex.put(0x02000400, 0x100000, 4)
                    ex.put(0x0200040c, 1)
                    ex.put(0x020005fc, int(media == 0x50))
                    ex.put(0x04032048, 0xa5a50000 | initial * 8, 4)
                    ex.put(0x04050010, 0x5a5a0000 | initial * 4, 4)
                    result = ex.run(0x1b14e, count=12000)
                    require(result['termination'] == 'returned' and result['sense'] == [0, 0, 0],
                            'Raw DVD-R/RAM request retained an overridden error')
                    require(ex.events == ['cancel' if cancel else 'complete'] and
                            ex.dma_formats == [0x98] and
                            ex.dma_controls == [(8, 4) if requested else (0, 0)],
                            'Raw DVD-R/RAM request failed to apply requested controls')
                    require(ex.get(SECTOR_FORMAT, 4) == 0xa5a50010 and
                            ex.get(0x04032048, 4) & 8 == initial * 8 and
                            ex.get(0x04050010, 4) & 4 == initial * 4,
                            'Previous controls were not restored after raw completion/cancellation')
                    require(ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
                            'Raw state restoration changed the native stack')
                    if media == 0x60:
                        require(0x17d57c in result['trace'], 'DVD-R fixture missed the native rejection')
                    cases.append(dict(media=media, initial_descramble=bool(initial),
                                      requested_descramble=bool(requested), cancel=cancel))
    return dict(raw_state_and_recordable_cases=cases, optical_transfer_verified=False)
