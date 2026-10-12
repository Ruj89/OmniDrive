#!/usr/bin/env python3
"""Execute MT1939 media hooks with explicit optical acquisition models.

Native byte/word structure accessors execute. Optical read/copy and initial
TOC acquisition are external boundaries; these tests cannot prove disc loading.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import Experiment, REGS, START, LENGTH, CDB, MEDIA, SENSE, SENTINEL, require
from native_adapter import assemble
from verify_native_adapter import AdapterExperiment, prepare, packet, READERS
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R6, UC_ARM_REG_SP

MEMORY = 0x01000000
STRUCT = MEMORY + 0x100000


class MediaExperiment(AdapterExperiment):
    def __init__(self, image, *, failures=0, identifier=0xd1, native_toc=1, **kwargs):
        stubs = {0xcc184: native_toc, **kwargs.pop('stubs', {})}
        ranges = [(0xa644a, 0xa648c)] + kwargs.pop('ranges', [])
        super().__init__(image, stubs=stubs, ranges=ranges, **kwargs)
        self.cpu.mem_map(MEMORY, 0x200000)
        self.put(0x02000644, MEMORY, 4)
        self.put(0x02000648, 0x100000, 4)
        self.failures = failures
        self.identifier = identifier
        self.read_attempts = []
        self.copies = []

    def code(self, cpu, address, size, data):
        if address == 0xcd454:
            self.read_attempts.append((self.get(START, 4), cpu.reg_read(REGS[0]),
                                       cpu.reg_read(REGS[1]), self.get(0x0200071e)))
            # Model a reader which mutates its working address/count.
            self.put(START, 0xdeadbeef, 4)
            self.put(LENGTH, 0x1234, 4)
            self.cpu.mem_write(SENSE, b'\x03\x11\x05')
            cpu.reg_write(REGS[0], int(len(self.read_attempts) > self.failures))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x17bac8:
            offset, sector = (cpu.reg_read(r) for r in REGS[:2])
            self.copies.append((offset, sector))
            # An optical fixture is intentionally supplied only at this boundary.
            self.put(STRUCT + offset, self.identifier)
            self.cpu.mem_write(STRUCT + offset + 12, (0x208000).to_bytes(4, 'big'))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().code(cpu, address, size, data)


def verify(original):
    overlay, symbols = assemble(original)
    cases = []
    for toc in (0, 1):
        for multi, ptp, dmi, failures, identifier, nintendo in (
                (0, 0, 1, 0, 0xd1, False), (1, 1, 1, 0, 0xd1, False),
                (1, 0, 0, 0, 0xd1, False), (1, 0, 3, 0, 0xd1, False),
                (1, 0, 1, 0, 0xd1, False), (1, 0, 2, 4, 0xe1, False),
                (1, 0, 1, 5, 0xd1, False), (1, 0, 2, 0, 0xff, False),
                (0, 0, 0, 0, 0, True)):
            ex = MediaExperiment(overlay, failures=failures, identifier=identifier, native_toc=toc)
            ex.put(0x0200072a, multi)
            ex.put(0x0200072b, ptp)
            ex.put(STRUCT + 0x5800, dmi)
            ex.put(STRUCT + 0x5000, 0xff if nintendo else 1)
            ex.cpu.mem_write(STRUCT + 0x5008, (0xfaffff).to_bytes(4, 'big'))
            for address, value in ((START, 0x32100), (LENGTH, 0x67),
                                    (0x02000400, 0x200000), (0x020006b8, 0x400000)):
                ex.put(address, value, 4)
            ex.put(0x0200071e, 0xa5)
            ex.cpu.mem_write(SENSE, b'\x06\x28\x01')
            result = ex.run(symbols['Mt1939ReadDVDTOCHook'])
            eligible = bool(toc and multi and not ptp and dmi in (1, 2))
            attempts = min(failures + 1, 5) if eligible else 0
            require(ex.read_attempts == [(0xfd0210 + 0x40 * i, 8, 16, 1)
                                        for i in range(attempts)], 'XGD retry address/ABI mismatch')
            copied = eligible and failures < 5
            require(ex.copies == ([(0x6800, 14)] if copied else []), 'XGD copy boundary mismatch')
            accepted = copied and identifier in (0xd1, 0xe1)
            last = (0xfffaffff + 2 * (0x208000 + 1)) & 0xffffffff
            require(ex.get(0x02000400, 4) == (0x208000 if accepted else 0x200000) and
                    ex.get(0x020006b8, 4) == (last if accepted else 0x400000),
                    'XGD geometry mismatch or failed-read mutation')
            expected_toc = ((last + 1 - 0x30000) & 0xffffff).to_bytes(3, 'big') if accepted else bytes(3)
            require(bytes(ex.cpu.mem_read(STRUCT + 0x9f69, 3)) == expected_toc, 'XGD TOC size mismatch')
            require(ex.get(STRUCT + 0x5010) == (0x80 if toc and nintendo else 0),
                    'Nintendo BCA handling mismatch')
            require(result['start'] == 0x32100 and result['length'] == 0x67 and
                    ex.get(0x0200071e) == 0xa5 and ex.cpu.reg_read(REGS[0]) == toc,
                    'Media hook lost native return value or read state')
            require(result['sense'] == [6, 0x28, 1], 'XGD probe leaked sense status')
            cases.append(dict(toc=toc, multi=multi, ptp=ptp, dmi=dmi,
                              failures=failures, identifier=identifier, accepted=accepted))
    # Unknown PFI book types (Nintendo 0xF, also 4-8, 11-13) use the DVD-ROM
    # case, as MT1959's DVDCharacteristicsPatch does; known types are unchanged.
    classifiers = []
    for book in range(16):
        for low in (0x000000, 0x003000):
            pfi = (book << 28) | 0x0f000000 | low
            ex = AdapterExperiment(overlay, stops=(0xcb7e2,))
            ex.cpu.reg_write(REGS[0], pfi)
            result = ex.run(symbols['Mt1939DVDCharacteristicsHook'])
            known = book <= 3 or book in (9, 10, 14)
            require(result['calls'][-1]['args'][0] == (pfi if known else pfi & 0x0fffffff),
                    'Unknown PFI book type argument mismatch')
            classifiers.append(pfi)
    # Native classification keeps the layer decode of the DVD-ROM case.
    native_pfi = []
    for pfi in (0xff000000, 0xff002000, 0xff003000, 0x4f003000, 0xbf002000):
        expected = Experiment(original, [(0xcb7e2, 0xcb9f6)], stubs={0x400c0: 0}, stops=(0x67bdc,))
        expected.put(MEDIA, 0x40)
        expected.cpu.reg_write(REGS[0], pfi & 0x0fffffff)
        expected.run(0xcb7e2)
        ex = AdapterExperiment(overlay, ranges=[(0xcb7e2, 0xcb9f6)],
                               stubs={0x400c0: 0}, stops=(0x67bdc,))
        ex.put(MEDIA, 0x40)
        ex.cpu.reg_write(REGS[0], pfi)
        result = ex.run(symbols['Mt1939DVDCharacteristicsHook'])
        media = expected.cpu.reg_read(REGS[0])
        require(result['pc'] == 0x67bdc and ex.cpu.reg_read(REGS[0]) == media,
                'Native PFI classifier selected the wrong media')
        native_pfi.append(dict(pfi=pfi, native_media=media))
    require({c['native_media'] for c in native_pfi} == {0x40, 0x44, 0x46},
            'PFI cases did not cover single, dual and OTP layers')
    bd = []
    for header in (bytes(4), b'DI\x01\x00'):
        ex = MediaExperiment(overlay, stops=(0xb0fe6,))
        ex.put(0x01ffafdc, 0x2000, 4)
        original_di = bytearray(range(0x80))
        original_di[:4] = header
        ex.cpu.mem_write(MEMORY + 0x2000, bytes(original_di))
        ex.run(symbols['Mt1939SetBDCharacteristicsHook'])
        expected = original_di.copy()
        if not any(header):
            for offset, value in ((0x15, 0xca), (0x16, 0x73), (0x17, 0xff),
                                  (0x19, 0x10), (0x1d, 0xca), (0x1e, 0x73), (0x1f, 0xfe)):
                expected[offset] = value
        require(bytes(ex.cpu.mem_read(MEMORY + 0x2000, 0x80)) == expected,
                'BD DI fallback changed unrelated bytes')
        bd.append(header.hex())
    # Run the actual BD geometry parser, including native byte/word reads.
    # Only critical-section entry/exit and the diagnostic sink are stubbed.
    ex = MediaExperiment(overlay, ranges=[(0xb0fe6, 0xb1134), (0xa6758, 0xa6798),
                                         (0xa6850, 0xa687c), (0xa6bce, 0xa6bea)],
                         stubs={0xa63a8: 0, 0xa63b0: 0, 0x400c0: 0})
    ex.put(MEDIA, 0xc0)
    ex.put(0x01ffabc5, 2)
    ex.put(0x01ffafdc, 0x2000, 4)
    ex.run(symbols['Mt1939SetBDCharacteristicsHook'])
    require(ex.get(0x02000400, 4) == 0xca73ff and ex.get(0x020006b8, 4) == 0xca7400
            and ex.get(0x02000484, 4) == 0x100000 and ex.cpu.reg_read(REGS[0]) == 1,
            'Native Wii U geometry parser produced an incorrect bound')
    guards = 0
    for family, hook, native in ((0x40, 'DVDReadCmdHook', 0xc8404),
                                  (0xc0, 'BDReadCmdHook', 0xace90)):
        for special in (False, True):
            for flags in range(256):
                ex = MediaExperiment(overlay, stops=(native,))
                ex.put(0x01ffafdc, 0x2000, 4)
                ex.put(MEMORY + 0x2000, 0 if special else 0x4944, 4)
                ex.put(STRUCT + 0x5000, 0xff if special else 1)
                prepare(ex, bytes([0x28, flags]) + bytes(10), family)
                result = ex.run(symbols[hook])
                if special:
                    require(result['termination'] == 'returned' and result['sense'] == [5, 0x30, 2]
                            and ex.get(CDB + 1) == flags, 'Special-disc ordinary read was not rejected')
                else:
                    require(result['pc'] == native and ex.get(CDB + 1) == flags & 8,
                            'Normal read flags were not sanitized at native entry')
                guards += 1
    rom_psn = 0
    for multi in (0, 1):
        for ptp in (0, 1):
            for address in (0x30000, 0x800000, 0xdf8000, 0xffffff):
                ex = AdapterExperiment(overlay, stops=READERS.values())
                prepare(ex, packet(0x15, address=address, count=1), 0x44)
                ex.put(0x0200072a, multi)
                ex.put(0x0200072b, ptp)
                ex.put(0x02000400, 0x208000, 4)
                expected = ((address + 2 * 0x208001) & 0xffffff
                            if multi and not ptp and address & 0x800000 else address)
                result = ex.run(0x1b14e)
                require(result['start'] == expected and result['pc'] == READERS[0x40],
                        'DVD-ROM OTP/XGD PSN conversion failed')
                rom_psn += 1
    # BD DI identification: an empty (Wii U) or unknown DI is classified as
    # BD-ROM like a real BD-ROM DI, as main.asm's BDIdentifierPatch does.
    identification = []
    rom = bytearray(32)
    rom[0:2], rom[4:6], rom[8] = b'DI', b'BD', ord('O')
    dual = bytearray(rom)
    dual[0xa] = 0x20
    for name, di in (('empty', bytes(32)), ('bd-rom', bytes(rom)), ('bd-rom-dual', bytes(dual)),
                     ('unknown', b'DI\x01\x00XY\x00\x00Z' + bytes(23))):
        media = []
        for image in (original, overlay):
            ex = Experiment(image, [(0x133920, 0x133b20)], stubs={0x400c0: 0},
                            stops=(0x133346, 0x133a48, 0x133a4a))
            ex.cpu.mem_write(0x0200f800 + 0x28, di)
            ex.put(0x01ffabc0, 0x55)
            ex.cpu.reg_write(UC_ARM_REG_SP, 0x0200f800)
            ex.cpu.reg_write(UC_ARM_REG_R6, 0x01ffabc0)
            ex.cpu.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
            ex.cpu.emu_start(0x133920 | 1, SENTINEL, count=4000)
            require(ex.finished == 'boundary', 'BD identification did not finish')
            media.append(ex.get(0x01ffabc0))
        if name.startswith('bd-rom'):
            require(media[0] == media[1] and media[0] & 0xc0 == 0xc0, 'Real BD-ROM DI classification changed')
        else:
            require(media == [0, 0xc1], 'Empty/unknown DI was not classified as BD-ROM')
        identification.append(dict(di=name, original_media=media[0], patched_media=media[1]))
    # DVD control data read (MT1959 DVDTOCReadPatch): exhausted retries and
    # aborts return success, so a disc with unreadable PFI (NR/RVT-R) proceeds.
    control = []
    for abort, other_abort, start in ((1, 0, 0), (0, 1, 0), (0, 0, 0), (0, 0, 0xffffffff)):
        for media in (0x40, 0x60):
            results = []
            for image in (original, overlay):
                # Every native read attempt fails; the retry policy executes.
                ex = Experiment(image, [(0xcc0d8, 0xcc184)], stubs={0xce30c: 0})
                ex.put(MEDIA, media)
                ex.put(0x020006f0, abort)
                ex.put(0x01ffabbe, other_abort)
                ex.put(START, start, 4)
                ex.run(0xcc0d8, count=20000)
                results.append(ex.cpu.reg_read(REGS[0]))
            require(results[1] == 1 and results[0] in (0, 1), 'Control data read failure was not reported as success')
            control.append(dict(abort=abort, other_abort=other_abort, start=start, media=media,
                                original=results[0], patched=results[1]))
    require(any(c['original'] == 0 for c in control), 'No control data failure case was exercised')
    return dict(toc_cases=cases, pfi_cases=classifiers, bd_di_cases=bd,
                native_pfi_cases=native_pfi,
                native_bd_geometry_verified=True, ordinary_read_guard_cases=guards,
                dvd_rom_psn_cases=rom_psn, bd_identification_cases=identification,
                control_data_cases=control,
                optical_acquisition_verified=False)


def verify_identification(original):
    """Execute ROM template initialization followed by native standard INQUIRY.

    Host layout checked against redumper b1d5ff6e: reserved5 begins at byte 74,
    then nine signature bytes and three version bytes. No host DMA is modeled.
    """
    from audit_integrity import output_name
    overlay, _ = assemble(original)
    rows = []
    for allocation in (0, 36, 74, 86, 94, 96, 255):
        ex = MediaExperiment(overlay, ranges=[(0xa5080, 0xa50da), (0xa6646, 0xa6672),
            (0xa6b42, 0xa6b5e), (0x9cab0, 0x9cba8), (0x9b8c0, 0x9b8e6)],
            stubs={0xa63a8: 0, 0xa63b0: 0, 0x9ca70: 0}, stops=(0xa50da,))
        ex.run(0xa5080, count=20000)
        template = bytes(ex.cpu.mem_read(STRUCT + 0x1c780, 164))
        require(template == overlay[0x1c6f38:0x1c6f38 + 164], 'Native INQUIRY template copy mismatch')
        ex.stops.clear()
        ex.finished = None
        ex.cpu.mem_write(CDB, bytes([0x12, 0, 0, 0, allocation, 0]) + bytes(6))
        ex.run(0x9cab0)
        length = ex.get(0x02000636, 2)
        require(length == (min(allocation, 96) + 1) & ~1, 'Native INQUIRY length regression')
        if allocation:
            response = bytes(ex.cpu.mem_read(STRUCT + 0x1c780, length))
            require(response[4:5] == (b'\x5b' if length >= 5 else b''), 'Advertised INQUIRY length mismatch')
            require(response[8:min(length,64)] == template[8:min(length,64)], 'Drive identity changed')
            if length >= 86:
                require(response[74:83] == b'OmniDrive', 'Host cannot recognize OmniDrive signature')
                version = '.'.join(str(v) for v in response[83:86])
                require(output_name().endswith('-' + version + '.bin'), 'INQUIRY/build versions differ')
        rows.append(dict(allocation=allocation, transfer_length=length))
    extended = []
    for image in (original, overlay):
        ex = MediaExperiment(image, ranges=[(0xa5080, 0xa50da), (0xa6632, 0xa6672),
            (0xa6b42, 0xa6b5e), (0x9cab0, 0x9cba8), (0x9b8c0, 0x9b8e6)],
            stubs={0xa63a8: 0, 0xa63b0: 0, 0x9ca70: 0}, stops=(0xa50da,))
        ex.run(0xa5080, count=20000)
        ex.stops.clear()
        ex.finished = None
        ex.cpu.mem_write(CDB, bytes.fromhex('12000000f040000000000000'))
        ex.run(0x9cab0)
        require(ex.get(0x02000636, 2) == 164, 'Extended INQUIRY length changed')
        extended.append(bytes(ex.cpu.mem_read(STRUCT + 0x1c780, 164)))
    require(extended[1][74:86] == b'OmniDrive\x01\x00\x04',
            'Extended INQUIRY lost candidate marker')
    require(extended[0][:74] == extended[1][:74] and extended[0][86:] == extended[1][86:],
            'Extended INQUIRY changed outside the reviewed marker')
    return dict(native_template_copy_verified=True, host_signature_offset=74, inquiry_cases=rows,
                extended_inquiry_marker_only_change=True)
