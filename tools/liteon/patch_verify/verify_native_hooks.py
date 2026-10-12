#!/usr/bin/env python3
"""Differential execution of the MT1939 mode, error, read-check and FUA paths.

The shared main.c hooks run against native MT1939 code; byte patches are
compared with the original instructions they replace.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import Experiment, REGS, require
from native_adapter import assemble, FORCE_UNIT_ACCESS
from verify_native_adapter import AdapterExperiment, MODE_CALLEES, prepare, packet

CDB_ADDRESS = 0x02000d20
CACHE_CHECK = 0x1be960
CACHE_STUBS = {0x40390: 0x10, 0x40778: 0, 0x4487c: 0, 0x44874: 0, 0x44890: 0}


def verify(original):
    overlay, symbols = assemble(original)
    error_cases = 0
    for raw in (0, 0x80):
        for disc_type in (0, 2, 3, 5):
            sites = {2: (0x1bf5ae,), 3: (0xb6668,)}.get(disc_type, (symbols['SetErrorModeHook'],))
            for site in sites:
                direct = site == symbols['SetErrorModeHook']
                for mask in (0, 0xff000000, 0xff00ff00, 0xffffffff):
                    for mode in (0, 0xf, 0x608105, 0xc00000, 0xa5a5a5a5):
                        for initial in (0, 0xffffffff, 0xa5a55a5a):
                            expected = Experiment(original, [(0x46918, 0x46a04)])
                            actual = AdapterExperiment(overlay,
                                ranges=[(0x46918, 0x46a04), (site, site + 4)],
                                stops=() if direct else (site + 4,))
                            actual.cpu.mem_write(CDB_ADDRESS, bytes([0xa8, raw | 2]))
                            clear = {2: 1, 3: 6}.get(disc_type, 0) if raw else 0
                            for ex, value in ((expected, mode & ~clear), (actual, mode)):
                                for reg, argument in zip(REGS, (disc_type, mask, value)):
                                    ex.cpu.reg_write(reg, argument)
                                for address in (0x04002100, 0x04002110, 0x04002118):
                                    ex.put(address, initial, 4)
                            before = expected.run(0x46918)
                            after = actual.run(site)
                            effects = lambda result: [(w['address'], w['size'], w['value'])
                                                      for w in result['writes']]
                            require(effects(before) == effects(after), 'Error-mode native effects differ')
                            require(bytes(expected.cpu.mem_read(0x04002100, 0x40)) ==
                                    bytes(actual.cpu.mem_read(0x04002100, 0x40)),
                                    'Error-mode registers differ')
                            error_cases += 1

    # main.c sets forceUnitAccess = 0xFF for a C0 FUA read. The native CD cache
    # check compares the flag with the cached mode (0 or 1), as on MT1959, so
    # 0xFF always takes the mismatch branch and the sector is read again.
    cache_cases = []
    for flag in (0, 1, 0xff):
        for mode in (0, 3):
            ex = AdapterExperiment(overlay, stubs=CACHE_STUBS, ranges=[(CACHE_CHECK, 0x1bebe4)])
            prepare(ex, packet(0), 4)
            ex.put(FORCE_UNIT_ACCESS, flag)
            ex.put(CDB_ADDRESS + 11, mode)
            ex.run(CACHE_CHECK, count=5000)
            taken = ex.trace[ex.trace.index(0x1be9d0) + 1]
            reuse = flag == (1 if mode == 3 else 0)
            require(taken == (0x1be9d2 if reuse else 0x1bea3c), 'Native FUA comparison changed')
            cache_cases.append({'flag': flag, 'cdb11': mode, 'cache_reusable': reuse})
    # The native CD reader keeps the flag main.c wrote until its cache check.
    ex = AdapterExperiment(overlay,
        stubs={0xa70e0: 0, **{a: 0 for a in MODE_CALLEES}, 0x1ba99c: 1,
               0x43440: 0, 0x43de6: 0, 0xa7600: 0, CACHE_CHECK: 1},
        ranges=[(0x18ae2c, 0x18aeca), (0x18afa4, 0x18afac)], stops=(0x18afac, 0x18b096))
    prepare(ex, packet(8), 4)
    ex.put(FORCE_UNIT_ACCESS, 0xff)
    ex.run(0x18ae2c)
    require(any(c['target'] == CACHE_CHECK for c in ex.calls) and ex.get(FORCE_UNIT_ACCESS) == 0xff,
            'Native CD reader changed the FUA flag before its cache check')
    return {'error_mode_cases': error_cases, 'cd_fua_cases': cache_cases,
            'optical_transfer_verified': False}


def verify_addressing_and_controls(original):
    """Run assembled conversion/control hooks and native boundary helpers."""
    from map_scsi import START, LENGTH, SENSE
    from verify_native_adapter import READERS
    overlay, symbols = assemble(original)
    descramble_cases = 0
    for media in (4, 0x40, 0x50, 0xc0):
        for flags in (0, 0x10, 0x80, 0x90):
            for seed in (0, 0xffffffff, 0xa5a55a5a):
                ex = AdapterExperiment(overlay, stubs={0xa70e0: 0, **{a: 0 for a in MODE_CALLEES}})
                prepare(ex, bytes([0xa8, flags]) + bytes(10), media)
                for address in (0x04032048, 0x04050010):
                    ex.put(address, seed, 4)
                ex.cpu.reg_write(REGS[0], 0xb)
                ex.run(symbols['ChangeDiscRWModeHook'])
                for address, bit in ((0x04032048, 8), (0x04050010, 4)):
                    off = flags & 0x80 and not flags & 0x10
                    require(ex.get(address, 4) == ((seed & ~bit) | (0 if off else bit)),
                            'Descrambling register mismatch')
                descramble_cases += 1
    # Execute the real BD prologue with its native cached-mode guard set; the
    # BDScramblePatch nop must still reach the mode hook.
    for raw in (0, 0x80):
        ex = AdapterExperiment(overlay, stubs={0x1789ac: 0, 0xa70e0: 0,
            **{a: 0 for a in MODE_CALLEES}}, ranges=[(0xb5828, 0xb5890)], stops=(0xb5890,))
        prepare(ex, bytes([0xa8, raw | 2]) + bytes(10), 0xc0)
        ex.put(0x020005fc, 1)
        ex.put(0x02000600, 0x40)
        ex.put(0x020005ff, 0)
        ex.run(0xb5828)
        require(ex.get(0x04032048, 4) & 8 == (0 if raw else 8),
                'Cached BD mode skipped the descrambling hook')
    # Generic read-mode selection (MT1959 ScrambleHookAddr) reaches the hook
    # for every media family it handles.
    generic = 0
    for media in (4, 0x60, 0x50, 0x40, 0xc0):
        for raw in (0, 0x80):
            ex = AdapterExperiment(overlay, stubs={0xa70e0: 0, **{a: 0 for a in MODE_CALLEES}},
                                   ranges=[(0xa59a4, 0xa59f0)])
            prepare(ex, bytes([0xa8, raw | 1]) + bytes(10), media)
            ex.put(int.from_bytes(overlay[0xa5b80:0xa5b84], 'little'), 0)  # not busy
            ex.put(0x04032048, 0xa5a5a5a5, 4)
            ex.run(0xa59a4)
            require(ex.get(0x04032048, 4) & 8 == (0 if raw else 8), 'Generic mode selection missed the hook')
            generic += 1
    bd_cases = 0
    for media in (0xc0, 0xc4):
        for boundary in (0x7fffff, 0xca73ff):
            threshold = 0x1ffffff - boundary
            for psn in (0, 0x100000, boundary, threshold - 1, threshold, 0x1ffffff):
                ex = AdapterExperiment(overlay, stops=READERS.values())
                prepare(ex, packet(0x16, address=psn, count=1), media)
                ex.put(0x02000400, boundary, 4)
                result = ex.run(0x1b14e)
                logical = (psn + 2 * boundary - 0x1fffffe
                           if media & 4 and psn >= threshold else psn)
                require(result['pc'] == READERS[0xc0] and result['start'] == logical,
                        'BD reverse PSN mismatch')
                if media & 4 and psn >= threshold:
                    native = Experiment(original, [(0xb059e, 0xb05ac)])
                    native.put(0x02000400, boundary, 4)
                    native.cpu.reg_write(REGS[0], logical)
                    native.run(0xb059e)
                    require(native.cpu.reg_read(REGS[0]) == psn, 'BD PSN round trip failed')
                bd_cases += 1
    cd_cases = 0
    for lba in (-4650, -151, -150, -149, -1, 0, 449849):
        for count in (1, 200):
            ex = AdapterExperiment(overlay, stops=READERS.values())
            prepare(ex, packet(0, address=lba & 0xffffffff, count=count), 4)
            result = ex.run(0x1b14e)
            require(result['pc'] == READERS[4] and result['start'] == (lba + 150) & 0xffffffff,
                    'CD signed lead-in address was rejected or changed')
            cd_cases += 1
    # DVD-R: raw reads have already been spoofed as A8 + bit 7. Bypass only
    # raw requests, and restore the sense that preceded the rejected check.
    checks = 0
    for opcode, flags, raw in ((0xa8, 1, False), (0xa8, 0x81, True),
                               (0xc0, 1, True), (0x28, 0x81, False)):
        for sense in (b'\x00\x00\x00', b'\x02\x04\x01'):
            for status in (0, 1, 3, 4, 5, 0x11, 0x12):
                for start in (0x100000, 0x100001):
                    native = Experiment(original, [(0x17d57c, 0x17d826)])
                    ex = AdapterExperiment(overlay, ranges=[(0x1bf3ba, 0x1bf3be), (0x17d57c, 0x17d826)],
                                           stops=(0x1bf3be,))
                    for e in (native, ex):
                        e.put(START, start, 4)
                        e.put(LENGTH, 1, 4)
                        e.put(0x020006b8, 0x100000, 4)
                        e.put(0x0200040c, status)
                        e.cpu.mem_write(SENSE, sense)
                    ex.cpu.mem_write(CDB_ADDRESS, bytes([opcode, flags]))
                    before = native.run(0x17d57c)
                    after = ex.run(0x1bf3ba)
                    rejected = native.cpu.reg_read(REGS[0]) == 0
                    require(ex.cpu.reg_read(REGS[0]) == (1 if raw and rejected else
                            native.cpu.reg_read(REGS[0])), 'DVD-R read-check override mismatch')
                    require(after['sense'] == (list(sense) if raw and rejected else before['sense']),
                            'DVD-R read-check sense differs')
                    checks += 1
    # BD lead-out: same bne -> b as main.asm, in the native BD read check.
    for kind in (0, 1, 2, 3):
        for start, length in ((0x100000, 1), (0x200000, 0x10)):
            results = []
            for image in (original, overlay):
                ex = Experiment(image, [(0x1bc41c, 0x1bc498)])
                ex.put(START, start, 4)
                ex.put(LENGTH, length, 4)
                ex.put(0x020006b8, 0x100000, 4)
                ex.put(0x02000609, 0)  # Not a recorded-range continuation.
                ex.cpu.mem_write(SENSE, bytes(3))
                ex.cpu.reg_write(REGS[0], kind)
                result = ex.run(0x1bc41c)
                results.append((ex.cpu.reg_read(REGS[0]), result['sense']))
            beyond = start + length - 1 > 0x100000
            if kind == 2 and beyond:
                require(results[0] == (0, [5, 0x21, 0]) and results[1] == (1, [0, 0, 0]),
                        'BD lead-out patch did not allow the read')
            else:
                require(results[0] == results[1], 'BD read check changed outside the lead-out case')
            checks += 1
    boundaries = 0
    for media in (0x40, 0x50, 0x60, 0x68):
        for start, count in ((0x60000, 1), (0x6ffff, 4), (0x70000, 1), (0x80001, 4)):
            ex = AdapterExperiment(overlay)
            prepare(ex, packet(0x11), media)
            ex.put(START, start, 4)
            ex.put(LENGTH, count, 4)
            for a, v in ((0x02000400, 0x6ffff), (0x02000458, 0x70000),
                         (0x020006b8, 0x80000), (0x02000484, 0x80000), (0x02000488, 0x80000)):
                ex.put(a, v, 4)
            ex.put(0x0200072a, 1)
            ex.cpu.reg_write(REGS[0], 2)
            ex.run(0x1bbc1c)
            require(ex.cpu.reg_read(REGS[0]) == 2, 'Raw DVD range rejected')
            require([ex.get(a) for a in (0x0200071e, 0x02000704)] ==
                    [int(start >= 0x70000), int(start < 0x70000 <= start + count - 1)],
                    'Lead-out relaxation lost DVD layer preparation')
            boundaries += 1
    for crossing in (False, True):
        ex = AdapterExperiment(overlay, ranges=[(0x1bd73c, 0x1bd77e)])
        ex.put(START, 90, 4)
        ex.put(LENGTH, 20 if crossing else 1, 4)
        ex.put(0x020006cc, 0x01000064, 4)
        ex.put(0x020006b8, 100, 4)
        ex.run(0x1bd73c)
        require(ex.cpu.reg_read(REGS[0]) == (0 if crossing else 1), 'CD lead-out classification failed')
        boundaries += 1
    return dict(descrambling_cases=descramble_cases, cached_bd_mode_cases=2,
                generic_mode_cases=generic,
                bd_psn_cases=bd_cases, cd_leadin_cases=cd_cases,
                native_read_check_cases=checks, boundary_cases=boundaries)


def verify_transfer_modes(original):
    """Execute actual copy-engine setup and DVD recovery register writes."""
    from unicorn.arm_const import UC_ARM_REG_SP
    overlay, _ = assemble(original)
    cases = 0
    for opcode in (0x28, 0xa8, 0xc0):
        for flags in (0x01, 0x11, 0x81, 0x91, 0x82, 0x92):
            raw_off = opcode == 0xa8 and flags & 0x80 and not flags & 0x10
            for mode in (1, 9, 10, 11, 0xa5a50009):
                # 0x44054 returns the saved interrupt state that the hook
                # must keep in r0 until 0x4404c restores it.
                ex = AdapterExperiment(overlay, ranges=[(0x44474, 0x445ea)],
                    stubs={0x44054: 0x5a, 0x4404c: 0})
                ex.cpu.mem_write(CDB_ADDRESS, bytes([opcode, flags]) + bytes(10))
                ex.put(0x0200fff0, mode, 4)  # Fifth native argument.
                for reg, value in zip(REGS, (3, 0, 0x10000, 0x1010)):
                    ex.cpu.reg_write(reg, value)
                ex.run(0x44474)
                require(ex.get(0x04032048, 4) == (mode & ~8 if raw_off else mode),
                        'Sector copy reenabled descrambling')
                require(ex.get(0x0200fff0, 4) == mode and
                        ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
                        'Copy hook corrupted native stride argument or stack')
                # Differentially compare every other native write. The mode
                # on the stack still determines 0x800/0x810-byte strides.
                before = Experiment(original, [(0x44474, 0x445ea)],
                                    stubs={0x44054: 0x5a, 0x4404c: 0})
                before.put(0x0200fff0, mode, 4)
                for reg, value in zip(REGS, (3, 0, 0x10000, 0x1010)):
                    before.cpu.reg_write(reg, value)
                before.run(0x44474)
                effects = lambda e: [(w['address'], w['size'], w['value']) for w in e.writes
                                     if w['address'] != 0x04032048]
                require(effects(ex) == effects(before), 'Copy stride/DMA effects changed')
                restores = lambda e: [c['args'][0] for c in e.calls if c['target'] == 0x4404c]
                require(restores(ex) == restores(before) and set(restores(ex)) == {0x5a},
                        'Copy hook lost the saved interrupt state')
                cases += 1
            ex = AdapterExperiment(overlay, ranges=[(0x1bf9fc, 0x1bfa08)], stops=(0x1bfa08,))
            ex.cpu.mem_write(CDB_ADDRESS, bytes([opcode, flags]) + bytes(10))
            ex.put(0x04032048, 0xa5a5a5a5, 4)
            ex.cpu.reg_write(REGS[0], 0x1234)  # Live transfer size at the site.
            ex.run(0x1bf9fc)
            expected = (0xa5a5a5a5 & ~0x2b) + 9
            require(ex.get(0x04032048, 4) == (expected & ~8 if raw_off else expected),
                    'DVD recovery reenabled descrambling')
            require(ex.cpu.reg_read(REGS[0]) == 0x1234 and ex.cpu.reg_read(REGS[1]) == 0x04032040,
                    'DVD transfer hook lost r0 or the register base in r1')
            cases += 1
    for kind in range(8):
        ex = AdapterExperiment(overlay, ranges=[(0xe4a26, 0xe4a2c)], stops=(0xe4a2c, 0xe4ae6))
        ex.cpu.reg_write(REGS[1], CDB_ADDRESS)
        ex.put(CDB_ADDRESS + 11, kind)
        result = ex.run(0xe4a26)
        require(result['pc'] == (0xe4a2c if kind < 6 else 0xe4ae6), 'CD lead-out gate regression')
    return dict(transfer_mode_cases=cases, cd_leadout_gate_cases=8)
