#!/usr/bin/env python3
"""Exercise the assembled MT1939 C0 path with bounded native execution.

Expected results come from a model of the shared main.c entry point, so the
checks cover main.c's own semantics running against native MT1939 code.
"""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import (CDB, MEDIA, START, LENGTH, SENSE, Experiment,
                      dispatch, require)
from native_adapter import (assemble, FLASH_PAYLOAD_BASE, FLASH_PAYLOAD_LIMIT,
                            FORCE_UNIT_ACCESS, NORMAL_READ_HOOKS)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_SP)

SECTOR_FORMAT = 0x04050064
READERS = {4: 0x18ae2c, 0x40: 0x1bf38c, 0x50: 0xe3370, 0xc0: 0xb5828}
MODE_CALLEES = (0x45998, 0x41a44, 0x448a0, 0x41f16, 0x421de,
                0x4233e, 0x44b14, 0x44e50, 0x44eba)
NATIVE_RANGES = [(0x1b14e, 0x1bdea), (0xe8ba0, 0xe8bbc),
                 (0x1bd8d8, 0x1bd93c), (0x1b9b0c, 0x1b9b24),
                 (0x1bbc1c, 0x1bbd70),
                 (0xcb78a, 0xcb7e2),
                 (0x45b8a, 0x45bde)]


class AdapterExperiment(Experiment):
    def __init__(self, overlay, *, stubs=None, stops=(), ranges=()):
        super().__init__(overlay, NATIVE_RANGES + [(FLASH_PAYLOAD_BASE, FLASH_PAYLOAD_LIMIT)] + list(ranges),
                         stubs={0x1afb4: 1, **(stubs or {})}, stops=stops)

    def raw_marked(self):
        """main.c marks DVD/BD raw reads as READ(12) with CDB[1] bit 7."""
        cdb = self.cpu.mem_read(CDB, 2)
        return cdb[0] == 0xa8 and bool(cdb[1] & 0x80)


def packet(flags, address=0x123456, count=0x234, extras=0):
    cdb = bytearray(12)
    cdb[0:2] = bytes([0xc0, flags])
    cdb[2:6] = address.to_bytes(4, 'big')
    cdb[6:10] = count.to_bytes(4, 'big')
    cdb[10] = extras
    return bytes(cdb)


def prepare(ex, cdb, media):
    ex.cpu.mem_write(CDB, cdb)
    ex.put(MEDIA, media)
    ex.put(0x02000611, 1)
    ex.put(SECTOR_FORMAT, 0xa5a50010, 4)
    ex.put(0x04082103, 1)  # Native DVD layer mode is already configured.


def expected_c0(media, cdb):
    """Shared C0 semantics with MT1939 validation before entering main.c.

    Returns ('read', None), ('noop', None) or ('sense', [key, asc, ascq]). MT1939 stops after
    MEDIUM NOT PRESENT and keeps rejected requests out of the raw handler.
    """
    if cdb[6]:
        return 'sense', [5, 0x24, 0]
    if not media:
        return 'sense', [2, 0x3a, 0]
    kind = cdb[1] & 3
    cd, dvd, bd = (media & 0xc4) == 4, (media & 0xc0) == 0x40, (media & 0xc0) == 0xc0
    if kind == 3:
        return 'sense', [5, 0x24, 0]
    if not (cd, dvd, bd)[kind]:
        return 'sense', [5, 0x30, 2]
    if (kind == 0 and cdb[1] & 0x10) or (kind and cdb[10]):
        return 'sense', [5, 0x24, 0]
    if not any(cdb[6:10]):
        return 'noop', None
    return 'read', None


def verify(original):
    overlay, symbols = assemble(original)
    baseline = dispatch(original)['cases']
    targets = {c['pc'] for c in baseline if c['termination'] == 'boundary'}
    # Compare dispatcher routing at handler entry. Guard behavior is tested
    # separately by executing the shared hooks with mapped disc-structure memory.
    guards = {symbols[name]: target for target, name in NORMAL_READ_HOOKS.values()}
    passthrough = 0
    for case in baseline:
        if case['opcode'] == 0xc0:
            continue
        ex = AdapterExperiment(overlay, stops=targets | guards.keys())
        prepare(ex, bytes([case['opcode']]) + bytes(11), case['media'])
        result = ex.run(0x1b14e)
        if result['pc'] in guards:
            result['pc'] = guards[result['pc']]
            result['calls'][-1]['target'] = result['pc']
        for key in ('termination', 'pc', 'sense', 'start', 'length', 'cdb_after', 'calls'):
            require(result[key] == case[key], f'Non-C0 regression for {case["opcode"]:#x}: {key}')
        effects = lambda r: [(w['address'], w['size'], w['value']) for w in r['writes']]
        require(effects(result) == effects(case), 'Non-C0 memory effects changed')
        passthrough += 1

    reads = []
    for media, flags, bias, raw_format in ((4, 0, 150, 0x10), (0x40, 0x11, 0x30000, 0x98),
                                         (0x50, 0x11, 0x31000, 0x98), (0xc0, 0x12, 0x100000, 0xf8)):
        for fua in (0, 8):
            for count in (1, 0x234, 0xffffff):
                for extras in (range(8) if media == 4 else (0,)):
                    ex = AdapterExperiment(overlay, stops=READERS.values())
                    cdb = packet(flags | fua, count=count, extras=extras)
                    prepare(ex, cdb, media)
                    ex.put(FORCE_UNIT_ACCESS, 0)
                    result = ex.run(0x1b14e)
                    require(result['pc'] == READERS[media], 'Native reader routing mismatch')
                    require(result['start'] == 0x123456 + bias and result['length'] == count,
                            'Raw read parameters differ')
                    # main.c writes the whole register, as on MT1959.
                    expected = raw_format | (bool(extras & 3)) | (2 if extras & 4 else 0)
                    require(ex.get(SECTOR_FORMAT, 4) == (expected if media == 4 else raw_format),
                            'Raw sector format mismatch')
                    if media == 4:
                        subq = 0x800 if (extras & 3) == 2 else 0
                        require(ex.get(0x04050060, 4) & 0xf00 == subq, 'Native CD selector mismatch')
                        require(ex.get(FORCE_UNIT_ACCESS) == (0xff if fua else 0),
                                'CD FUA did not reach the native flag')
                    else:
                        require(result['calls'][-1]['args'][0] == fua, 'Native FUA argument mismatch')
                        require(ex.raw_marked() and ex.get(CDB + 1) == flags | fua | 0x80,
                                'Raw marker mismatch')
                    reads.append({'media': media, 'packet': cdb.hex(), 'format': ex.get(SECTOR_FORMAT, 4),
                                  **result})

    msf = AdapterExperiment(overlay, stops=READERS.values())
    prepare(msf, packet(4, address=0x010203), 4)
    result = msf.run(0x1b14e)
    require(result['pc'] == READERS[4] and result['start'] == (62 * 75 + 3), 'Native MSF conversion mismatch')
    reads.append({'media': 4, 'binary_msf': True, **result})

    rejected = []
    accepted = 0
    for media in (0, 4, 0x40, 0x50, 0xc0):
        for flags in range(0x20):
            for extras, count in ((0, 1), (1, 1), (0, 0x1000000)):
                cdb = packet(flags, count=count, extras=extras)
                outcome, sense = expected_c0(media, cdb)
                ex = AdapterExperiment(overlay, stops=READERS.values())
                prepare(ex, cdb, media)
                ex.put(0x02000634, 0x4321, 2)
                result = ex.run(0x1b14e)
                if outcome == 'read':
                    require(result['termination'] == 'boundary' and result['pc'] in READERS.values(),
                            'Accepted C0 did not reach a native reader')
                    accepted += 1
                    continue
                require(result['termination'] == 'returned' and result['sense'] == sense,
                        f'C0 response differs from main.c for media {media:#x} cdb {cdb.hex()}')
                require(ex.get(0x02000634, 2) == 0x4321 and
                        ex.get(SECTOR_FORMAT, 4) == 0xa5a50010 and
                        result['cdb_after'] == cdb.hex(),
                        'Rejected C0 changed read timer, format or packet')
                rejected.append({'media': media, 'packet': cdb.hex(), 'sense': sense})

    for media, flags in ((4, 0), (0x40, 0x11), (0x50, 0x11), (0xc0, 0x12)):
        ex = AdapterExperiment(overlay, stubs={0x1afb4: 0}, stops=READERS.values())
        cdb = packet(flags)
        prepare(ex, cdb, media)
        ex.cpu.mem_write(SENSE, bytes([2, 4, 1]))
        result = ex.run(0x1b14e)
        require(result['termination'] == 'returned' and result['cdb_after'] == cdb.hex()
                and result['start'] == result['length'] == 0 and result['sense'] == [2, 4, 1]
                and ex.get(SECTOR_FORMAT, 4) == 0xa5a50010,
                'Not-ready operation reached a reader or changed parameters')

    # Other unknown opcodes keep the native ILLEGAL REQUEST from the default arm.
    for opcode in (0xc1, 0xdf, 0xff):
        ex = AdapterExperiment(overlay, stops=READERS.values())
        prepare(ex, bytes([opcode]) + bytes(11), 0x40)
        result = ex.run(symbols['Mt1939DispatchHook'])
        require(result['termination'] == 'returned' and result['sense'] == [5, 0x20, 0]
                and not result['calls'], 'Unknown opcode activated C0')

    # Execute the real native reader prologues and the patched BL instructions,
    # stopping after mode selection; later optical execution is unmodelled.
    # The sector format written by main.c must survive native mode selection.
    prologues = []
    mode_stubs = {0xa70e0: 0, **{a: 0 for a in MODE_CALLEES}}
    for media, flags, region, stop, extra_stubs, raw_format in (
            (0x40, 0x01, (0x1bf38c, 0x1bf414), 0x1bf414, {}, 0x98),
            (0xc0, 0x02, (0xb5828, 0xb5890), 0xb5890, {0x1789ac: 0}, 0xf8)):
        ex = AdapterExperiment(overlay, ranges=[region], stops=[stop],
                               stubs={**mode_stubs, **extra_stubs})
        prepare(ex, packet(flags), media)
        ex.put(0x020005fc, 1)  # BD native prologue state, bypass unrelated readiness check
        ex.put(0x04032048, 0xffffffff, 4)
        ex.put(0x04050010, 0xffffffff, 4)
        result = ex.run(0x1b14e)
        mode_calls = [c for c in result['calls'] if c['target'] in MODE_CALLEES]
        require(result['pc'] == stop and mode_calls, 'Native mode selector did not run')
        require(ex.get(SECTOR_FORMAT, 4) == raw_format, 'Native mode selection changed the raw format')
        require(ex.get(0x04032048, 4) & 8 == 0 and ex.get(0x04050010, 4) & 4 == 0,
                'Mode hook did not disable descrambling')  # no 0x10 descramble flag
        prologues.append({'media': media, 'format': ex.get(SECTOR_FORMAT, 4), **result})

    # Callee-saved registers and the original dispatch frame survive a returning reader.
    ex = AdapterExperiment(overlay, stubs={READERS[0x40]: 0})
    prepare(ex, packet(0x11), 0x40)
    regs = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7)
    saved = (0x12345678, 0x23456789, 0x3456789a, 0x456789ab)
    for register, value in zip(regs, saved):
        ex.cpu.reg_write(register, value)
    result = ex.run(0x1b14e)
    require(result['termination'] == 'returned' and ex.cpu.reg_read(UC_ARM_REG_SP) == 0x0200fff0,
            'Adapter corrupted native dispatch stack')
    require(tuple(ex.cpu.reg_read(r) for r in regs) == saved, 'Adapter corrupted callee-saved registers')

    # Compare layer state with execution of the original helper on the same
    # addresses. Exercise reads before, across and after the layer boundary.
    layer_cases = []
    for address, count in ((0x3fffe, 1), (0x3fffe, 4), (0x40000, 1),
                           (0x40001, 4), (0, 0x40001), (0, 0x100001)):
        native = Experiment(original, [(0x1bbc1c, 0x1bbd70)])
        adapted = AdapterExperiment(overlay, stops=READERS.values())
        for experiment in (native, adapted):
            prepare(experiment, packet(0x11, address=address, count=count), 0x60)
            experiment.put(0x0200072a, 1)  # Native multi-layer indication.
            experiment.put(0x02000458, 0x70000, 4)  # Native layer boundary.
            experiment.put(0x02000484, 0x7fffff, 4)  # Native recorded-area end.
            experiment.put(0x04082103, 1)  # Already configured layer mode.
            experiment.put(0x0200071e, 0xff)
            experiment.put(0x02000704, 0xff)
        native.put(START, address + 0x30000, 4)
        native.put(LENGTH, count, 4)
        native.cpu.reg_write(UC_ARM_REG_R0, 2)
        native.run(0x1bbc1c)
        actual = adapted.run(0x1b14e)
        require(actual['pc'] == READERS[0x40], 'Layer preparation lost the native reader')
        flags = [adapted.get(a) for a in (0x0200071e, 0x02000704)]
        require(flags == [native.get(a) for a in (0x0200071e, 0x02000704)],
                'Adapter differs from native layer preparation')
        layer_cases.append({'address': address, 'count': count, 'flags': flags,
                            'native_helper_return': native.cpu.reg_read(UC_ARM_REG_R0)})
    require({tuple(c['flags']) for c in layer_cases} == {(0, 0), (0, 1), (1, 0)},
            'Layer tests did not exercise all three observed states')

    psn_cases = []
    for media in (0x50, 0x60, 0x68):
        for multilayer in (0, 1):
            for ptp in (0, 1):
                for psn in (0x30000, 0x1fffff, 0x7fffff, 0xdfffff, 0xe00000, 0xffffff):
                    native = Experiment(original, [(0xcb78a, 0xcb7e2)])
                    adapted = AdapterExperiment(overlay, stops=READERS.values())
                    for experiment in (native, adapted):
                        prepare(experiment, packet(0x15, address=psn, count=4), media)
                        experiment.put(0x0200072a, multilayer)
                        experiment.put(0x0200072b, ptp)
                        experiment.put(0x02000458, 0x200000, 4)
                        experiment.put(0x02000490, 0x210000, 4)
                        experiment.put(0x02000484, 0xffffffff, 4)
                        experiment.put(0x02000488, 0xffffffff, 4)
                        experiment.put(0x020006b8, 0xffffffff, 4)
                        experiment.put(0x04082103, 1)
                    native.cpu.reg_write(UC_ARM_REG_R0, psn)
                    native.run(0xcb78a)
                    converted = native.cpu.reg_read(UC_ARM_REG_R0)
                    boundary = 0x210000 if media == 0x60 else 0x200000
                    expected = ((psn + 2 * boundary) & 0xffffff
                                if multilayer and not ptp and psn & 0x800000 else psn)
                    require(converted == expected, 'Native reverse-PSN semantics differ from mapped formula')
                    result = adapted.run(0x1b14e)
                    require(result['pc'] == READERS[0x50 if media == 0x50 else 0x40]
                            and result['start'] == converted and result['length'] == 4,
                            'DVD PSN command differs from native conversion')
                    psn_cases.append({'media': media, 'multilayer': multilayer, 'ptp': ptp,
                                      'psn': psn, 'converted_start': converted})

    return {'adapter_abi_verified': True, 'full_omnidrive_port': False, 'flash_ready': False,
            'original_sha256': hashlib.sha256(original).hexdigest(),
            'overlay_sha256': hashlib.sha256(overlay).hexdigest(),
            'dependencies': {name: version(name) for name in ('capstone', 'unicorn')},
            'overlay_size': len(overlay), 'placement': 'production-profile',
            'payload_base': FLASH_PAYLOAD_BASE,
            'symbols': {k: v for k, v in symbols.items() if FLASH_PAYLOAD_BASE <= v < FLASH_PAYLOAD_LIMIT},
            'passthrough_dispatch_cases': passthrough, 'raw_parameter_cases': reads,
            'accepted_cases': accepted, 'rejected_cases': rejected, 'not_ready_cases': 4,
            'native_mode_prologues': prologues, 'callee_saved_registers_and_stack_preserved': True,
            'native_dvd_layer_cases': layer_cases,
            'native_dvd_psn_cases': psn_cases,
            'limitations': ['Data readers are stopped or substituted; only their mode-selection prologues run.',
                            'Readiness, DVD/BD optical helpers and mode-callee MMIO effects use explicit models.',
                            'MT1939 validates C0 before main.c; rejected requests keep the packet, '
                            'read timer and format unchanged, including MEDIUM NOT PRESENT.',
                            'Error-mode, addressing, media and transfer hooks are tested by separate verifiers.',
                            'Alternate command-state routes and complete optical behavior remain unverified.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('--report', type=Path, required=True, help='New JSON report')
    args = parser.parse_args()
    report = verify(args.original.read_bytes())
    with args.report.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(f'Native adapter verified: {report["passthrough_dispatch_cases"]} unchanged dispatch cases, '
          f'{len(report["raw_parameter_cases"])} raw parameter cases, '
          f'{len(report["rejected_cases"])} rejected cases; flash_ready: false')


if __name__ == '__main__':
    main()
