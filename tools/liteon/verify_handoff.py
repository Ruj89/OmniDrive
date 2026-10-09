#!/usr/bin/env python3
"""Offline native update gate -> handoff -> imported writer -> handler return.

Peripheral completion and SPI NOR are modeled. The native code-copy loop runs;
its controller-selected executable view is applied at an explicit model boundary.
No device is opened and no physical recovery or timing is established.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from verify_loader import ReaderGates, Utility, IMAGE_SHA256, build, require, sha, validate_inquiry
from verify_programmer import Nor, PROGRAMMER_SHA256
from audit_recovery import REGIONS
from stage_update import transfer_image


def run(original, incoming, inquiry, utility, jedec, fault=None):
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
    profile, descriptor = utility.profile(inquiry)
    programmer = profile[6:6 + descriptor['code_size']]
    require(sha(programmer) == PROGRAMMER_SHA256, 'Unexpected programmer')
    key, iv = inquiry[148:164], inquiry[16:32]
    cipher, tag = utility.encode(profile, key, iv)
    profile_payload = cipher + tag
    cipher, final_tag = utility.encode(incoming[0x70000:0x80000], key, iv, window=True)
    staged = incoming[:0x70000] + cipher + incoming[0x80000:]
    reader = ReaderGates(original, inquiry)

    class Device:
        def transfer(self, cdb, payload=None):
            if payload is None:
                return reader.read_buffer(cdb)
            status = reader.command(cdb, payload)
            require(not status['invalid_field'] and not status['auth_failure'], 'Staging rejected')

    staged_result = transfer_image(Device(), profile_payload, staged)
    require(staged_result['all_blocks_matched'], 'Incomplete native staging')
    reader.stop = 0x1baeb4
    final_cdb = utility.cdb(16, control=0x80)
    status = reader.command(final_cdb, final_tag)
    require(status['pc'] == reader.stop and not status['invalid_field'] and
            not status['auth_failure'], 'Native gate did not reach handoff')
    # Resume the SAME CPU state, stack, staging memory and caller return address.
    reader.stop = None
    u = reader.cpu
    u.mem_map(0x400000, 0x2000)
    u.mem_map(0x800000, 0x1000)
    nor = Nor(original, jedec, fault)
    observations, copies, entries, returns, mismatches = [], [], [], [], []

    def native(uc, address, size, unused):
        if address in (0xa361c, 0xa3624):
            # Interrupt state is outside this synchronous model.
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == 0x19a9c:
            mismatches.append(address)
            return
        observations.append(address)
        if address == 0x1baf22:
            length = 0x1bfc
            copied = bytes(uc.mem_read(0x400000, length))
            source = bytes(uc.mem_read(0x11e4000, length))
            require(copied == source and copied[:len(programmer)] == programmer,
                    'Native imported-programmer copy differs')
            windows = [reader.get(a) for a in (0x4011f10, 0x4011f14, 0x4011f18, 0x4011f1c)]
            require(windows == [0x19000, 0x19bff, 0x19c00, 0x1abff],
                    'Native executable mapping registers differ')
            copies.append({'source': 0x11e4000, 'temporary_alias': 0x400000,
                           'length': length, 'sha256': sha(copied), 'windows': windows})
            # Explicit controller model: expose the bytes copied by native code
            # at its selected executable address. No handoff function is skipped.
            uc.mem_write(0x19000, copied)
        elif address == 0x1baf46:
            header = bytes(uc.mem_read(0x11e6000, 27))
            require(header[:4] == bytes.fromhex('5aa5464c') and header[11] == 0x80,
                    'Native handoff header differs')
            require(struct.unpack_from('<III', header, 12) == (0x10000, 0x10000, 0x1d0000),
                    'Native boot-skipping writer bounds differ')
            require(reader.get(0x40d000c) == 0x100, 'Native staging base differs')
            require(bytes(uc.mem_read(0x19000, len(programmer))) == programmer,
                    'Executable imported writer differs')
            entries.append({'header_hex': header.hex(), 'staging_base': 0x1000000,
                            'firmware_chip_parameters_hex': bytes(uc.mem_read(0x2000d2c, 12)).hex()})
        elif address in (0x1baf48, 0x9ef7e):
            returns.append(address)

    def ready(uc, access, address, size, value, unused):
        if address in (0x4011014, 0x4011088):
            reader.put(address, 1)
        elif address == 0x4011010:
            reader.put(address, 2)
        elif address == 0x4010008:
            reader.put(address, reader.get(address) & ~0x100)

    def serial(uc, access, address, size, value, unused):
        if not value & 2:
            return
        require(size == 4, 'Unexpected SPI trigger width')
        tx_length, rx_length = reader.get(0x4011008) & 0x3ff, reader.get(0x4011004) & 0x3ff
        require(tx_length + rx_length <= 0x1000, 'SPI buffer overflow')
        tx = bytes(uc.mem_read(0x800000, tx_length))
        response = nor.transact(tx, rx_length, uc.reg_read(UC_ARM_REG_PC))
        if response:
            uc.mem_write(0x800000 + tx_length, response)

    observed = (0xa361c, 0xa3624, 0xa3b20, 0xa3952, 0xa3802, 0x1baf22,
                0x1baf46, 0x19000, 0x19a9c, 0x1baf48, 0x9ef7e)
    for address in observed:
        u.hook_add(UC_HOOK_CODE, native, begin=address, end=address)
    for address in (0x4011014, 0x4011088, 0x4011010, 0x4010008):
        u.hook_add(UC_HOOK_MEM_READ, ready, begin=address, end=address)
    u.hook_add(UC_HOOK_MEM_WRITE, serial, begin=0x401100c, end=0x401100c)
    u.emu_start(0x1baeb5, 0x3000000, count=150000000, timeout=20000000)
    pc = u.reg_read(UC_ARM_REG_PC)
    require(pc == 0x3000000, f'Native handoff execution limit at {pc:#x}')
    require(len(copies) == len(entries) == 1 and returns == [0x1baf48, 0x9ef7e],
            'Native writer/handler return path differs')
    expected = original[:0x10000] + incoming[0x10000:0x1e0000] + original[0x1e0000:]
    return {'jedec': f'{jedec:06x}', 'fault': fault, 'control': 0x80,
            'native_commands': len(reader.command_hashes), 'readback_comparisons': len(reader.readbacks),
            'finalization_cdb_hex': final_cdb.hex(), 'finalization_tag_sha256': sha(final_tag),
            'native_copy': copies[0], 'writer_entry': entries[0],
            'native_observations': observations, 'native_returns': returns, 'stop_pc': pc,
            'handler_invalid_field': u.mem_read(0x2000616, 1)[0],
            'handler_auth_failure': u.mem_read(0x20007e4, 1)[0],
            'native_readback_mismatches': len(mismatches), 'injected_fault_count': nor.fault_count,
            'spi_counts': {f'{op:02x}': count for op, count in sorted(nor.counts.items())},
            'first_erase': nor.erases[0], 'erase_commands': len(nor.erases),
            'program_commands': len(nor.programs), 'spi_trace_sha256': nor.trace.hexdigest(),
            'final_array_matches_expected': nor.data == expected, 'final_array_sha256': sha(nor.data),
            'changed_bytes_from_expected': sum(a != b for a, b in zip(nor.data, expected)),
            'regions': [{'name': name, 'matches_expected': nor.data[a:b] == expected[a:b],
                         'erased_bytes': sum(nor.erased[a:b]), 'programmed_bytes': sum(nor.programmed[a:b])}
                        for name, a, b in REGIONS]}


def verify(original, experimental, inquiry, binary):
    require(sha(original) == IMAGE_SHA256, 'Expected pinned original')
    require(experimental == build(original)[0], 'Unexpected experimental image')
    validate_inquiry(original, inquiry)
    utility = Utility(binary)
    cases = []
    for name, image, jedec, fault in (
            ('original', original, 0xc22015, None),
            ('original', original, 0xc22415, None),
            ('experimental', experimental, 0xc22015, None),
            ('experimental', experimental, 0xc22415, None),
            ('experimental_retry', experimental, 0xc22015, 'drop_once'),
            ('experimental_persistent_fault', experimental, 0xc22015, 'drop_always')):
        case = run(original, image, inquiry, utility, jedec, fault)
        case['case'] = name
        require(case['final_array_matches_expected'] == (fault != 'drop_always'),
                f'Unexpected modeled flash result: {name}')
        require(case['native_commands'] == 1026 and case['readback_comparisons'] == 512,
                'Native input sequence differs')
        require(not case['handler_invalid_field'] and not case['handler_auth_failure'],
                'Unexpected handler input failure')
        require(case['first_erase']['start'] == 0x1d0000 and
                case['regions'][0]['erased_bytes'] == case['regions'][0]['programmed_bytes'] == 0,
                'Unexpected boot/profile erase behavior')
        require(all(r['erased_bytes'] == r['programmed_bytes'] == 0 for r in case['regions'][3:]),
                'Reserved tails were touched')
        cases.append(case)
    return {'offline_native_handoff_audit_passed': True, 'cases': cases,
            'hardware_tested': False, 'physical_flash_verified': False, 'flash_ready': False,
            'models': ['Inherited input-gate DMA/AES, peripheral and EEPROM models from ReaderGates.',
                       'Additional interrupt mask/restore stubs at 0xa3624/0xa361c.',
                       'Native 7164-byte programmer copy executes; its checked executable mapping is applied at 0x1baf22.',
                       'Controller ready/completed responses and SPI NOR use synthetic compatible JEDEC IDs.',
                       'First-4-KiB RAM/SPI buffers are flat views; physical alias ownership and timing are not established.'],
            'limits': ['No real SATA transport, flash chip protection, electrical timing or interrupted-write recovery.',
                       'Handler return with clear input-error flags also occurs after a persistent write failure.',
                       'Full cold-start flash readback is required to validate any physical write.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('experimental', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--utility', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        inquiry = bytes.fromhex(json.loads(args.report.read_text())['extended_inquiry_hex'])
        result = verify(args.original.read_bytes(), args.experimental.read_bytes(),
                        inquiry, args.utility.read_bytes())
        with args.output.open('x') as output:
            output.write(json.dumps(result, indent=2) + '\n')
        print(f'Native handoff: 6 cases passed; report: {args.output}; flash_ready=false')
        return 0
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(f'Handoff audit stopped: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
