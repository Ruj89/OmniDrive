#!/usr/bin/env python3
# Purpose: Emulate the pinned Windows utility's finalization worker and retry handling offline.
"""Execute the pinned utility's finalization worker offline, without a device.

Transport returns are injected at the Windows-independent wrapper boundary.
The native worker, CDB builder, retry counter and result writes execute as-is.
This does not emulate the firmware handoff or establish flash completion.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from verify_loader import Utility, require
from analyze_utility import EXPECTED_SHA256


def worker(utility, returns):
    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP
    u = utility.cpu
    thread, reference, form, tag = 0x1500000, 0x1501000, 0x1502000, 0x1503000
    # Synthetic host object and tag: this audit checks control flow, not CMAC.
    u.mem_write(thread, bytes(64))
    u.mem_write(thread + 0x30, struct.pack('<I', 0x12345678))
    u.mem_write(thread + 0x34, bytes([0, 1, 0]))  # no boot, encoded, boot byte zero
    u.mem_write(thread + 0x38, struct.pack('<I', tag))
    u.mem_write(tag, bytes(range(16)))
    u.mem_write(0x51daa8, struct.pack('<I', reference))
    u.mem_write(reference, struct.pack('<I', form))
    u.mem_write(form + 0x3e0, bytes(4))
    calls = []

    def transport(uc, address, size, unused):
        stack = uc.reg_read(UC_X86_REG_ESP)
        ret, drive, pointer, cdb_length, buffer, length, direction = struct.unpack(
            '<7I', uc.mem_read(stack, 28))
        require(len(calls) < len(returns), 'Unexpected extra transport call')
        result = returns[len(calls)]
        calls.append({'cdb_hex': bytes(uc.mem_read(pointer, cdb_length)).hex(),
                      'direction': direction, 'length': length, 'transport_return': result,
                      'synthetic_payload_hex': bytes(uc.mem_read(buffer, length)).hex()})
        require(drive == 0x12345678, 'Native worker changed the selected drive')
        uc.reg_write(UC_X86_REG_EAX, result & 0xffffffff)
        uc.reg_write(UC_X86_REG_ESP, stack + 4)
        uc.reg_write(UC_X86_REG_EIP, ret)

    hook = u.hook_add(UC_HOOK_CODE, transport, begin=0x40afe4, end=0x40afe4)
    try:
        u.mem_write(0x8ff000, struct.pack('<I', 0x890000))
        u.reg_write(UC_X86_REG_ESP, 0x8ff000)
        u.reg_write(UC_X86_REG_EAX, thread)
        u.emu_start(0x40bec8, 0x890000, count=10000, timeout=1000000)
        require(u.reg_read(UC_X86_REG_EIP) == 0x890000, 'Native worker did not return')
    finally:
        u.hook_del(hook)
    for call in calls:
        require(call['cdb_hex'] == '3b0501000000000010800000' and
                call['length'] == 16 and call['direction'] == 2 and
                call['synthetic_payload_hex'] == bytes(range(16)).hex(),
                'Unexpected native finalization command')
    return {'calls': calls, 'native_worker_returned': True,
            'native_result_field': int.from_bytes(u.mem_read(form + 0x3e0, 4), 'little')}


def verify(binary):
    utility = Utility(binary)
    cases = []
    for name, returns, count, expected in (
            ('zero_return_accepted', [0], 1, 2),
            ('full_length_accepted', [16], 1, 2),
            ('failure_retried_then_accepted', [-1, 16], 2, 2),
            ('two_failures_return_error', [-1, -1], 2, 1),
            ('short_positive_return_retried', [15, 15], 2, 1)):
        result = worker(utility, returns)
        require(len(result['calls']) == count and result['native_result_field'] == expected,
                f'Unexpected worker outcome: {name}')
        result['case'] = name
        cases.append(result)
    return {'utility_sha256': EXPECTED_SHA256, 'native_worker_address': 0x40bec8,
            'native_cdb_builder_address': 0x402760, 'transport_boundary': 0x40afe4,
            'cases': cases, 'offline_host_finalization_audit_passed': True,
            'hardware_tested': False, 'physical_flash_verified': False, 'flash_ready': False,
            'limits': [
                'Only the encoded, boot-skipping worker path is executed; host UI is excluded.',
                'Transport returns and the tag payload are synthetic; no Windows API or SG_IO runs.',
                'The worker makes no independent status-poll or physical-readback command.',
                'A transport failure may follow an actual write; native retry is not safe evidence for replay.',
                'Firmware handoff, controller remapping and physical timing remain unverified.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--utility', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.utility.read_bytes())
        with args.output.open('x') as output:
            output.write(json.dumps(result, indent=2) + '\n')
        print(f'Native host finalization: 5 cases passed; report: {args.output}; flash_ready=false')
        return 0
    except (OSError, ValueError, ImportError) as error:
        print(f'Audit stopped: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
