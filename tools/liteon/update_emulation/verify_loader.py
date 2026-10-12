#!/usr/bin/env python3
# Purpose: Verify original and patched firmware update-input checks by running native code offline.
"""Verify firmware update input gates offline with original ARM and x86 code.

No devices or Windows APIs. AES MMIO, DMA and peripheral preparation are modeled;
all tag comparisons, decoding, field validation and additive checks run natively.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import build, IMAGE_SHA256
from analyze_utility import EXPECTED_SHA256


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


INQUIRY_VALID_SHA256 = '6d1dc11d8918d4745ef6edfe0eb3cef8e7b28fb4841bf7834c7dcf28f8a6972b'


def validate_inquiry(original, inquiry):
    """Limit the modeled protocol to the retained specimen, including session data."""
    require(len(inquiry) >= 164 and inquiry[4] + 5 == 164, 'Unexpected INQUIRY valid length')
    valid = inquiry[:164]
    require(valid[8:64] == original[0x1c6f40:0x1c6f78], 'INQUIRY identity differs from firmware')
    require(valid[0x60:0x68] == b'EXTRAINQ', 'Unexpected INQUIRY extension')
    require(valid[0x6a:0x6e] == bytes.fromhex('c215002d'), 'Unexpected INQUIRY profile metadata')
    require(valid[0x6f] == 0x20, 'Unexpected INQUIRY flash size')
    require(valid[0x70] & 0x1f == 0, 'Unsupported INQUIRY writer type')
    require(valid[0x72] == 0xc2, 'Unsupported INQUIRY protocol flags')
    require(sha(valid) == INQUIRY_VALID_SHA256, 'INQUIRY differs from pinned captured specimen')
    return {'received_sha256': sha(inquiry), 'valid_sha256': sha(valid),
            'received_length': len(inquiry), 'valid_length': len(valid),
            'writer_type': valid[0x70] & 0x1f, 'protocol_flags': valid[0x72]}


class Utility:
    def __init__(self, binary):
        import pefile
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
        from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP
        require(sha(binary) == EXPECTED_SHA256, 'Unexpected Flash Utility binary')
        self.cpu = u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, 0x200000)
        u.mem_write(0x400000, pefile.PE(data=binary).get_memory_mapped_image())
        u.mem_map(0x800000, 0x100000)
        u.reg_write(UC_X86_REG_ESP, 0x8ff000)
        u.emu_start(0x54e790, 0x54e8be, count=20000000, timeout=20000000)
        require(u.reg_read(UC_X86_REG_EIP) == 0x54e8be, 'Unpack boundary not reached')
        u.mem_map(0x1000000, 0x600000)

    def call(self, address, args):
        from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP
        self.cpu.mem_write(0x8ff000, struct.pack('<' + 'I' * (len(args) + 1), 0x890000, *args))
        self.cpu.reg_write(UC_X86_REG_ESP, 0x8ff000)
        self.cpu.emu_start(address, 0x890000, count=15000000, timeout=10000000)
        require(self.cpu.reg_read(UC_X86_REG_EIP) == 0x890000, 'Utility function did not return')

    def profile(self, inquiry):
        # The utility matches FOUR metadata bytes across 239 six-byte records.
        metadata = inquiry[0x6a:0x6e]
        table = int.from_bytes(self.cpu.mem_read(0x50cd3c, 4), 'little')
        groups = int.from_bytes(self.cpu.mem_read(0x50cd44, 4), 'little')
        rows = bytes(self.cpu.mem_read(table, 239 * 6))
        matches = [i for i in range(239) if rows[i * 6:i * 6 + 4] == metadata]
        require(matches == [166], 'Unexpected specimen loader/profile selection')
        index = matches[0]
        offset = 0
        for i in range(index):
            if bytes(self.cpu.mem_read(groups + i * 4, 4)) != bytes(self.cpu.mem_read(groups + (i + 1) * 4, 4)):
                offset += int.from_bytes(rows[i * 6 + 4:i * 6 + 6], 'big')
        descriptor = rows[index * 6:index * 6 + 6]
        length = int.from_bytes(descriptor[4:6], 'big')
        address = 0x4d3b0e + offset
        code = bytes(self.cpu.mem_read(address, length))
        require(length == 3942 and sha(code) == '25341b2fc683c3b8bd0796c698f398d015565a0c71ef94de76ced9f8a6fdb666',
                'Unexpected extracted loader code')
        plain = descriptor + code
        plain += bytes((-len(plain)) % 16)
        return plain, {'index': index, 'descriptor_hex': descriptor.hex(), 'utility_address': address,
                       'code_size': length, 'code_sha256': sha(code), 'padded_size': len(plain)}

    def encode(self, plain, key, iv, *, window=False):
        from Crypto.Cipher import AES
        from Crypto.Hash import CMAC
        u = self.cpu
        u.mem_write(0x880000, key)
        u.mem_write(0x881000, iv)
        u.mem_write(0x1000000, plain)
        self.call(0x403e24, [0x1000000, 0x1200000, len(plain), 0x880000, 0x881000])
        encoded = bytes(u.mem_read(0x1200000, len(plain)))
        require(encoded == AES.new(key, AES.MODE_CBC, iv).encrypt(plain), 'Native utility CBC differs')
        self.call(0x404060 if window else 0x403f38, [0x1200000, 0x1400000, len(plain), 0x880000])
        tag = bytes(u.mem_read(0x1400000, 16))
        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(encoded)
        require(tag == cmac.digest(), 'Native utility tag differs from AES-CMAC')
        require(bytes(u.mem_read(0x1200000, len(plain))) == encoded, 'Tag function altered ciphertext')
        return encoded, tag

    def cdb(self, length, offset=0, control=0, boot=0, *, read=False):
        from unicorn import UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_ESP
        captured = []

        def hook(u, address, size, unused):
            stack = u.reg_read(UC_X86_REG_ESP)
            _, drive, pointer, cdb_length, buffer, size, direction = struct.unpack('<7I', u.mem_read(stack, 28))
            captured.append((bytes(u.mem_read(pointer, cdb_length)), size, direction))
            u.emu_stop()

        hook_id = self.cpu.hook_add(UC_HOOK_CODE, hook, begin=0x40afe4, end=0x40afe4)
        try:
            # Stops at the transport boundary; there is no SG_IO or Windows API.
            self.cpu.mem_write(0x8ff000, struct.pack('<7I', 0x890000, 0, 0x1000000,
                                                  offset, length, control, boot))
            self.cpu.reg_write(UC_X86_REG_ESP, 0x8ff000)
            self.cpu.emu_start(0x4026cc if read else 0x402760, 0x890000, count=1000, timeout=1000000)
            require(len(captured) == 1, 'CDB builder did not reach transport')
        finally:
            self.cpu.hook_del(hook_id)
        cdb, size, direction = captured[0]
        expected = bytes([0x3c, 1, 1] if read else [0x3b, 5, 1]) + offset.to_bytes(3, 'big') + length.to_bytes(3, 'big') + bytes([control, boot, 0])
        require(cdb == expected and size == length and direction == (1 if read else 2 if length else 0), 'Unexpected native buffer vector')
        return cdb

    def compare(self, expected, actual):
        """The writer's original byte comparison at 0x4046e9 calls this function."""
        from unicorn.x86_const import UC_X86_REG_EAX
        require(len(actual) == len(expected), 'Short READ BUFFER response')
        self.cpu.mem_write(0x1000000, expected)
        self.cpu.mem_write(0x1200000, actual)
        self.call(0x4c2b9c, [0x1000000, 0x1200000, len(expected)])
        return self.cpu.reg_read(UC_X86_REG_EAX) == 0


class ReadbackTransferError(ValueError):
    """A controller/command failure eligible for the utility's read retry."""


class ReaderGates:
    STUBS = {0x9b888: 'interrupt mask', 0x9b880: 'interrupt restore',
             0xa63b0: 'buffer interrupt mask', 0xa63a8: 'buffer interrupt restore',
             0x400c0: 'debug output', 0xa3638: 'peripheral preparation',
             0xa78b8: 'peripheral/state preparation',
             0xa499e: 'EEPROM update after input validation',
             0xa4830: 'EEPROM commit after input validation'}
    OBSERVE = (0x10c5dc, 0x10c7bc, 0x10c840, 0x10c3e2, 0x9ee20, 0x9ef2a, 0x9f140, 0x1baeb4)

    def __init__(self, firmware, inquiry):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        self.cpu = u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(0, 0x200000)
        u.mem_write(0, firmware)
        u.mem_map(0x1000000, 0x600000)
        u.mem_map(0x1ff0000, 0x20000)
        u.mem_map(0x3000000, 0x1000)
        u.mem_map(0x4000000, 0x100000)
        self.put(0x2000644, 0x1000000)
        self.put(0x2000648, 0x400000)
        # Response-template and flash-ID locations, separate from incoming data.
        u.mem_write(0x141c780, inquiry)
        u.mem_write(0x141ce96, inquiry[0x6a:0x6c])
        self.current = b''
        self.events, self.dma, self.command_hashes = [], [], []
        self.readbacks = []
        self.aes_operations = 0
        self.stop = None
        for address in (*self.STUBS, *self.OBSERVE, 0x3fd62):
            u.hook_add(UC_HOOK_CODE, self.code, begin=address, end=address)
        u.hook_add(UC_HOOK_MEM_WRITE, self.aes_write, begin=0x4063000, end=0x4063050)

    def get(self, address):
        return int.from_bytes(self.cpu.mem_read(address, 4), 'little')

    def put(self, address, value):
        self.cpu.mem_write(address, struct.pack('<I', value))

    def block(self, offset):
        return b''.join(self.get(0x4063000 + offset + i).to_bytes(4, 'big') for i in (12, 8, 4, 0))

    def output_block(self, offset, data):
        for i in range(4):
            self.put(0x4063000 + offset + 12 - i * 4, int.from_bytes(data[i * 4:i * 4 + 4], 'big'))

    def aes_write(self, u, access, address, size, value, unused):
        from Crypto.Cipher import AES
        if address != 0x4063000 or not value & 1:
            return
        # Model register ordering and AES operations, NOT tag-comparison results.
        cipher = AES.new(self.block(0x10), AES.MODE_ECB)
        source = self.block(0x20)
        mode = self.get(0x4063008)
        if mode & 4:
            if mode & 2:
                source = bytes(a ^ b for a, b in zip(source, self.block(0x30)))
            result = cipher.encrypt(source)
        else:
            result = cipher.decrypt(source)
            if mode & 2:
                result = bytes(a ^ b for a, b in zip(result, self.block(0x40)))
                self.output_block(0x40, source)
        self.output_block(0x30, result)
        self.put(0x4063004, 0)  # completed, no busy bit
        self.aes_operations += 1

    def code(self, u, address, size, unused):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR
        if address == 0x3fd62:
            offset, length = self.get(0x40300e8), self.get(0x4042154)
            require(length == len(self.current) and offset + length <= 0x200000, 'DMA request differs from supplied vector')
            u.mem_write(0x1000000 + offset, self.current)
            self.dma.append({'offset': offset, 'length': length})
        elif address not in self.STUBS:
            self.events.append({'address': address, 'args': [u.reg_read(r) for r in
                                (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]})
            if address == self.stop:
                u.emu_stop()
            return
        u.reg_write(UC_ARM_REG_R0, 0)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def command(self, cdb, payload=b''):
        from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        self.current = payload
        self.command_hashes.append(sha(cdb))
        self.cpu.mem_write(0x2000d20, cdb)
        self.cpu.reg_write(UC_ARM_REG_SP, 0x200f000)
        self.cpu.reg_write(UC_ARM_REG_LR, 0x3000001)
        require(cdb[0] in (0x3b, 0x3c), 'Unsupported verification command')
        self.cpu.emu_start(0x9d66d if cdb[0] == 0x3c else 0x9ec8d,
                         0x3000000, count=15000000, timeout=20000000)
        pc = self.cpu.reg_read(UC_ARM_REG_PC)
        require(pc in (0x3000000, self.stop), f'Unmodelled execution or limit at {pc:#x}')
        return {'pc': pc, 'invalid_field': self.cpu.mem_read(0x2000616, 1)[0],
                'auth_failure': self.cpu.mem_read(0x20007e4, 1)[0],
                'sense': list(self.cpu.mem_read(0x2000602, 3))}

    def read_buffer(self, cdb):
        status = self.command(cdb)
        if status['invalid_field'] or status['auth_failure']:
            raise ReadbackTransferError('READ BUFFER rejected')
        offset, length = self.get(0x40300e8), self.get(0x4042154)
        requested = int.from_bytes(cdb[6:9], 'big')
        require(length == requested and offset + length <= 0x200000, 'Invalid READ BUFFER DMA range')
        require(self.cpu.mem_read(0x2000613, 1)[0] == 1, 'READ BUFFER did not schedule data-in')
        data = bytes(self.cpu.mem_read(0x1000000 + offset, length))
        self.readbacks.append({'requested_offset': int.from_bytes(cdb[3:6], 'big'),
                               'dma_offset': offset, 'length': length, 'data_sha256': sha(data)})
        # Modeled controller data-in completion after the native handler returns.
        self.cpu.mem_write(0x2000613, b'\x00')
        return data


def profile_chip_cases(code):
    """Native imported profile ID predicate; only serial read responses modeled."""
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
    rows = []
    for jedec, expected in ((0xc22015, True), (0xc22415, True), (0xabcdef, False)):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(0x19000, 0x2000)
        u.mem_write(0x19000, code)
        u.mem_map(0x2000000, 0x10000)
        u.mem_map(0x3000000, 0x1000)
        u.mem_write(0x2000f20, b'\xff' * 12)
        reads = []

        def serial(uc, address, size, unused):
            command = uc.reg_read(UC_ARM_REG_R0)
            reads.append(command)
            uc.mem_write(uc.reg_read(UC_ARM_REG_R1), struct.pack('<I', jedec if command == 0x9f else 0xffffffff))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        u.hook_add(UC_HOOK_CODE, serial, begin=0x19cb4, end=0x19cb4)
        u.reg_write(UC_ARM_REG_SP, 0x200f000)
        u.reg_write(UC_ARM_REG_LR, 0x3000001)
        u.emu_start(0x19d47, 0x3000000, count=10000, timeout=1000000)
        require(u.reg_read(UC_ARM_REG_PC) == 0x3000000, 'Chip predicate did not return')
        accepted = u.reg_read(UC_ARM_REG_R0) == 1
        require(accepted == expected, 'Unexpected imported-profile chip selection')
        rows.append({'jedec': jedec, 'accepted': accepted, 'serial_read_commands': reads,
                     'selected_parameters_hex': bytes(u.mem_read(0x2000f20, 12)).hex()})
    return rows


def profile_programmer_cases(code):
    """Execute imported entry separately, stopping BEFORE the first erase command."""
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R3,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    rows = []
    for jedec in (0xc22015, 0xc22415):
        for control in (0x80, 0xa0):
            u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            for address, length in ((0x19000, 0x2000), (0x2000000, 0x10000),
                                    (0x3000000, 0x1000), (0x4000000, 0x100000),
                                    (0x1000000, 0x200000), (0x800000, 0x1000)):
                u.mem_map(address, length)
            u.mem_write(0x19000, code)
            u.mem_write(0x2000f20, b'\xff' * 12)
            u.mem_write(0x40d000c, struct.pack('<I', 0x100))
            u.mem_write(0x11e600b, bytes([control]))
            start = 0x10000 if control == 0x80 else 0
            u.mem_write(0x11e600c, struct.pack('<III', start, start, 0x1e0000 - start))
            reads = []

            def ready(uc, access, address, size, value, unused):
                if address == 0x4010008:
                    value = int.from_bytes(uc.mem_read(address, 4), 'little') & ~0x100
                    uc.mem_write(address, struct.pack('<I', value))
                elif address == 0x4011010:
                    uc.mem_write(address, b'\x02')  # transfer complete, not busy
                elif address == 0x800001:
                    uc.mem_write(address, b'\x00')  # serial status register: ready

            def boundary(uc, address, size, unused):
                if address == 0x19cb4:
                    command = uc.reg_read(UC_ARM_REG_R0)
                    reads.append(command)
                    uc.mem_write(uc.reg_read(UC_ARM_REG_R1), struct.pack(
                        '<I', jedec if command == 0x9f else 0xffffffff))
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                else:
                    uc.emu_stop()

            for address in (0x4010008, 0x4011010, 0x800001):
                u.hook_add(UC_HOOK_MEM_READ, ready, begin=address, end=address)
            for address in (0x19cb4, 0x19c4c):
                u.hook_add(UC_HOOK_CODE, boundary, begin=address, end=address)
            u.reg_write(UC_ARM_REG_SP, 0x200f000)
            u.reg_write(UC_ARM_REG_LR, 0x3000001)
            u.emu_start(0x19001, 0x3000000, count=100000, timeout=1000000)
            require(u.reg_read(UC_ARM_REG_PC) == 0x19c4c, 'Programmer did not reach first erase boundary')
            require(u.reg_read(UC_ARM_REG_R3) == 0xd8, 'Unexpected first erase opcode')
            erase_address = int.from_bytes(u.mem_read(u.reg_read(UC_ARM_REG_SP), 4), 'little')
            require(erase_address == 0x1df000, 'Unexpected first erase address')
            rows.append({'jedec': jedec, 'control': control, 'stop_pc': 0x19c4c,
                         'first_erase_opcode': 0xd8, 'first_erase_address': erase_address,
                         'serial_read_commands': reads})
    return rows


class ReadbackError(ValueError):
    pass


def transfer_block(utility, reader, offset, payload, *, fault=None):
    """Write then read/compare, with the utility's 3 transport / 2 compare limits.

    Optional faults affect the modeled controller response AFTER native READ BUFFER.
    """
    status = reader.command(utility.cdb(len(payload), offset), payload)
    require(not status['invalid_field'] and not status['auth_failure'], f'Block rejected at {offset:#x}')
    reads = 0
    for comparison in range(2):
        for attempt in range(3):
            reads += 1
            try:
                data = reader.read_buffer(utility.cdb(len(payload), offset, read=True))
            except ReadbackTransferError:
                continue
            if fault == 'failed':
                data = None
            elif fault == 'short':
                data = data[:-1]
            if data is not None and len(data) == len(payload):
                break
        else:
            raise ReadbackError(f'READ BUFFER transport failed after {reads} attempts at {offset:#x}')
        if fault == 'mismatch':
            data = bytes([data[0] ^ 1]) + data[1:]
        if utility.compare(payload, data):
            return reads
    raise ReadbackError(f'READ BUFFER mismatch after {reads} comparisons at {offset:#x}')


def verify(original, experimental, inquiry, binary, *, native_adapter=False):
    require(sha(original) == IMAGE_SHA256, 'Expected pinned original firmware')
    if native_adapter:
        from native_adapter import assemble
        expected_image = assemble(original)[0]
    else:
        expected_image = build(original)[0]
    require(experimental == expected_image, 'Unexpected experimental image')
    inquiry_report = validate_inquiry(original, inquiry)
    key, iv = inquiry[148:164], inquiry[16:32]
    utility = Utility(binary)
    profile, profile_report = utility.profile(inquiry)
    chip_cases = profile_chip_cases(profile[6:6 + 3942])
    programmer_cases = profile_programmer_cases(profile[6:6 + 3942])
    profile_cipher, profile_tag = utility.encode(profile, key, iv)
    profile_payload = profile_cipher + profile_tag
    profiles = []
    # Include rejection with a valid cryptographic tag but wrong flash ID/version.
    for name, payload, accepted in (
            ('valid', profile_payload, True),
            ('bad_tag', profile_cipher + bytes([profile_tag[0] ^ 1]) + profile_tag[1:], False),
            ('wrong_flash_id', b'', False), ('wrong_profile_version', b'', False)):
        if not payload:
            changed = bytearray(profile)
            changed[0 if name == 'wrong_flash_id' else 3] ^= 1
            cipher, tag = utility.encode(bytes(changed), key, iv)
            payload = cipher + tag
        ex = ReaderGates(original, inquiry)
        status = ex.command(utility.cdb(len(payload), control=0x7f), payload)
        passed = not status['invalid_field'] and not status['auth_failure']
        require(passed == accepted, f'Unexpected profile result: {name}')
        if accepted:
            require(bytes(ex.cpu.mem_read(0x11e4000, 3942)) == profile[6:6 + 3942], 'Profile not recovered byte-for-byte')
        profiles.append({'case': name, 'accepted': passed, 'status': status, 'events': ex.events,
                         'aes_operations': ex.aes_operations})
    cases = []
    for name, image, control, corruption, expected in (
            ('original_keep_boot', original, 0x80, None, True),
            ('experimental_keep_boot', experimental, 0x80, None, True),
            ('original_check_boot', original, 0xa0, None, True),
            ('experimental_check_boot', experimental, 0xa0, None, True),
            ('changed_instruction_stale_checksum', experimental, 0x80, 0x1cfffa, False),
            ('damaged_profile_checksum', experimental, 0x80, 0x1dfff8, False),
            ('damaged_boot_checksum', experimental, 0xa0, 0xfff8, False),
            ('damaged_main_tag', experimental, 0x80, 'tag', False),
            ('readback_mismatch', experimental, 0x80, 'mismatch', False),
            ('readback_failed', experimental, 0x80, 'failed', False),
            ('readback_short', experimental, 0x80, 'short', False)):
        ex = ReaderGates(original, inquiry)
        status = ex.command(utility.cdb(len(profile_payload), control=0x7f), profile_payload)
        require(not status['invalid_field'] and not status['auth_failure'], 'Baseline profile rejected')
        incoming = bytearray(image)
        if isinstance(corruption, int):
            incoming[corruption] ^= 2
        window, tag = utility.encode(bytes(incoming[0x70000:0x80000]), key, iv, window=True)
        incoming[0x70000:0x80000] = window
        # The original writer uses 4096-byte blocks and stages the complete file.
        readbacks = 0
        aborted = None
        try:
            for offset in range(0, 0x200000, 0x1000):
                payload = bytes(incoming[offset:offset + 0x1000])
                readbacks += transfer_block(utility, ex, offset, payload,
                                           fault=corruption if name.startswith('readback_') else None)
        except ReadbackError as error:
            require(name.startswith('readback_') and not expected, 'Unexpected readback failure')
            aborted = str(error)
        if aborted:
            require(not any(e['address'] == 0x1baeb4 for e in ex.events), 'Writer reached after failed readback')
            cases.append({'case': name, 'accepted': False, 'abort_reason': aborted,
                          'commands': len(ex.command_hashes), 'final_command_sent': False,
                          'readback_attempts': len(ex.readbacks),
                          'events': ex.events})
            continue
        if corruption == 'tag':
            tag = bytes([tag[0] ^ 1]) + tag[1:]
        ex.stop = 0x1baeb4  # native writer handoff after every input gate and range setup
        status = ex.command(utility.cdb(16, control=control), tag)
        passed = status['pc'] == ex.stop and not status['invalid_field'] and not status['auth_failure']
        require(passed == expected, f'Unexpected image acceptance: {name}')
        if passed:
            require(bytes(ex.cpu.mem_read(0x1000000, 0x1e0000)) == image[:0x1e0000], 'Decoded staging image differs')
            start = 0x10000 if control == 0x80 else 0
            require([ex.get(a) for a in (0x20006bc, 0x20006c0, 0x20006c4)] ==
                    [start, start, 0x1e0000 - start], 'Unexpected native writer ranges')
        cases.append({'case': name, 'accepted': passed, 'status': status, 'commands': len(ex.command_hashes),
                      'readback_comparisons': readbacks, 'final_command_sent': True,
                      'readbacks': ex.readbacks,
                      'command_sequence_sha256': sha(''.join(ex.command_hashes).encode('ascii')),
                      'dma_count': len(ex.dma), 'last_dma': ex.dma[-1], 'events': ex.events,
                      'writer_arguments': {hex(a): ex.get(a) for a in (0x20006bc, 0x20006c0, 0x20006c4)},
                      'aes_operations': ex.aes_operations})
    # Native sum endpoint is 512 bytes BEFORE the trailer, not a seeded full sum.
    trailer = struct.unpack_from('<I', original, 0x1cfff8)[0]
    native_sum = sum(w[0] for w in struct.iter_unpack('<I', original[0x10000:0x1cfdf8])) & 0xffffffff
    require(native_sum == trailer and original[0x1cfdf8:0x1cfff8] == b'\xff' * 512, 'Native sum layout differs')
    return {'input_sha256': IMAGE_SHA256, 'experimental_sha256': sha(experimental),
            'image_kind': 'native-adapter' if native_adapter else 'inquiry94-baseline',
            'utility_sha256': EXPECTED_SHA256, 'inquiry': inquiry_report, 'profile': profile_report,
            'imported_profile_chip_cases': chip_cases,
            'imported_programmer_entry_cases': programmer_cases,
            'profile_cases': profiles, 'image_cases': cases, 'native_input_gates_accept_experimental': True,
            'block_readback_verified': True,
            'native_main_sum': {'start': 0x10000, 'end_exclusive': 0x1cfdf8, 'stored_at': 0x1cfff8,
                                'original_sum': native_sum, 'excluded_ff_bytes': 512},
            'stubs': {hex(a): name for a, name in ReaderGates.STUBS.items()},
            'models': ['DMA completes with the exact host payload.',
                       'READ BUFFER data-in DMA copies bytes from the native handler offset/length; completion clears its pending flag.',
                       'Host retry loop reconstructed from utility 0x4046a3-0x404715; CDBs and byte comparisons execute original x86.',
                       'AES MMIO uses reversed BE32 register ordering, ECB/CBC and immediate completion.',
                       'Separate programmer runs model ready serial/controller status and synthetic compatible JEDEC IDs.',
                       'RAM bases and live response templates are synthetic, populated from captured INQUIRY.'],
            'flash_ready': False, 'hardware_tested': False,
            'limits': ['Stops at 0x1baeb4 before hardware preparation and imported flash-programmer execution.',
                       'Separate programmer runs use ready serial/controller responses and stop before first erase; controller remapping is not emulated.',
                       'Does not establish physical SATA transport or erase/write completion.',
                       'Captured INQUIRY does not establish the physical chip complete JEDEC ID or protection state.',
                       'Applies only to the pinned specimen and the modeled Flash Utility protocol.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('experimental', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--utility', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-adapter', action='store_true', help='Validate the exact native port build')
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text())
        result = verify(args.original.read_bytes(), args.experimental.read_bytes(),
                        bytes.fromhex(report['extended_inquiry_hex']), args.utility.read_bytes(),
                        native_adapter=args.native_adapter)
        with args.output.open('x') as output:
            output.write(json.dumps(result, indent=2) + '\n')
        count = sum(len(result[k]) for k in ('profile_cases', 'image_cases',
                                           'imported_profile_chip_cases', 'imported_programmer_entry_cases'))
        print(f'Native input gates verified: {count} scenarios; report: {args.output}; flash_ready=false')
        return 0
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(f'Verification stopped: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
