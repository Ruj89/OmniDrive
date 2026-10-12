#!/usr/bin/env python3
"""Build the production BW-12B1LT 1.03 OmniDrive image in isolation.

The verifiers execute exactly what CMake produces: libOmniDrive.a and
libOmniDriveMT1939.a are compiled with the CMake flags, armips assembles the
real profile asm/ASUS_BW-12B1LT_1.03.asm in a temporary tree, and the native
word sums are set as scripts/update_cmac.py does. Every changed byte must
belong to a reviewed site below. Nothing here opens a device.
"""
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import IMAGE_SHA256, output_name
from finalize_native import finalize

ROOT = Path(__file__).resolve().parents[3]
PROFILE = 'ASUS_BW-12B1LT_1.03'
# arm-toolchain.cmake flags plus CMAKE_C_STANDARD 11; see cmake/mt1939.cmake.
C_FLAGS = ('-Wall', '-nostdlib', '-fno-builtin', '-ffreestanding', '-mthumb',
           '-mthumb-interwork', '-march=armv5te', '-std=gnu11')
LIBRARIES = {'libOmniDrive.a': ('src/main.c', ()),
             'libOmniDriveMT1939.a': ('src/liteon/mt1939.c', ('-Os',))}
SOURCES = ('src/main.c', 'src/defs.h', 'src/mmio.h', 'src/liteon/mt1939.c',
           'asm/version.asm', f'asm/{PROFILE}.asm', 'asm/liteon/mt1939.asm',
           'cmake/mt1939.cmake', 'tools/liteon/patch_build/native_adapter.py',
           'tools/liteon/patch_build/finalize_native.py', 'scripts/update_cmac.py')

FLASH_PAYLOAD_BASE = 0x1dea00
FLASH_PAYLOAD_LIMIT = 0x1dff00
CHECKSUM_OFFSET = 0x1cfff8
PROFILE_CHECKSUM_OFFSET = 0x1dfff8
FORCE_UNIT_ACCESS = 0x020006fd

DISPATCH_HOOK = 0x1bba4
# Native BL sites -> (original callee, hook). Shared main.c hooks where MT1939
# has the MT1959 mechanism; Mt1939* where it differs.
MODE_HOOKS = (0xa59c6, 0x1bf410, 0xb588c, 0xe3384)  # generic, DVD, BD, RAM
CONTINUATION_HOOKS = (0x1c05f8, 0xe3d2a, 0xb6b3a)
ERROR_HOOKS = (0x1bf5ae, 0xb6668)  # DVD, BD
BD_MODE_GUARD = 0xb5888
READ_CHECK_HOOKS = {0x1bf3ba: (0x17d57c, 'Mt1939DVDMinusReadCheckHook'),
                    0xcbb50: (0xcb7e2, 'Mt1939DVDCharacteristicsHook'),
                    0xa24d4: (0xcc184, 'Mt1939ReadDVDTOCHook'),
                    0xa1e10: (0xb0fe6, 'Mt1939SetBDCharacteristicsHook')}
NORMAL_READ_HOOKS = {0x1b47e: (0xc8404, 'DVDReadCmdHook'),
                     0x1b43c: (0xace90, 'BDReadCmdHook')}
IDENTIFICATION_SPANS = ((0x1c6f82, 0x1c6f8e),)
# Same byte patches as main.asm / the MT1959 runtime patches, at this
# specimen's offsets: address -> (original byte, patched byte).
BYTE_PATCHES = {0x1bbc63: (0xd9, 0xe0),  # DVD lead-out bls -> b
                0x1bc453: (0xd1, 0xe0),  # BD lead-out bne -> b
                0xe4a28: (0x05, 0x06),   # CD lead-out cmp #5 -> #6
                0x1bd770: (0x40, 0x00),  # CD lead-out mov r0,#0
                0x13392d: (0xd0, 0xe0),  # BD identifier beq -> b
                0xcc16a: (0x00, 0x01)}   # control data read: failure -> success
NOP_PATCHES = (0x1bbca0, 0x1bbcb2, 0x1bbcbe, 0x1bbcd0, 0x1bbcde, 0x1bbcee,
               0x1bd7d4, 0x1bd7dc, 0x1bd7e4, 0x1bd890, 0x1bd8aa,
               0x133926, 0x1339d4, BD_MODE_GUARD)
# MT1939 only: site -> (C hook, patched bytes): BL plus reloads of the bases.
TRANSFER_HOOKS = {0x1bf9fe: ('Mt1939DVDTransferModeHook', 10),
                  0x44484: ('Mt1939CopyTransferModeHook', 14)}


def reviewed_offsets():
    """File offsets the production profile may change."""
    allowed = set(range(DISPATCH_HOOK, DISPATCH_HOOK + 8))
    for site in (*MODE_HOOKS, *ERROR_HOOKS, *READ_CHECK_HOOKS, *NORMAL_READ_HOOKS,
                 *CONTINUATION_HOOKS):
        allowed.update(range(site, site + 4))
    for site, (_, size) in TRANSFER_HOOKS.items():
        allowed.update(range(site, site + size))
    allowed.update(BYTE_PATCHES)
    for site in NOP_PATCHES:
        allowed.update(range(site, site + 2))
    for start, end in IDENTIFICATION_SPANS:
        allowed.update(range(start, end))
    allowed.update(range(FLASH_PAYLOAD_BASE, FLASH_PAYLOAD_LIMIT))
    for offset in (CHECKSUM_OFFSET, PROFILE_CHECKSUM_OFFSET):
        allowed.update(range(offset, offset + 4))
    return allowed


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def _run(command, **kwargs):
    try:
        result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    except FileNotFoundError as error:
        raise ValueError(f'{command[0]} is required on PATH') from error
    if result.returncode:
        raise ValueError(f'{command[0]} failed:\n{result.stdout}{result.stderr}')


def build_libraries(directory, compiler='arm-none-eabi-gcc'):
    archiver = compiler[:-len('gcc')] + 'ar'
    for name, (source, extra) in LIBRARIES.items():
        obj = directory / (Path(source).name + '.obj')
        _run([compiler, *C_FLAGS, *extra, '-c', str(ROOT / source), '-o', str(obj)])
        _run([archiver, 'rcs', str(directory / name), str(obj)])


def _call_target(image, site):
    h1, h2 = struct.unpack_from('<HH', image, site)
    if h1 & 0xf800 != 0xf000 or h2 & 0xf800 != 0xf800:
        raise ValueError(f'{site:#x} is not a Thumb BL')
    displacement = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
    if displacement & 0x400000:
        displacement -= 0x800000
    return site + 4 + displacement


def check_original_sites(original):
    """Each patched native instruction is the call or byte it is documented as."""
    callees = {**{s: 0x45b8a for s in MODE_HOOKS}, **{s: 0x46918 for s in ERROR_HOOKS},
               **{s: t for s, (t, _) in (READ_CHECK_HOOKS | NORMAL_READ_HOOKS).items()}}
    for site, target in callees.items():
        if _call_target(original, site) != target:
            raise ValueError(f'Native call at {site:#x} does not reach {target:#x}')
    for site, (before, _) in BYTE_PATCHES.items():
        if original[site] != before:
            raise ValueError(f'Unexpected original byte at {site:#x}')
    for site in CONTINUATION_HOOKS:
        # Replaced ldr r0,[pc,...]; ldrb r0,[r0] reads the native packet flag.
        h1, h2 = struct.unpack_from('<HH', original, site)
        literal = ((site + 4) & ~3) + (h1 & 0xff) * 4
        if h1 & 0xff00 != 0x4800 or h2 != 0x7800 or struct.unpack_from('<I', original, literal)[0] != 0x02000611:
            raise ValueError(f'Unexpected native continuation gate at {site:#x}')
    if original[FLASH_PAYLOAD_BASE:FLASH_PAYLOAD_LIMIT] != b'\xff' * (FLASH_PAYLOAD_LIMIT - FLASH_PAYLOAD_BASE):
        raise ValueError('Free space is not erased in the original')


def assemble(original, compiler='arm-none-eabi-gcc'):
    """Return the finalized production image and its armips symbols."""
    if len(original) != 0x200000 or hashlib.sha256(original).hexdigest() != IMAGE_SHA256:
        raise ValueError('Native adapter requires the exact original BW-12B1LT 1.03 specimen')
    check_original_sites(original)
    with tempfile.TemporaryDirectory(prefix='mt1939-build-') as directory:
        work = Path(directory)
        shutil.copytree(ROOT / 'asm', work / 'asm')
        for name in ('build', 'firmware', 'patched_firmware'):
            (work / name).mkdir()
        (work / 'firmware' / f'{PROFILE}.bin').write_bytes(original)
        build_libraries(work / 'build', compiler)
        _run(['armips', f'{PROFILE}.asm', '-sym2', str(work / 'image.sym')], cwd=work / 'asm')
        image = finalize((work / 'patched_firmware' / output_name()).read_bytes())
        symbols = {}
        for line in (work / 'image.sym').read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and not fields[1].startswith('.'):
                symbols[fields[1].split(',')[0]] = int(fields[0], 16)
    if len(image) != len(original):
        raise ValueError('Production profile changed the firmware size')
    allowed = reviewed_offsets()
    if any(a != b and i not in allowed for i, (a, b) in enumerate(zip(original, image))):
        raise ValueError('Unexpected change outside the reviewed hook sites')
    hooks = {name for name, _ in TRANSFER_HOOKS.values()} | {
        name for _, name in (READ_CHECK_HOOKS | NORMAL_READ_HOOKS).values()}
    for name in hooks | {'Mt1939DispatchHook', 'ChangeDiscRWModeHook', 'SetErrorModeHook',
                         'Mt1939ContinuationPendingHook'}:
        if not FLASH_PAYLOAD_BASE <= symbols.get(name, 0) < FLASH_PAYLOAD_LIMIT:
            raise ValueError(f'{name} is not placed in the free space')
    for site in CONTINUATION_HOOKS:
        if _call_target(image, site) != symbols['Mt1939ContinuationPendingHook']:
            raise ValueError(f'Continuation hook missing at {site:#x}')
    for site, (_, after) in BYTE_PATCHES.items():
        if image[site] != after:
            raise ValueError(f'Byte patch missing at {site:#x}')
    return image, symbols
