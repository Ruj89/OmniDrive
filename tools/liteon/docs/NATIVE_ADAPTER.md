# Native MT1939 adapter for BW-12B1LT 1.03

The port follows the same structure as the MT1959 profiles:

| File | Role |
| --- | --- |
| `asm/ASUS_BW-12B1LT_1.03.asm` | Profile: free space, RAM/MMIO, native functions and patch addresses |
| `asm/liteon/mt1939.asm` | Counterpart of `asm/main.asm`: imports the C libraries into the free space, then only `bl` hooks and byte/`nop` patches, in `main.asm` order |
| `src/main.c` (`libOmniDrive.a`) | Shared OmniDrive payload, linked **unchanged**; its hooks are used directly where MT1939 has the MT1959 mechanism |
| `src/liteon/mt1939.c` (`libOmniDriveMT1939.a`) | Only what differs on MT1939 (see below) |
| `cmake/mt1939.cmake` | Builds the platform library (`-Os`) before armips runs |

There is no hand-written logic in assembly and the adapter allocates no RAM.
Like `main.c`, a raw read is marked in the CDB itself (`C0`, or the spoofed
`A8` with `CDB[1]` bit 7). Where a native register contract must survive a
call, the hook site is a `bl` to C plus reloads of the clobbered literal
bases; live `r0` values are passed through the C function's return value.
`update_cmac.py` recognizes this platform and sets its native word sums
instead of a CMAC. This remains an experimental port: offline checks do not
establish physical optical support. See [OMNIDRIVE_PORT.md](OMNIDRIVE_PORT.md).

## MT1959 → MT1939 mapping

Every `main.asm` patch was located in the decoded BW-16D1HT 3.02 original
and compared with this specimen, side by side in disassembly and by
emulation. `compare_mt1959.py` reproduces the comparison: it masks
PC-relative fields, scores every site, and unpacks the MT1959 RAM overlay
(flash `0x15c000`, Huffman/LZ77, loaded at `0x01f72000`) that holds the
code `main.c` patches at runtime. Low scores in its table are sites whose
counterparts were established by reading both functions, not by the score.

| `main.asm` / `main.c` | MT1939 | Notes |
| --- | --- | --- |
| C0 command table entry | `0x1bba4`, dispatcher default arm → `Mt1939DispatchHook` | No command table on MT1939; other unknown opcodes keep `05/20/00` |
| `InquiryDataPatch` | `0x1c6f82` (byte 74) | Native 96-byte response unchanged |
| `CommandTableDVDRead1-3` | `0x1b47e` → `DVDReadCmdHook` | One call covers READ(10), READ(12), READ CD |
| `CommandTableBDRead1-2` | `0x1b43c` → `BDReadCmdHook` | READ(10), READ(12); MT1959 rejects READ CD on BD natively, MT1939 serves it (not hooked) |
| `ScrambleHookAddr` | `0xa59c6` → `ChangeDiscRWModeHook` | Same generic read-mode function |
| `DVDScrambleHookAddr` | `0x1bf410` | |
| `DVDScramblePatchAddr1/2` | — | MT1939's DVD reader never skips the mode change |
| `BDScramblePatchAddr`, `BDScrambleHookAddr` | `0xb5888`, `0xb588c` | |
| `DVDEDCHookAddr`, `BDEDCHookAddr` | `0x1bf5ae`, `0xb6668` → `SetErrorModeHook` | |
| `DVDMinusReadCheckHookAddr` | `0x1bf3ba` → `Mt1939DVDMinusReadCheckHook` | Recognizes spoofed raw A8 and restores sense when bypassing rejection |
| `DVDLeadOutPatchAddr0-6` | `0x1bbc63`, `0x1bbca0`…`0x1bbcee` | Identical instructions |
| `BDLeadOutPatchAddr` | `0x1bc453` | Same `bne → b` in the BD read check |
| `CDLeadOutPatchAddr0-6` | `0xe4a28`, `0x1bd770`, `0x1bd7d4`…`0x1bd8aa` | |
| `BDIdentifierPatchAddr1-3` | `0x133926`, `0x13392d`, `0x1339d4` | "BD" signature and disc-type letter checks of the DI classifier |
| `BDIdentifierPatchAddr4` | — | Second W/U/R/O check only exists on MT1959 (and is reached only for 'R') |
| `ReadDVDTOCHookAddr` | `0xa24d4` → `Mt1939ReadDVDTOCHook` | XGD + Nintendo BCA, native layer state |
| `SetBDCharacteristicsHookAddr` | `0xa1e10` → `Mt1939SetBDCharacteristicsHook` | Wii U DI, native inclusive end |
| `DVDCharacteristicsPatch` (overlay `0x01f96daa`) | `0xcbb50` → `Mt1939DVDCharacteristicsHook` | Unknown book types → DVD-ROM; see below |
| `DVDTOCReadPatch` (overlay `0x01f976c2`) | `0xcc16a` = `0x01` | Control-data read failure returns success (NR/RVT-R) |
| `forceUnitAccess` | `0x020006fd` | Same cache-mode comparison as MT1959 (`0x1be9ca` / `0x14575a`) |
| `DISC_SECTOR_REGISTER` | `0x04050064` | Same peripheral; native readers do not rewrite it |
| `ReadSpeedPatchAddr` | — | MT1959's read-load accumulator does not exist; C0 resets the idle counter (`readTimeCounter`) |
| `CDDataSpeedPatchAddr` | — | MT1959's subcode-driven CD speed routine does not exist |
| `0x105C8` magic, `0x1EC056` | — | MT1959 update-loader downgrade policy; the MT1939 loader is documented separately |

`DVDCharacteristicsPatch`: MT1959 retargets the book-type switch's default
branch to the DVD-ROM case. The same byte on MT1939 (`0xcb826 = 0x19`) skips
the layer decode and classifies dual-layer discs as single-layer (emulated:
`0x40` instead of `0x44`/`0x46`). The hook instead rewrites unknown book types
(4–8, 11–13, 15) to DVD-ROM before the native switch, preserving the layers.

## What `mt1939.c` provides

- `ReturnSense`: MT1939 stores sense bytes directly; there is no function.
- `ReadDVDData`, `ReadDVDRAMData`, `ReadBDData`: re-encode a PSN request as
  LBA in the spoofed packet, because native restart parsers read it again.
- `DVDCheckLayer`: native DVD PSN mapping and layer state.
- `ReadDiscData`: preserves `startAddress` across the native reader (XGD retry).
- `Mt1939DispatchHook`: opcode check, 24-bit DMA count, native readiness,
  medium/type/field validation, then the shared `CmdOmniDriveReadDiscRaw`;
  restores the sector format and descrambling bits after the reader returns.
- `Mt1939ReadDVDTOCHook`, `Mt1939SetBDCharacteristicsHook`,
  `Mt1939DVDCharacteristicsHook`: see the table.
- `Mt1939DVDTransferModeHook`, `Mt1939CopyTransferModeHook`: MT1939-only
  native code (DVD recovery `0x1bf9fe`, copy engine `0x44484`) re-enables
  descrambling; absent from MT1959 ROM and overlay.
- `Mt1939DVDMinusReadCheckHook`: recognizes raw `A8` with bit 7, as well as
  `C0`; a bypassed native rejection must not leave its sense error behind.
- `Mt1939ContinuationPendingHook`: three `bl` sites replace only the native
  packet-ready loads (`0x1c05f8`, `0xe3d2a`, `0xb6b3a`). Only queued READ(10/12)
  with raw sector format in the low byte (`0x98` / `0xf8`) are withheld from
  native continuation. C0 and other opcodes retain the packet-ready result,
  so native opcode rejection returns immediately without an idle timeout.
  Ordinary formats retain the original packet-ready result and fast path.

## Request isolation and DVD-RAM controls

The adapter corrects request-state problems in the shared MT1959 strategy
without changing `main.c`. C0 saves the sector format and the two descrambling
bits on the stack, then restores them after native cleanup, also on cancellation.
Queued packets remain pending and pass through the normal dispatcher and its
ordinary-read guards. A queued READ uses the existing native idle timeout;
consecutive C0 requests do not. The hook compares only the low format byte,
so other register fields do not disable isolation. No persistent flag or
scatter change is required.

The DVD-RAM mode call at `0xe3384` uses `ChangeDiscRWModeHook`, so both values
of the descramble flag are applied independently of the previous controls.
The DVD-R check uses the spoofed raw marker rather than testing only `C0`.
Validation before `main.c` preserves MEDIUM NOT PRESENT and leaves rejected
requests' packets, read timers and formats unchanged.

A valid C0 request for zero sectors completes as a no-op after readiness,
medium and field validation, before entering `main.c` or any native reader.
This avoids arming DMA with a previous request's count: native CD/DVD/RAM
DMA setup does not overwrite the count register when its argument is zero.
The zero-length audit checks all four media families, FUA, LBA/PSN and CD
subchannels/C2 with a nonzero previous count; it requires no reader entry,
MMIO writes or changes to read state.

CD FUA follows the shared upstream behavior: `main.c` writes
`forceUnitAccess = 0xff` only when C0 requests FUA; it does not clear the flag
for C0 without FUA. Static review found that native CD command preparation
at `0x18a23e` rewrites the flag, while `ReadCDDA` does not. Consequently, after
a C0 with FUA, subsequent C0 commands without FUA still bypass the cache until
native CD preparation changes the flag. This can reduce throughput. Conversely,
C0 without FUA inherits the last native CD command's setting. Physical step 2
therefore includes a normal READ CD immediately followed by C0 without FUA on
the same area, checking raw data and layout against a reference drive. The
static review does not establish the behavior of real cached optical data.

## Build and reproduce the evidence

The original decoded specimen must have SHA-256
`c0a5d073ccfce917712a459b73bff51bcf42bf41ee0703575c0408a59828f84d`.
Use the normal CMake build with ARM GCC, armips and Python/PyCryptodome on PATH.
For offline verification, install Capstone, Unicorn and NumPy. The optional
loader audit also requires pefile and the pinned Flash Utility binary
documented in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md).

```sh
python tools/liteon/patch_verify/verify_native_port.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  --generated patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --capture dump/report.json \
  --output dump/mt1939-native-port.json
python tools/liteon/reverse_engineering/compare_mt1959.py dump/DE_ASUS_BW-16D1HT_3.02.bin \
  firmware/ASUS_BW-12B1LT_1.03.bin
python -m unittest discover -s tests
```

The report destination must be new. Omit both `--utility` and `--capture` to
exclude the loader audit. The report records the generated image hash, source
hashes, individual verifier results and their model boundaries. No device is
opened.

## Allocation and integrity

The C payload occupies `FreeSpaceStart..FreeSpaceEnd` = `[0x1dea00,0x1dff00)`,
the erased tail of the profile block, before the profile sum at `0x1dfff8`.
Both libraries use less than `0xd00` of its `0x1500` bytes. Scatter records and
RAM are untouched: startup emulation with two poison patterns produces
byte-identical RAM. `update_cmac.py` sets the main sum (`[0x10000,0x1cfdf8)` →
`0x1cfff8`) and the profile sum (`[0x1d0000,0x1dfff8)` → `0x1dfff8`).
`native_adapter.py` builds the same profile in a temporary tree with the CMake
flags (a test compares them with the configured build) and rejects any change
outside the reviewed sites. The historical INQUIRY-94 marker is not part of
this build; it remains reproducible through `asm/liteon/inquiry94.asm`.

Additional static review found no runtime path rewriting the profile block
`0x1d0000`–`0x1dffff`: `0xa6ddc` decompresses tables from `0x1d0100` without
writing back to flash, and vendor command `0xfe880` computes checksums and
returns them to the host without writing flash. The identified flash erase
and program paths are in the loader (erase site `0x19c70`). Integrity record
`0x1041c` covers the profile, but the observed scanner stops at the first
`ffffffff` record before reaching it; see [INTEGRITY.md](INTEGRITY.md).
These are static observations, not proof that every runtime path preserves
the payload or that all firmware integrity checks are bypassed.

The CMake module also depends on the input firmware, profile, hook assembly,
version and checksum scripts. An isolated CMake regression test changes these
inputs and checks image regeneration, then confirms an unchanged build is idle.

## Coverage and boundaries

| Verifier | Executed checks |
| --- | --- |
| Adapter | 1,530 unchanged dispatcher cases; 67 raw parameter cases; 480 C0 requests against a model of `main.c` (32 accepted, 448 rejected); 4 not-ready; 72 native DVD PSN cases; layer setup; DVD/BD reader prologues keep the raw format; register/stack preservation |
| Hooks | 480 error-mode comparisons; 6 native FUA comparisons and FUA flag survival; 48 descrambling and 10 generic mode cases; 24 BD PSN; 112 DVD-R read checks; 8 BD lead-out differentials; DVD/CD boundaries |
| Copy/recovery | 108 cases comparing native DMA/stride effects, interrupt state and filtering; 8 CD lead-out classes |
| Media | 18 TOC/XGD fixtures; 32 PFI book types and 5 native layer classifications; 4 BD DI identification differentials; 8 control-data failure paths; 1,024 ordinary-read guards; DVD-ROM PSN |
| BD-ROM DI acquisition | 12 fixtures through native acquisition, retries, copies and geometry parser |
| Read timer | 28 C0 cases incl. 20 idle-speed counterexamples; 12 non-reading cases; 6 IRQ tick cases |
| Identification | Native template copy and INQUIRY responses for 7 allocation lengths |
| CD / DVD/RAM/BD transfer | 144 / 216 cases through native DMA setup and cleanup |
| Zero-length C0 | 44 valid requests return without entering readers, writing MMIO or changing read state |
| Packet consistency | 90 native address-parser cases |
| Queued commands | 24 READ(10/12) cleanup/dispatch cases incl. nonzero upper format bits; 252 gate contracts across formats, opcodes and packet-ready values; 36 C0/INQUIRY/TUR cases return after one packet check without idle waiting or synthetic ticks (DVD/RAM's initial timer check is preserved) |
| DVD-R/RAM request state | 16 full transfer/cancellation cases with both previous and requested descrambling settings; rejected native DVD-R checks reach raw DMA without stale sense |
| Placement | Byte-identical startup RAM, changed ranges and checksum |
| MT1959 comparison | Overlay unpacking and strong-match agreement (`test_liteon_mt1959_compare.py`) |
| Loader (optional) | 22 input, authentication, checksum and corruption scenarios |

Native reader, error-mode, flag, DMA setup and cleanup instructions execute;
mode callees, servo, cache availability, hardware time and other peripherals
use explicit models. No optical bytes are synthesized and real interrupts and
host delivery are not established. `full_omnidrive_port` and `flash_ready`
remain false until the physical tests in [OMNIDRIVE_PORT.md](OMNIDRIVE_PORT.md)
pass.
