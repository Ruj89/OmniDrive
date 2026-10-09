# BW-12B1LT 1.03 / MT1939 porting study

This is an offline research map, not a supported drive profile. The input is
the unmodified, decoded 2 MiB image, SHA-256
`c0a5d073ccfce917712a459b73bff51bcf42bf41ee0703575c0408a59828f84d`.
MT1939 is identified by image markers; the MWDU suffix is user-provided,
not established by these markers.

## Reproduce

Use a separate research environment with Capstone and Unicorn:

```sh
/tmp/liteon-research/bin/pip install capstone unicorn
/tmp/liteon-research/bin/python tools/liteon/map_firmware.py \
  firmware/ASUS_BW-12B1LT_1.03.bin --output-dir dump/porting
```

The output directory must be new. The tool checks the specimen hash and saves
`map.json` and selected `disassembly.txt` excerpts. It never opens a SATA device.
`dump/` is ignored by Git. JSON addresses are decimal; addresses below are hex
file offsets unless labelled RAM/MMIO. Main-code execution uses plausible identity-mapped branch targets. The SCSI
follow-up identifies a separate low-code alias; see [SCSI_MAP.md](SCSI_MAP.md).

## Original patch dependencies

`asm/main.asm` inserts opcode `C0` through a command table, hooks DVD/BD read
handlers, changes lead-out and disc-recognition checks, and injects a C payload.
`src/main.c` depends on a particular command-buffer ABI, media-type bits,
sector/transfer variables, native functions and hardware register semantics.
Two patches also modify decompressed code in RAM.

The MT1959 stock binaries are absent from this checkout. Assembly comments
provide some signatures, not a complete function comparison. A signature miss
does not demonstrate that the corresponding function or capability is absent.

| Dependency | Evidence in MT1939 | Status |
|---|---|---|
| ARM/Thumb | ARM vectors `0x10000`, reset target `0x1bb8e0`; Thumb functions call ARM switch helper `0x1b9b0c` | Static decoding and small-function emulation confirmed; CPU revision unverified |
| `ChangeDiscRWMode` | Unique six-byte signature at `0x45b8a`, switch and plausible direct calls | Candidate; establish mode values, callees and side effects |
| `SetCDType` | Unique ten-byte signature at `0x1bd8d8`; caller `0x18a802` supplies mode and sub-Q arguments | Strong candidate supported by emulation; selector meanings unverified |
| `cdb` | RAM `0x02000d20`; receive routine at file `0x10040` / runtime `0x40` copies 12 bytes from controller FIFO | Copy and pending flag emulated; global buffer is mutated by handlers; interrupt lifetime unresolved |
| `mediaType` | RAM candidate `0x01ffabf0`; `0x17e0ee` / `0x17e124` test its top two bits against 1 and 3 | Plausible DVD/BD classification; other bit masks unresolved |
| CD mode register | MMIO `0x04050060`, reached through base `0x04050040` | Emulated writes confirmed; optical behavior untested |
| Sector-format register | OmniDrive uses `0x04050064` | Unresolved; do not equate it with CD mode register `0x04050060` |
| Command dispatcher | Thumb `0x1b14e`: comparisons and inline halfword jump tables; key opcode/media routes emulated | Mapped in [SCSI_MAP.md](SCSI_MAP.md); original chained-table insertion does not apply |
| Read / error / sense functions | Read handlers, parameter RAM, FUA calls, INQUIRY data-in setup and REQUEST SENSE mapped in the SCSI follow-up | Original instructions exercised with explicit synthetic dependencies; optical behavior unresolved |
| Payload space | Uniform runs in main area catalogued | Contents alone do not establish free space |
| Integrity / flashing | Native header selection in [INTEGRITY.md](INTEGRITY.md); update-input checks and writer handoff in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md) | Software acceptance verified in emulation; physical write, restore and preservation unverified |

Linear-sweep call and literal references in the report may include data decoded
as instructions. They are navigation aids, not a verified call graph. Selected
disassembly excerpts exclude the identified inline switch tables and literals.

## SCSI follow-up

[SCSI_MAP.md](SCSI_MAP.md) and `map_scsi.py` extend this initial reconnaissance
with 1,570 bounded experiments. The receive routine lies before the original
linear-sweep range (`0x19000`), explaining why that report did not find it.
The low block must be decoded at its execution address, not its file offset.

## Small-function emulation

The original candidate at `0x1bd8d8` was executed with its original switch
helper, varying argument 0 over 0–7, argument 1 over 0–2, and the synthetic
register's initial value over `0`, `ffffffff`, and `a5a5a5a5`: **72 cases**.
All returned within 300 instructions. Non-stack writes were confined to 32-bit
writes at `0x04050060`; changed bits were confined to bits 8–11.

Individual inputs and outputs are saved. This supports a CD mode/sub-Q role
and a two-argument interface. It does not establish identical selectors to
MT1959 or successful optical reads. MMIO and the stack are simulated.

## Integrity header

At `0x10400`, 28-byte records resemble those consumed by
`scripts/update_cmac.py`: flag, start/end addresses, and 16 tag bytes.

| Offset | Flag | Inclusive range | Tag |
|---|---|---|---|
| `0x10400` | `ffffffff` | `0x11000`–`0x18fff` | Non-erased |
| `0x1041c` | `00000000` | `0x1d0000`–`0x1dffef` | All `ff` |
| `0x10438` | `00000000` | `0x19000`–`0x1cfdef` | All `ff` |
| `0x10454` | `00000001` | `ffffffff`–`ffffffff` | All `ff` |
| `0x10470` | `00000000` | `0x10400`–`0x1046f` | All `ff` |

The native selector's termination and flag matching are now traced in
[INTEGRITY.md](INTEGRITY.md): the first `ffffffff` record terminates the observed
scan, and the startup selector is `1`. This does not establish loader checks
or the hardware tag algorithm. The original script treats every flag except
`ffffffff` as enabled, including the out-of-image range. **Do not apply
`update_cmac.py` to this image.** Layout similarity does not validate flags/key.

An exploratory AES-CMAC calculation for `0x11000`–`0x18fff` with the original
MT1959 key did not reproduce the non-erased tag. Direct input and the original
script's per-16-byte input reversal were tried, also checking tag reversal.
The record's purpose remains unknown: this does not demonstrate corruption or
prove a different key. The native update main checksum is now traced:
`[0x10000,0x1cfdf8)` excludes 512 `ff` bytes, explaining the apparent `+0x80`.

## Porting order

1. Command dispatch and the initial RAM ABI are mapped in
   [SCSI_MAP.md](SCSI_MAP.md), with reproducible reception, opcode routing,
   read-field/FUA and response experiments. Complete the low-code remap,
   state-dependent alternate paths and response-buffer ownership before hooking.
2. Establish integrity and restore format. Trace checksum routines/header
   flags and preservation rules. Verify loading/references before allocating
   payload space from any erased or zero-filled run.
3. Build a minimal diagnostic command through the native data-in response path.
   Establish hooks, calling convention, relocation, payload bounds and integrity
   offline before creating a hardware-test image.
4. Implement a CD path, then DVD/BD. CD has the strongest initial function lead.
   DVD/BD require sector format, descrambling, EDC and boundary checks. Nintendo
   and XGD recognition changes follow the underlying raw-read paths.

The older drive's disc-format capabilities cannot be inferred from the MT1959
feature table. The study does not provide a supported MT1939 profile.

## Minimal modification experiment

[INQUIRY_TEST.md](INQUIRY_TEST.md) now provides a one-instruction-byte experiment:
standard INQUIRY reports at most 94 instead of 96 bytes. It uses the existing
handler, needs no payload allocation or dispatch hook, and includes a pinned
image generator, checksum change manifest and bounded differential emulation.
It produces an offline experimental image. Native update-input acceptance is
verified in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md); physical flashing and
restoration remain unverified.
