# BW-12B1LT 1.03: native update-input acceptance

The original backup and the OmniDrive image **pass the native update input
checks and reach the flash-writer handoff at `0x1baeb4`** in bounded offline
emulation. Corrupted inputs are rejected by the original instructions.
This verifier supplies software acceptance evidence and retains `flash_ready`
and `hardware_tested` false. Separate subsequent hardware trials now pass for
the original and minimal patch, including exact full readback and the 94-byte
marker; see [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md). Working-drive
rollback from the patch also passes with exact original readback.

## Reproduce

Dependencies: Python, Unicorn, Capstone for the related INQUIRY trace,
PyCryptodome and pefile. Supply the original Flash Utility 7.2.0 binary from
the [archived distribution](https://cheapiesystems.com/media/odd-firmware/PLDS/Flash_Utility-7.2.0/),
SHA-256 `34dd3c6a21be113fc30bfd0514647d1e2c6fe192263e49dea9c70410cf19f9f3`.
Neither firmware nor utility is executed on a host or drive: their instructions
run inside Unicorn, without Windows APIs or device access.

```sh
/tmp/liteon-research/bin/python tools/liteon/verify_loader.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --report dump/report.json \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --output patched_firmware/loader-acceptance.json
```

Choose a new output filename if one already exists. The report records input hashes,
native call addresses, command counts, modeled dependencies and outcomes.
The verifier rejects an unknown original, a different patch or utility binary.
It also checks identity, extension, flash size, profile metadata, writer type and
protocol flags before emulation. The valid 164-byte captured INQUIRY is pinned
to SHA-256 `6d1dc11d8918d4745ef6edfe0eb3cef8e7b28fb4841bf7834c7dcf28f8a6972b`.
The report records hashes of both the valid bytes and the received response;
transport padding after byte 164 does not affect specimen validation. Session
material changes require separate research and are deliberately rejected.

## Utility protocol and selected profile

The captured extended INQUIRY selects index **166 of 239** six-byte records,
matching four bytes at `INQUIRY[0x6a:0x6e]`. The descriptor is `c215002d0f66`;
the associated 3942-byte programmer at utility address `0x4ee476` has SHA-256
`25341b2fc683c3b8bd0796c698f398d015565a0c71ef94de76ced9f8a6fdb666`.
The extraction follows the table's shared-code groups.

The utility's original x86 CBC and CMAC functions are executed and independently
compared with PyCryptodome. It encrypts the padded descriptor/programmer,
appends a 16-byte CMAC, and encrypts the 64 KiB image window
`[0x70000,0x80000)`. Its tag covers that ciphertext window, rather than the
entire image. The patched instruction at `0x9cb76` lies outside this window.
Session material comes from the captured extended response; keys are not
written into the acceptance report.

The native CDB builder at `0x402760` produces
`3b 05 01 AA AA AA LL LL LL CC BB 00`, with BE24 offset and length.
The sequence is a profile command (`CC=7f`), 512 image blocks of 4096 bytes,
each followed by READ BUFFER and byte comparison, then a 16-byte window tag
(`CC=80` or `a0`): **1,026 commands** without retries. The native read CDB builder
at `0x4026cc` produces `3c 01 01 AA AA AA LL LL LL 00 00 00`.
The original ARM read handler at `0x9d66c` supplies the data-in offset/length;
the controller model copies those bytes from staging RAM. The original x86
comparison at `0x4c2b9c`, called by the utility at `0x4046e9`, compares the result.
This includes the handler's scratch remapping for offsets at or above `0x1e0000`.

The host retry loop is reconstructed from `0x4046a3`–`0x404715`: at most three
read transport attempts per comparison, with at most two completed comparisons
per block. Mixed transport failures and a mismatch can therefore require up to
six read attempts for the same block. Native read
command failures are eligible for transport retry. A short modeled response is
also treated as transport failure. Persistent mismatch, short transfer or failed
transfer aborts before the final command. Faults are injected after the native
read handler, at the modeled controller response boundary.
Transport is intercepted before the host API. The complete utility
UI/file-selection and write-command retry state machines are not run; this is
still bounded handler/protocol evidence. A separate `verify_finalization.py`
audit now executes the native finalization worker through return. That worker
uses the synchronous transport result, allows two attempts and issues no
independent status-poll or physical-readback command. See
[STAGING_TEST.md](STAGING_TEST.md) for the hardware staging result and next check.

## Native firmware checks

WRITE BUFFER routes to Thumb `0x9ec8c`. Its native instructions compute and
compare profile CMAC, decrypt the profile, check its flash ID and version,
then copy its programmer into staging memory. At finalization, the native
instructions verify the window CMAC, decrypt that window, check the `PLDS`
marker and the main/profile additive sums. Mode `a0` additionally checks boot.
All cryptographic comparisons execute in the firmware; no comparison is stubbed
to return success.

The main sum is **LE32 addition modulo 2^32 over `[0x10000,0x1cfdf8)`**,
stored at `0x1cfff8`. The intervening 512 bytes are `ff` in this specimen.
Including those 128 words in a full-region sum subtracts 128 modulo 2^32,
explaining the earlier apparent `+0x80` seed. The generator now uses the native
endpoint; its output remains byte-identical to the earlier experimental image.

After input validation, two EEPROM calls are modeled as returning, and native
range setup reaches `0x1baeb4`:

| Final control | Destination/source start | Length | End exclusive |
|---|---:|---:|---:|
| `80` | `0x10000` | `0x1d0000` | `0x1e0000` |
| `a0` | `0` | `0x1e0000` | `0x1e0000` |

These are handoff arguments, rather than a claim about every physical erase.
Separate runs execute the extracted programmer from `0x19000`. Its native chip
predicate accepts synthetic JEDEC `c22015` and `c22415`, and rejects `abcdef`.
The captured INQUIRY alone does not identify the middle byte of the physical
chip's complete JEDEC ID. Four programmer-entry runs, using both compatible
IDs and controls, reach `0x19c4c`, **before issuing opcode `d8` at address
`0x1df000`**. This first erase occurs inside initialization, before the main
programming loop. No erase command is emitted by the verification tool.

## Positive and negative evidence

There are **22 bounded scenarios**:

* Four profile cases: valid passes; bad CMAC, wrong flash ID and wrong version
  fail. The latter two have correctly recomputed cryptographic tags.
* Eight full-transfer cases: original and patch pass in both modes; stale main
  checksum, damaged profile checksum, damaged boot checksum in mode `a0`, and
  damaged window tag fail. Each case supplies all 1,026 commands and requires
  512 native byte comparisons to pass before finalization.
* Three controller-response fault cases: persistent mismatched bytes, failed
  reads and short reads abort after two, three and three reads respectively.
  None submits the final command or reaches the writer handoff.
* Three imported chip-predicate cases, and four separate programmer-entry cases.

Successful full-transfer cases also require the decrypted staging bytes through
`0x1dffff` to match the corresponding input exactly, and check the handoff ranges.
Failures must occur before reaching the writer handoff.

## Model boundaries and remaining hardware evidence

RAM bases and response templates are synthetic, populated from the captured
INQUIRY. DMA copies exactly the requested host payload. Read data-in DMA copies
staging bytes using the native handler's MMIO offset/length, then clears its
pending flag to model completion. AES MMIO models reversed
BE32 register ordering, ECB/CBC and immediate completion. Interrupt helpers,
debug output and peripheral preparation are explicitly stubbed. Separate
programmer runs model ready serial/controller status and JEDEC responses.
Controller code remapping, EEPROM persistence, physical protection state,
erase/program completion and post-write startup are not established.

This proves acceptance for the pinned image and modeled protocol, rather than
unconditional acceptance under every live drive state. A drive is not attached
here. Hardware confirmation requires the actual chip ID/state and a restore
rehearsal with complete readback, as described in [INTEGRITY.md](INTEGRITY.md).

The separate follow-up [programmer audit](PROGRAMMER_AUDIT.md) executes the entry
through return using an in-memory NOR model, with complete erase/program ranges,
native retries and interrupted-image comparisons. This does not change the
boundaries of this input-acceptance verifier.

A further `verify_handoff.py` audit executes the native handoff, imported writer
and handler return in the same CPU state, with explicit executable-visibility
and SPI models. Six cases and an original-only experimental Linux write trial
are documented in [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md). Neither
that software audit nor the successful RAM staging test establishes physical
write completion.
