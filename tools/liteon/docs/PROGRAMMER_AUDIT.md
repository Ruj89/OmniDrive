# BW-12B1LT 1.03: native programmer and Linux hardware baseline

This document describes the historical **minimal INQUIRY-94 image** at
`dump/inquiry94-test/BW-12B1LT_1.03.inquiry94.experimental.bin`. The normal CMake output now contains
the native adapter; its separate evidence is described in
[NATIVE_ADAPTER.md](NATIVE_ADAPTER.md).

`verify_programmer.py` extends the separate programmer-entry experiment through
the original Thumb programmer's return. It executes the 3942-byte programmer
selected from pinned Flash Utility 7.2.0, including serial command construction,
page readback comparisons and retries. Operations target an in-memory NOR array.
No device is opened. Hardware flashing is validated separately in the write/readback trials.

## Reproduce the offline audit

Use the existing research environment with Unicorn, pefile, PyCryptodome and
armips on PATH:

```sh
/tmp/liteon-research/bin/python tools/liteon/update_emulation/verify_programmer.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  dump/inquiry94-test/BW-12B1LT_1.03.inquiry94.experimental.bin \
  --report dump/report.json \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --output dump/inquiry94-test/programmer-audit.json
```

Choose an unused report filename. Original, patch, INQUIRY and utility are pinned
using the loader verifier's checks; the extracted programmer hash is checked too.
The output contains erase addresses, page counts, region coverage, status writes
and a digest of ordered SPI transactions/responses, without firmware or keys.

The NOR model follows Macronix commands: `d8` erases 64 KiB, `20` erases 4 KiB,
and `02` programs within a 256-byte page by changing one bits to zero. WREN is
required and ready status is immediate. Primary references:
[MX25L1605D, PM1290 rev 1.5](https://www.macronix.com/Lists/Datasheet/Attachments/8554/MX25L1605D%2C%25203V%2C%252016Mb%2C%2520v1.5.pdf),
[MX25L1635D, PM1374 rev 2.2](https://www.macronix.com/Lists/Datasheet/Attachments/8587/MX25L1635D%2C%203V%2C%2016Mb%2C%20v2.2.pdf).
This does not establish which chip is fitted to the physical drive.

## Observed coverage and failures

Eight successful runs cover original/patch, synthetic JEDEC IDs `c22015`/`c22415`
and both final controls. Each resulting full 2 MiB array matches the expected
image. Byte equality and command coverage are checked separately.

| Control | Erased/programmed range | Erase commands | Page program/readback commands | Untouched regions |
| --- | --- | ---: | ---: | --- |
| `80` | `[0x10000,0x1e0000)` | 30 | 7,424 each | Boot and last 128 KiB |
| `a0` | `[0,0x1e0000)` | 31 | 7,680 each | Last 128 KiB |

The first erase is `d8 1d f0 00` at native PC `0x19c70`. With 64 KiB geometry
it erases **all of `[0x1d0000,0x1e0000)`**, including the profile. The main loop
erases that block again and restores it from the incoming image. Matching
profile bytes in the finished image do not imply preservation during the update.
These runs issue only `d8` erases and 256-byte `02` page programs. The report's
`program_touched_bytes` counts addresses submitted for programming, including
deliberately dropped writes in fault cases.

Five further scenarios exercise failures and interruption:

* Dropping the first page write triggers a native mismatch, block erase and retry.
  The final array matches. Corrupting the first serial readback has the same result.
* Persistently dropping that page triggers four native mismatches. The entry
  **still returns**, continuing with later blocks while the affected block
  remains incomplete. The final-array comparison rejects the result. This does
  not establish how the firmware caller or host reports the failure.
* Stopping after the first erase leaves the profile erased with boot intact.
  Stopping after the first page program also leaves main partly erased.

`offline_programmer_audit_passed` means all 13 expected scenarios were observed,
including damaged outcomes. `flash_ready` and `hardware_tested` stay false.
Controller remapping, handoff continuity, peripheral commands at `0x4010000`,
actual timing/protection, EEPROM/OTP and startup remain unverified. Staging and
controller bases are synthetic; the peripheral busy bit is modeled ready. Input
acceptance is documented separately in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md).

## Start hardware validation on Linux via SATA

On the PC with the drive, identify its optical device using `lsscsi -g` if
available. From the repository root, with original 1.03 still installed,
collect a fresh pair of reads into a new directory:

```sh
mkdir -p dump
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-preflash
```

Use the actual `/dev/srN` or `/dev/sgN`. The reader requires the exact ASUS
BW-12B1LT 1.03 identity and allows only data-in operations. Keep `report.json`
and both complete raw files together. Validate against the retained decoded
original using Python with PyCryptodome:

```sh
/tmp/liteon-research/bin/python tools/liteon/dump_analysis/validate_flash.py \
  dump/bw12b1lt-preflash \
  --image firmware/ASUS_BW-12B1LT_1.03.bin \
  --output dump/bw12b1lt-preflash-validation.json
```

Expect exit status zero, equal raw hashes and `offline_structure_consistent: true`.
The validation report is a sibling of the root-owned acquisition directory,
so the offline validator can run as your normal user.
This freshly decodes the new dump using its own INQUIRY. Investigate any changed
byte before writing. Copy the raw files, report and decoded original to separate
storage and compare copied hashes. New INQUIRY session material can differ;
offline loader/programmer audits deliberately use the retained pinned capture.

## Follow-up handoff audit and first write trial

The subsequent `verify_handoff.py` audit connects native input gates, programmer
copy/header setup, imported writer and handler return in six modeled cases.
Its executable-visibility model and limits are documented in
[ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md).
The separate `verify_finalization.py` audit executes the original host worker
through return in five transport-result cases: it sends a 16-byte control `80`
command, accepts transport returns 0 or 16, and retries once on failure. It
issues no independent physical-readback or status-poll command. The host UI,
firmware handoff and physical transport are excluded from the host-worker audit.
The persistent-fault case cannot be judged by native
return alone; full physical readback is required.

The first write trial should restore the **original decoded image** with control
`80`, followed by full power removal/startup and two complete reads. Require an
exact full-image match using [INTEGRITY.md](INTEGRITY.md), including boot, profile
and tail. Then test the minimal patch and its 94-byte INQUIRY marker described
in [INQUIRY_TEST.md](INQUIRY_TEST.md). An experimental original-only Linux rewrite
runner in [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md) has now passed with
one accepted finalization and full byte-identical cold-start readback on the
retained specimen. The commands above remain read-only. The minimal patch trial
also passes with exact full readback and the expected INQUIRY marker; evidence
is documented in [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md).

The [staging test](STAGING_TEST.md) has passed on hardware, with a verified full
journal and byte-identical original readback after reported power removal.
Working-drive rollback from the patch also passes with exact original readback;
see [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md). Optical/media behavior remains open.
