# BW-12B1LT 1.03: integrity and recovery audit

The available original backup and OmniDrive image pass the offline audit.
The original-image rewrite trial now passes on the retained specimen, with one
accepted finalization and full identical repeated readback after reported power
removal. Evidence is in `dump/bw12b1lt-original-restore-validation.json`.
The minimal patch write/marker/full-readback trial also passes, with only the
two expected changed bytes; see `dump/bw12b1lt-inquiry94-validation.json`.
**Working-drive rollback from the patch and failure recovery remain unvalidated.** No drive is attached
to this development environment. The offline audit tools never open a device
or execute a Windows flasher. An experimental original-only Linux write trial
is documented separately in [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md).

## Reproduce the file audit

Use the environment containing `pycryptodome` for fresh decoding:

```sh
/tmp/liteon-research/bin/python tools/liteon/audit_recovery.py dump \
  --original firmware/ASUS_BW-12B1LT_1.03.bin \
  --experimental patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --output patched_firmware/recovery-audit.json
/tmp/liteon-research/bin/python tools/liteon/trace_integrity.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  --output patched_firmware/integrity-trace.json
/tmp/liteon-research/bin/python -m unittest discover -s tests -v
```

Outputs must not already exist. The trace also needs Unicorn. Both inputs remain
untouched. The audit checks both raw backups, their recorded hashes, a fresh
decode and all 14 original structure checks. It requires the pinned original
and the exact generated patch, independently of the saved patch manifest.
It records SHA-256 for the raw files, report, decoded original and each region.
Keep those files together and copy them to separate storage before hardware work;
this audit does not establish that a separate backup copy exists.

Only offsets `0x09cb76` and `0x1cfffa` change. Boot (`0`–`0xffff`), the full
16-record header (`0x10400`–`0x105bf`), profile (`0x1d0000`–`0x1dffff`) and both
reserved tail regions remain byte-identical. Boot/profile additive sums still
match. The native main sum excludes 512 bytes before the trailer, explaining
the full-region `+0x80` delta. A valid sum alone cannot detect
compensating corruption; exact-image and per-region comparisons address that.
The native checks and positive/negative runs are documented in
[LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md).

## New evidence about the integrity header

Thumb routine `0xa19d6` loads header base `0x10400` and scans up to 16 records
of 28 bytes. At `0xa19ea` it adds one to the flag and branches to the return
path if the result is zero: **`ffffffff` terminates the scan**, rather than
skipping only that record. Other records are checked only when the flag equals
the function argument. A failure stops the scan. This differs from the MT1959
script's interpretation.

The observed startup call at `0x1c756` supplies selector `1`. The first record
of this specimen already has flag `ffffffff`, so the isolated selector returns
`1` without calling the tag verifier. The next caller instruction loads a new
value into `r0`, overwriting the return value. This result holds for the original
and experimental image at selectors `0`, `1`, `2`, and `ffffffff`: **8 runs**.
Peripheral preparation and debug output are stubbed; full startup is not emulated.

Four further **synthetic navigation runs** set only the first flag to zero in
emulated memory. Selector `0` then selects four records, with successful tag
checks stubbed solely to expose traversal. Selector `1` reaches the record at
`0x10454`; the native verifier at `0xa18f0` rejects its equal start/end values
`ffffffff` before accessing the tag engine and returns `0`. The native selector
emits debug arguments `(f6,a9)` and `(5e,3)`. Selectors `2` and `ffffffff` select
none. No synthetic image is written to disk.

This establishes the local scan semantics, not an AES key, valid tags, every
execution path, or the checks performed by a flash loader. It does **not** mean
all firmware authentication is disabled. Do not run `scripts/update_cmac.py`
on this specimen.

## What the Flash Utility evidence establishes

The previously unpacked C0deKing Flash Utility 7.2.0 binary is pinned to SHA-256
`34dd3c6a21be113fc30bfd0514647d1e2c6fe192263e49dea9c70410cf19f9f3`.
It was obtained from the [archived distribution](https://cheapiesystems.com/media/odd-firmware/PLDS/Flash_Utility-7.2.0/).
The following are static observations of that binary, not hardware validation:

* Metadata parsing at `0x402c9b` stores `INQUIRY[0x70] & 0x1f`; `0x402cad`
  stores byte `0x72`. On this specimen these are `0` and `c2`.
* At `0x406796`–`0x4067c5`, type at most `1` and flags low three bits at most
  `2` take the internal-write UI branch. The observed specimen satisfies it.
  Merely possessing `FU_Flasher.exe` does not establish the correct restore path.
* At `0x402cf5`–`0x402d0b`, flags low bits being nonzero select an additional
  encoded-write state. That state is set for `c2`. The type-zero writer at
  `0x404354` has code for encrypting its loader/profile buffer, appending a tag,
  and transforming a 64 KiB input window before transfer (`0x404434`–`0x404612`).
  File bytes therefore cannot be equated directly with SATA write payload bytes.
* The UI includes an update-boot-code choice. Profile selection, encoded payloads,
  native checks and writer handoff ranges are now verified offline in
  [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md). Physical preservation and recovery
  remain unverified.

The commands in this audit document do not write flash. The experimental
original-only trial is supplied separately in [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md);
the normal original and minimal patch write/readback trials are accepted, while
working-drive rollback from the patch and failure recovery remain unvalidated. Modern MT1959/LG
recovery instructions and a different model's PL06 image provide no validation
for this ASUS specimen.

The subsequent [programmer audit](PROGRAMMER_AUDIT.md) establishes complete
erase/program command ranges in a separate in-memory run. In mode `80`, boot
and the final 128 KiB are untouched by those commands, but the profile is erased
first and rewritten last. Persistent page-program failure can leave an incomplete
block even when the entry returns. This evidence does not establish controller
handoff, EEPROM/OTP preservation, actual write completion or recovery. A newer
handoff audit now connects the native gate/copy/writer/handler return with
explicit controller/SPI models; see [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md)
for that evidence and its remaining hardware limits.

## Recovery acceptance procedure

Before loading the modified firmware, the remaining evidence must cover:

1. A pinned writer version accepting the **original decoded backup**, with its
   exact file interpretation, write/erase ranges and boot/profile policy recorded.
   Verify that any drive-specific data, including storage outside this dump,
   is accounted for. The erased tail alone does not prove calibration is absent.
2. A restore rehearsal with that original image on the same drive, followed by
   cold startup, identification, two complete reads and comparison below. This
   rehearsal itself writes flash and should follow completion of the writer audit.
3. Recovery if normal firmware no longer responds: an established boot recovery
   path for this exact board, or an external programmer with verified chip model,
   supply voltage, connection and a separately checked physical-chip backup.
   Retaining boot bytes in the input is insufficient if the writer erases them
   or recovery depends on commands in the damaged main firmware.

A successful normal restore proves that route while the drive responds. It does
not by itself prove recovery from interrupted erase/write or a nonresponsive drive.

After an **independently established** restore, collect a new dump using the
existing reader (these commands read only):

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 --dump --output /tmp/bw12b1lt-restored
/tmp/liteon-research/bin/python tools/liteon/decode_flash.py \
  /tmp/bw12b1lt-restored/flash1.raw.bin /tmp/bw12b1lt-restored/report.json \
  --output /tmp/bw12b1lt-restored/restored.decoded.bin
/tmp/liteon-research/bin/python tools/liteon/audit_recovery.py dump \
  --original firmware/ASUS_BW-12B1LT_1.03.bin \
  --experimental patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --readback-directory /tmp/bw12b1lt-restored \
  --readback-image /tmp/bw12b1lt-restored/restored.decoded.bin \
  --output /tmp/bw12b1lt-restored/rollback-audit.json
```

The comparator requires valid repeated reads and a fresh decode of the new raw
stream using its own INQUIRY metadata. It compares the entire decoded result,
including boot/profile/reserved regions, to the pinned original. An INQUIRY
96-byte result alone is insufficient. Any differing byte fails the comparison;
investigate documented mutable fields rather than silently excluding regions.
The tool verifies file evidence, not when or how the supplied readback was acquired.
Even an identical supplied readback leaves `recovery_ready` and `flash_ready`
false: hardware provenance, writer policy and failure recovery are separate evidence.
