# BW-12B1LT 1.03: original update staging test on Linux

This test sends the original update profile and encrypted input image to the
drive's staging RAM, then reads back and compares all 512 blocks. The transport
allowlist rejects final controls `80` and `a0`: it cannot start the audited flash
programmer. It sends no reset, unlock or erase command. This is an experimental
hardware transport test; physical flash validation is still a later step.

The supplied preflash capture passed all 14 structure checks and matches the
retained original across all 2 MiB. It is retained at
`dump/dump/bw12b1lt-preflash`; the comparison is saved separately in
`dump/bw12b1lt-preflash-validation.json`. The nested path reflects the user's copy
and has not been moved or overwritten.

## Package prepared offline

The package at `dump/bw12b1lt-staging-package` contains:

* `profile.enc.bin`: 3,968-byte encrypted programmer descriptor/code and tag.
* `original.staged.bin`: 2 MiB original image with the native encrypted 64 KiB window.
* `package.json`: input and payload fingerprints, block counts and explicit
  `finalization_included: false`.

Preparation runs the pinned utility's original x86 encoding functions offline
and compares every generated CDB to its native builder. It requires the pinned
original and a complete matching baseline. To reproduce with a fresh output:

```sh
/tmp/liteon-research/bin/python tools/liteon/stage_update.py prepare \
  --image firmware/ASUS_BW-12B1LT_1.03.bin \
  --report dump/dump/bw12b1lt-preflash/report.json \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --output dump/bw12b1lt-staging-package-2
```

Only preparation requires Unicorn, pefile and PyCryptodome. The Linux runner
uses Python's standard library and the existing SCSI generic ABI. The package
contains no finalization tag file or runnable host executable. Keep the package
private with the original backup; it contains firmware-derived binary data.

## Run the next hardware test

Copy the updated `tools/liteon` scripts and package to the same relative paths
on the PC with the drive. The convenience archive `dump/bw12b1lt-staging-test.zip`
contains these paths and can be extracted in the repository root. No Python
package installation is required for `inspect` or `stage`.

Check the package without accessing hardware:

```sh
python3 tools/liteon/stage_update.py inspect \
  --package dump/bw12b1lt-staging-package
```

From the repository root, run the RAM test against the actual optical device:

```sh
sudo python3 tools/liteon/stage_update.py stage \
  --package dump/bw12b1lt-staging-package \
  --device /dev/sr0 \
  --output dump/bw12b1lt-stage-01
```

The output directory must not exist. Before any data-out, the runner checks
the original 96-byte standard INQUIRY (received and advertised length), exact ASUS model/revision and the hash
of all 164 valid extended-INQUIRY bytes. This intentionally pins the same
specimen/session. A changed response aborts before sending the profile.
The payload hashes are checked against constants in the runner independently
of package metadata; editing a manifest cannot authorize different code.

Normal completion sends 1,025 update commands: one profile upload, followed by
512 block writes and 512 readbacks. Each block is 4 KiB. A read transport failure
or short transfer allows three attempts; a byte mismatch permits a second
comparison. Persistent failure aborts before advancing to the next block.
Writes are not retried automatically. There is no finalization option.

The live test records:

* `staging-result.json`: `blocks_matched: 512`, `all_blocks_matched: true`,
  `finalization_sent: false` and `physical_flash_verified: false` on success.
* `transport.jsonl`: every update CDB, direction, length, residual, status,
  sense, duration and payload/response digest. Firmware bytes and keys are omitted.

Copy the entire result directory back for analysis, including partial results
on failure. Stop on an error rather than modifying the package or trying other
commands. The report describes the RAM comparison, not a physical-chip readback.

After collecting the staging result, fully remove power from the drive and
restart it to discard the volatile update state. Collect another pair of reads:

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-after-stage
```

Compare that fresh decode with the original as in [PROGRAMMER_AUDIT.md](PROGRAMMER_AUDIT.md).
The first physical write trial uses an original-image restore. The subsequent
handoff audit and experimental runner are documented in
[ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md); interrupted-write recovery
remains unverified.

## Reported hardware result

The user supplied a successful `original_update_staging_ram` JSON result for
`/dev/sr0`: package SHA-256
`afa72a028d3a56ff34aabbebad39c6a66b332aea3a99092ab9d11d2d138f8cfb`,
matching pinned identity/INQUIRY, 512 matched blocks, 512 read attempts and 1,025
update commands. It explicitly reports no finalization and no physical flash
verification. The initial user-reported copy retains that provenance in
`dump/bw12b1lt-stage-01-user-reported.json`.

The journal and post-staging captures have now been supplied under
`dump/dump/bw12b1lt-stage-01` and `dump/dump/bw12b1lt-after-stage`. All 1,025 CDBs,
directions, lengths, statuses and data hashes match the expected sequence. Both
fresh raw reads match the original raw backup; fresh decoding passes all 14
checks and matches the original full 2 MiB with zero changed bytes. The original
standard INQUIRY is unchanged. Evidence is saved in
`dump/bw12b1lt-after-stage-validation.json`. This validates RAM transport and the
post-staging original state; no physical write was performed. Power removal is
user-reported rather than independently instrumented.

## Native host finalization audit

Run this offline using the pinned utility:

```sh
/tmp/liteon-research/bin/python tools/liteon/verify_finalization.py \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --output dump/bw12b1lt-host-finalization.json
```

Five cases execute the native worker at `0x40bec8` and CDB builder at `0x402760`
through return, with synthetic transport outcomes at `0x40afe4`. The selected
path sends `3b0501000000000010800000`, with a synthetic 16-byte tag. It accepts
transport returns 0 or 16, retries one failed/short-positive result, and writes
result 1 after two failures or 2 after an accepted return. It issues no separate
status-poll or physical-readback command. Those native result values therefore
do not establish physical flash completion. This audit does not authorize
replaying a finalization command after an ambiguous hardware error.

The tag, objects and transport outcomes in this audit are synthetic; it opens
no device and does not execute the firmware handoff, controller remapping or
host UI. The offline report retains `physical_flash_verified: false` and
`flash_ready: false`.
