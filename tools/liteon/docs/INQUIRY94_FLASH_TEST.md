# BW-12B1LT 1.03: minimal INQUIRY-94 flash trial

This document describes the historical **minimal INQUIRY-94 image** at
`dump/inquiry94-test/BW-12B1LT_1.03.inquiry94.experimental.bin`. The normal CMake output now contains
the native adapter; its separate evidence is described in
[NATIVE_ADAPTER.md](NATIVE_ADAPTER.md).

The minimal patch trial has now passed on the retained specimen. All 512 RAM
blocks matched and exactly one finalization completed without errors in 22,060 ms.
Two post-restart raw reads match the predicted encrypted stream. Fresh decoding
matches the expected patch across all 2 MiB, with zero differing bytes and all
14 structure checks passing. Only offsets `0x09cb76` and `0x1cfffa` differ from
the original; boot, profile and both tails are identical. Standard INQUIRY byte
4 is `59`, advertising 94 bytes; this Linux transport delivers a 96-byte buffer
with two padding bytes. Identity is unchanged; the 94 valid response bytes match
the original except for the length field. Evidence:
`dump/bw12b1lt-inquiry94-validation.json`. Acquisition files are retained under
`dump/dump/bw12b1lt-inquiry94-01` and `dump/dump/bw12b1lt-after-inquiry94`.
Power removal is user-reported; SPI transactions were not instrumented.
The working-drive rollback trial also passes: one accepted finalization in
22,363 ms, all 512 RAM blocks matched, two identical original-image readbacks
and all 14 structure checks passing. Standard INQUIRY is back to 96 bytes.
Evidence: `dump/bw12b1lt-inquiry94-rollback-validation.json`.

The original rewrite trial passed on the retained specimen: all 512 RAM blocks
matched, one finalization completed without transport errors in 22,212 ms, and
two subsequent full reads decoded identically to the original across all 2 MiB.
All 14 structure checks pass, including boot/profile/tails. Evidence:
`dump/bw12b1lt-original-restore-validation.json`. Files/logs were supplied by the
user; power removal is user-reported and physical SPI transactions were not
instrumented.

This trial applies only the exact two-byte patch in [INQUIRY_TEST.md](INQUIRY_TEST.md):
INQUIRY maximum 96 -> 94 and the main checksum. It does not implement the full
OmniDrive disc-reading hooks. Expected decoded patch SHA-256:
`46be83575f28161ff3a851604d476070220a4a4970c7b5343622bf31b55ddc6b`.
Boot/profile/tails are unchanged in the input; the writer still erases
main/profile, including erasing profile first. The marker/startup/full-readback
trial is accepted; optical/media behavior remains unverified.

## Package and guards

`dump/bw12b1lt-inquiry94-package` contains profile, original/patched staging
images, window tag and `trial.json`. Constants independently pin every payload;
editing metadata cannot authorize another image. The two changed bytes lie
outside the encrypted window, so its ciphertext/tag equal the original trial.
Native gate/handoff audits accept the patch. Two additional modeled rollback
runs execute from patched firmware through writer/handler return and produce
the original image on both compatible synthetic chip IDs. Evidence:
`dump/bw12b1lt-inquiry94-rollback-audit.json`; explicit alias/SPI/ready/EEPROM
model limits are inherited from [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md).

Preparation independently derives encrypted read-stream hashes using CBC reset
per 128-byte response and confirms the original prediction against captured
bytes. Expected patch stream SHA-256:
`fcde95308fc372ac2fae5d2f76ec82d03f5a599210a161196f46701d38232bfd`.
It now matches both hardware readbacks. Both directions check repeated
baseline reads and a fresh full current-flash read against their exact source
before data-out. Finalization reuses the tested once-only method, durable intent
record and five-minute timeout. The original-only runner still rejects patched
payloads and defaults to the original advertised 96-byte INQUIRY check.

## Apply and read back

Copy `dump/bw12b1lt-inquiry94-test.zip` to the SATA PC and extract it in the
repository root. Retain `dump/bw12b1lt-after-restore` as the baseline. Live commands
need only Python's standard library. Keep package and backups private. Optional
`inspect` checks package/baseline without accessing hardware; use the same package
and baseline arguments as below.
Bundles prepared before `tools/liteon` was split into subfolders keep the
scripts directly in `tools/liteon/`; with such a bundle, drop the subfolder
(`device/`) from the commands below.

With no disc inserted and other drive-using applications closed:

```sh
sudo python3 tools/liteon/device/inquiry94_trial.py apply \
  --package dump/bw12b1lt-inquiry94-package \
  --baseline dump/bw12b1lt-after-restore \
  --device /dev/sr0 --output dump/bw12b1lt-inquiry94-01
```

**This physically writes the patch.** Keep power connected and let it finish.
The output directory must be new. Success reports
`transport_accepted_requires_cold_readback`; `physical_flash_verified` and
`flash_ready` remain false until separate comparison. `trial-result.json`,
`transport.jsonl`, `live-preflight.raw.bin` and `preflight-probe.json` retain
the evidence, including separate finalization intent/result entries.

If finalization fails, times out or is interrupted, keep power connected and
copy the entire result directory before retrying or power cycling. The physical
outcome is unknown; the runner never retries. A killed host process may leave
only the durable intent, and an earlier summary cannot exclude a physical write.

After an accepted return and process exit, fully remove drive power, restart
and collect two complete reads:

```sh
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-after-inquiry94
```

Copy both result directories back. Require matching raw reads, a fresh decoded
full-image match to the exact patch, original boot/profile/tails, valid checksum
and standard INQUIRY byte 4 equal to `59` (advertised total 94). Received length
may be 94 or padded to 96; received length alone is insufficient. Identity stays
ASUS BW-12B1LT 1.03.

## Working-drive rollback

After validating the patch readback, this separate physical write returns a
responding drive with the exact known patch to the original:

```sh
sudo python3 tools/liteon/device/inquiry94_trial.py rollback \
  --package dump/bw12b1lt-inquiry94-package \
  --baseline dump/bw12b1lt-after-inquiry94 \
  --device /dev/sr0 --output dump/bw12b1lt-inquiry94-rollback-01
```

It explicitly requires the advertised 94-byte marker (94-byte delivery or
96-byte padding) and both complete pinned patch raw reads. It then freshly
reads the current chip again before writes. After an accepted return, remove
drive power/start again and acquire two full reads into a new directory such
as `dump/bw12b1lt-after-inquiry94-rollback`. Require exact original equality and
advertised INQUIRY total 96. The same no-retry ambiguity rules apply. This route
has now passed on the retained specimen. The full 2 MiB readback matches the
pinned original with zero differing bytes, including boot, profile and both tails.
Power removal/startup is user-reported; host logs and both raw acquisitions
are retained under `dump/dump/bw12b1lt-inquiry94-rollback-01` and
`dump/dump/bw12b1lt-after-inquiry94-rollback`.

To reproduce the package offline, choose a new output path:

```sh
/tmp/liteon-research/bin/python tools/liteon/device/inquiry94_trial.py prepare \
  --original-package dump/bw12b1lt-original-restore-package \
  --original firmware/ASUS_BW-12B1LT_1.03.bin \
  --patched dump/inquiry94-test/BW-12B1LT_1.03.inquiry94.experimental.bin \
  --baseline dump/dump/bw12b1lt-after-restore \
  --output dump/bw12b1lt-inquiry94-package
```
