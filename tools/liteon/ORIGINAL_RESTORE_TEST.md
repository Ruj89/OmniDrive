# BW-12B1LT 1.03: first physical original-image rewrite trial

The retained specimen has now passed this trial. The supplied journal verifies
all 1,026 commands, exactly one accepted finalization (22,212 ms) and no transport
errors. Two post-restart reads freshly decode to the original across all 2 MiB,
with all 14 checks passing and zero changed bytes. Evidence is saved separately
in `dump/bw12b1lt-original-restore-validation.json`; acquisition logs are unchanged.
Power removal/startup is user-reported and SPI was not instrumented. The normal
rewrite/readback trial is accepted.
The minimal patch trial has also passed with its expected marker and exact full
readback; evidence is documented in [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md).

This experimental Linux/SATA trial rewrites the original main/profile using
native control `80`. Boot and the last 128 KiB are excluded by the audited
writer. The profile is erased first and rewritten last: interruption can leave
the drive unusable with boot intact. Acceptance requires two full matching
reads after cold startup; a successful transport result is insufficient.

The supplied staging journal now matches every expected CDB, direction, length,
status and payload digest: 1,025 successful complete transfers, 512 matched
blocks, no retries/finalization. Subsequent repeated raw reads match the preflash
backup. Fresh decoding passes all 14 structure checks and differs from the
original by zero bytes across boot/main/profile/tails. Evidence:
`dump/bw12b1lt-after-stage-validation.json`. Power removal is user-reported.

## Native handoff evidence

`verify_handoff.py` runs profile upload, all 512 write/read comparisons, final
input checks, firmware handoff, imported writer, cleanup and handler return.
A checkpoint at `0x1baeb4` resumes the same CPU state, stack and memory. Native
`0xa3b20` creates the header; `0xa3952` discovers the synthetic chip through SPI
and selects parameters; `0xa3802` copies 7,164 bytes from staging to a temporary
alias. The audit checks that copy and executable-window registers, then models
its visibility at `0x19000` before native `blx r5` calls the writer.

Six cases pass: original/patch on synthetic IDs `c22015`/`c22415`, a transient
write fault and a persistent write fault. The persistent fault produces four
native readback mismatches and 44,232 incorrect bytes but returns with clear
input-error flags. Neither handler return nor transport success proves complete
programming. Ready/completed peripheral status, NOR and executable visibility
are models. RAM/SPI buffers use flat views; physical alias ownership, chip
protection, EEPROM persistence and timing remain unverified.

Reproduce with a new output filename:

```sh
/tmp/liteon-research/bin/python tools/liteon/verify_handoff.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --report dump/report.json --utility /tmp/omnidrive-Flash_Utility.exe \
  --output dump/bw12b1lt-native-handoff.json
```

Saved evidence: `dump/bw12b1lt-native-handoff.json` and
`dump/bw12b1lt-host-finalization.json`. Both retain `flash_ready: false`.

## Package and Linux procedure

`dump/bw12b1lt-original-restore-package` contains the unchanged staging package
in `staging/`, plus `original.final-tag.bin` and `restore.json`. Preparation runs
the pinned native utility encoder/tag/CDB functions and independently checks
the cryptography. The runner pins original/session/payload/tag constants
independently of editable manifests. It accepts neither arbitrary images nor
boot-update control `a0`. Preparation needs research dependencies; `inspect`
and `run` use only Python's standard library. Keep package and backups private.

Copy `dump/bw12b1lt-original-restore-test.zip` to the SATA PC and extract it in
the repository root. Keep the existing `dump/bw12b1lt-after-stage` backup there;
adjust `--baseline` if its actual path differs. Inspect without device access:

```sh
python3 tools/liteon/restore_original.py inspect \
  --package dump/bw12b1lt-original-restore-package \
  --baseline dump/bw12b1lt-after-stage
```

With no disc inserted and other drive-using applications closed, run:

```sh
sudo python3 tools/liteon/restore_original.py run \
  --package dump/bw12b1lt-original-restore-package \
  --baseline dump/bw12b1lt-after-stage \
  --device /dev/sr0 --output dump/bw12b1lt-restore-01
```

**This command physically writes flash.** Keep drive power connected and let it
finish. The output directory must be new. Before data-out it checks package,
both baseline reads, live identity/INQUIRY and an additional full current flash
read against the pinned original encrypted-stream hash. It then uploads the
profile/image and compares all 512 RAM blocks. Only after those pass does it
durably journal finalization intent and send the fixed 16-byte control-`80`
command once, with a five-minute SG_IO timeout. That timeout is an operational
bound, not a measured physical flash time. It sends no finalization retry,
reset, reboot or unlock command. The native programmer does issue main/profile
erase and status-register writes inside the drive.

Normal success records 1,026 update commands and outcome
`transport_accepted_requires_cold_readback`; `physical_flash_verified` and
`flash_ready` remain false. Results are in `restore-result.json` and
`transport.jsonl` (including distinct durable intent/result entries).
`live-preflight.raw.bin` and `preflight-probe.json` retain the additional baseline.

If finalization fails, times out, is short or interrupted, the physical outcome
is unknown. The runner never retries and reports `finalization_sent: null`
after an attempted command without accepted result. Preserve logs, keep drive
power connected and supply the entire result directory before retrying or
power cycling. After a forced host-process kill, the durable intent may be the
only evidence: an earlier summary cannot exclude a physical write.

After an accepted return and process exit, fully remove drive power, restart
and collect two full reads:

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-after-restore
```

Copy **both** `dump/bw12b1lt-restore-01` and `dump/bw12b1lt-after-restore` back.
Require a fresh cold-start decoded full-image match using [INTEGRITY.md](INTEGRITY.md).
Any differing byte fails this trial. A separate minimal-patch write trial can
follow acceptance. Normal restore does not validate the full OmniDrive feature set.

To regenerate the package offline, choose a new output path:

```sh
/tmp/liteon-research/bin/python tools/liteon/restore_original.py prepare \
  --image firmware/ASUS_BW-12B1LT_1.03.bin \
  --report dump/dump/bw12b1lt-after-stage/report.json \
  --utility /tmp/omnidrive-Flash_Utility.exe \
  --output dump/bw12b1lt-original-restore-package
```
