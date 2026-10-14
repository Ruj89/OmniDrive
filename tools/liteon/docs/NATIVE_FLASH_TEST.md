# BW-12B1LT 1.03: full MT1939 OmniDrive candidate trial

For the consolidated handoff ZIP, use [FLASH_MT1939_IT.md](FLASH_MT1939_IT.md).
It supports a guarded direct update with --force-source and fresh live backups; the earlier bundles
and historical baseline paths below are not required for that procedure.
The current runner pins the watchdog candidate `db7979b1…`; the instructions
below describe the older read-preparation candidate and require its archived
runner. See [MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md).

This procedure is for the exact retained ASUS BW-12B1LT specimen on SATA and
OmniDrive 1.0.4 candidate SHA-256
`56432d9b48213aea5ea4f82e0146e319083ec609a426b1510a45b2c8cad5dcf9`.
This candidate includes the zero-sector C0 no-op fix and explicit native READ preparation. Earlier full-port
packages refer to a different image and must not be used for this trial.
It is an experimental hardware test, not established optical support.
`native_trial.py` pins decoded, staged and raw-read hashes independently of
package manifests. The original-only and historical INQUIRY-94 runners retain
their original restrictions; neither is the rollback runner for this image.

If the previous zero-length candidate is already installed, first follow
[NATIVE_READ_PREPARATION_TEST.md](NATIVE_READ_PREPARATION_TEST.md) to restore
the original with the previous bundle. This runner accepts only original flash
for apply and the new candidate for rollback.

## Offline preparation

With ARM GCC, armips and the research Python dependencies available, generate a
new complete evidence report using `verify_native_port.py` with both `--utility`
and `--capture` (see NATIVE_ADAPTER.md). Preparation rejects evidence whose
image hashes or source hashes are stale or whose loader/programmer audits are
missing. The candidate must also match a fresh isolated build. Boot, reserved
tails and the authenticated window must match the original.

```sh
python tools/liteon/device/native_trial.py prepare \
  --original-package dump/bw12b1lt-original-restore-package \
  --original firmware/ASUS_BW-12B1LT_1.03.bin \
  --patched patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --baseline dump/bw12b1lt-native-original-baseline \
  --evidence dump/mt1939-force-source-evidence.json \
  --output dump/bw12b1lt-native-read-prepare-restart-package
```

The prepared bundle `dump/bw12b1lt-native-read-prepare-restart-test.zip` includes the fixed package,
original backup, candidate, evidence and Python runtime helpers. Keep it private.
Extract it in the repository root on the SATA PC. The remaining commands need
only Python 3's standard library. All output directories must be new.
Bundles prepared before `tools/liteon` was split into subfolders keep the
scripts directly in `tools/liteon/`; with such a bundle, drop the subfolder
(`device/`) from the commands below.

```sh
python3 tools/liteon/device/native_trial.py inspect \
  --package dump/bw12b1lt-native-read-prepare-restart-package \
  --baseline dump/bw12b1lt-native-original-baseline
```

## Apply and verify

With no disc inserted and other drive-using applications closed:

```sh
sudo python3 tools/liteon/device/native_trial.py apply \
  --package dump/bw12b1lt-native-read-prepare-restart-package \
  --baseline dump/bw12b1lt-native-original-baseline \
  --device /dev/sr0 --output dump/bw12b1lt-native-read-prepare-apply-01
```

**This writes physical flash.** Keep drive power connected until the process
exits. Before data-out, the runner verifies the exact live INQUIRY/session and
reads the entire current flash, requiring the pinned original. It uploads the
profile and image, compares all 512 RAM blocks, durably journals finalization
intent, then sends control `80` exactly once. Boot and the last 128 KiB are
excluded by the native writer. Main and profile are erased; interruption can
leave an unusable drive even though boot is preserved.

An accepted transport result means `transport_accepted_requires_cold_readback`.
It does not certify programming. If finalization fails, times out or is
interrupted, keep power connected, preserve the entire result directory and
review it before retrying or power cycling. There is no finalization retry.
A responding drive and exact verified source image are required for rollback;
this procedure does not recover a nonresponding or partially programmed drive.

After an accepted return and process exit, fully remove drive power, restart,
then acquire and verify two complete reads:

```sh
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-after-read-prepare
python3 tools/liteon/device/native_trial.py verify-readback \
  --state candidate --baseline dump/bw12b1lt-after-read-prepare
```

Acceptance requires both full raw hashes to equal the pinned candidate stream,
96-byte standard INQUIRY with `OmniDrive` and version bytes `01 00 04` at bytes
74–85, and the exact expected extended INQUIRY, including session/protocol data.
Preparation independently derives the expected raw stream by AES-CBC with IV
reset for every 128-byte block. An exact stream match therefore binds all 2 MiB,
including boot, profile, checksums and reserved tails, to the candidate.

Proceed with ordinary CD/DVD/BD reads, then small C0 reads. Initially use CD
FUA and single/dual-layer DVD/BD. BDXL raw PSN is excluded: the shared triple-layer
predicate is always false and MT1939 layer state has not been mapped for it.
Later CD tests must compare normal READ CD followed by C0 without FUA and C0
with FUA followed by C0 without FUA, including subchannels/C2 and latency.
C0 without FUA inherits the native CD FUA state; real cache compatibility is
unverified. Continue with the physical tests in OMNIDRIVE_PORT.md.

## Working-drive rollback

After accepting the full candidate readback, return the responding drive to the
original using the same fixed package:

```sh
sudo python3 tools/liteon/device/native_trial.py rollback \
  --package dump/bw12b1lt-native-read-prepare-restart-package \
  --baseline dump/bw12b1lt-after-read-prepare \
  --device /dev/sr0 --output dump/bw12b1lt-native-read-prepare-rollback-01
```

Rollback validates both candidate backup reads and both INQUIRY signatures,
then freshly reads the entire live flash before any data-out. Only the exact
candidate can be the source. The target is always the pinned original; a
package manifest cannot authorize another image. The same once-only
finalization, journal and ambiguity rules apply.

After an accepted return and process exit, remove drive power, restart, acquire
two reads and verify the original:

```sh
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-after-read-prepare-rollback
python3 tools/liteon/device/native_trial.py verify-readback \
  --state original --baseline dump/bw12b1lt-after-read-prepare-rollback
```

Retain apply/rollback result directories and both readback directories.
`full_omnidrive_port` and `flash_ready` remain false pending the physical feature
tests. Prior physical success of the minimal INQUIRY-94 trial does not validate
this full candidate. Offline handoff tests execute both directions on modeled
`c22015` and `c22415` NOR chips; hardware timing and peripherals remain modeled.
