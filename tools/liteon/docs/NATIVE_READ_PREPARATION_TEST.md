# MT1939 native READ preparation: follow-up to the Wii test

The current experimental release is `dist/bw12b1lt-mt1939-watchdog-fix.zip`.
See [MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md) for the later
timestamp finding and native 03/11/05 regression. The attempts below are
historical and did not establish an optical fix. Follow
[FLASH_MT1939_IT.md](FLASH_MT1939_IT.md) for its complete commands; it contains
the guarded direct update and collects fresh backups, replacing the separate
historical bundles described below.

The prior candidate `5eac461d23ebcd42ed80c53705822619d245d14a322396c1cb43983b65f9906d`
passed the user's complete cold-start readback. The user reports an ordinary
DVD raw control with zero errors and a known-good Wii disc failing at every
tested sector with `03/11/05`. Four one-sector C0 reads (raw, raw+FUA, native
descrambling, native descrambling+FUA) all returned that error, with sense
response code `71`. These are user-reported observations, not locally captured
transport journals. Residual zero on an errored command does not prove that
valid optical data reached the buffer.

Offline investigation found a missing native setup step: `MtNativeReady(1)`
calls the low-alias routine `0x398` only for READ(10/12), READ CD and READ CD
MSF. It returns ready for C0 without calling this routine. The routine ORs
`0x000b0000` into `0x04041050` and `0x100` into `0x04040098`, preserving the
interrupt state. The new C0 adapter calls it explicitly after validation and
the zero-sector guard. A differential regression fails on the installed prior
candidate and passes on the correction, comparing real native instructions
for READ and C0. A repeated-request regression clears both setup registers
between three C0 requests for each of CD, DVD-ROM, DVD-RAM and BD, alternating
FUA, and requires exactly one preparation before every reader entry without
any native READ priming. No ECC or sense error is suppressed by this fix.

The subsequent physical probe on the installed prior candidate returned
`03/11/05` and an empty buffer before READ(10), then successfully transferred
2064 nonzero-containing bytes after READ(10) returned the expected Nintendo
guard `05/30/02`. The user subsequently reported over 10,000 Wii sectors
without errors with redumper's automatic preparation, and another error-free
start after Ctrl+C. This strongly supports the preparation diagnosis. These
observations cover the host workaround on the prior firmware; they do not
constitute a complete dump or physical validation of this corrected candidate.

New candidate SHA-256:
`56432d9b48213aea5ea4f82e0146e319083ec609a426b1510a45b2c8cad5dcf9`.

## Receive classification follow-up (2026-10-15)

The user verified two matching complete reads of candidate `56432d9b…`,
then reproduced the failure with all four C0 flag combinations. READ CD MSF
returned 05/30/02 without enabling C0; READ(10) returned the same sense and
then C0 succeeded with the same 2064-byte hash as earlier physical probes.
This supports a difference before the shared readiness preparation, but does
not by itself prove MMIO causality.

The new candidate `535510d835843bca12094eb8380564574cc920978e7b08bb8b5c63bd923b0c56`
adds C0 to the native receive classification at flash 0x101a2 (low alias
0x1a2). It reuses the native clear of the low 16 bits of 0x040400c4 at 0x1b4.
The 18-byte classifier fits by removing two redundant CDB opcode loads;
no new hook, payload routine or RAM allocation is needed. All C0 packets
receive this setup before dispatch validation, just as native READ packets
do; a zero-sector C0 still never enters a reader or starts DMA.

The receive verifier executes all 256 opcodes with three register seeds,
compares non-C0 write effects and calls to the original, and executes 12
repeated receive-to-reader cases over CD/DVD/DVD-RAM/BD. MMIO and helper
calls are modeled, and the low code alias follows the existing emulator
model. Optical recovery and hardware timing remain unverified.

Only nine instruction bytes and three main-checksum bytes differ from the
previous candidate. Boot, authentication window, reserved tails and the
existing C payload remain unchanged. Use the current direct-update guide;
the restoration procedure below documents earlier releases only.

## Historical procedure: first restore the previous candidate using its own bundle

Keep `bw12b1lt-native-zero-length-test.zip`: its runner and payload hashes are
the ones that accept the currently installed firmware. Work in that previous
bundle's extracted directory. Close redumper and remove the disc.

```sh
sudo python3 tools/liteon/device/native_trial.py rollback \
  --package dump/bw12b1lt-native-zero-length-package \
  --baseline dump/bw12b1lt-after-native \
  --device /dev/sr0 --output dump/bw12b1lt-before-read-prepare-rollback-01
```

The baseline must be the actual two-read candidate backup already verified
on the SATA PC. Do not replace it with a synthetic or original-image baseline.
Only after `transport_accepted_requires_cold_readback` and process exit, fully
remove and restore drive power, then collect and verify the original:

```sh
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output dump/bw12b1lt-before-read-prepare-original
python3 tools/liteon/device/native_trial.py verify-readback \
  --state original --baseline dump/bw12b1lt-before-read-prepare-original
```

On finalization error, timeout or interruption, keep power connected, preserve
the result directory and review it before retrying or power cycling. Rollback
requires a responding drive and the exact source image.

## Then use the new bundle in a separate directory

Extract `bw12b1lt-native-read-prepare-restart-test.zip` into a new directory, without
overwriting the previous bundle. Follow [NATIVE_FLASH_TEST.md](NATIVE_FLASH_TEST.md)
for inspect, apply, cold-start two-read verification and the new candidate's
rollback. The new runner intentionally rejects the old candidate as an apply
source and as a rollback source. Apply requires the original flash; its live
preflight verifies the complete source again before any data-out.

After accepting the new full readback, repeat the ordinary DVD control, then
the bounded Wii sector probe **without** `--prime-native-read`, directly after
power restoration and with no prior ordinary read. Use the original redumper
binary without automatic READ(10) preparation for the Wii acquisition test:
the updated host workaround would conceal whether C0 is now self-contained.
Repeat after an interruption and a new drive power cycle. Keep the
same disc and request sizes for comparison. Record SCSI sense, timing and
whether successful data passes redumper's EDC checks. If Wii still fails, keep
the drive on the responding candidate, preserve evidence, and continue
investigation without increasing retries or masking errors.
