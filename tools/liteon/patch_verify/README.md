# Patch verification

Offline checks that a built patch behaves as intended, by executing original
and patched firmware code in bounded emulation (`reverse_engineering/map_scsi.py`
provides the harness). Nothing here opens a device. The native verifiers
rebuild the image with `patch_build/native_adapter.py`, so they need
`arm-none-eabi-gcc` and `armips` on `PATH`.

## Entry point

| File | Purpose |
| --- | --- |
| `verify_native_port.py` | Run every native verifier below against one generated image and write an evidence report bound to the SHA-256 of all sources (including every `tools/liteon/**/*.py`). `device/native_trial.py` refuses stale reports. See [NATIVE_ADAPTER.md](../docs/NATIVE_ADAPTER.md) and [NATIVE_FLASH_TEST.md](../docs/NATIVE_FLASH_TEST.md). |

## MT1939 OmniDrive verifiers

Called by `verify_native_port.py` (those marked CLI can also run alone).

| File | What it executes |
| --- | --- |
| `verify_adapter_placement.py` (CLI) | Native startup of the candidate: size, checksum, scatter initialization and hook ABI. |
| `verify_native_adapter.py` (CLI) | The C0 command path against a model of `main.c`; provides `AdapterExperiment` to the verifiers below. |
| `verify_native_hooks.py` | Mode, error, read-check and FUA paths; byte patches compared with the instructions they replace. |
| `verify_native_media.py` | Media hooks with explicit optical-acquisition models; INQUIRY identification. |
| `verify_native_recognition.py` | BD-ROM DI acquisition, copies and empty-header adaptation. |
| `verify_native_speed.py` | C0 timer initialization against native IRQ and idle-speed decisions. |
| `verify_native_transfer.py` | Native DMA setup and reader return for CD, DVD-RAM and BD. |
| `verify_native_programmer.py` | C payload preservation and programming through the native NOR writer (uses `update_emulation`). |

## INQUIRY-94 patch and baseline

| File | Purpose | Documentation |
| --- | --- | --- |
| `verify_inquiry_patch.py` | Compare original and INQUIRY-94 INQUIRY behavior in 20 bounded runs. | [INQUIRY_TEST.md](../docs/INQUIRY_TEST.md) |
| `verify_port_baseline.py` | Negative control: measures the OmniDrive hooks missing from the INQUIRY-94 image. | [OMNIDRIVE_PORT.md](../docs/OMNIDRIVE_PORT.md) |
