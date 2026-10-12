# Physical drive tools

Everything here can talk to a real drive over Linux SG_IO (`/dev/sr0` or
`/dev/sgN`, usually with `sudo`). Only Python's standard library is needed for
the device-facing subcommands. `prepare` subcommands are offline and may need
the research environment because they rerun the emulators.

Each tool accepts only pinned images (checked by SHA-256): there is no option to
send an arbitrary image or CDB. Output directories must be new.

| File | Writes to the drive? | Purpose | Procedure |
| --- | --- | --- | --- |
| `read_flash.py` | No (data-in only) | Probe identity (standard + extended INQUIRY) and dump the raw flash twice. Every other tool reads baselines through it. | [README](../README.md) |
| `stage_update.py` | RAM only | `prepare` a pinned original update package offline, `inspect` it, `stage` it into drive staging RAM. Finalization, erase, reset and unlock are excluded from its transport. | [STAGING_TEST.md](../docs/STAGING_TEST.md) |
| `restore_original.py` | **Flash** | `prepare`/`inspect`/`run` the once-only rewrite of the pinned original firmware (boot preserved, main/profile erased). | [ORIGINAL_RESTORE_TEST.md](../docs/ORIGINAL_RESTORE_TEST.md) |
| `inquiry94_trial.py` | **Flash** | Apply the two-byte INQUIRY-94 patch to a known original, or roll it back. Reuses `restore_original` finalization. | [INQUIRY94_FLASH_TEST.md](../docs/INQUIRY94_FLASH_TEST.md) |
| `native_trial.py` | **Flash** | Apply the full MT1939 OmniDrive candidate, `verify-readback`, or roll back. Requires fresh evidence from `patch_verify/verify_native_port.py`. | [NATIVE_FLASH_TEST.md](../docs/NATIVE_FLASH_TEST.md) |

Dependencies on other folders: `stage_update.py` takes hashes from
`dump_analysis/audit_integrity.py` and `reverse_engineering/analyze_utility.py`;
`native_trial.py` validates evidence with `patch_verify/verify_native_port.py`.
