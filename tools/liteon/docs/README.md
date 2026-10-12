# Lite-On documentation

Research notes, offline evidence and physical test procedures. Commands in
these files are run from the repository root.

## Analysis and design

| File | Content |
| --- | --- |
| [PORTING.md](PORTING.md) | MT1939 porting study: function map, small-function emulation, integrity header. |
| [SCSI_MAP.md](SCSI_MAP.md) | Command reception, dispatch, read parameters/FUA, data-in and sense. |
| [INTEGRITY.md](INTEGRITY.md) | Integrity audit, selector experiments, readback comparator. |
| [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md) | Native update-input acceptance, corruption rejection, utility encoding. |
| [PROGRAMMER_AUDIT.md](PROGRAMMER_AUDIT.md) | Flash programmer erase/program coverage, retries, interruption damage. |
| [NATIVE_ADAPTER.md](NATIVE_ADAPTER.md) | Mapping of every `main.asm` patch onto MT1939 and the native adapter design. |
| [OMNIDRIVE_PORT.md](OMNIDRIVE_PORT.md) | OmniDrive feature status and physical test plan. |

## Physical test procedures

In chronological order. Each one documents its results.

| File | Trial | Tool |
| --- | --- | --- |
| [STAGING_TEST.md](STAGING_TEST.md) | Original update transferred to staging RAM only | `device/stage_update.py` |
| [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md) | Rewrite of the original firmware | `device/restore_original.py` |
| [INQUIRY_TEST.md](INQUIRY_TEST.md) | Offline INQUIRY-94 patch (prerequisite of the next trial) | `patch_verify/verify_inquiry_patch.py` |
| [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md) | INQUIRY-94 flash and rollback | `device/inquiry94_trial.py` |
| [NATIVE_FLASH_TEST.md](NATIVE_FLASH_TEST.md) | Full MT1939 OmniDrive flash, readback and rollback | `device/native_trial.py` |
