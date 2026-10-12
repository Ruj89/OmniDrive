# Reverse engineering

Offline study of the pinned original firmware and of the Windows Flash Utility,
mostly through Capstone disassembly and bounded Unicorn emulation. These tools
produce maps and evidence; they do not build or flash anything. Install
`capstone unicorn` (plus `pefile` for the utility, `numpy` for the MT1959
comparison) in the research environment.

| File | Purpose | Documentation |
| --- | --- | --- |
| `analyze_utility.py` | Unpack the pinned `Flash_Utility.exe` and recover its INQUIRY and flash-read CDBs. Defines the utility's `EXPECTED_SHA256`. | [README](../README.md#reproduce-the-offline-evidence) |
| `map_firmware.py` | Signature and function/reference map of the BW-12B1LT 1.03 image. | [PORTING.md](../docs/PORTING.md) |
| `map_scsi.py` | SCSI dispatch map by bounded emulation. Provides the `Experiment` emulation harness and memory constants used by every `patch_verify` tool. | [SCSI_MAP.md](../docs/SCSI_MAP.md) |
| `trace_integrity.py` | Bounded emulation of the firmware's integrity-record selector. | [INTEGRITY.md](../docs/INTEGRITY.md) |
| `compare_mt1959.py` | Score each MT1959 OmniDrive patch site (including its compressed RAM overlay) against the MT1939 dump. | [NATIVE_ADAPTER.md](../docs/NATIVE_ADAPTER.md) |
