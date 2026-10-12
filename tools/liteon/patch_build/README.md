# Patch build

Generation of the MT1939 OmniDrive image. The production build is CMake
(`cmake/mt1939.cmake`); these modules are what it and the verifiers share.
Neither is a command-line tool.

| File | Purpose | Used by |
| --- | --- | --- |
| `native_adapter.py` | Rebuild the BW-12B1LT 1.03 OmniDrive image in isolation exactly as CMake does (gcc for `libOmniDrive.a` and `libOmniDriveMT1939.a`, armips on `asm/ASUS_BW-12B1LT_1.03.asm`, native word sums), then check that every changed byte belongs to a reviewed site. `SOURCES` lists the files whose hashes bind the evidence. | Every `patch_verify` tool, tests |
| `finalize_native.py` | Write the native MT1939 main and profile word sums instead of a CMAC. Standard library only, no imports from other tools. | `scripts/update_cmac.py`, `cmake/mt1939.cmake` |

Both paths appear in `native_adapter.SOURCES`, `cmake/mt1939.cmake` and
`scripts/update_cmac.py`: update them together if a file moves. Design and
patch-site mapping: [NATIVE_ADAPTER.md](../docs/NATIVE_ADAPTER.md).

The historical two-byte INQUIRY-94 patch is assembled by
`dump_analysis/audit_integrity.py` (`build()`), see
[INQUIRY_TEST.md](../docs/INQUIRY_TEST.md).
