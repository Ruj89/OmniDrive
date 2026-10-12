# Update path emulation

Offline execution of the native firmware-update chain, without a drive: the
utility's x86 code and the drive's ARM loader and NOR programmer run in Unicorn,
with peripherals, SPI and the NOR array modeled in memory. Most tools need the
pinned `Flash_Utility.exe` (`--utility`).

The chain, in order:

| File | Stage | Documentation |
| --- | --- | --- |
| `verify_loader.py` | Update-input gates of original and patched images (tag comparisons, decoding, field and checksum checks), utility encoding/CDBs and READ BUFFER verification. Provides `Utility`, `require` and `sha` to the other tools. | [LOADER_ACCEPTANCE.md](../docs/LOADER_ACCEPTANCE.md) |
| `verify_finalization.py` | The utility's finalization worker and retry handling, with injected transport results. | [STAGING_TEST.md](../docs/STAGING_TEST.md), [PROGRAMMER_AUDIT.md](../docs/PROGRAMMER_AUDIT.md) |
| `verify_handoff.py` | Update gate → handoff → imported writer → handler return. | [ORIGINAL_RESTORE_TEST.md](../docs/ORIGINAL_RESTORE_TEST.md) |
| `verify_programmer.py` | The imported flash programmer through its native return: erase/program coverage, retries and interruption damage. Provides the `Nor` model. | [PROGRAMMER_AUDIT.md](../docs/PROGRAMMER_AUDIT.md) |

The physical trials in `device/` reuse these emulators when preparing packages.
