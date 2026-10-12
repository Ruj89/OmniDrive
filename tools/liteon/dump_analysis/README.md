# Dump analysis

Offline processing of raw flash reads saved by `device/read_flash.py`. Nothing
here opens a device, and no existing file is overwritten.

Typical order: `decode_flash.py` → `validate_flash.py` → `audit_integrity.py`.

| File | Purpose | Notes |
| --- | --- | --- |
| `decode_flash.py` | Decode `flashN.raw.bin` into a firmware image, with the AES key/IV taken from the captured extended INQUIRY in `report.json`. | Needs `pycryptodome`. See the [README](../README.md#offline-decoding). |
| `validate_flash.py` | Structural checks of a decoded dump: raw-read equality, partition descriptors, ARM vectors, identity, checksums; optional comparison with a reference image. Also provides `checksum()`. | [README](../README.md#offline-validation) |
| `audit_integrity.py` | Compare the pinned original and experimental images and audit a restored readback region by region. Shared module: pinned `IMAGE_SHA256`, `REGIONS`, native word sums, and `build()`, which assembles the historical INQUIRY-94 patch (`asm/liteon/inquiry94.asm`) with armips. | [INTEGRITY.md](../docs/INTEGRITY.md), [INQUIRY_TEST.md](../docs/INQUIRY_TEST.md) |

`audit_integrity.py` is imported by most emulators and by the patch builder,
so moving or renaming its constants affects many tools.
