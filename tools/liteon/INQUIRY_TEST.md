# BW-12B1LT 1.03: first minimal firmware experiment

INQUIRY is the SCSI identification command (`0x12`). A host requests bytes
describing the drive, including vendor, model and firmware revision. It does
not require a disc. This experiment changes the **standard response limit
from 96 to 94 bytes**, providing an observable marker before adding OmniDrive
hooks or custom commands. Identification remains within the first 36 bytes.

This exact minimal image has now passed the normal SATA write, startup, marker
and full-readback trial on the retained specimen, as documented in
[INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md). Native update-input checks
also accept it offline in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md). Working-drive
rollback from the patch also passes with exact original readback. Optical/media
behavior remains unverified. This image does not implement the full OmniDrive hooks. The commands in
this offline build document invoke no flasher. The decoded image is distinct from
the encrypted raw dump. Do not pass it to the existing
MT1959 `update_cmac.py` script.

## Build and verify offline

From the repository root, using the original decoded specimen:

```sh
cmake -S . -B build -G Ninja
cmake --build build --target ASUS_BW_12B1LT_1_03
/tmp/liteon-research/bin/python tools/liteon/verify_inquiry_patch.py \
  firmware/ASUS_BW-12B1LT_1.03.bin \
  patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --output patched_firmware/emulation.json
python3 -m unittest discover -s tests -v
```

The build requires the normal project toolchain, Python and `armips` on `PATH`
([armips build instructions](https://github.com/Kingcom/armips#building)).
It invokes armips on [ASUS_BW-12B1LT_1.03.asm](../../asm/ASUS_BW-12B1LT_1.03.asm)
from the `asm` directory. The assembly checks the image size and original
INQUIRY instruction, applies the patch and adjusts the stored LiteOn checksum
by the changed word's delta. It produces only the versioned binary in
`patched_firmware/`; no Python postprocessor or build JSON manifest is needed.

The offline verifier rebuilds its reference image in a temporary directory using
helpers in `audit_integrity.py`. These helpers pin the original SHA-256, verify
that only the intended instruction and checksum changed, and independently check
the final checksum. The verifier additionally uses the Capstone/Unicorn research
environment described in [SCSI_MAP.md](SCSI_MAP.md) and refuses an existing report
destination.

The input is `firmware/ASUS_BW-12B1LT_1.03.bin`, a copy of the original decoded
backup. Output naming follows the other profiles, using `asm/version.asm`:
`patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin`.
CMake invokes armips and `scripts/update_cmac.py` for every profile. The script
recognizes the exact LiteOn INQUIRY-94 output by SHA-256 and leaves it unchanged;
armips has already set its native checksum. Other images follow the MT1959 CMAC
update path.
With the normal ARM toolchain configured, the target is
`cmake --build build --target ASUS_BW_12B1LT_1_03`.
The historical CMake file does not track changes to firmware inputs or assembly
sources. After changing these files, force regeneration with
`cmake --build build --clean-first --target ASUS_BW_12B1LT_1_03`.

The patch is `60 20` -> `5e 20` at file/execution address `0x9cb76`:
Thumb `movs r0, #96` becomes `movs r0, #94`. The following native `strh` stores
the response limit; existing allocation-length checks and data-in setup run.
The handler also passes `94 - 5 = 89` to its native writer for INQUIRY byte 4,
the additional-length field. The standard path is taken for control byte zero.
The extended vendor path bypasses this instruction; it is not exercised here.

The generator recomputes the additive main trailer using the native LE32 sum
over `[0x10000,0x1cfdf8)`, stored at `0x1cfff8`. The apparent `+0x80` difference
comes from 512 excluded `ff` bytes, rather than a seed. It leaves the integrity header,
boot, profile and remaining regions byte-identical. The resulting byte changes
on this specimen are:

| File offset | Original | Experimental | Role |
|---|---|---|---|
| `0x09cb76` | `60` | `5e` | INQUIRY limit |
| `0x1cfffa` | `9f` | `9d` | Main additive checksum |

The verifier checks the exact output against the generator and executes 20
bounded runs: original/modified at allocation lengths 0, 1, 36, 93, 94, 95,
96 and 255, plus EVPD and nonzero-page rejection. It checks even-length
rounding, native data-in pointer/length, pending/error flags and arguments
to the additional-length writer. As in `map_scsi.py`, the template writer
and control-state helper are stubbed; RAM/MMIO are synthetic. This tests the
instruction change, not DMA delivery, optical behavior or loader acceptance.

## Observe the marker on hardware, once loading is established

For an eventual hardware test, request at least 96 bytes of **standard**
INQUIRY. A 36-byte request does not distinguish the transfer lengths. The
existing reader's probe already uses `12 00 00 00 60 00` and records the result:

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 --output /tmp/bw12b1lt-probe
python3 - <<'PY'
import json
from pathlib import Path
report = json.loads(Path('/tmp/bw12b1lt-probe/report.json').read_text())
data = bytes.fromhex(report['standard_inquiry_hex'])
print('Identity:', report['identity'])
print('Transferred:', len(data))
print('Advertised total:', data[4] + 5)
PY
```

The probe also performs the existing extended INQUIRY; omit `--dump` for this
identification test. Expected standard byte 4 changes from `5b` to `59`, giving
an advertised total of 94. The expected data-in length is 94; transport residual
reporting was checked on the retained specimen: the marker is `59` as predicted,
while this Linux transport delivers 96 bytes with two padding bytes.

See [INTEGRITY.md](INTEGRITY.md) for the offline integrity audit, native header
selector trace, restoration acceptance criteria and future readback comparator.
The generated image is a starting point for firmware modification. The
hardware evidence includes the passed minimal patch trial and full readback in
[INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md). A later diagnostic-command
experiment can then build on the dispatch and response ABI in [SCSI_MAP.md](SCSI_MAP.md).
