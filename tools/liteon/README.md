# Experimental Linux Lite-On flash reading

Target: ASUS BW-12B1LT firmware 1.03, connected via SATA. This is a research
tool. A user supplied two matching raw dumps and an INQUIRY report from one
specimen; the offline decoder recovered recognizable firmware from them.
No drive is attached in the development environment. A successful transfer and
two identical hashes alone do not establish that the returned bytes are a
complete, usable firmware image.

## Collect identification first

Python 3 and the Linux SCSI generic interface are sufficient; no Python packages
are required for the reader. From the OmniDrive repository root:

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 --output /tmp/bw12b1lt-probe
cat /tmp/bw12b1lt-probe/report.json
```

The output directory must be new. The reader sends standard INQUIRY, checks the
exact vendor/model/revision, then sends the extended INQUIRY recovered from the
original utility. It records both responses as hex. An unrecognized extension
is saved for investigation; it does not trigger guesses or command scanning.
If `/dev/sr0` is unavailable, use the corresponding `/dev/sgN` node (for example,
identify it with `lsscsi -g`). Permission and ioctl failures are reported.

## Experimental raw dump

Once the probe's metadata has been reviewed:

```sh
sudo python3 tools/liteon/read_flash.py /dev/sr0 --dump --output /tmp/bw12b1lt-dump
```

This reads the reported size twice in 128-byte blocks, writing
`flash1.raw.bin`, `flash2.raw.bin`, and `report.json`. The reader stops at the
first transport error or short block and preserves partial files. Existing
files are never overwritten. If the two hashes differ, it exits with an error.
All-00/all-FF data, repeating blocks, firmware layout, and size still need
independent analysis before treating an image as valid.

There are no flash write, erase, unlock, reset, or arbitrary-CDB options.
Only an explicit command allowlist can reach SG_IO, always with
`SG_DXFER_FROM_DEV`. Opening the device with `O_RDWR` allows proprietary
read CDBs through kernel permission checks; no data-out operation is implemented.
This constrains what the host sends; it does not prove how every unsupported
firmware interprets a proprietary command.

## Protocol evidence

Source binary: C0deKing Flash Utility 7.2.0, `Flash_Utility.exe`, obtained from
[the archived distribution](https://cheapiesystems.com/media/odd-firmware/PLDS/Flash_Utility-7.2.0/).
SHA-256:
`34dd3c6a21be113fc30bfd0514647d1e2c6fe192263e49dea9c70410cf19f9f3`.
Addresses below are virtual addresses in its unpacked memory image, base
`0x400000`. No third-party executable is included in this repository.

| Routine | Address | Recovered CDB / behavior |
| --- | --- | --- |
| Extended INQUIRY | `0x4021c8` | `12 00 00 00 f0 40 00 00 00 00 00 00`, up to 240 bytes in |
| Legacy flash read | `0x40259c` | `df 83 00 00 ff 00 AA AA AA 00 00 00`, 128 bytes in |
| Alternate flash read | `0x402618` | `3c 01 f0 AA AA AA 00 00 80 00 00 00`, 128 bytes in |
| Read dispatcher | `0x402694` | Selects one of the preceding read routines |
| Dump loop | `0x4041e8` | Increments byte offset by `0x80` |
| Metadata interpretation | `0x402c58`–`0x402d32` | Size, protocol flags, and decoding state |

`AA AA AA` is a big-endian byte offset. The utility accepts `EXTRAINQ` or
`LITEONIT` at extended-INQUIRY offset `0x60`. It interprets byte `0x6f` as flash
size in 64 KiB units. Byte `0x72` selects the alternate read protocol when
`(flags & 0x83) == 1` or bit `0x80` is set. Those variants also pass the returned
blocks through a decoding routine (`0x403eb4`), using data from the extended
INQUIRY. The reader preserves the original data-in stream as `.raw.bin`;
the separate offline decoder below implements this transformation.

The 8 MiB listed in the optical-drive hardware table is the drive's buffer,
not its flash capacity. The reader's 8 MiB ceiling is a conservative protocol
limit, not an assertion about this drive. Metadata interpretation comes from
the utility and matched the supplied ASUS specimen; other revisions remain
unverified.

## Reproduce the offline evidence

The research helper only emulates unpacking and two short CDB builders. It
stops before Windows import resolution and intercepts the SCSI transport
boundary, without accessing devices or executing the Windows application.
It refuses binaries with any other SHA-256.

```sh
python3 -m venv /tmp/liteon-research
/tmp/liteon-research/bin/pip install pefile unicorn
/tmp/liteon-research/bin/python tools/liteon/analyze_utility.py /path/to/Flash_Utility.exe
python3 -m unittest discover -s tests -v
```

## Offline decoding

The BW-12B1LT 1.03 sample supplied during development produced two identical
2 MiB raw reads. Offline decoding recovered the model, firmware revision and
timestamp `1.03 / 2011/04/18 21:15`, and `MT1939 Boot Code` markers. This validates
reading and decoding on that specimen, not flashing or all Lite-On variants.

The sample's INQUIRY returned 240 bytes but advertised only 164 valid bytes.
The decoder takes its AES-128 key from the last 16 **valid** bytes and its IV
from bytes `0x10` through `0x1f`. CBC restarts at every 128-byte response. Using
the padded 240-byte tail produces incorrect data. The raw bytes and original
report are preserved unchanged.

Install `pycryptodome` in the research environment, then run:

```sh
/tmp/liteon-research/bin/pip install pycryptodome
/tmp/liteon-research/bin/python tools/liteon/decode_flash.py \
  /tmp/bw12b1lt-dump/flash1.raw.bin /tmp/bw12b1lt-dump/report.json \
  --output firmware/ASUS_BW-12B1LT_1.03.bin
```

The decoder checks both recorded raw hashes and the size before proceeding.
It never contacts a drive or overwrites an existing file. Do not use a decoded
research image for flashing without separately establishing the file format,
checksums, and any drive-specific regions required by a flasher.

## Offline validation

```sh
/tmp/liteon-research/bin/python tools/liteon/validate_flash.py \
  /tmp/bw12b1lt-dump --image firmware/ASUS_BW-12B1LT_1.03.bin \
  --output /tmp/bw12b1lt-dump/validation-report.json
```

The researched specimen passed 14 consistency checks: raw-read equality,
fresh decoding, the four INQUIRY partition descriptors, ARM vectors and target
ranges, exact firmware identity, model/profile markers, erased unused tail,
and observed checksum structure. The boot and profile regions match an additive
little-endian 32-bit word sum modulo 2^32, excluding the final eight bytes.
The main region's stored value exceeds that full-region sum by `0x80`; an
independently downloaded iHBS112 2 PL06 reference has the same delta. For the
ASUS specimen, native update instructions now establish the sum endpoint as
`0x1cfdf8`, excluding 512 `ff` bytes before storage at `0x1cfff8`. See
[LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md) for native acceptance evidence.

The reference at
`https://cheapiesystems.com/media/odd-firmware/PLDS/stockfw/iHBS112%202/PL06.BIN`
has size 2,097,152 bytes and SHA-256
`b0dbd71a240b71c79e8f6c8c7905a1e44c3c653719412f8b9579477cf001ce8c`.
It is a different model and must not be used as a replacement ASUS image.
Use `--reference /path/to/PL06.BIN` to include this structural comparison in
the report. An incomplete download is rejected.

Partition descriptors use a two-byte little-endian identifier followed by
three-byte big-endian start and inclusive end addresses. The specimen has boot
at `0x000000`–`0x00ffff` and reserved regions at `0x1d0000`, `0x1e0000`, and
`0x1f0000`, each 64 KiB. The gap contains the main firmware. These region roles
are inferred from their contents; the precise preservation policy for a
restoration flasher remains unverified.

`offline_structure_consistent: true` means the file is coherent for analysis.
`flash_ready` remains false in this structure-only report; hardware write and
drive-specific region checks are recorded in separate trial reports. The native main
checksum and update-input gates are traced in [LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md).
Validation never repairs checksums, modifies a file, or contacts the drive.

The captured vectors in `tests/liteon_read_vectors.json` are independent of the
Linux CDB builder and are checked by the tests. Tests also cover target checks,
write-command rejection, short transfers, failed commands, and partial files.
They include a synthetic block decoded by the original utility's routine and
checked against the Python AES-CBC implementation. They do not replace hardware
validation.

## MT1939 porting study

See [PORTING.md](PORTING.md) for the reproducible offline function map,
small-function emulation, integrity-header observations and remaining ABI work.
The follow-up [SCSI_MAP.md](SCSI_MAP.md) maps command reception, dispatch,
read parameters/FUA, data-in setup and sense responses, with reproducible
bounded emulation in `map_scsi.py`.
The MT1939 profile is included in the build with its current minimal patch;
hardware flashing remains unvalidated.

## First minimal modification

[INQUIRY_TEST.md](INQUIRY_TEST.md) documents a specimen-specific offline patch
that changes the standard INQUIRY response limit from 96 to 94 bytes, its
armips assembly patch (with Python input checks and LiteOn checksum update)
and 20 bounded original/modified emulation runs. It produces an
experimental image and change manifest, not a validated flashing file.

[INTEGRITY.md](INTEGRITY.md) adds a fresh integrity audit, 12 bounded integrity
selector experiments and a strict comparator for future restored readbacks.
The original and minimal-patch write/readback trials are documented separately below.

[LOADER_ACCEPTANCE.md](LOADER_ACCEPTANCE.md) documents native update-input
acceptance for both original and OmniDrive, corruption rejection, utility
encoding/CDB verification and a separate programmer-entry trace to the first
erase boundary. These are offline proofs with explicit hardware models.
The verifier now includes each block's native READ BUFFER and x86 byte comparison,
readback failure/short-transfer/mismatch aborts, and pinned INQUIRY metadata.

[PROGRAMMER_AUDIT.md](PROGRAMMER_AUDIT.md) extends the separate programmer run
through its native return with an in-memory NOR array: erase/program coverage,
native retries and interruption damage across 13 scenarios. It also documents
the fresh baseline to collect on Linux via SATA. The profile is erased during
initialization even with boot excluded. The subsequent original rewrite trial
now passes on the retained specimen.

[STAGING_TEST.md](STAGING_TEST.md) provides an original-image RAM transfer test
for Linux via SATA. Preparation checks the fresh baseline and derives a pinned
package offline; the standard-library live runner compares 512 staging blocks
and excludes the flash finalization commands from its transport allowlist.

The RAM test has passed with a verified 1,025-command journal and a subsequent
byte-identical full original readback. A separate experimental original-only
physical rewrite trial in [ORIGINAL_RESTORE_TEST.md](ORIGINAL_RESTORE_TEST.md)
also passes with full identical readback after reported power removal. The
minimal patch write/marker/full-readback trial now passes as well, with exactly
two expected changed bytes and advertised INQUIRY total 94 (96-byte received
buffer including two padding bytes). Evidence and the prepared working-drive
rollback path are documented in [INQUIRY94_FLASH_TEST.md](INQUIRY94_FLASH_TEST.md).
Working-drive rollback from the patch also passes with exact original readback.
Optical/media behavior remains unvalidated.
