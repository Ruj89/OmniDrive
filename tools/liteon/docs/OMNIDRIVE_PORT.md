# OmniDrive port status: ASUS BW-12B1LT 1.03 / MT1939

The normal build produces the MT1939 port of every `main.asm` feature that
has a counterpart on this firmware; the mapping and the features without one
are in [NATIVE_ADAPTER.md](NATIVE_ADAPTER.md). Offline checks include raw-request
cleanup, queued ordinary reads, DVD-R bypass and DVD-RAM descrambling control.
Physical testing is still required: **nothing below has been run on a drive**, and the
historical INQUIRY-94 trials do not certify this payload.

The port follows the existing OmniDrive strategy: a profile of addresses
(`asm/ASUS_BW-12B1LT_1.03.asm`), a platform counterpart of `main.asm`
(`asm/liteon/mt1939.asm`) that imports C into declared free space, and C for
all logic (`src/main.c` unchanged, plus `src/liteon/mt1939.c`). Assembly is
limited to `bl` hooks and binary patches. Compared with
`da01346befd2fe0db160f074229b7793858d88b9`, the shared C sources, toolchain,
`main.asm`/`mmio.asm` and MT1959 profiles are unchanged. `CMakeLists.txt` gains
one `include(cmake/mt1939.cmake)` line, `update_cmac.py` a small native-sum
dispatch, plus the README pointer and ignore rules.

## Feature status

“Verified offline” means executed against native MT1939 code under the
models in [NATIVE_ADAPTER.md](NATIVE_ADAPTER.md), not physical-media support.

| Feature | Verified offline | Physical test required |
| --- | --- | --- |
| C0 dispatch and validation | 480 requests; 24-bit count; readiness; no-medium response; rejected requests preserve timer/packet/format | Host interoperability (redumper) |
| CD raw/MSF/FUA/subchannels/C2 | Format register, SubQ selector, native FUA flag and cache comparison, DMA setup/return | Real sector layout, subchannel and C2 data |
| DVD/RAM raw/PSN/FUA, descrambling, EDC | Native readers, layer/PSN mapping, raw DVD-R bypass, RAM mode hook, copy/recovery descrambling; previous controls restored | Scrambled/unscrambled sectors; intentional EDC errors; DVD-RAM descrambling |
| Ordinary READ after C0 | Native raw cleanup before queued READ(10/12); original format restored; ordinary guards run; normal fast paths preserved | Host sequencing and ordinary data on real media |
| BD raw/PSN/FUA, descrambling, EDC | Single/dual-layer PSN, mode and error hooks, lead-out patch | Real transfers; BDXL addressing (main.c treats it as single-layer) |
| Lead-in/out | CD signed addressing, CD/DVD/BD lead-out patches | Boundary reads on real discs |
| XGD1/2/3 | DMI/security-sector retry, geometry/TOC update, state restoration | Real security-sector acquisition |
| Nintendo GC/Wii | Unknown PFI book types → DVD-ROM with layers; BCA flag; ordinary-read guard | Disc recognition and dumping |
| NR/RVT-R | Control-data read failure returns success | Real discs with unreadable PFI |
| Wii U | Empty/unknown DI classified as BD-ROM; DI geometry; ordinary-read guard | Recognition and dumping |
| Read speed | C0 resets the native idle counter (no MT1959 accumulator exists) | Spindle speed during long C0 reads |
| Identification | Native INQUIRY response with signature at byte 74 | Host detection |
| Build/integrity | CMake = isolated build; incremental input-dependency checks; native sums; reviewed sites; byte-identical startup RAM; native loader (optional audit) | Flashing and full readback |

## Physical test plan

Run in this order and stop at the first failure. Keep the original backup and
the candidate-specific apply/rollback procedure in [NATIVE_FLASH_TEST.md](NATIVE_FLASH_TEST.md)
ready; flash only the exact image whose hash `verify_native_port.py` reports.
The historical original-only and INQUIRY-94 runners reject this full candidate.

1. Flash, power-cycle and read back the whole image; INQUIRY shows
   `OmniDrive` and `1.0.4` at byte 74; ordinary CD/DVD/BD reading works.
2. C0 on CD: LBA and MSF, subchannels (none/SubQ/all), C2, FUA; compare with
   a reference drive. Include C0 with FUA followed by C0 without FUA, and a
   normal READ CD followed immediately by C0 without FUA on the same area.
   Verify the requested raw sector layout and data against the reference,
   including any requested subchannels/C2, to detect incompatible cached data.
   Record latency as well: C0 without FUA inherits the native CD FUA state
   (see [NATIVE_ADAPTER.md](NATIVE_ADAPTER.md)).
3. C0 on DVD-ROM and BD-ROM: LBA/PSN, with and without descrambling; dual
   layer across the boundary; lead-in/out sectors. Exclude BDXL raw PSN from
   the first trial: the shared triple-layer predicate is always false and
   MT1939's additional layer state has not been mapped.
4. Immediately after C0, issue READ(10)/READ(12) and verify the ordinary data
   (dispatcher after raw cleanup, see NATIVE_ADAPTER.md).
5. DVD-R/RW and DVD-RAM raw reads, including descrambling on DVD-RAM.
6. XGD1/2/3, GameCube/Wii (incl. dual layer), NR/RVT-R and Wii U discs.
7. Measure read speed and consecutive C0 commands per second over a long dump
   on CD, DVD, DVD-RAM and BD. Record request sizes and command latency to
   distinguish spindle throughput from per-command waiting; measure timer
   tick duration rather than inferring it from idle thresholds.

Update `full_omnidrive_port` / `flash_ready` in the reports only after these
pass. `verify_port_baseline.py` and the INQUIRY-94 commands remain tied to
the historical minimal image (commit `1102a32`).
