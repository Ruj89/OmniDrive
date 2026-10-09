# OmniDrive
Copyright © 2026 Rib

## Description
OmniDrive is a firmware modification for MediaTek MT1959-based optical disc drives manufactured by Hitachi-LG Data Storage that enables features that allow for better, more complete reading of discs, including proprietary game discs.

## Features
* Lead-in/lead-out reading for CD/DVD/BD and derivatives.
* Raw sector reading for CD/DVD/BD and derivatives (2352 bytes/sector for CD, 2064 bytes/sector for DVD, 2072 bytes/sector for BD).
* Custom READ DISC RAW command to read discs, with flags for FUA (bypassing cache), raw addressing (MSF for CD, PSN for DVD/BD), and descrambling (for DVD/BD).
* The ability to read various proprietary game discs (see table):

| Disc Type | Support | Notes |
| ---: | :---: | --- |
| CD (ROM/R/RW) | ☑️ |
| DVD (ROM/RAM/±R/±RW) | ☑️ |
| BD (ROM/R/RE) | ☑️ |
| BD-XL (R/RE) | ☑️ |
| UHD-BD | ☑️ |
| PlayStation 3 BD-ROM | ☑️ | Disc contents are encrypted, disc key is not retrievable
| PlayStation 4 BD-ROM | ☑️ | Game files are encrypted, encryption key is not retrievable
| PlayStation 5 BD-ROM | ☑️ | Game files are encrypted, encryption key is not retrievable
| Xbox (XGD1) | ✅ |
| Xbox 360 (XGD2/XGD3) | ✅ |
| Xbox One/Series (XGD4) | ✅ | Game files are encrypted, encryption key is not retrievable
| GameCube (NROM)/Wii (RVL-ROM) | ✅ |
| GameCube (NR)/Wii (RVT-R) | ✅ | May take a few minutes for the drive to recognise the disc. Support still needs to be added in dumping software.
| Wii U (WUP-ROM?) | ⚠️ | Can be read/descrambled but not decrypted, disc key is not retrievable
| Wii U (CAT-R) | ☑️ |
| Dreamcast (GD-ROM/GD-R) | ❎ | Only low-density area can be read

Key:
* ☑️ - Native Support (without patched firmware)
* ✅ - Supported with OmniDrive
* ⚠️ - Partial support (see notes)
* ❓ - Unknown support (needs testing)
* ❎ - Not currently supported

## Building
### Dependencies
* CMake
* ninja
* arm-none-eabi-gcc toolchain
* [armips](https://github.com/Kingcom/armips)
* Python 3
* pycryptodome
### Instructions
1. Put the stock LG BU40N 1.00 and ASUS BW-16D1HT 3.02 firmware files in the `firmware` folder. The files should be named the following and have the following checksums:

| Filename | CRC32 | MD5 | SHA-1 |
| --- | --- | --- | --- |
| HL-DT-ST_BD-RE_BU40N_1.00.bin | `E3C1A315` | `EDB28FCD7A239281ACE26A468D382A9C` | `9C48677B155154D24A3B95A32B4A29CA02FF40B3` |
| ASUS_BW-16D1HT_3.02.bin | `84000B21` | `97F0EEABD0B675B4363B2C4749226016` | `F8DF5B579F25DA8D4E5AA5EF79F3005DAC5EB8C7` |
2. Create a `build` folder and run `cmake -G Ninja ..` from the build folder.
3. Run `ninja`. The patched firmware files should be output in the `patched_firmware` folder.

## Flashing
Currently the recommended method to flash the drives is to use `sdftool` which comes as part of [MakeMKV](https://makemkv.com/). The BU40N firmware should work with all slim drives and the BW-16D1HT firmware should work with all desktop drives.

[Redumper](https://github.com/superg/redumper) has initial support for flashing, but cannot cross-flash drives yet.

## Experimental Lite-On firmware research

An experimental Linux reader for investigating the ASUS BW-12B1LT 1.03 is
documented in [tools/liteon/README.md](tools/liteon/README.md). Reading, RAM staging,
an original-image rewrite and the minimal INQUIRY-94 patch trial have passed on
the retained specimen, including full readback after reported power removal.
Working-drive rollback from the patch also passes with exact original readback; see
[rollback evidence](tools/liteon/INQUIRY94_FLASH_TEST.md#working-drive-rollback).

The current minimal firmware profile uses `asm/ASUS_BW-12B1LT_1.03.asm`.
Place the decoded original at `firmware/ASUS_BW-12B1LT_1.03.bin`, then build the CMake
target `ASUS_BW_12B1LT_1_03` with the normal project toolchain.
The output is `patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin`.
This profile currently changes only the standard INQUIRY length and its
LiteOn checksum; the full OmniDrive hooks are not yet implemented.

[Native loader acceptance](tools/liteon/LOADER_ACCEPTANCE.md) is verified offline
for the original backup and minimal OmniDrive patch, including corrupted-input
rejection. The original and minimal patch rewrite trials pass with exact full
readbacks. The patched drive advertises the expected 94-byte standard INQUIRY.
Optical/media behavior remains unverified.

The native handoff/writer/handler return is also audited with explicit
controller/SPI models. An experimental Linux original-only physical rewrite
trial is prepared in [tools/liteon/ORIGINAL_RESTORE_TEST.md](tools/liteon/ORIGINAL_RESTORE_TEST.md).
It passed with cold-start full-image readback on the retained specimen. The
minimal INQUIRY-94 trial also passed, with exactly the two expected changed bytes.
Procedure, evidence and the prepared working-drive rollback path are documented
in [tools/liteon/INQUIRY94_FLASH_TEST.md](tools/liteon/INQUIRY94_FLASH_TEST.md).
