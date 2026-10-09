; Invoked by tools/liteon/patch_firmware.py in an isolated temporary directory.
; Python validates the exact decoded specimen and updates its LiteOn checksum.
.arm.little
.thumb

.include "version.asm"
.open "../firmware/ASUS_BW-12B1LT_1.03.bin", "../patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-" + VersionMajor + "." + VersionMinor + "." + VersionPatch + ".bin", 0
.org 0x9cb76
; Thumb MOV immediate sets flags: MOVS r0, #94 (5e 20).
; Replace the original limit of 96; preserve the following STRH and handler.
.area 2
    mov r0, #94
.endarea
.close
