; armips applies the INQUIRY patch and adjusts the native LiteOn checksum.
.arm.little
.thumb

.include "version.asm"
OriginalFirmware equ "../firmware/ASUS_BW-12B1LT_1.03.bin"
.definelabel InquiryLimit, 94

.if filesize(OriginalFirmware) != 0x200000
    .error "Expected a decoded 2 MiB BW-12B1LT 1.03 firmware"
.endif
.if readu32(OriginalFirmware, 0x9cb76) != 0x80302060
    .error "Unexpected original INQUIRY instructions"
.endif

.open "../firmware/ASUS_BW-12B1LT_1.03.bin", "../patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-" + VersionMajor + "." + VersionMinor + "." + VersionPatch + ".bin", 0
.org 0x9cb76
; Thumb MOV immediate sets flags: MOVS r0, #94 (5e 20).
; Replace the original limit of 96; preserve the following STRH and handler.
.area 2
    mov r0, #InquiryLimit
.endarea
; The only changed word is at 0x9cb74, inside the native checksum range
; [0x10000, 0x1cfdf8). Its upper halfword contains MOVS r0, #96.
; Adjust the original LE32 sum by the exact word delta, modulo 2^32.
.org 0x1cfff8
.word (readu32(OriginalFirmware, 0x1cfff8) + ((InquiryLimit - 96) * 0x10000)) & 0xffffffff
.close
