; MT1939 counterpart of main.asm. The shared payload (libOmniDrive.a) and the
; platform layer (libOmniDriveMT1939.a, src/liteon/mt1939.c) go into the free
; space; everything below only branches to C or patches native instructions.
; Patches follow main.asm in order; MT1939-only hooks are marked as such.

.org FreeSpaceStart
.region (FreeSpaceEnd - FreeSpaceStart)
.importobj "../build/libOmniDrive.a"
.importobj "../build/libOmniDriveMT1939.a"

.align 4
.arm ; otherwise values are offset by 1
    TocOffset:
        .d32 TocOffsetValue
    ; Only main.c's ReadDVDTOCHook writes through these; MT1939 has no
    ; compressed code and uses Mt1939ReadDVDTOCHook, so they stay unused.
    DVDCharacteristicsPatchPtr:
        .d32 0
    DVDTOCReadPatchPtr:
        .d32 0
.thumb
.endregion

; Native packet reception clears the low half of 0x040400C4 for READs.
; Include C0 at the same point, before dispatch/readiness. Removing duplicate
; opcode loads fits the extra comparison in the original 18 bytes. Branches
; are PC-relative, so they also work when this block runs at its low alias.
.org ReceiveReadClassifyAddr
.area 18
    ldrb r0,[r4]
    cmp r0,#0x28
    beq ReceiveReadSetupAddr
    cmp r0,#0xA8
    beq ReceiveReadSetupAddr
    cmp r0,#0xBE
    beq ReceiveReadSetupAddr
    cmp r0,#0xC0
    bne ReceiveReadSetupEndAddr
.endarea

; READ DISC RAW (C0h): no command table, so use the dispatcher's default arm
.org DispatchHookAddr
.area 8
    bl Mt1939DispatchHook
    b DispatchReturnAddr
.endarea

.org InquiryDataPatch
    .ascii "OmniDrive"
    .d8 VersionMajor ; major
    .d8 VersionMinor ; minor
    .d8 VersionPatch ; patch

.org DVDReadCmdHookAddr ; READ(10), READ(12) and READ CD
    bl DVDReadCmdHook
.org BDReadCmdHookAddr ; READ(10) and READ(12)
    bl BDReadCmdHook

.org DVDCharacteristicsHookAddr
    bl Mt1939DVDCharacteristicsHook ; unknown book types use the DVD-ROM case
.org DVDTOCReadPatchAddr
    .d8 0x01 ; control data read failure returns success

.org DVDLeadOutPatchAddr0
    .d8 0xe0 ; bls -> b
.org DVDLeadOutPatchAddr1
    nop
.org DVDLeadOutPatchAddr2
    nop
.org DVDLeadOutPatchAddr3
    nop
.org DVDLeadOutPatchAddr4
    nop
.org DVDLeadOutPatchAddr5
    nop
.org DVDLeadOutPatchAddr6
    nop

.org BDLeadOutPatchAddr
    .d8 0xE0 ; bne -> b

.org CDLeadOutPatchAddr0
    .d8 0x06 ; check if gte 6 rather than 5, 5 is lead-out
.org CDLeadOutPatchAddr1
    mov r0,#0x00
.org CDLeadOutPatchAddr2
    nop
.org CDLeadOutPatchAddr3
    nop
.org CDLeadOutPatchAddr4
    nop
.org CDLeadOutPatchAddr5
    nop
.org CDLeadOutPatchAddr6
    nop

.org ScrambleHookAddr
    bl ChangeDiscRWModeHook

.org DVDMinusReadCheckHookAddr
    bl Mt1939DVDMinusReadCheckHook

.org BDScramblePatchAddr
    nop
.org BDScrambleHookAddr
    bl ChangeDiscRWModeHook

; The MT1939 DVD reader always changes the read mode (no DVDScramblePatch)
.org DVDScrambleHookAddr
    bl ChangeDiscRWModeHook
.org DVDRAMScrambleHookAddr
    bl ChangeDiscRWModeHook

; Finish a raw request before the native fast path consumes another packet.
; The following cmp/beq and native cleanup remain in place.
.org DVDContinuationHookAddr
    bl Mt1939ContinuationPendingHook
.org DVDRAMContinuationHookAddr
    bl Mt1939ContinuationPendingHook
.org BDContinuationHookAddr
    bl Mt1939ContinuationPendingHook

.org ReadDVDTOCHookAddr
    bl Mt1939ReadDVDTOCHook

.org DVDEDCHookAddr
    bl SetErrorModeHook

.org BDEDCHookAddr
    bl SetErrorModeHook

.org BDIdentifierPatchAddr1
    nop
.org BDIdentifierPatchAddr2
    .d8 0xE0 ; beq -> b
.org BDIdentifierPatchAddr3
    nop

.org SetBDCharacteristicsHookAddr
    bl Mt1939SetBDCharacteristicsHook

; MT1939 only: native code re-enables descrambling; reload the clobbered bases
.org DVDTransferModeHookAddr
.area 10
    bl Mt1939DVDTransferModeHook ; r0 is live and returned unchanged
    ldr r1,[DVDTransferModeLiteral]
    nop
    nop
.endarea
.org CopyTransferModeHookAddr
.area 14
    ldr r1,[sp,#0x28] ; copy mode, fifth argument
    bl Mt1939CopyTransferModeHook ; r0 is live and returned unchanged
    ldr r1,[CopyStatusLiteral]
    ldr r2,[CopyModeLiteral]
    nop
    nop
.endarea
