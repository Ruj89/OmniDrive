# MT1939 platform library, imported next to libOmniDrive.a by asm/liteon/mt1939.asm.
if(TARGET ASUS_BW_12B1LT_1_03)
    add_library(OmniDriveMT1939 STATIC
            src/liteon/mt1939.c
    )
    # The free space is 0x1500 bytes; libOmniDrive.a keeps the shared flags.
    target_compile_options(OmniDriveMT1939 PRIVATE -Os)
    add_custom_command(APPEND
            OUTPUT "${CMAKE_SOURCE_DIR}/patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-${PROJECT_VERSION}.bin"
            DEPENDS OmniDriveMT1939
                    "${CMAKE_SOURCE_DIR}/firmware/ASUS_BW-12B1LT_1.03.bin"
                    "${CMAKE_SOURCE_DIR}/asm/ASUS_BW-12B1LT_1.03.asm"
                    "${CMAKE_SOURCE_DIR}/asm/liteon/mt1939.asm"
                    "${CMAKE_SOURCE_DIR}/asm/version.asm"
                    "${CMAKE_SOURCE_DIR}/scripts/update_cmac.py"
                    "${CMAKE_SOURCE_DIR}/tools/liteon/patch_build/finalize_native.py"
    )
endif()
