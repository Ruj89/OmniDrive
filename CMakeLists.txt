cmake_minimum_required(VERSION 3.26)

if (NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/arm-toolchain.cmake")
endif()

project(OmniDrive VERSION 1.0.4
        LANGUAGES C ASM)

set(CMAKE_C_STANDARD 11)

add_library(OmniDrive STATIC
        src/main.c
)

file(GLOB firmware_list LIST_DIRECTORIES false "${CMAKE_SOURCE_DIR}/firmware/*.bin")
foreach(firmware_file ${firmware_list})
    cmake_path(GET firmware_file STEM LAST_ONLY firmware_name)
    set(patched_firmware_name "${firmware_name}_OmniDrive-${PROJECT_VERSION}.bin")
    add_custom_command(OUTPUT "${CMAKE_SOURCE_DIR}/patched_firmware/${patched_firmware_name}"
            COMMAND armips ${firmware_name}.asm
            COMMAND python ../scripts/update_cmac.py ${CMAKE_SOURCE_DIR}/patched_firmware/${patched_firmware_name}
            DEPENDS OmniDrive
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/asm
            COMMENT "Patching firmware ${firmware_name}.bin"
            VERBATIM
    )
    string(MAKE_C_IDENTIFIER ${firmware_name} target_name)
    add_custom_target(${target_name} ALL 
            DEPENDS "${CMAKE_SOURCE_DIR}/patched_firmware/${patched_firmware_name}"
    )
endforeach()
