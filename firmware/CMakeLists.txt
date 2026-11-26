# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.1)
set(toolchainVersion 15_2_Rel1)
set(picotoolVersion 2.3.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Board: pico (RP2040) by default; pico2 also works
set(PICO_BOARD pico CACHE STRING "Board type")

include(pico_sdk_import.cmake)

project(usb_sniffer C CXX ASM)

pico_sdk_init()

add_executable(usb_sniffer
    usb_sniffer.c
    usb_descriptors.c
)

pico_generate_pio_header(usb_sniffer ${CMAKE_CURRENT_LIST_DIR}/usb_sniffer.pio)

target_include_directories(usb_sniffer PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_compile_options(usb_sniffer PRIVATE -Wall -O2)

target_link_libraries(usb_sniffer
    pico_stdlib
    pico_multicore
    pico_unique_id
    hardware_pio
    hardware_clocks
    tinyusb_device
    pico_usb_reset
)

# picotool "load -f" / 1200 baud touch -> BOOTSEL without pressing the button
target_compile_definitions(usb_sniffer PRIVATE
    PICO_ENABLE_USB_RESET_VIA_VENDOR_INTERFACE=1
    PICO_ENABLE_USB_RESET_VIA_BAUD_RATE=1
    PICO_USB_RESET_INCLUDE_DEFAULT_APP_DRIVER_CB=1
    PICO_USB_RESET_SUPPORT_MS_OS_20_DESCRIPTOR=1
    PICO_USB_RESET_MS_OS_20_DESCRIPTOR_ITF=2
)

# RP2040 input Schmitt trigger on the D+/D- tap pins (0 = off, default)
set(SNIFFER_INPUT_SCHMITT 0 CACHE STRING "Enable the input Schmitt trigger on D+/D- (0/1)")
target_compile_definitions(usb_sniffer PRIVATE SNIFFER_INPUT_SCHMITT=${SNIFFER_INPUT_SCHMITT})

# Run everything from RAM: deterministic timing, no XIP cache misses
pico_set_binary_type(usb_sniffer copy_to_ram)

# USB is used by our own CDC streaming interface (no stdio)
pico_enable_stdio_usb(usb_sniffer 0)
pico_enable_stdio_uart(usb_sniffer 0)

pico_add_extra_outputs(usb_sniffer)
