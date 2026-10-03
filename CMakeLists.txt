cmake_minimum_required(VERSION 3.20)

project(deep_wire VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Deep Wire requires Linux AF_PACKET sockets")
endif()

# Both front ends use the same capture engine and protocol decoders.
add_library(deep-wire-core STATIC
    src/capture_engine.cpp
    src/packet_decoder.cpp
    src/packet_decode_internal.cpp
    src/ethernet_decoder.cpp
    src/arp_decoder.cpp
    src/ip_decoder.cpp
    src/transport_decoder.cpp
)
target_compile_features(deep-wire-core PUBLIC cxx_std_20)
target_include_directories(deep-wire-core PUBLIC src)

add_executable(deep-wire src/main.cpp)
target_link_libraries(deep-wire PRIVATE deep-wire-core)

option(DEEP_WIRE_BUILD_GUI "Build the Qt 6 desktop interface" ON)
if(DEEP_WIRE_BUILD_GUI)
    find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)
    find_package(Threads REQUIRED)
    add_executable(deep-wire-gui
        src/gui_main.cpp
        src/main_window.cpp
        src/packet_table_model.cpp
        src/packet_details.cpp
        src/capture_session.cpp
    )
    target_link_libraries(deep-wire-gui PRIVATE deep-wire-core Qt6::Widgets Threads::Threads)
endif()

foreach(target deep-wire-core deep-wire deep-wire-gui)
    if(TARGET ${target})
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow
        )
    endif()
endforeach()
