cmake_minimum_required(VERSION 3.20)

project(deep_wire VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Deep Wire requires Linux AF_PACKET sockets")
endif()

add_executable(deep-wire
    src/main.cpp
    src/capture_engine.cpp
    src/packet_parser.cpp
)

target_compile_features(deep-wire PRIVATE cxx_std_20)
target_include_directories(deep-wire PRIVATE src)

target_compile_options(deep-wire PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)
