cmake_minimum_required(VERSION 3.1)

project (libtelio_panic_test)

include_directories(${CMAKE_SOURCE_DIR}/../bindings)
link_directories(${CMAKE_SOURCE_DIR}/../../dist/linux/release/x86_64)

file(GLOB_RECURSE SRC_FILES ./*.c)

add_executable (test_panic test_panic.c)

target_link_libraries (test_panic telio pthread m dl)
