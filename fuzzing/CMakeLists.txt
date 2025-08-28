cmake_minimum_required(VERSION 3.10)

# Simple standalone fuzzer project
project(StandaloneFuzzer
        VERSION 1.0
        DESCRIPTION "Standalone Export Private Key Fuzzer"
        LANGUAGES C)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzer needs to be built with Clang")
endif()

# Simple compilation flags for fuzzing
if (NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    set(COMPILATION_FLAGS "-g -Wall -fsanitize=fuzzer,address,undefined")
else()
    set(COMPILATION_FLAGS "$ENV{LIB_FUZZING_ENGINE} $ENV{CFLAGS}")
endif()

string(REPLACE " " ";" COMPILATION_FLAGS ${COMPILATION_FLAGS})

# Create the standalone fuzzer - just one source file!
add_executable(standalone_fuzzer src/standalone_fuzzer.c)

target_compile_options(standalone_fuzzer PUBLIC ${COMPILATION_FLAGS})
target_link_options(standalone_fuzzer PUBLIC ${COMPILATION_FLAGS})