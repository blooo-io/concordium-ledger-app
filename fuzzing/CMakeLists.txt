cmake_minimum_required(VERSION 3.10)
project(StandaloneFuzzer VERSION 1.0 DESCRIPTION "Standalone Fuzzing Suite for Concordium Ledger App" LANGUAGES C)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Fuzzer needs to be built with Clang")
endif()

# Favor ClusterFuzzLite-provided flags if present; otherwise use safe defaults.
set(FALLBACK_CFLAGS "-O1 -g -fno-omit-frame-pointer -fsanitize-coverage=trace-cmp,indirect-calls,8bit-counters")
if(DEFINED ENV{SANITIZER})
  if("$ENV{SANITIZER}" STREQUAL "address")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=address -fsanitize-address-use-after-scope")
  elseif("$ENV{SANITIZER}" STREQUAL "undefined")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=undefined -fno-sanitize-recover=undefined")
  elseif("$ENV{SANITIZER}" STREQUAL "memory")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=memory -fsanitize-memory-track-origins=2")
  endif()
endif()

# compatible with ClusterFuzzLite
if (NOT DEFINED ENV{LIB_FUZZING_ENGINE})
	set(COMPILATION_FLAGS_ "-g -Wall -fsanitize=fuzzer,address,undefined")
else()
	set(COMPILATION_FLAGS_ "$ENV{LIB_FUZZING_ENGINE} $ENV{CFLAGS}")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
string(REPLACE " " ";" COMPILATION_FLAGS ${COMPILATION_FLAGS_})

# Set up include directories for the real CBOR implementation
set(FUZZER_INCLUDE_DIRS 
    ${CMAKE_CURRENT_SOURCE_DIR}/include  # Our fuzzer-specific headers
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/tinycbor/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/tinycbor-ledger
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/common
)

# Create a library with the real CBOR and string parsing implementation
add_library(cbor_parsing_lib STATIC
    # Real TinyCBOR implementation from ledger-specific version
    ../lib/tinycbor-ledger/cborparser.c
    ../lib/tinycbor-ledger/cborvalidation.c
    
    # Real string parsing implementation
    ../src/cborStrParsing.c
    
    # Utility function stubs needed by dependencies
    src/util_stub.c
)

target_include_directories(cbor_parsing_lib PRIVATE ${FUZZER_INCLUDE_DIRS})

# Compile definitions to avoid Ledger SDK dependencies
target_compile_definitions(cbor_parsing_lib PRIVATE 
    -DFUZZING_BUILD=1  # Flag to enable fuzzing-specific code paths
    -D__STDC_FORMAT_MACROS
    -DCBOR_PARSER_MAX_RECURSIONS=1024
)

# Compiler flags for the library
target_compile_options(cbor_parsing_lib PRIVATE 
    -Wno-unused-parameter
    -Wno-unused-function
    -Wno-format
)

# Standalone PLT Transaction Fuzzer - now with real CBOR implementation
add_executable(standalone_plt_fuzzer 
    src/standalone_plt_fuzzer.c
)

target_include_directories(standalone_plt_fuzzer PRIVATE ${FUZZER_INCLUDE_DIRS})
target_compile_options(standalone_plt_fuzzer PUBLIC ${COMPILATION_FLAGS})
target_link_options(standalone_plt_fuzzer PUBLIC ${COMPILATION_FLAGS})
target_link_libraries(standalone_plt_fuzzer PUBLIC cbor_parsing_lib)

target_compile_definitions(standalone_plt_fuzzer PRIVATE 
    -DFUZZING_BUILD=1
    -D__STDC_FORMAT_MACROS
    -DCBOR_PARSER_MAX_RECURSIONS=1024
)

# Export Private Key Fuzzer (existing)
add_executable(standalone_export_pk_new_path_fuzzer src/standalone_export_pk_new_path_fuzzer.c)
target_compile_options(standalone_export_pk_new_path_fuzzer PUBLIC ${COMPILATION_FLAGS})
target_link_options(standalone_export_pk_new_path_fuzzer PUBLIC ${COMPILATION_FLAGS})
target_include_directories(standalone_export_pk_new_path_fuzzer PRIVATE ${FUZZER_INCLUDE_DIRS})

# Add target to build all fuzzers
add_custom_target(all_fuzzers DEPENDS 
    standalone_plt_fuzzer 
    standalone_export_pk_new_path_fuzzer
)

# Print build info
message(STATUS "Fuzzing build configured:")
message(STATUS "  - PLT Transaction Fuzzer: standalone_plt_fuzzer")
message(STATUS "  - Export Private Key Fuzzer: standalone_export_pk_new_path_fuzzer") 
message(STATUS "  - Using REAL CBOR implementation from tinycbor-ledger")
message(STATUS "  - Using REAL tag parsing from cborStrParsing.c")
