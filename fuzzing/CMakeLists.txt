cmake_minimum_required(VERSION 3.10)
project(StandaloneFuzzer VERSION 1.0 DESCRIPTION "Standalone Export Private Key Fuzzer" LANGUAGES C)

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

# Use env CFLAGS if the action provided them; otherwise our fallback.
if(DEFINED ENV{CFLAGS} AND NOT "$ENV{CFLAGS}" STREQUAL "")
  set(EFF_CFLAGS "$ENV{CFLAGS}")
else()
  set(EFF_CFLAGS "${FALLBACK_CFLAGS}")
endif()

# Engine flag (usually "-fsanitize=fuzzer" or a path to libFuzzer).
set(EFF_ENGINE "$ENV{LIB_FUZZING_ENGINE}")

add_executable(standalone_fuzzer src/standalone_fuzzer.c)

# Apply sanitizer & coverage flags to compile and link; add the engine ONLY at link.
separate_arguments(EFF_CFLAGS_LIST NATIVE_COMMAND "${EFF_CFLAGS}")
target_compile_options(standalone_fuzzer PRIVATE ${EFF_CFLAGS_LIST})
target_link_options(standalone_fuzzer PRIVATE ${EFF_CFLAGS_LIST} ${EFF_ENGINE})

# Optional: make it easier to debug what flags were used
message(STATUS "SANITIZER=$ENV{SANITIZER}")
message(STATUS "Using CFLAGS: ${EFF_CFLAGS}")
message(STATUS "Using LIB_FUZZING_ENGINE: ${EFF_ENGINE}")