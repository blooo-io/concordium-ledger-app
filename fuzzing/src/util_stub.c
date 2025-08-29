// Fuzzing stub implementations for utility functions
// This provides mock implementations of functions from src/common/util.c that are needed
// by cborStrParsing.c but don't exist in the fuzzing environment

#define FUZZING_BUILD 1
#include "globals.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef FUZZING_BUILD

// Mock implementations of any utility functions that cborStrParsing.c depends on
// We'll add these as compilation reveals what's needed

// If additional utility functions are needed, add them here as compilation errors occur

#endif  // FUZZING_BUILD
