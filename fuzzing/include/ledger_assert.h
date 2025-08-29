#pragma once

// Fuzzing-specific ledger_assert.h
// Provides mock implementations of Ledger assertions for fuzzing

#ifdef FUZZING_BUILD

#include <stdio.h>
#include "cbor.h"

// Mock assertion macros for different return types
#define LEDGER_ASSERT_BOOL(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("LEDGER_ASSERT_BOOL FAILED: %s\n", msg); \
            return false; \
        } \
    } while (0)

#define LEDGER_ASSERT_VOID(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("LEDGER_ASSERT_VOID FAILED: %s\n", msg); \
            return; \
        } \
    } while (0)

#define LEDGER_ASSERT_CBOR_ERROR(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("LEDGER_ASSERT_CBOR_ERROR FAILED: %s\n", msg); \
            return CborUnknownError; \
        } \
    } while (0)

#define LEDGER_ASSERT(condition, msg) LEDGER_ASSERT_VOID(condition, msg)

#define THROW(exception) \
    do { \
        printf("THROW: 0x%x (%s)\n", exception, #exception); \
        return; \
    } while (0)

#else

// Include the real ledger_assert.h when not fuzzing
#include "../src/ledger_assert.h"

#endif // FUZZING_BUILD
