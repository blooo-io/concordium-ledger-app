#pragma once

// Fuzzing-specific minimal globals.h
// This replaces the full globals.h for fuzzing builds to avoid Ledger SDK dependencies

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef FUZZING_BUILD

// Constants from the real globals.h that we need
#define MAX_TAG_CONTENT_SIZE        256
#define MAX_TAGS                    24
#define MAX_TAG_PARSED_CONTENT_SIZE 300
#define MAX_TOKEN_ID_LENGTH         255
#define MAX_CBOR_LENGTH             900
#define MAX_PLT_DIPLAY_STR          2000

// Error codes
#define ERROR_INVALID_PARAM       0x6B03
#define ERROR_INVALID_STATE       0x6B01
#define ERROR_BUFFER_OVERFLOW     0x6B06
#define ERROR_INVALID_TRANSACTION 0x6B04
#define ERROR_INVALID_PATH        0x6B05
#define SUCCESS                   0x9000

// Transaction types
#define PLT_TRANSACTION 27

// Buffer structure
typedef struct {
    const uint8_t *ptr;
    size_t size;
    size_t offset;
} buffer_t;

// Tag parsing structures (from cborStrParsing.h)
typedef struct {
    uint64_t tag_number;
    char content[MAX_TAG_CONTENT_SIZE];
    size_t content_length;
    bool is_valid;
    char parsedContent[MAX_TAG_PARSED_CONTENT_SIZE];
} tag_info_t;

typedef struct {
    tag_info_t tags[MAX_TAGS];
    size_t count;
} tag_list_t;

// Mock implementations for fuzzing
#define PRINTF printf

// Utility macro for reading big-endian 32-bit integers
#define U4BE(buf, off)                                                                \
    ((uint32_t)(((buf)[off] << 24) | ((buf)[off + 1] << 16) | ((buf)[off + 2] << 8) | \
                ((buf)[off + 3])))

// Mock explicit_bzero for secure memory clearing
static inline void explicit_bzero(void *ptr, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

#endif  // FUZZING_BUILD
```

```c : fuzzing / include /
        ledger_assert.h
#pragma once

// Fuzzing-specific ledger_assert.h
// Provides mock implementations of Ledger assertions for fuzzing

#ifdef FUZZING_BUILD

#include <stdio.h>
#include "cbor.h"

// Mock assertion macros for different return types
#define LEDGER_ASSERT_BOOL(condition, msg)                  \
    do {                                                    \
        if (!(condition)) {                                 \
            printf("LEDGER_ASSERT_BOOL FAILED: %s\n", msg); \
            return false;                                   \
        }                                                   \
    } while (0)

#define LEDGER_ASSERT_VOID(condition, msg)                  \
    do {                                                    \
        if (!(condition)) {                                 \
            printf("LEDGER_ASSERT_VOID FAILED: %s\n", msg); \
            return;                                         \
        }                                                   \
    } while (0)

#define LEDGER_ASSERT_CBOR_ERROR(condition, msg)                  \
    do {                                                          \
        if (!(condition)) {                                       \
            printf("LEDGER_ASSERT_CBOR_ERROR FAILED: %s\n", msg); \
            return CborUnknownError;                              \
        }                                                         \
    } while (0)

#define LEDGER_ASSERT(condition, msg) LEDGER_ASSERT_VOID(condition, msg)

#define THROW(exception)                                     \
    do {                                                     \
        printf("THROW: 0x%x (%s)\n", exception, #exception); \
        return;                                              \
    } while (0)

#else

// Include the real ledger_assert.h when not fuzzing
#include "../src/ledger_assert.h"

#endif  // FUZZING_BUILD
```

```c : fuzzing /
        include /
        util.h
#pragma once

// Fuzzing-specific util.h
// Provides minimal utility functions needed for CBOR parsing

#ifdef FUZZING_BUILD

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Mock utility functions that might be referenced in cborStrParsing.c
// These will be implemented in util_stub.c as needed

#else

// Include the real util.h when not fuzzing
#include "../src/common/util.h"

#endif  // FUZZING_BUILD
```

```c : fuzzing /
        src /
        util_stub.c
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
```

```c : fuzzing /
        src /
        standalone_plt_fuzzer.c
// FUZZING 102: Standalone PLT Transaction Fuzzer
// This fuzzes the handleSignPltTransaction function with REAL CBOR implementation

// ========== STEP 1: STANDARD INCLUDES ==========
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// ========== STEP 2: FUZZING-SPECIFIC HEADERS ==========
#define FUZZING_BUILD 1
#include "globals.h"
#include "ledger_assert.h"

// ========== STEP 3: REAL CBOR IMPLEMENTATION ==========
#include "cbor.h"
#include "cborStrParsing.h"

        // ========== STEP 4: TYPE DEFINITIONS ==========

        // Transaction context structure (from signPLT.h)
        typedef struct {
    uint8_t transactionType;
    uint8_t tokenId[MAX_TOKEN_ID_LENGTH];
    uint8_t tokenIdLength;
    uint8_t cbor[MAX_CBOR_LENGTH];
    size_t totalCborLength;
    size_t currentCborLength;
    char pltOperationDisplay[MAX_PLT_DIPLAY_STR];
} signPLTContext_t;

// Transaction state structure (simplified from globals.h)
typedef struct {
    uint8_t hash_state[64];  // Mock hash context
    uint8_t transactionHash[32];
    int currentInstruction;
} tx_state_t;

// ========== STEP 5: MOCK IMPLEMENTATIONS ==========

// Global mock contexts
static signPLTContext_t mock_plt_context;
static tx_state_t mock_tx_state;

// Mock hash function - just track calls
void updateHash(void *hashContext, const unsigned char *in, unsigned int len) {
    printf("MOCK updateHash: hashing %u bytes\n", len);
    // In real implementation this would update a cryptographic hash
    // For fuzzing we just track that it was called
}

// Mock header parsing function
int handleHeaderAndKind(uint8_t *cdata, uint8_t dataLength, uint8_t kind) {
    printf("MOCK handleHeaderAndKind: kind=%u, dataLength=%u\n", kind, dataLength);

    // Minimal validation
    if (dataLength < 8) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    // Mock parsing - just consume some bytes for header simulation
    // Real implementation would parse derivation path and validate header
    return 8;  // Return number of bytes consumed
}

// Mock IO function
void io_send_sw(uint16_t sw) {
    printf("MOCK io_send_sw: status=0x%04x\n", sw);
}

// Mock display function - just print what would be shown
void uiPltOperationDisplay(void) {
    printf("MOCK uiPltOperationDisplay: would display: %.100s...\n",
           mock_plt_context.pltOperationDisplay);
}

// ========== STEP 6: FORMAT FUNCTIONS ==========

int format_i64(char *dst, size_t dst_size, int64_t value) {
    int ret = snprintf(dst, dst_size, "%lld", (long long)value);
    return (ret > 0 && ret < (int)dst_size) ? ret : -1;
}

int format_u64(char *dst, size_t dst_size, uint64_t value) {
    int ret = snprintf(dst, dst_size, "%llu", (unsigned long long)value);
    return (ret > 0 && ret < (int)dst_size) ? ret : -1;
}

int format_hex(const uint8_t *src, size_t src_len, char *dst, size_t dst_size) {
    if (dst_size < src_len * 2 + 1) return -1;

    for (size_t i = 0; i < src_len; i++) {
        snprintf(dst + i * 2, 3, "%02x", src[i]);
    }
    dst[src_len * 2] = '\0';
    return 0;
}

// ========== STEP 7: REAL CBOR STRING READING FUNCTION ==========

bool cbor_read_string_or_byte_string(CborValue *it,
                                     char *output_ptr,
                                     size_t *output_size,
                                     bool isString) {
    if (isString) {
        LEDGER_ASSERT_BOOL(cbor_value_is_text_string(it), "expected string did not get it");
    } else {
        LEDGER_ASSERT_BOOL(cbor_value_is_byte_string(it), "expected byte string did not get it");
    }

    const char *string_ptr;
    CborError err = get_string_chunk(it, (const void **)&string_ptr, output_size);
    if (err) {
        return err != CborNoError;
    }

    PRINTF(
        "km-logs - [standalone_plt_fuzzer.c] (cbor_read_string_or_byte_string) - string_ptr: %s\n",
        string_ptr);
    PRINTF("km-logs - [standalone_plt_fuzzer.c] (cbor_read_string_or_byte_string) - size: %d\n",
           (int)*output_size);

    // Copy the string data to the output buffer
    if (*output_size > 0 && output_ptr != NULL) {
        memcpy(output_ptr, string_ptr, *output_size);
    }

    PRINTF(
        "km-logs - [standalone_plt_fuzzer.c] (cbor_read_string_or_byte_string) - output_ptr: 0x");
    for (size_t i = 0; i < *output_size; i++) {
        PRINTF("%02x", (uint8_t)output_ptr[i]);
    }
    PRINTF("\n");
    PRINTF(
        "km-logs - [standalone_plt_fuzzer.c] (cbor_read_string_or_byte_string) - output_ptr.str: "
        "%s\n",
        output_ptr);

    return false;
}

// ========== STEP 8: ACTUAL TRANSACTION PARSING FUNCTIONS ==========

static signPLTContext_t *ctx = &mock_plt_context;
static tx_state_t *tx_state = &mock_tx_state;

#define P1_INITIAL 0x01

static void indent(int nestingLevel) {
    while (nestingLevel--) PRINTF("  ");
}

bool add_char_array_to_buffer(buffer_t *dst, char *src, size_t src_size) {
    PRINTF("\nkm-logs - [standalone_plt_fuzzer.c] (add_char_array_to_buffer) - trying to add: %s\n",
           src);
    if (dst->size - dst->offset < src_size) {
        PRINTF(
            "km-logs - [standalone_plt_fuzzer.c] (add_char_array_to_buffer) - src_size: 0x%08X, "
            "dst->size-offset: 0x%08X\n",
            (uint32_t)src_size,
            (uint32_t)(dst->size - dst->offset));
        PRINTF("The destination buffer is too small\n");
        return false;
    }
    memcpy((void *)(dst->ptr + dst->offset), src, src_size);
    dst->offset += src_size;
    return true;
}

CborError decodeCborRecursive(CborValue *it, int nestingLevel, buffer_t *out_buf) {
    const char *temp;
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);

        indent(nestingLevel);
        switch (type) {
            case CborArrayType:
            case CborMapType: {
                CborValue recursed;
                LEDGER_ASSERT_CBOR_ERROR(cbor_value_is_container(it),
                                         "Should be a container but isn't");

                temp = (type == CborArrayType) ? "[" : "{";
                PRINTF("%s", temp);
                if (!add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp))) {
                    return CborErrorIO;
                }

                err = cbor_value_enter_container(it, &recursed);
                if (err) return err;
                err = decodeCborRecursive(&recursed, nestingLevel + 1, out_buf);
                if (err) return err;
                err = cbor_value_leave_container(it, &recursed);
                if (err) return err;

                indent(nestingLevel);
                temp = (type == CborArrayType) ? "]," : "},";
                PRINTF("%s", temp);
                if (!add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp))) {
                    return CborErrorIO;
                }
                continue;
            }

            case CborIntegerType: {
                char temp2[25], temp3[30];
                uint64_t raw_val = 0;

                if (cbor_value_get_raw_integer(it, &raw_val) != CborNoError) {
                    PRINTF("cbor_value_get_raw_integer error\n");
                }

                if (cbor_value_is_negative_integer(it)) {
                    int64_t signed_val = -(int64_t)(raw_val + 1);
                    format_i64(temp2, sizeof(temp2), signed_val);
                } else {
                    format_u64(temp2, sizeof(temp2), raw_val);
                }

                snprintf(temp3, sizeof(temp3), "Int:%s,", temp2);
                if (!add_char_array_to_buffer(out_buf, temp3, strlen(temp3))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborByteStringType: {
                uint8_t buf[250];
                size_t buf_len;
                err = cbor_read_string_or_byte_string(it, (char *)buf, &buf_len, false);
                if (err) return err;

                char string_value[100] = {0};
                if (format_hex(buf, buf_len, string_value, sizeof(string_value)) == -1) {
                    PRINTF("format_hex error\n");
                    return CborUnknownError;
                }

                if (!add_char_array_to_buffer(out_buf, (char *)"0x", 2) ||
                    !add_char_array_to_buffer(out_buf, string_value, strlen(string_value)) ||
                    !add_char_array_to_buffer(out_buf, (char *)",", 1)) {
                    return CborErrorIO;
                }
                PRINTF("ByteString(%d): 0x%s\n", (int)buf_len, string_value);
                break;
            }

            case CborTextStringType: {
                uint8_t buf[250];
                size_t buf_len;
                err = cbor_read_string_or_byte_string(it, (char *)buf, &buf_len, true);
                if (err) return err;

                buf[buf_len] = '\0';
                char temp2[256];
                snprintf(temp2, sizeof(temp2), "\"%s\",", buf);
                PRINTF("%s", temp2);
                if (!add_char_array_to_buffer(out_buf, temp2, strlen(temp2))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborTagType: {
                CborTag tag;
                char temp2[16], tag_str[32];
                cbor_value_get_tag(it, &tag);
                format_u64(temp2, sizeof(temp2), tag);
                snprintf(tag_str, sizeof(tag_str), "Tag(%s):", temp2);
                PRINTF("%s", tag_str);
                if (!add_char_array_to_buffer(out_buf, tag_str, strlen(tag_str))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborSimpleType: {
                uint8_t temp_type;
                cbor_value_get_simple_type(it, &temp_type);
                PRINTF("simple(%d)\n", temp_type);
                break;
            }

            case CborNullType:
                temp = "null,";
                PRINTF("null");
                if (!add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp))) {
                    return CborErrorIO;
                }
                break;

            case CborUndefinedType:
                temp = "undefined,";
                PRINTF("undefined");
                if (!add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp))) {
                    return CborErrorIO;
                }
                break;

            case CborBooleanType: {
                bool val;
                cbor_value_get_boolean(it, &val);
                temp = val ? "true," : "false,";
                PRINTF("%s", temp);
                if (!add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborDoubleType: {
                double val;
                char temp2[32];
                cbor_value_get_double(it, &val);
                snprintf(temp2, sizeof(temp2), "Double:0x%08x,", (uint32_t)val);
                PRINTF("Double: 0x%08x\n", (uint32_t)val);
                if (!add_char_array_to_buffer(out_buf, temp2, strlen(temp2))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborFloatType: {
                float val;
                char temp2[32];
                cbor_value_get_float(it, &val);
                snprintf(temp2, sizeof(temp2), "Float:0x%08x,", (uint32_t)val);
                PRINTF("Float: 0x%08x\n", (uint32_t)val);
                if (!add_char_array_to_buffer(out_buf, temp2, strlen(temp2))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborHalfFloatType: {
                uint16_t val;
                char temp2[16];
                cbor_value_get_half_float(it, &val);
                snprintf(temp2, sizeof(temp2), "__f16(%04x),", val);
                PRINTF("__f16(%04x)\n", val);
                if (!add_char_array_to_buffer(out_buf, temp2, strlen(temp2))) {
                    return CborErrorIO;
                }
                break;
            }

            case CborInvalidType:
                LEDGER_ASSERT_CBOR_ERROR(false, "Can't happen");
                break;
        }

        err = cbor_value_advance_fixed(it);
        if (err) return err;
    }
    return CborNoError;
}

bool parsePltCbor(uint8_t *cbor, size_t cborLength) {
    PRINTF("km-logs - [standalone_plt_fuzzer.c] (parsePltCbor) - cbor: ");
    for (size_t i = 0; i < cborLength; i++) {
        PRINTF("%02x", cbor[i]);
    }
    PRINTF("\n");
    PRINTF("km-logs - [standalone_plt_fuzzer.c] Starting CBOR parsing, %d bytes\n",
           (int)cborLength);

    CborParser parser;
    CborValue it;
    CborError err = cbor_parser_init(cbor, cborLength, 0, &parser, &it);
    if (err) {
        PRINTF("km-logs - [standalone_plt_fuzzer.c] CBOR parser init failed\n");
        return false;
    }

    char temp[MAX_PLT_DIPLAY_STR] = {0};
    buffer_t out_buf = {.ptr = (const uint8_t *)temp, .size = MAX_PLT_DIPLAY_STR, .offset = 0};
    tag_list_t tag_list;

    err = decodeCborRecursive(&it, 0, &out_buf);
    if (err) {
        PRINTF("Error while decoding cbor\n");
        return false;
    }

    // Use the real tag parsing function
    if (!parse_tags_in_buffer(&out_buf, &tag_list)) {
        PRINTF("Error while parsing cbor tags\n");
        return false;
    }

    if (sizeof(ctx->pltOperationDisplay) < out_buf.size) {
        PRINTF("display str is too small for value %zu < %zu\n",
               sizeof(ctx->pltOperationDisplay),
               out_buf.size);
        return false;
    }

    memcpy(ctx->pltOperationDisplay, out_buf.ptr, out_buf.size);
    ctx->pltOperationDisplay[out_buf.size - 1] = '\0';

    return true;
}

// ========== STEP 9: TARGET FUNCTION ==========

void handleSignPltTransaction(uint8_t *cdata, uint8_t lc, uint8_t chunk, bool more) {
    uint8_t remainingDataLength = lc;

    PRINTF(
        "km-logs [standalone_plt_fuzzer.c] (handleSignPltTransaction) - Starting handling of plt "
        "transaction\n");

    if (chunk == 0) {
        explicit_bzero(ctx, sizeof(signPLTContext_t));
        ctx->currentCborLength = 0;
        ctx->totalCborLength = 0;
        PRINTF(
            "km-logs [standalone_plt_fuzzer.c] (handleSignPltTransaction) Initial chunk about to "
            "process\n");

        uint8_t offset = handleHeaderAndKind(cdata, remainingDataLength, PLT_TRANSACTION);
        cdata += offset;
        remainingDataLength -= offset;

        updateHash((void *)&tx_state->hash_state, cdata, remainingDataLength);

        ctx->tokenIdLength = cdata[0];
        cdata++;
        remainingDataLength--;

        if (remainingDataLength < ctx->tokenIdLength) {
            PRINTF("Not enough data left\n");
            return;
        }

        memcpy(ctx->tokenId, cdata, ctx->tokenIdLength);
        cdata += ctx->tokenIdLength;
        remainingDataLength -= ctx->tokenIdLength;

        PRINTF("km-logs [standalone_plt_fuzzer.c] (handleSignPltTransaction) - TokenID ");
        for (int i = 0; i < ctx->tokenIdLength; i++) {
            PRINTF("%02x", ctx->tokenId[i]);
        }
        PRINTF("\n");

        if (remainingDataLength < 4) {
            PRINTF("Not enough data left\n");
            return;
        }

        ctx->totalCborLength = U4BE(cdata, 0);
        PRINTF("km-logs [standalone_plt_fuzzer.c] (handleSignPltTransaction) - cborLength %d\n",
               (int)ctx->totalCborLength);
        cdata += 4;
        remainingDataLength -= 4;

        if (ctx->totalCborLength > sizeof(ctx->cbor)) {
            PRINTF("Cbor buffer is too small to contain the complete cbor, %d > %zu\n",
                   (int)ctx->totalCborLength,
                   sizeof(ctx->cbor));
            return;
        }
    }

    if (remainingDataLength > sizeof(ctx->cbor) - ctx->currentCborLength) {
        PRINTF("Cbor received is larger than the buffer, %d > %zu\n",
               remainingDataLength,
               sizeof(ctx->cbor) - ctx->currentCborLength);
        return;
    }

    memcpy(ctx->cbor + ctx->currentCborLength, cdata, remainingDataLength);
    ctx->currentCborLength += remainingDataLength;

    if (more) {
        io_send_sw(SUCCESS);
        return;
    } else {
        if (ctx->currentCborLength == ctx->totalCborLength) {
            if (!parsePltCbor(ctx->cbor, ctx->totalCborLength)) {
                PRINTF("Cbor parsing failed\n");
                return;
            }
            uiPltOperationDisplay();
        } else {
            PRINTF("Cbor received is not complete, %zu < %zu\n",
                   ctx->currentCborLength,
                   ctx->totalCborLength);
        }
    }
}

// ========== STEP 10: FUZZER ==========

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    printf("\n=== PLT FUZZER ITERATION (size=%zu) ===\n", size);

    uint8_t chunk = data[0] % 2;
    bool more = (data[1] % 2) == 1;

    const uint8_t *command_data = data + 2;
    uint8_t lc = size - 2;

    printf("Fuzzing with chunk=%d, more=%s, lc=%d\n", chunk, more ? "true" : "false", lc);

    handleSignPltTransaction((uint8_t *)command_data, lc, chunk, more);

    printf("PLT Fuzzer completed: No crashes occurred\n");
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    printf("=== CONCORDIUM PLT TRANSACTION FUZZER ===\n");
    printf("Standalone fuzzer - using REAL CBOR implementation!\n");
    printf("Target: handleSignPltTransaction\n\n");

    explicit_bzero(&mock_plt_context, sizeof(mock_plt_context));
    explicit_bzero(&mock_tx_state, sizeof(mock_tx_state));

    return 0;
}
```
