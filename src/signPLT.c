#include "globals.h"
#include "read.h"
#include "io.h"  // io_send_sw
#include "cbor.h"
#include "ledger_assert.h"
#include "format.h"  // format_i64, format_hex
#include "cborStrParsing.h"
#include "cborinternal_p.h"

static signPLTContext_t *ctx = &global.withDataBlob.signPLTContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x01

static void indent(int nestingLevel) {
    while (nestingLevel--) PRINTF("  ");
}

bool cbor_read_string_or_byte_string(CborValue *it,
                                     char *output_ptr,
                                     size_t *output_size,
                                     bool isString) {
    if (isString) {
        LEDGER_ASSERT(cbor_value_is_text_string(it), "expected string did not get it");
    } else {
        LEDGER_ASSERT(cbor_value_is_byte_string(it), "expected byte string did not get it");
    }

    const char *string_ptr;
    CborError err = _cbor_value_get_string_chunk(it, (const void **)&string_ptr, output_size, NULL);
    if (err) {
        return true;
    }

    // Copy the string data to the output buffer
    if (*output_size > 0 && output_ptr != NULL) {
        memcpy(output_ptr, string_ptr, *output_size);
    }

    return false;
}

void add_char_array_to_buffer(buffer_t *dst, char *src, size_t src_size) {
    if (dst->size - dst->offset < src_size) {
        PRINTF(
            "src_size: 0x%08X, "
            "dst->size-offset: "
            "0x%08X\n",
            src_size,
            dst->size - dst->offset);
        PRINTF("The destination buffer is too small\n");
        THROW(ERROR_PLT_BUFFER_ERROR);
    }
    memcpy((void *)(dst->ptr + dst->offset), src, src_size);
    dst->offset += src_size;
}

CborError decode_cbor_recursive(CborValue *it, int nestingLevel, buffer_t *out_buf) {
    const char *temp;
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);

        indent(nestingLevel);
        switch (type) {
            case CborArrayType:
            case CborMapType: {
                // recursive type
                CborValue recursed;
                LEDGER_ASSERT(cbor_value_is_container(it), "Should be a container but isn't");
                if (type == CborArrayType) {
                    temp = "[";
                } else {
                    temp = "{";
                }
                PRINTF("%s", temp);
                add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp));

                err = cbor_value_enter_container(it, &recursed);
                if (err) return err;  // parse error
                err = decode_cbor_recursive(&recursed, nestingLevel + 1, out_buf);
                if (err) return err;  // parse error
                err = cbor_value_leave_container(it, &recursed);
                if (err) return err;  // parse error
                indent(nestingLevel);
                if (type == CborArrayType) {
                    temp = "],";
                } else {
                    temp = "},";
                }
                PRINTF("%s", temp);
                add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp));
                continue;
            }
            case CborIntegerType: {
                char temp2[25];  // 25 to handle max uint64
                char temp3[30];  // 30 to handle the "Int:" prefix and max uint64
                uint64_t raw_val = 0;

                // Get the raw integer value first
                if (cbor_value_get_raw_integer(it, &raw_val) != CborNoError) {
                    PRINTF("cbor_value_get_raw_integer error\n");
                }

                if (cbor_value_is_negative_integer(it)) {
                    // Handle negative integers
                    int64_t signed_val = -(int64_t)(raw_val + 1);
                    format_i64(temp2, sizeof(temp2), signed_val);
                } else {
                    // Handle positive integers
                    format_u64(temp2, sizeof(temp2), raw_val);
                }

                snprintf(temp3, sizeof(temp3), "Int:%s,", temp2);
                add_char_array_to_buffer(out_buf, temp3, strlen(temp3));
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
                    THROW(ERROR_PLT_CBOR_ERROR);
                }
                add_char_array_to_buffer(out_buf, (char *)"0x", 2);
                add_char_array_to_buffer(out_buf, string_value, strlen(string_value));
                add_char_array_to_buffer(out_buf, (char *)",", 1);
                PRINTF("ByteString(%d): 0x%s\n", buf_len, string_value);
                break;
            }

            case CborTextStringType: {
                uint8_t buf[250];
                size_t buf_len;
                err = cbor_read_string_or_byte_string(it, (char *)buf, &buf_len, true);
                if (err) return err;
                // null terminate the string
                buf[buf_len] = '\0';
                char temp2[256];
                snprintf(temp2, sizeof(temp2), "\"%s\",", buf);
                PRINTF("%s", temp2);
                add_char_array_to_buffer(out_buf, temp2, strlen(temp2));
                break;
            }

            case CborTagType: {
                CborTag tag;
                char temp2[16];
                cbor_value_get_tag(it, &tag);  // can't fail
                format_u64(temp2, sizeof(temp2), tag);
                char tag_str[32];
                snprintf(tag_str, sizeof(tag_str), "Tag(%s):", temp2);
                PRINTF("%s", tag_str);
                add_char_array_to_buffer(out_buf, tag_str, strlen(tag_str));

                break;
            }

            case CborSimpleType: {
                uint8_t temp_type;
                cbor_value_get_simple_type(it, &temp_type);  // can't fail
                PRINTF("simple(%d)\n", temp_type);
                break;
            }

            case CborNullType:
                temp = "null,";
                PRINTF("null");
                add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp));
                break;

            case CborUndefinedType:
                temp = "undefined,";
                PRINTF("undefined");
                add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp));
                break;

            case CborBooleanType: {
                bool val;
                cbor_value_get_boolean(it, &val);  // can't fail
                temp = val ? "true," : "false,";
                PRINTF(temp);
                add_char_array_to_buffer(out_buf, (char *)temp, strlen(temp));
                break;
            }

            case CborDoubleType: {
                double val;
                char temp2[32];
                cbor_value_get_double(it, &val);
                snprintf(temp2, sizeof(temp2), "Double:0x%08x,", (uint32_t)val);
                PRINTF("Double: 0x%08x\n", (uint32_t)val);
                add_char_array_to_buffer(out_buf, temp2, strlen(temp2));
                break;
            }

            case CborHalfFloatType: {
                uint16_t val;
                char temp2[16];
                cbor_value_get_half_float(it, &val);
                snprintf(temp2, sizeof(temp2), "__f16(%04x),", val);
                PRINTF("__f16(%04x)\n", val);
                add_char_array_to_buffer(out_buf, temp2, strlen(temp2));
                break;
            }

            case CborInvalidType:
                LEDGER_ASSERT(false, "Can't happen");  // can't happen
                break;
        }

        err = cbor_value_advance_fixed(it);
        if (err) return err;
    }
    return CborNoError;
}

bool parsePltCbor(uint8_t *cbor, size_t cborLength) {
    CborParser parser;
    CborValue it;
    CborError err;

    // Initialize parser
    err = cbor_parser_init(cbor, cborLength, 0, &parser, &it);
    if (err) {
        return false;
    }

    char temp[MAX_PLT_DIPLAY_STR] = {0};
    buffer_t out_buf = {.ptr = (const uint8_t *)temp, .size = MAX_PLT_DIPLAY_STR, .offset = 0};
    tag_list_t tag_list;  // initiate an empty tag_list_t
    err = decode_cbor_recursive(&it, 0, &out_buf);
    if (err) {
        PRINTF("Error while decoding cbor\n");
        THROW(ERROR_PLT_CBOR_ERROR);
    }

    if (!parse_tags_in_buffer(&out_buf, &tag_list)) {
        PRINTF("Error while parsing cbor tags\n");
        THROW(ERROR_PLT_CBOR_ERROR);
    }
    if (sizeof(ctx->pltOperationDisplay) < out_buf.size + 1) {
        PRINTF("display str is too small for value %d < %d\n",
               sizeof(ctx->pltOperationDisplay),
               out_buf.size);
        THROW(ERROR_PLT_BUFFER_ERROR);
    }
    memcpy(ctx->pltOperationDisplay, out_buf.ptr, out_buf.size);
    ctx->pltOperationDisplay[out_buf.size] = '\0';

    return true;
}

// Helper function to extract value between quotes or after colon
static const char* findSubstring(const char* haystack, const char* needle) {
    const char* pos = haystack;
    while (*pos) {
        const char* h = pos;
        const char* n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (*n == '\0') return pos;
        pos++;
    }
    return NULL;
}

static bool extractFieldValue(const char* input,
                              const char* fieldName,
                              char* output,
                              size_t outputSize) {
    // Look for pattern: "fieldName":value
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", fieldName);

    const char* fieldPos = findSubstring(input, pattern);
    if (!fieldPos) return false;

    // Move to after the pattern
    const char* valueStart = fieldPos + strlen(pattern);

    // Skip whitespace
    while (*valueStart == ' ') valueStart++;

    const char* valueEnd;
    size_t copyLen;

    if (*valueStart == '"') {
        // String value - find closing quote
        valueStart++;  // Skip opening quote
        valueEnd = valueStart;
        while (*valueEnd && *valueEnd != '"') valueEnd++;
        copyLen = valueEnd - valueStart;
    } else if (*valueStart == '{') {
        // Object value - find matching closing brace
        valueEnd = valueStart + 1;
        int braceCount = 1;
        while (*valueEnd && braceCount > 0) {
            if (*valueEnd == '{')
                braceCount++;
            else if (*valueEnd == '}')
                braceCount--;
            valueEnd++;
        }
        copyLen = valueEnd - valueStart;
    } else {
        // Numeric or other value - find next comma, brace, or end
        valueEnd = valueStart;
        while (*valueEnd && *valueEnd != ',' && *valueEnd != '}' && *valueEnd != ']') {
            valueEnd++;
        }
        copyLen = valueEnd - valueStart;
    }

    if (copyLen >= outputSize) copyLen = outputSize - 1;
    memcpy(output, valueStart, copyLen);
    output[copyLen] = '\0';

    return true;
}

static bool extractRecipientAddress(const char* recipientObject,
                                    char* address,
                                    size_t addressSize) {
    // Look for "address: " pattern in the recipient object
    const char* addressPos = findSubstring(recipientObject, "address: ");
    if (!addressPos) return false;

    const char* addressStart = addressPos + strlen("address: ");
    const char* addressEnd = addressStart;

    // Find end of address (until } or end)
    while (*addressEnd && *addressEnd != '}' && *addressEnd != ',') {
        addressEnd++;
    }

    size_t copyLen = addressEnd - addressStart;
    if (copyLen >= addressSize) copyLen = addressSize - 1;

    memcpy(address, addressStart, copyLen);
    address[copyLen] = '\0';

    return true;
}

static bool parseSingleOperation(const char* operationStr, singlePLTOperation_t* operation) {
    if (!operationStr || !operation) return false;

    // Find the operation type (first quoted string after opening brace)
    const char* firstQuote = findSubstring(operationStr, "\"");
    if (!firstQuote) return false;

    const char* typeStart = firstQuote + 1;
    const char* typeEnd = typeStart;
    while (*typeEnd && *typeEnd != '"') typeEnd++;

    size_t typeLen = typeEnd - typeStart;
    if (typeLen >= MAX_PLT_OPERATION_TYPE) typeLen = MAX_PLT_OPERATION_TYPE - 1;
    memcpy(operation->operationType, typeStart, typeLen);
    operation->operationType[typeLen] = '\0';

    // Extract amount
    if (!extractFieldValue(operationStr, "amount", operation->amount, MAX_PLT_AMOUNT_STR)) {
        strncpy(operation->amount, "N/A", MAX_PLT_AMOUNT_STR - 1);
    }

    // Extract recipient object first
    char recipientObject[256];
    if (extractFieldValue(operationStr, "recipient", recipientObject, sizeof(recipientObject))) {
        // Extract address from the recipient object
        if (!extractRecipientAddress(recipientObject,
                                     operation->recipient,
                                     MAX_PLT_RECIPIENT_STR)) {
            strncpy(operation->recipient, "N/A", MAX_PLT_RECIPIENT_STR - 1);
        }
    } else {
        strncpy(operation->recipient, "N/A", MAX_PLT_RECIPIENT_STR - 1);
    }

    return true;
}

bool parsePLTOperationForUI(const char* operationDisplay, parsedPLTOperation_t *parsed) {
    if (!operationDisplay || !parsed) return false;

    // Initialize parsed structure
    memset(parsed, 0, sizeof(parsedPLTOperation_t));
    parsed->isParsed = false;

    PRINTF("Parsing PLT operation: %s\n", operationDisplay);

    // Count operations by counting opening braces after the initial '['
    const char* pos = operationDisplay;
    uint8_t operationCount = 0;

    // Skip initial '['
    while (*pos && *pos != '[') pos++;
    if (*pos == '[') pos++;

    // Find each operation (starts with '{')
    while (*pos && operationCount < MAX_PLT_OPERATIONS) {
        // Skip whitespace and commas
        while (*pos && (*pos == ' ' || *pos == ',' || *pos == '\n')) pos++;

        if (*pos == '{') {
            // Found start of an operation, find the end
            const char* opStart = pos;
            int braceCount = 1;
            pos++;  // Skip opening brace

            while (*pos && braceCount > 0) {
                if (*pos == '{')
                    braceCount++;
                else if (*pos == '}')
                    braceCount--;
                pos++;
            }

            if (braceCount == 0) {
                // Extract this operation string
                size_t opLen = pos - opStart;
                char opStr[512];
                if (opLen < sizeof(opStr)) {
                    memcpy(opStr, opStart, opLen);
                    opStr[opLen] = '\0';

                    // Parse this single operation
                    if (parseSingleOperation(opStr, &parsed->operations[operationCount])) {
                        PRINTF("Parsed operation %d: Type=%s, Amount=%s, Recipient=%s\n",
                               operationCount + 1,
                               parsed->operations[operationCount].operationType,
                               parsed->operations[operationCount].amount,
                               parsed->operations[operationCount].recipient);
                        operationCount++;
                    }
                }
            }
        } else if (*pos == ']') {
            // End of array
            break;
        } else {
            pos++;
        }
    }

    parsed->operationCount = operationCount;

    if (operationCount == 0) {
        return false;
    }

    parsed->isParsed = true;

    PRINTF("Successfully parsed %d operations\n", operationCount);

    return true;
}

/**
 * @brief Handle Protected Ledger Transaction (PLT) signing operations
 *
 * This function processes PLT transactions which can be sent in multiple chunks due to 
 * APDU size limitations. The transaction contains a token ID and CBOR-encoded operation data
 * that gets parsed and displayed to the user for approval.
 *
 * Protocol flow:
 * 1. Initial chunk (chunk=0): Contains transaction header, token ID, and CBOR length
 * 2. Subsequent chunks: Contains CBOR operation data until complete
 * 3. Final processing: Parse CBOR, generate UI display, and show to user
 *
 * @param cdata Pointer to command data buffer
 * @param lc    Length of command data (APDU data length)
 * @param chunk Chunk number (0 for initial chunk, incremented for subsequent chunks)
 * @param more  Flag indicating if more chunks are expected (true) or this is the last chunk (false)
 *
 * Initial chunk (chunk=0) data format:
 * - path_length (1 byte)
 * - derivation_path (path_length * 4 bytes)
 * - account_transaction_header (60 bytes) 
 * - transaction_kind (1 byte) - must be PLT_TRANSACTION (27)
 * - token_id_length (1 byte) - length of token ID (1-255)
 * - token_id (token_id_length bytes) - token identifier
 * - cbor_length (4 bytes, big-endian) - total length of CBOR data
 * - cbor_data (remaining bytes) - start of CBOR operation data
 *
 * Subsequent chunks data format:
 * - cbor_data (lc bytes) - continuation of CBOR operation data
 *
 * Constraints:
 * - Maximum token ID length: 255 bytes (MAX_TOKEN_ID_LENGTH)
 * - Maximum CBOR data length: 900 bytes (MAX_CBOR_LENGTH)
 * - CBOR data must be valid according to CBOR specification
 * - Total display string length must not exceed 2000 bytes (MAX_PLT_DIPLAY_STR)
 *
 * Error conditions:
 * - ERROR_PLT_DATA_ERROR: Insufficient data, incomplete CBOR, or validation failures
 * - ERROR_PLT_BUFFER_ERROR: Buffer overflow, CBOR too large, or chunk size exceeded
 * - ERROR_PLT_CBOR_ERROR: CBOR parsing failures, tag parsing errors, or format issues
 *
 * @throws ERROR_PLT_DATA_ERROR If data validation fails or insufficient data provided
 * @throws ERROR_PLT_BUFFER_ERROR If buffer overflow occurs or data exceeds limits
 * @throws ERROR_PLT_CBOR_ERROR If CBOR parsing or processing fails
 *
 * @note This function updates global context (signPLTContext_t) and transaction state
 * @note User approval is required via UI display before transaction completion
 * @note All sensitive data is cleared from memory on error conditions
 */
void handleSignPltTransaction(uint8_t *cdata, uint8_t lc, uint8_t chunk, bool more
                              //   bool isInitialCall
) {
    uint8_t remainingDataLength = lc;

    if (chunk == 0) {
        explicit_bzero(ctx, sizeof(signPLTContext_t));
        ctx->currentCborLength = 0;
        ctx->totalCborLength = 0;
        // Parse and hash the header and kind
        uint8_t offset = handleHeaderAndKind(cdata, remainingDataLength, PLT_TRANSACTION);
        cdata += offset;
        remainingDataLength -= offset;

        // Hash the rest of the chunk
        updateHash((cx_hash_t *)&tx_state->hash, cdata, remainingDataLength);

        // Parse token Id info
        ctx->tokenIdLength = cdata[0];
        cdata++;
        remainingDataLength--;

        if (remainingDataLength < ctx->tokenIdLength) {
            PRINTF("Not enough data left\n");
            THROW(ERROR_PLT_DATA_ERROR);
        }
        memcpy(ctx->tokenId, cdata, ctx->tokenIdLength);
        cdata += ctx->tokenIdLength;
        remainingDataLength -= ctx->tokenIdLength;

        // Parse OperationLength
        if (remainingDataLength < 4) {
            PRINTF("Not enough data left\n");
            THROW(ERROR_PLT_DATA_ERROR);
        }
        ctx->totalCborLength = U4BE(cdata, 0);
        cdata += 4;
        remainingDataLength -= 4;

        // Check if the OperationLength is larger than the buffer
        if (ctx->totalCborLength > sizeof(ctx->cbor)) {
            PRINTF("Cbor buffer is too small to contain the complete cbor, %d > %d\n",
                   ctx->totalCborLength,
                   sizeof(ctx->cbor));
            THROW(ERROR_PLT_BUFFER_ERROR);
        }
    }

    // Add the cbor to the context
    if (remainingDataLength > sizeof(ctx->cbor) - ctx->currentCborLength) {
        PRINTF("Cbor received is larger than the buffer, %d > %d\n",
               remainingDataLength,
               sizeof(ctx->cbor) - ctx->currentCborLength);
        THROW(ERROR_PLT_BUFFER_ERROR);
    }
    memcpy(ctx->cbor + ctx->currentCborLength, cdata, remainingDataLength);
    ctx->currentCborLength += remainingDataLength;

    if (more) {
        io_send_sw(SUCCESS);
        return;
    } else {
        if (ctx->currentCborLength == ctx->totalCborLength) {
            // Parse the cbor
            if (!parsePltCbor(ctx->cbor, ctx->totalCborLength)) {
                PRINTF("Cbor parsing failed\n");
                THROW(ERROR_PLT_CBOR_ERROR);
            }

            // Parse the operation for improved UI display
            parsePLTOperationForUI(ctx->pltOperationDisplay, &ctx->parsedOperation);

            uiPltOperationDisplay();
        } else {
            PRINTF("Cbor received is not complete, %d < %d\n",
                   ctx->currentCborLength,
                   ctx->totalCborLength);
            THROW(ERROR_PLT_DATA_ERROR);
        }
    }
}
