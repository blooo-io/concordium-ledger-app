#include "globals.h"
#include "read.h"
#include "io.h"  // io_send_sw
#include "cbor.h"
#include "ledger_assert.h"
#include "format.h"  // format_i64, format_hex

static signPLTContext_t *ctx = &global.withDataBlob.signPLTContext;
static cborContext_t *cbor_context = &global.withDataBlob.cborContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x01

// CborError _cbor_value_dup_string_ledger(const CborValue *value,
//                                         void **buffer,
//                                         size_t *buflen,
//                                         CborValue *next) {
//     CborError err;
//     LEDGER_ASSERT(buffer, "Missing buffer");
//     LEDGER_ASSERT(buflen, "Missing buflen");
//     PRINTF("km-logs: [ cborparser_dup_string] (_cbor_value_dup_string) - buflen b4: %d\n",
//            (uint32_t)*buflen);  // Dereference buflen
//     size_t temp_buflen = 100;
//     err = _cbor_value_copy_string(value, NULL, &temp_buflen, NULL);  // Pass address
//     if (err) return err;
//     PRINTF("km-logs: [ cborparser_dup_string] (_cbor_value_dup_string) - buflen after: %d\n",
//            (uint32_t)temp_buflen);
//     if (temp_buflen > *buflen) {  // Dereference buflen
//         PRINTF("buflen is smaller than needed size\n");
//         return CborErrorOutOfMemory;
//     }
//     err = _cbor_value_copy_string(value, *buffer, buflen, next);  // buflen is already a pointer
//     if (err) {
//         free(*buffer);
//         return err;
//     }
//     return CborNoError;
// }

static void indent(int nestingLevel) {
    while (nestingLevel--) PRINTF("  ");
}

static void dumpbytes(const uint8_t *buf, size_t len) {
    while (len--) PRINTF("%02X ", *buf++);
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

    // PRINTF("km-logs - [signPLT.c] (cbor_read_string_or_byte_string) - size: %d\n",
    //        (uint32_t)*output_size);
    // PRINTF("km-logs - [signPLT.c] (cbor_read_string_or_byte_string) - output_ptr: 0x%.*H\n",
    //        *output_size,
    //        output_ptr);

    return false;
}

CborError dumprecursive(CborValue *it, int nestingLevel) {
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);

        indent(nestingLevel);
        switch (type) {
            case CborArrayType:
            case CborMapType: {
                // recursive type
                CborValue recursed;
                LEDGER_ASSERT(cbor_value_is_container(it), "Should be a container but isnt");
                PRINTF(type == CborArrayType ? "Array[\n" : "Map[\n");
                err = cbor_value_enter_container(it, &recursed);
                if (err) return err;  // parse error
                err = dumprecursive(&recursed, nestingLevel + 1);
                if (err) return err;  // parse error
                err = cbor_value_leave_container(it, &recursed);
                if (err) return err;  // parse error
                indent(nestingLevel);
                PRINTF("]\n");
                continue;
            }

            case CborIntegerType: {
                int64_t val;
                char temp[16];
                cbor_value_get_int64(it, &val);  // can't fail
                PRINTF("Int:");
                format_i64(temp, sizeof(temp), val);
                PRINTF("%s\n", temp);
                break;
            }

            case CborByteStringType: {
                uint8_t buf[250];
                size_t buf_len;
                // err = cbor_value_calculate_string_length(it, buf_len);
                // err = _cbor_value_copy_string(it, buf, sizeof(buf), NULL);
                err = cbor_read_string_or_byte_string(it, buf, &buf_len, false);
                if (err) return err;
                char string_value[100] = {0};
                if (format_hex(buf, buf_len, string_value, sizeof(string_value)) == -1) {
                    PRINTF("format_hex error");
                    THROW(0x0010);
                }

                PRINTF("ByteString(%d): 0x%s\n", buf_len, string_value);
                break;
            }

            case CborTextStringType: {
                uint8_t buf[250];
                size_t buf_len;
                // err = cbor_value_calculate_string_length(it, buf_len);
                // err = _cbor_value_copy_string(it, buf, sizeof(buf), NULL);
                err = cbor_read_string_or_byte_string(it, buf, &buf_len, true);
                if (err) return err;
                // char string_value[20];
                // if (!format_hex(buf, buf_len, string_value, sizeof(string_value))) {
                //     PRINTF("format_hex error");
                //     THROW(0x0010);
                // }
                PRINTF("String(%d): %s\n", (uint32_t)buf_len, buf);
                // PRINTF("%.*H\n", buf_len, buf);
                // err = cbor_value_dup_text_string(it, &buf, &n, it);
                // if (err) return err;  // parse error
                // PRINTF("CborTextStringType\n");
                // free(buf);
                break;
            }

            case CborTagType: {
                CborTag tag;
                char temp[16];
                cbor_value_get_tag(it, &tag);  // can't fail
                format_u64(temp, sizeof(temp), tag);
                PRINTF("Tag(%s): ", temp);

                break;
            }

            case CborSimpleType: {
                uint8_t temp_type;
                cbor_value_get_simple_type(it, &temp_type);  // can't fail
                PRINTF("simple(%d)\n", temp_type);
                break;
            }

            case CborNullType:
                PRINTF("null");
                break;

            case CborUndefinedType:
                PRINTF("undefined");
                break;

            case CborBooleanType: {
                bool val;
                cbor_value_get_boolean(it, &val);  // can't fail
                PRINTF(val ? "true" : "false");
                break;
            }

            case CborDoubleType: {
                double val;
                if (false) {
                    float f;
                    case CborFloatType:
                        cbor_value_get_float(it, &f);
                        val = f;
                } else {
                    cbor_value_get_double(it, &val);
                }
                PRINTF("Double: 0x%08x\n", val);
                break;
            }
            case CborHalfFloatType: {
                uint16_t val;
                cbor_value_get_half_float(it, &val);
                PRINTF("__f16(%04x)\n", val);
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
    PRINTF("km-logs - [signPLT.c] (parsePltCbor) - cbor: %.*H\n", cborLength, cbor);
    PRINTF("km-logs - [signPLT.c] Starting CBOR parsing, %d bytes\n", cborLength);

    CborParser parser;
    CborValue it;
    CborError err;

    // Initialize parser
    err = cbor_parser_init(cbor, cborLength, 0, &parser, &it);
    if (err) {
        PRINTF("km-logs - [signPLT.c] CBOR parser init failed\n");
        return false;
    }
    err = dumprecursive(&it, 0);
    if (err) {
        PRINTF("Error while parsing cbor");
        THROW(ERROR_INVALID_PARAM);
    }
    return true;
}

void handleSignPltTransaction(uint8_t *cdata,
                              uint8_t p1,
                              uint8_t p2,
                              uint8_t lc,
                              volatile unsigned int *flags,
                              bool isInitialCall) {
    uint8_t remainingDataLength = lc;
    PRINTF(
        "km-logs [signPLT.c] (handleSignPltTransaction) - Starting handling of plt transaction\n");
    PRINTF("km-logs [signPLT.c] (handleSignPltTransaction) - isInitialCall:  %s\n",
           isInitialCall ? "true" : "false");

    if (isInitialCall) {
        ctx->state = TX_PLT_INITIAL;
    }

    if (p1 == P1_INITIAL && ctx->state == TX_PLT_INITIAL) {
        PRINTF("km-logs [signPLT.c] (handleSignPltTransaction) Initial chunk about to process\n");
        uint8_t offset = handleHeaderAndKind(cdata, remainingDataLength, PLT_TRANSACTION);
        cdata += offset;
        remainingDataLength -= offset;

        // Hash the resh of the transaction ()
        updateHash((cx_hash_t *)&tx_state->hash, cdata, remainingDataLength);

        // Parse token Id info
        ctx->tokenIdLength = cdata[0];
        cdata++;
        remainingDataLength--;

        if (remainingDataLength < ctx->tokenIdLength) {
            PRINTF("Not enough data left");
            THROW(ERROR_INVALID_PARAM);
        }
        memcpy(ctx->tokenId, cdata, ctx->tokenIdLength);
        cdata += ctx->tokenIdLength;
        remainingDataLength -= ctx->tokenIdLength;

        PRINTF("km-logs [signPLT.c] (handleSignPltTransaction) - TokenID %.*H\n",
               ctx->tokenIdLength,
               ctx->tokenId);

        // Parse OperationLength
        cbor_context->cborLength = U4BE(cdata, 0);
        PRINTF("km-logs [signPLT.c] (handleSignPltTransaction) - cborLength %d\n",
               cbor_context->cborLength);
        cdata += 4;
        remainingDataLength -= 4;
        // Parse Operations
        // Hash it all
        if (!parsePltCbor(cdata, remainingDataLength)) {
            PRINTF("Cbor parsing failed\n");
            THROW(ERROR_INVALID_PARAM);
        }

        // hash the remaining data
        // if (remainingDataLength < 2) {
        //     THROW(ERROR_BUFFER_OVERFLOW);
        // }
        // memo_ctx->cborLength = U2BE(cdata, 0);
        // if (memo_ctx->cborLength > MAX_MEMO_SIZE) {
        //     THROW(ERROR_INVALID_PARAM);
        // }

        // ctx->state = TX_TRANSFER_MEMO_INITIAL;
        PRINTF("km-logs - about to be cool\n");
        PRINTF("km-logs - cool\n");
        io_send_sw(SUCCESS);

    }
    // else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_MEMO_INITIAL) {
    //     updateHash((cx_hash_t *)&tx_state->hash, cdata, dataLength);
    //     readCborInitial(cdata, dataLength);
    //     if (memo_ctx->cborLength == 0) {
    //         finishMemo();
    //     } else {
    //         ctx->state = TX_TRANSFER_MEMO;
    //         sendSuccessNoIdle();
    //     }
    // } else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_MEMO) {
    //     updateHash((cx_hash_t *)&tx_state->hash, cdata, dataLength);
    //     readCborContent(cdata, dataLength);
    //     if (memo_ctx->cborLength != 0) {
    //         // The memo size is <=256 bytes, so we should always have received the complete memo
    //         by
    //             // this point
    //             THROW(ERROR_INVALID_STATE);
    //     }
    //     finishMemo();
    // } else if (p1 == P1_AMOUNT && ctx->state == TX_TRANSFER_AMOUNT) {
    //     // Build display value of the amount to transfer, and also add the bytes to the hash.
    //     if (remainingDataLength < 8) {
    //         THROW(ERROR_BUFFER_OVERFLOW);
    //     }
    //     uint64_t amount = U8BE(cdata, 0);
    //     amountToGtuDisplay(ctx->displayAmount, sizeof(ctx->displayAmount), amount);
    //     updateHash((cx_hash_t *)&tx_state->hash, cdata, 8);
    //     startTransferDisplay(true, flags);
    // }
    else {
        THROW(ERROR_INVALID_STATE);
    }
}
