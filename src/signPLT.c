#include "globals.h"
#include "read.h"
#include "io.h"  // io_send_sw
#include "cbor.h"
#include "ledger_assert.h"
#include "format.h"  // format_i64, format_hex
#include "cborStrParsing.h"
#include "cborinternal_p.h"

static signPLTContext_t *ctx = &global.withDataBlob.signPLTContext;
// static cborContext_t *cbor_context = &global.withDataBlob.cborContext;
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
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memcpy((void *)(dst->ptr + dst->offset), src, src_size);
    dst->offset += src_size;
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
                err = decodeCborRecursive(&recursed, nestingLevel + 1, out_buf);
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
                // err = cbor_value_calculate_string_length(it, buf_len);
                // err = _cbor_value_copy_string(it, buf, sizeof(buf), NULL);
                err = cbor_read_string_or_byte_string(it, (char *)buf, &buf_len, false);
                if (err) return err;
                char string_value[100] = {0};
                if (format_hex(buf, buf_len, string_value, sizeof(string_value)) == -1) {
                    PRINTF("format_hex error\n");
                    THROW(0x0010);
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
                // err = cbor_value_calculate_string_length(it, buf_len);
                // err = _cbor_value_copy_string(it, buf, sizeof(buf), NULL);
                err = cbor_read_string_or_byte_string(it, (char *)buf, &buf_len, true);
                if (err) return err;
                // null terminate the string
                buf[buf_len] = '\0';
                // char string_value[20];
                // if (!format_hex(buf, buf_len, string_value, sizeof(string_value))) {
                //     PRINTF("format_hex error");
                //     THROW(0x0010);
                // }
                char temp2[256];
                snprintf(temp2, sizeof(temp2), "\"%s\",", buf);
                PRINTF("%s", temp2);
                add_char_array_to_buffer(out_buf, temp2, strlen(temp2));
                // PRINTF("%.*H\n", buf_len, buf);
                // err = cbor_value_dup_text_string(it, &buf, &n, it);
                // if (err) return err;  // parse error
                // PRINTF("CborTextStringType\n");
                // free(buf);
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
                if (false) {
                    float f;
                    case CborFloatType:
                        cbor_value_get_float(it, &f);
                        val = f;
                } else {
                    cbor_value_get_double(it, &val);
                }
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
    err = decodeCborRecursive(&it, 0, &out_buf);
    if (err) {
        PRINTF("Error while decoding cbor\n");
        THROW(ERROR_INVALID_PARAM);
    }

    if (!parse_tags_in_buffer(&out_buf, &tag_list)) {
        PRINTF("Error while parsing cbor tags\n");
        THROW(ERROR_INVALID_PARAM);
    }
    if (sizeof(ctx->pltOperationDisplay) < out_buf.size + 1) {
        PRINTF("display str is too small for value %d < %d\n",
               sizeof(ctx->pltOperationDisplay),
               out_buf.size);
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memcpy(ctx->pltOperationDisplay, out_buf.ptr, out_buf.size);
    ctx->pltOperationDisplay[out_buf.size] = '\0';

    return true;
}

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
            THROW(ERROR_INVALID_PARAM);
        }
        memcpy(ctx->tokenId, cdata, ctx->tokenIdLength);
        cdata += ctx->tokenIdLength;
        remainingDataLength -= ctx->tokenIdLength;

        // Parse OperationLength
        if (remainingDataLength < 4) {
            PRINTF("Not enough data left\n");
            THROW(ERROR_INVALID_PARAM);
        }
        ctx->totalCborLength = U4BE(cdata, 0);
        cdata += 4;
        remainingDataLength -= 4;

        // Check if the OperationLength is larger than the buffer
        if (ctx->totalCborLength > sizeof(ctx->cbor)) {
            PRINTF("Cbor buffer is too small to contain the complete cbor, %d > %d\n",
                   ctx->totalCborLength,
                   sizeof(ctx->cbor));
            THROW(ERROR_BUFFER_OVERFLOW);
        }
    }

    // Add the cbor to the context
    if (remainingDataLength > sizeof(ctx->cbor) - ctx->currentCborLength) {
        PRINTF("Cbor received is larger than the buffer, %d > %d\n",
               remainingDataLength,
               sizeof(ctx->cbor) - ctx->currentCborLength);
        THROW(ERROR_BUFFER_OVERFLOW);
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
                THROW(ERROR_INVALID_PARAM);
            }
            uiPltOperationDisplay();
        } else {
            PRINTF("Cbor received is not complete, %d < %d\n",
                   ctx->currentCborLength,
                   ctx->totalCborLength);
            THROW(ERROR_INVALID_STATE);
        }
    }
}
