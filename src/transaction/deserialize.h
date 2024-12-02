#pragma once

#include "buffer.h"

#include "types.h"
#include "../types.h"

/**
 * @brief Deserializes the common header part of a transaction from a buffer.
 *
 * The header consists of:
 * - Sender address (32 bytes)
 * - Sequence number (8 bytes, skipped)
 * - Energy allowance (8 bytes, skipped)
 * - Payload size (4 bytes, skipped)
 * - Expiration (8 bytes, skipped)
 *
 * @param[in] buf Buffer containing the serialized transaction data
 * @param[out] tx Transaction context to store the deserialized data
 * @return parser_status_e PARSING_OK if successful, appropriate error code otherwise:
 *         - WRONG_LENGTH_ERROR if buffer size exceeds MAX_TX_LEN
 *         - SENDER_PARSING_ERROR if sender address parsing fails
 *         - PARSING_ERROR if any other field parsing fails
 */
parser_status_e header_deserialize(buffer_t *buf, transaction_ctx_t *tx);

/**
 * @brief Deserializes a simple transfer transaction from a buffer.
 *
 * The simple transfer transaction consists of:
 * - Transaction header (deserialized using header_deserialize)
 * - Transaction type (1 byte)
 * - Recipient address (32 bytes)
 * - Amount (8 bytes, big-endian)
 *
 * @param[in] buf Buffer containing the serialized transaction data
 * @param[out] tx Transaction context to store the deserialized data
 * @return parser_status_e PARSING_OK if successful, appropriate error code otherwise:
 *         - Any error from header_deserialize
 *         - TYPE_PARSING_ERROR if transaction type parsing fails
 *         - RECIPIENT_PARSING_ERROR if recipient address parsing fails
 *         - AMOUNT_PARSING_ERROR if amount parsing fails
 */
parser_status_e simple_transfer_deserialize(buffer_t *buf, transaction_ctx_t *tx);
