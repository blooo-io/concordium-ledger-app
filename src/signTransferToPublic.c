#include "globals.h"

static signTransferToPublic_t *ctx = &global.signTransferToPublic;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL          0x00
#define P1_REMAINING_AMOUNT 0x01
#define P1_PROOF            0x02

void handleSignTransferToPublic(uint8_t *cdata,
                                uint8_t p1,
                                uint8_t dataLength,
                                volatile unsigned int *flags,
                                bool isInitialCall) {
    if (isInitialCall) {
        ctx->state = TX_TRANSFER_TO_PUBLIC_INITIAL;
    }

    if (p1 == P1_INITIAL && ctx->state == TX_TRANSFER_TO_PUBLIC_INITIAL) {
        size_t offset = parseKeyDerivationPath(cdata);
        if (offset > dataLength) {
            THROW(ERROR_BUFFER_OVERFLOW);  // Ensure safe access
        }
        cdata += offset;
        cx_sha256_init(&tx_state->hash);
        offset = hashAccountTransactionHeaderAndKind(cdata, TRANSFER_TO_PUBLIC);
        if (offset > dataLength) {
            THROW(ERROR_BUFFER_OVERFLOW);  // Ensure safe access
        }
        ctx->state = TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT;
        // Ask the caller for the next command.
        sendSuccessNoIdle();
    } else if (p1 == P1_REMAINING_AMOUNT && ctx->state == TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT) {
        // Hash remaining amount. Remaining amount is encrypted, and so we cannot display it.
        updateHash((cx_hash_t *)&tx_state->hash, cdata, 192);
        cdata += 192;

        // Parse transaction amount so it can be displayed.
        uint64_t amountToPublic = U8BE(cdata, 0);
        amountToGtuDisplay(ctx->amount, sizeof(ctx->amount), amountToPublic);
        updateHash((cx_hash_t *)&tx_state->hash, cdata, 8);
        cdata += 8;

        // Hash amount index
        updateHash((cx_hash_t *)&tx_state->hash, cdata, 8);
        cdata += 8;

        // Parse size of incoming proofs.
        ctx->proofSize = U2BE(cdata, 0);

        ctx->state = TX_TRANSFER_TO_PUBLIC_PROOF;
        sendSuccessNoIdle();
    } else if (p1 == P1_PROOF && ctx->state == TX_TRANSFER_TO_PUBLIC_PROOF) {
        updateHash((cx_hash_t *)&tx_state->hash, cdata, dataLength);

        if (ctx->proofSize == dataLength) {
            // We have received all proof bytes, continue to signing flow.
            uiSignTransferToPublicDisplay(flags);
        } else if (ctx->proofSize < dataLength) {
            // We received more proof bytes than expected, and so the received
            // transaction is invalid.
            THROW(ERROR_INVALID_TRANSACTION);
        } else {
            // There are additional bytes to be received, so ask the caller
            // for more data.
            ctx->proofSize -= dataLength;
            sendSuccessNoIdle();
        }
    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
