#include "globals.h"
#include "read.h"

static signPLTContext_t *ctx = &global.withDataBlob.signPLTContext;
static cborContext_t *cbor_context = &global.withDataBlob.cborContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x01

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

        PRINTF("km-logs - here 1 \n");
        // Parse OperationLength
        cbor_context->cborLength = U4BE(cdata, 0);
        PRINTF("km-logs [signPLT.c] (handleSignPltTransaction) - cborLength %d\n",
               cbor_context->cborLength);
        cdata += 4;
        remainingDataLength -= 4;
        PRINTF("km-logs - here 2\n");
        // Parse Operations
        // Hash it all

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
