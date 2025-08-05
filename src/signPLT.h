#pragma once

#include <stdint.h>
#include <stdbool.h>

#define MAX_TOKEN_ID_LENGTH 255

void handleSignPltTransaction(uint8_t *cdata,
                              uint8_t p1,
                              uint8_t p2,
                              uint8_t lc,
                              volatile unsigned int *flags,
                              bool isInitialCall);

typedef enum {
    TX_PLT_INITIAL = 49,
} signPLTState_t;

typedef struct {
    uint8_t transactionType;
    signPLTState_t state;
    uint8_t tokenId[MAX_TOKEN_ID_LENGTH];
    uint8_t tokenIdLength;
} signPLTContext_t;
