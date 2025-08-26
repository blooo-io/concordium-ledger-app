#pragma once

#include <stdint.h>
#include <stdbool.h>

#define MAX_TAG_CONTENT_SIZE 256
#define MAX_TAGS             24

#define MAX_TAG_PARSED_CONTENT_SIZE 300
#define MAX_TOKEN_ID_LENGTH         255
#define MAX_CBOR_LENGTH             900
#define MAX_PLT_DIPLAY_STR          2000

void handleSignPltTransaction(uint8_t *cdata, uint8_t lc, uint8_t chunk, bool more);

// typedef enum {
//     TX_PLT_INITIAL = 49,
//     TX_PLT_CBOR_INITIAL,
//     TX_PLT_CBOR,
// } signPLTState_t;

typedef struct {
    uint8_t transactionType;
    // signPLTState_t state;
    uint8_t tokenId[MAX_TOKEN_ID_LENGTH];
    uint8_t tokenIdLength;
    uint8_t cbor[MAX_CBOR_LENGTH];
    size_t totalCborLength;
    size_t currentCborLength;
    char pltOperationDisplay[MAX_PLT_DIPLAY_STR];
} signPLTContext_t;
