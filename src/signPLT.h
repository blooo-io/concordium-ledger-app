#pragma once

#include <stdint.h>
#include <stdbool.h>

#define MAX_TAG_CONTENT_SIZE 256
#define MAX_TAGS             24

#define MAX_TAG_PARSED_CONTENT_SIZE 300
#define MAX_TOKEN_ID_LENGTH         255
#define MAX_CBOR_LENGTH             900
#define MAX_PLT_DIPLAY_STR          2000
#define MAX_PLT_OPERATION_TYPE      32
#define MAX_PLT_AMOUNT_STR          32
#define MAX_PLT_RECIPIENT_STR       128

void handleSignPltTransaction(uint8_t *cdata, uint8_t lc, uint8_t chunk, bool more);

typedef struct {
    char operationType[MAX_PLT_OPERATION_TYPE];
    char amount[MAX_PLT_AMOUNT_STR];
    char recipient[MAX_PLT_RECIPIENT_STR];
    bool isParsed;
} parsedPLTOperation_t;

typedef struct {
    uint8_t transactionType;
    uint8_t tokenId[MAX_TOKEN_ID_LENGTH];
    uint8_t tokenIdLength;
    uint8_t cbor[MAX_CBOR_LENGTH];
    size_t totalCborLength;
    size_t currentCborLength;
    char pltOperationDisplay[MAX_PLT_DIPLAY_STR];
    parsedPLTOperation_t parsedOperation;
} signPLTContext_t;

bool parsePLTOperationForUI(const char* operationDisplay, parsedPLTOperation_t* parsed);
