#pragma once

typedef enum {
    UPDATE_CONTRACT_INITIAL = 60,
    UPDATE_CONTRACT_NAME_FIRST = 61,
    UPDATE_CONTRACT_NAME_NEXT = 62,
    UPDATE_CONTRACT_PARAMS_FIRST = 63,
    UPDATE_CONTRACT_PARAMS_NEXT = 64,
    UPDATE_CONTRACT_END = 65
} updateContractState_t;

/**
 * Handles the INIT_CONTRACT instruction, which initializes a contract
 *
 *
 */
void handleUpdateContract(uint8_t *cdata, uint8_t p1, uint8_t lc);

typedef struct {
    uint64_t amount;
    uint8_t moduleRef[32];
    char amountDisplay[30];
    char indexDisplay[30];
    char subIndexDisplay[30];
    uint32_t nameLength;
    uint32_t remainingNameLength;
    uint32_t paramsLength;
    uint32_t remainingParamsLength;
    updateContractState_t state;
} updateContract_t;
