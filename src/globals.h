#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include <stdbool.h>

#include "os.h"
#include "cx.h"
#include "descriptionView.h"
#include "exportPrivateKey.h"
#include "verifyAddress.h"

#include "getPublicKey.h"
#include "displayCbor.h"
#include "signAddAnonymityRevoker.h"
#include "signAddBakerOrUpdateBakerKeys.h"
#include "signAddIdentityProvider.h"
#include "signCredentialDeployment.h"
#include "signEncryptedAmountTransfer.h"
#include "signHigherLevelKeyUpdate.h"
#include "signPublicInformationForIp.h"
#include "signTransfer.h"
#include "signTransferToEncrypted.h"
#include "signTransferToPublic.h"
#include "signTransferWithSchedule.h"
#include "signUpdateAuthorizations.h"
#include "signUpdateBakerRestakeEarnings.h"
#include "signRegisterData.h"

#include "signUpdateBakerStakeThreshold.h"
#include "signUpdateElectionDifficulty.h"
#include "signUpdateExchangeRate.h"
#include "signUpdateFoundationAccount.h"
#include "signUpdateGasRewards.h"
#include "signUpdateMintDistribution.h"
#include "signUpdateProtocol.h"
#include "signUpdateTransactionFeeDistribution.h"
#include "ux.h"

#define CONCORDIUM_PURPOSE   1105
#define CONCORDIUM_COIN_TYPE 0

#define MAX_CDATA_LENGTH 255

#define ACCOUNT_TRANSACTION_HEADER_LENGTH 60
#define UPDATE_HEADER_LENGTH              28

typedef enum {
    DEPLOY_MODULE = 0,
    INIT_CONTRACT = 1,
    UPDATE = 2,
    TRANSFER = 3,
    ADD_BAKER = 4,
    REMOVE_BAKER = 5,
    UPDATE_BAKER_STAKE = 6,
    UPDATE_BAKER_RESTAKE_EARNINGS = 7,
    UPDATE_BAKER_KEYS = 8,
    UPDATE_CREDENTIAL_KEYS = 13,
    ENCRYPTED_AMOUNT_TRANSFER = 16,
    TRANSFER_TO_ENCRYPTED = 17,
    TRANSFER_TO_PUBLIC = 18,
    TRANSFER_WITH_SCHEDULE = 19,
    UPDATE_CREDENTIALS = 20,
    REGISTER_DATA = 21,
    TRANSFER_WITH_MEMO = 22,
    ENCRYPTED_AMOUNT_TRANSFER_WITH_MEMO = 23,
    TRANSFER_WITH_SCHEDULE_WITH_MEMO = 24
} transactionKind_e;

/**
 * Enumeration of all available update types. The exact numbering has
 * to correspond with the on-chain values as it is used as part of the
 * transaction serialization, and it is used to validate that a received
 * transaction has a valid type.
 */
typedef enum {
    UPDATE_TYPE_AUTHORIZATION = 0,
    UPDATE_TYPE_PROTOCOL = 1,
    UPDATE_TYPE_ELECTION_DIFFICULTY = 2,
    UPDATE_TYPE_EURO_PER_ENERGY = 3,
    UPDATE_TYPE_MICRO_GTU_PER_EURO = 4,
    UPDATE_TYPE_FOUNDATION_ACCOUNT = 5,
    UPDATE_TYPE_MINT_DISTRIBUTION = 6,
    UPDATE_TYPE_TRANSACTION_FEE_DISTRIBUTION = 7,
    UPDATE_TYPE_GAS_REWARDS = 8,
    UPDATE_TYPE_BAKER_STAKE_THRESHOLD = 9,
    UPDATE_TYPE_UPDATE_ROOT_KEYS = 10,
    UPDATE_TYPE_UPDATE_LEVEL1_KEYS = 11,
    UPDATE_TYPE_ADD_ANONYMITY_REVOKER = 12,
    UPDATE_TYPE_ADD_IDENTITY_PROVIDER = 13
} updateType_e;

typedef struct {
    uint8_t identity;
    uint8_t accountIndex;

    // Max length of path is 8. Currently we expect to receive the root, i.e. purpose and cointype as well.
    // This could be refactored into having those values hardcoded if we determine they will be static.
    uint8_t pathLength;
    uint32_t keyDerivationPath[8];
    uint32_t rawKeyDerivationPath[8];
} keyDerivationPath_t;
extern keyDerivationPath_t path;

// Helper object used when computing the hash of a transaction,
// and to keep track of the state of a multi command APDU flow.
typedef struct {
    cx_sha256_t hash;
    uint8_t transactionHash[32];
    int currentInstruction;
} tx_state_t;
extern tx_state_t global_tx_state;

// Helper struct that is used to hold the account sender
// address from an account transaction header.
typedef struct {
    uint8_t sender[57];
} accountSender_t;
extern accountSender_t global_account_sender;

typedef struct {
    union {
        signAddAnonymityRevokerContext_t signAddAnonymityRevokerContext;
        signAddIdentityProviderContext_t signAddIdentityProviderContext;
    };
    descriptionContext_t descriptionContext;

} updateWithDescription_t;

typedef struct {
    union {
        signTransferContext_t signTransferContext;
        signEncryptedAmountToTransfer_t signEncryptedAmountToTransfer;
        signTransferWithScheduleContext_t signTransferWithScheduleContext;
        signRegisterData_t signRegisterData;
    };
    cborContext_t cborContext;

} transactionWithDataBlob_t;

/**
 * As the memory we have available is very limited, the context for each instruction is stored
 * in a shared global union, so that we do not use more memory than that of the most memory
 * consuming instruction context.
 */
typedef union {
    exportPrivateKeyContext_t exportPrivateKeyContext;
    exportPublicKeyContext_t exportPublicKeyContext;
    verifyAddressContext_t verifyAddressContext;

    signPublicInformationForIp_t signPublicInformationForIp;
    signCredentialDeploymentContext_t signCredentialDeploymentContext;

    signTransferToEncrypted_t signTransferToEncrypted;
    signTransferToPublic_t signTransferToPublic;
    signAddBakerContext_t signAddBaker;
    signUpdateBakerStakeContext_t signUpdateBakerStake;
    signUpdateBakerRestakeEarningsContext_t signUpdateBakerRestakeEarnings;

    signExchangeRateContext_t signExchangeRateContext;
    signUpdateAuthorizations_t signUpdateAuthorizations;
    signUpdateProtocolContext_t signUpdateProtocolContext;
    signTransactionDistributionFeeContext_t signTransactionDistributionFeeContext;
    signUpdateGasRewardsContext_t signUpdateGasRewardsContext;
    signUpdateFoundationAccountContext_t signUpdateFoundationAccountContext;
    signUpdateMintDistribution_t signUpdateMintDistribution;
    signElectionDifficultyContext_t signElectionDifficulty;
    signUpdateBakerStakeThresholdContext_t signUpdateBakerStakeThreshold;
    signUpdateKeysWithRootKeysContext_t signUpdateKeysWithRootKeysContext;
    updateWithDescription_t withDescription;
    transactionWithDataBlob_t withDataBlob;
} instructionContext;
extern instructionContext global;

#endif
