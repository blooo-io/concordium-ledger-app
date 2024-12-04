#ifndef _CBOR_H_
#define _CBOR_H_

#include "ux.h"

/**
 * Read a CBOR encoded dataBlob's initial part, i.e. the header, which contains the major type and
 * length Only supports major type 0, 1 and 3 (non-negative integers, negative integers and utf-8
 * strings) Does not support streaming (shortCount = 31).
 */
void readCborInitial(uint8_t *cdata, uint8_t dataLength);
/**
 * Read part of a CBOR encoded dataBlob. Should only be used after readCborInitial.
 */
void readCborContent(uint8_t *cdata, uint8_t dataLength);
// extern const ux_flow_step_t *const ux_display_memo[];
typedef struct {
    uint32_t cborLength;
    uint32_t displayUsed;
    uint8_t display[255];
    uint8_t majorType;
} cborContext_t;

void handleCborStep(void);

#endif

#ifdef HAVE_BAGL

extern const ux_flow_step_t ux_display_memo_step_nocb;
extern const ux_flow_step_t ux_sign_flow_account_sender_view;

#endif

void uiComparePubkey(void);
void uiGeneratePubkey(volatile unsigned int *flags);
void uiExportPrivateKey(volatile unsigned int *flags);

#ifdef HAVE_BAGL
// Define the dynamic UI elements. These are required as the majority of
// the transaction elements are optional, so the UI has to be dynamically set.
extern const ux_flow_step_t *ux_sign_configure_baker_first[8];
extern const ux_flow_step_t *ux_sign_configure_baker_url[6];
extern const ux_flow_step_t *ux_sign_configure_baker_commission[9];
#endif

void startConfigureBakerCommissionDisplay(void);
void startConfigureBakerUrlDisplay(bool lastUrlPage);
void startConfigureBakerDisplay(void);

void startConfigureDelegationDisplay();

void uiSignUpdateCredentialInitialDisplay(volatile unsigned int *flags);
void uiSignUpdateCredentialIdDisplay(volatile unsigned int *flags);
void uiSignUpdateCredentialThresholdDisplay(volatile unsigned int *flags);
void uiSignCredentialDeploymentVerificationKeyDisplay(volatile unsigned int *flags);
void uiSignCredentialDeploymentVerificationKeyFlowDisplay(volatile unsigned int *flags);
void uiSignCredentialDeploymentNewIntroDisplay(void);
void uiSignCredentialDeploymentNewDisplay(void);

void uiSignCredentialDeploymentExistingIntroDisplay(void);
void uiSignCredentialDeploymentExistingDisplay(void);

// Encrypted amount transfer

#ifdef HAVE_BAGL
extern const ux_flow_step_t *ux_sign_encrypted_amount_transfer[8];
#endif

void startEncryptedTransferDisplay(bool displayMemo);

// Public information for IP
void uiReviewPublicInformationForIpDisplay(void);
void uiSignPublicInformationForIpPublicKeyDisplay(void);
void uiSignPublicInformationForIpCompleteDisplay(void);
void uiSignPublicInformationForIpFinalDisplay(void);

// Register data
void uiSignFlowSharedDisplay(void);
void uiRegisterDataInitialDisplay(volatile unsigned int *flags);
void uiRegisterDataPayloadDisplay(volatile unsigned int *flags);
