#ifdef HAVE_NBGL

#include "os.h"
#include "ux.h"

#include "display.h"
#include "globals.h"
#include "glyphs.h"
#include "menu.h"
#include "getPublicKey.h"
#include "util.h"
#include "sign.h"

#include "nbgl_use_case.h"
accountSender_t global_account_sender;

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}
void uiComparePubkey(void) {
    // TODO: Implement this
    nbgl_useCaseAddressReview(global.exportPublicKeyContext.publicKey,
                              NULL,
                              &C_app_concordium_64px,
                              "Compare",
                              NULL,
                              review_choice);
}

void uiGeneratePubkey(volatile unsigned int *flags) {
    nbgl_useCaseAddressReview((char *) global.exportPublicKeyContext.display,  // Address to display
                              NULL,                    // No additional tag-value list
                              &C_app_concordium_64px,  // Icon to display
                              "Public Key",            // Review title
                              NULL,                    // No review subtitle
                              sendPublicKey            // Callback function
    );
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiExportPrivateKey(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void startConfigureBakerCommissionDisplay(void) {
    // TODO: Implement this
}

void startConfigureBakerDisplay(void) {
    // TODO: Implement this
}

void startConfigureBakerUrlDisplay(bool lastUrlPage) {
    lastUrlPage = false;
    // TODO: Implement this
}

// TODO: To fix
void startConfigureDelegationDisplay(void) {
    // Get context from global state
    signConfigureDelegationContext_t *ctx = &global.signConfigureDelegation;

    // Create tag-value pairs for the content
    nbgl_layoutTagValue_t pairs[4];  // Maximum possible pairs
    uint8_t pairIndex = 0;

    // Add sender address
    pairs[pairIndex].item = "Sender";
    pairs[pairIndex].value = (char *) global_account_sender.sender;
    pairIndex++;

    // Add capital amount if present
    if (ctx->hasCapital) {
        if (ctx->stopDelegation) {
            pairs[pairIndex].item = "Action";
            pairs[pairIndex].value = "Stop delegation";
        } else {
            pairs[pairIndex].item = "Amount to delegate";
            pairs[pairIndex].value = (char *) ctx->displayCapital;
        }
        pairIndex++;
    }

    // Add restake earnings if present
    if (ctx->hasRestakeEarnings) {
        pairs[pairIndex].item = "Restake earnings";
        pairs[pairIndex].value = (char *) ctx->displayRestake;
        pairIndex++;
    }

    // Add delegation target if present
    if (ctx->hasDelegationTarget) {
        pairs[pairIndex].item = "Delegation target";
        pairs[pairIndex].value = (char *) ctx->displayDelegationTarget;
        pairIndex++;
    }

    // Create the page content
    nbgl_pageContent_t content;
    content.type = TAG_VALUE_LIST;
    content.title = "Review Transaction";
    content.isTouchableTitle = true;
    content.topRightIcon = NULL;
    content.tagValueList.nbPairs = pairIndex;
    content.tagValueList.pairs = pairs;
    content.tagValueList.smallCaseForValue = false;
    content.tagValueList.nbMaxLinesForValue = 0;

    // Setup the review screen
    nbgl_useCaseReviewStart(&C_app_concordium_64px,
                            "Review Transaction",
                            NULL,  // No subtitle
                            "Reject transaction",
                            buildAndSignTransactionHash,
                            sendUserRejection);
}

void uiSignUpdateCredentialThresholdDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignUpdateCredentialInitialDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignUpdateCredentialIdDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignCredentialDeploymentVerificationKeyDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignCredentialDeploymentNewIntroDisplay(void) {
    // TODO: Implement this
}

void uiSignCredentialDeploymentExistingIntroDisplay(void) {
    // TODO: Implement this
}

void uiSignCredentialDeploymentNewDisplay(void) {
    // TODO: Implement this
}

void uiSignCredentialDeploymentExistingDisplay(void) {
    // TODO: Implement this
}

void uiSignCredentialDeploymentVerificationKeyFlowDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void startEncryptedTransferDisplay(bool displayMemo) {
    displayMemo = false;
    // TODO: Implement this
}

void uiSignPublicInformationForIpCompleteDisplay(void) {
    // TODO: Implement this
}

void uiReviewPublicInformationForIpDisplay(void) {
    // TODO: Implement this
}

void uiSignPublicInformationForIpFinalDisplay(void) {
    // TODO: Implement this
}

void uiSignPublicInformationForIpPublicKeyDisplay(void) {
    // TODO: Implement this
}

void uiRegisterDataInitialDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiRegisterDataPayloadDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void startTransferDisplay(bool displayMemo, volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    displayMemo = false;
    // TODO: Implement this
}

void uiSignTransferToEncryptedDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignTransferToPublicDisplay(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void uiSignScheduledTransferPairFlowDisplay(void) {
    // TODO: Implement this
}

void uiSignScheduledTransferPairFlowSignDisplay(void) {
    // TODO: Implement this
}

void uiSignScheduledTransferPairFlowFinalDisplay(void) {
    // TODO: Implement this
}

void uiVerifyAddress(volatile unsigned int *flags) {
    *flags |= IO_ASYNCH_REPLY;
    // TODO: Implement this
}

void startInitialScheduledTransferDisplay(bool displayMemo) {
    displayMemo = false;
    // TODO: Implement this
}

#endif
