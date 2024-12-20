#include "globals.h"
#include "getAppName.h"

int handler(uint8_t INS,
            uint8_t *cdata,
            uint8_t p1,
            uint8_t p2,
            uint8_t lc,
            volatile unsigned int *flags,
            bool isInitialCall) {
    switch (INS) {
        case INS_GET_PUBLIC_KEY:
            handleGetPublicKey(cdata, p1, p2, flags);
            break;
        case INS_VERIFY_ADDRESS:
            handleVerifyAddress(cdata, p1, flags);
            break;
        case INS_SIGN_TRANSFER:
            handleSignTransfer(cdata, flags);
            break;
        case INS_SIGN_TRANSFER_WITH_MEMO:
            handleSignTransferWithMemo(cdata, p1, lc, flags, isInitialCall);
            break;
        case INS_SIGN_TRANSFER_WITH_SCHEDULE:
            handleSignTransferWithSchedule(cdata, p1, flags, isInitialCall);
            break;
        case INS_SIGN_TRANSFER_WITH_SCHEDULE_AND_MEMO:
            handleSignTransferWithScheduleAndMemo(cdata, p1, lc, flags, isInitialCall);
            break;
        case INS_CREDENTIAL_DEPLOYMENT:
            handleSignCredentialDeployment(cdata, p1, p2, flags, isInitialCall);
            break;
        case INS_EXPORT_PRIVATE_KEY:
            handleExportPrivateKey(cdata, p1, p2, flags);
            break;
        case INS_TRANSFER_TO_PUBLIC:
            handleSignTransferToPublic(cdata, p1, lc, flags, isInitialCall);
            break;
        case INS_REGISTER_DATA:
            handleSignRegisterData(cdata, p1, lc, flags, isInitialCall);
            break;
        case INS_PUBLIC_INFO_FOR_IP:
            handleSignPublicInformationForIp(cdata, p1, flags, isInitialCall);
            break;
        case INS_CONFIGURE_BAKER:
            handleSignConfigureBaker(cdata, p1, lc, flags, isInitialCall);
            break;
        case INS_CONFIGURE_DELEGATION:
            handleSignConfigureDelegation(cdata, lc, flags);
            break;
        case INS_SIGN_UPDATE_CREDENTIAL:
            handleSignUpdateCredential(cdata, p1, p2, flags, isInitialCall);
            break;
        case INS_GET_APP_NAME:
            return handleGetAppName();
            break;
        case INS_DEPLOY_MODULE:
            handleDeployModule(cdata, p1, lc);
            break;
        case INS_INIT_CONTRACT:
            handleInitContract(cdata, p1, lc);
            break;
        case INS_UPDATE_CONTRACT:
            handleUpdateContract(cdata, p1, lc);
            break;
        default:
            THROW(ERROR_INVALID_INSTRUCTION);
            break;
    }
    return 0;
}
