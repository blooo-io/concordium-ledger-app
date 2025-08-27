#pragma once

#define MAX_DERIVATION_PATH_LENGTH 6
#define MAX_KEYS_TO_EXPORT         3

#define LENGTH_AND_PRIVATE_KEY_SIZE 33  // 1 byte for length, 32 bytes for private key
/**
 * Handles the export of private keys that are allowed to leave the device.
 * The export paths are restricted so that the method cannot access any account paths.
 * @param p1 has to be 0x00 for export of PRF key for decryption, 0x01 for export of PRF key for
 * recovering credentials and 0x02 for export of PRF key and IdCredSec.
 * @param p2 If set to 0x01, then the seeds are exported (Using this is deprecated). If set to 0x02,
 * then the BLS keys are exported. 0x00 is not used to ensure that old clients fail when calling
 * this functionality.
 */
void handleExportPrivateKeyLegacyPath(uint8_t *dataBuffer,
                                      uint8_t p1,
                                      uint8_t p2,
                                      uint8_t lc,
                                      volatile unsigned int *flags);

void handleExportPrivateKeyNewPath(uint8_t *dataBuffer,
                                   uint8_t p1,
                                   uint8_t lc,
                                   volatile unsigned int *flags);

typedef struct {
    uint8_t displayHeader[31];
    uint8_t display[40];
    bool exportBoth;
    bool exportSeed;
    uint32_t path[7];
    uint8_t pathLength;
    bool isNewPath;
    uint8_t outputPrivateKeys[MAX_KEYS_TO_EXPORT * LENGTH_AND_PRIVATE_KEY_SIZE];
} exportPrivateKeyContext_t;

void uiExportPrivateKey(volatile unsigned int *flags);
void uiExportPrivateKeysNewPath(volatile unsigned int *flags);
void exportPrivateKey(void);
void sendPrivateKeysNewPath(void);
