# Protected Ledger Transaction (PLT)

A transaction type for handling protected ledger operations. The transaction includes a token ID and CBOR-encoded operation data.

## Protocol description

- Multiple commands with different chunk values to process the transaction in stages.

| INS    | P1     | P2     | CDATA                                                                                                                | Comment                                                                                |
| ------ | ------ | ------ | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `0x27` | `0x01` | `0x00` | `path_length path[uint32]x[8] account_transaction_header[60 bytes] transaction_kind[uint8] token_id_length[uint8] token_id[1..255 bytes] cbor_length[uint32]` | Initial chunk (chunk=0). Transaction kind must be 27. |
| `0x27` | `0x01` | `0x00` | `cbor_data[1..900 bytes]`                                                                                            | Subsequent chunks. CBOR data can be sent in multiple chunks until complete. |

## Constraints

- Maximum token ID length: 255 bytes
- Maximum CBOR data length: 900 bytes
- CBOR data must be valid according to the CBOR specification
- Total display string length must not exceed 2000 bytes

## PLT-Specific Error Codes

In addition to the standard Concordium Ledger error codes, PLT transactions can return the following specific errors:

| Code   | Name                   | Description |
|--------|------------------------|-------------|
| `0x6B0D` | `ERROR_PLT_CBOR_ERROR` | PLT CBOR parsing or processing error |
| `0x6B0E` | `ERROR_PLT_BUFFER_ERROR` | PLT buffer overflow or size error |
| `0x6B0F` | `ERROR_PLT_DATA_ERROR` | PLT data validation or integrity error |

### When these errors occur:

- **ERROR_PLT_CBOR_ERROR**: CBOR decoding failed, tag parsing failed, hex formatting failed, or general CBOR processing issues
- **ERROR_PLT_BUFFER_ERROR**: Display buffer overflow, CBOR buffer too small, or chunk size exceeds available space
- **ERROR_PLT_DATA_ERROR**: Incomplete CBOR data, insufficient token/length data, or data integrity validation failures

## Error Handling

When a PLT-specific error occurs:
1. The transaction processing stops immediately
2. The appropriate error code is returned to the client
3. All sensitive data is cleared from memory
4. The device returns to a safe state