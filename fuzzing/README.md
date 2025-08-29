# Comprehensive Fuzzing for Concordium Ledger App

## Overview

This comprehensive fuzzing framework tests the entire Concordium Ledger application ecosystem, focusing primarily on the `handleSignPltTransaction` function while also covering all other major operations.

Fuzzing allows us to test how the application behaves when provided with invalid, unexpected, or random data as input. Our fuzz target implements `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`, which provides an array of random bytes that can be used to simulate APDU command structures.

If the application crashes, or a [sanitizer](https://github.com/google/sanitizers) detects any kind of access violation, the fuzzing process is stopped, a report regarding the vulnerability is shown, and the input that triggered the bug is written to disk under the name `crash-*`.

## Fuzzing Targets

The fuzzer includes 12 different harness functions, selected by the first byte of input data:

| Target | Function                       | Description                                                  |
| ------ | ------------------------------ | ------------------------------------------------------------ |
| 0      | `fuzzSignPltTransaction`       | **PRIMARY TARGET**: PLT (Private Lending Token) transactions |
| 1      | `fuzzSignTransfer`             | Simple transfer transactions                                 |
| 2      | `fuzzSignTransferWithMemo`     | Transfers with memo data                                     |
| 3      | `fuzzSignRegisterData`         | Data registration transactions                               |
| 4      | `fuzzSignConfigureBaker`       | Baker configuration operations                               |
| 5      | `fuzzSignConfigureDelegation`  | Delegation configuration                                     |
| 6      | `fuzzGetPublicKey`             | Public key retrieval                                         |
| 7      | `fuzzVerifyAddress`            | Address verification                                         |
| 8      | `fuzzExportPrivateKeyNewPath`  | Private key export (new paths)                               |
| 9      | `fuzzContractOperations`       | Contract deployment/init/update                              |
| 10     | `fuzzSignCredentialDeployment` | Credential deployment                                        |
| 11     | `fuzzSignTransferWithSchedule` | Scheduled transfer transactions                              |

## Architecture

### Key Components

- **`src/fuzzer.c`**: Main fuzzing harness with multiple target functions
- **`src/mock.c`**: Comprehensive mock implementations for all Ledger SDK functions
- **`src/glyphs.h`**: Compatibility header for UI resources
- **`CMakeLists.txt`**: Advanced build configuration following ClusterFuzzLite patterns

### Mock Strategy

All hardware-dependent and cryptographic functions are thoroughly mocked:

- **Crypto Operations**: `cx_*` functions return deterministic results
- **I/O Operations**: UI and communication functions are safely stubbed
- **Memory Management**: Secure memory clearing and allocation
- **Hardware Abstraction**: All Ledger SDK hardware calls are mocked

## Manual Usage (Ledger Container)

### Preparation

The fuzzer runs in the `ledger-app-builder-legacy` Docker container:

```console
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-legacy:latest
sudo docker run --rm -ti --user "$(id -u):$(id -g)" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-legacy:latest
```

### Compilation

Once in the container, compile the comprehensive fuzzer:

```console
cd fuzzing

# cmake initialization with address sanitizer
cmake -DBOLOS_SDK=/opt/ledger-secure-sdk -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address -B build -S .

# Fuzzer compilation
cmake --build build
```

For memory sanitizer (alternative):

```console
cmake -DBOLOS_SDK=/opt/ledger-secure-sdk -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=memory -B build -S .
cmake --build build
```

### Running Fuzzing

#### Comprehensive Fuzzing (All Targets)

```console
./build/fuzzer -max_len=8192 -timeout=30
```

#### Focus on PLT Transactions (Primary Target)

```console
# Create corpus focused on PLT transactions (target 0)
mkdir corpus_plt
echo -en '\x00\x10\x00\x01' > corpus_plt/basic_plt
echo -en '\x00\x20\x01\x00' > corpus_plt/chunked_plt

./build/fuzzer corpus_plt -max_len=2048 -timeout=10
```

#### Focus on Specific Functions

```console
# Test transfers (target 1)
echo -en '\x01\x40\x12\x34\x56' | ./build/fuzzer -max_len=1024

# Test baker operations (target 4)
echo -en '\x04\x01\x80\x00' | ./build/fuzzer -max_len=1024
```

#### Extended Fuzzing Campaign

```console
# Multi-core fuzzing for 1 hour
./build/fuzzer -jobs=4 -max_total_time=3600 -print_stats=1
```

## ClusterFuzzLite Integration

### Preparation

```console
# Prepare directory structure
mkdir fuzzing/{corpus,out}

# Container generation
docker build -t concordium-app-fuzzer --file .clusterfuzzlite/Dockerfile .
```

### Compilation

```console
docker run --rm --privileged -e FUZZING_LANGUAGE=c -v "$(realpath .)/fuzzing/out:/out" -ti concordium-app-fuzzer
```

### Run

```console
docker run --rm --privileged -e FUZZING_ENGINE=libfuzzer -e RUN_FUZZER_MODE=interactive -v "$(realpath .)/fuzzing/corpus:/tmp/fuzz_corpus" -v "$(realpath .)/fuzzing/out:/out" -ti gcr.io/oss-fuzz-base/base-runner run_fuzzer fuzzer
```

## Advanced Usage

### Coverage Analysis

Generate coverage reports to understand code coverage:

```console
# Build with coverage instrumentation
cmake -DBOLOS_SDK=/opt/ledger-secure-sdk -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address -B build -S .
cmake --build build

# Run fuzzer to generate coverage
./build/fuzzer -runs=10000 corpus/

# Generate coverage report (if llvm-cov is available)
llvm-cov show ./build/fuzzer -instr-profile=default.profdata
```

### Reproducing Crashes

When the fuzzer finds a crash, reproduce it:

```console
# Fuzzer creates crash files like crash-<hash>
./build/fuzzer crash-da39a3ee5e6b4b0d3255bfef95601890afd80709

# Debug with GDB
gdb ./build/fuzzer
(gdb) run crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
```

### Custom Corpus Generation

Create targeted test cases for specific scenarios:

```console
# PLT transaction with large token ID
python3 -c "
import struct
data = b'\\x00'  # Target PLT fuzzer
data += b'\\x50'  # lc = 80 bytes
data += b'\\x00'  # chunk = 0
data += b'\\x01'  # more = true
data += b'\\x42' * 76  # Fill with test data
open('corpus/plt_large.bin', 'wb').write(data)
"

# Multi-chunk PLT transaction
python3 -c "
import struct
data = b'\\x00\\x20\\x00\\x01'  # PLT, lc=32, chunk=0, more=true
data += b'\\x11' * 32
open('corpus/plt_chunk1.bin', 'wb').write(data)

data = b'\\x00\\x20\\x01\\x00'  # PLT, lc=32, chunk=1, more=false
data += b'\\x22' * 32
open('corpus/plt_chunk2.bin', 'wb').write(data)
"
```

## Security Focus Areas

The fuzzer is designed to discover vulnerabilities in:

1. **Buffer Management**: Overflow/underflow in transaction parsing
2. **State Management**: Multi-chunk transaction state corruption
3. **Input Validation**: Malformed APDU parameters and data
4. **Memory Safety**: Use-after-free and double-free bugs
5. **Cryptographic Operations**: Invalid key operations and signing
6. **CBOR Parsing**: Malformed CBOR data in PLT transactions
7. **UI Logic**: Display buffer overflows and format string bugs

## Performance Tuning

### Fuzzer Options

```console
# Fast fuzzing for quick feedback
./build/fuzzer -max_len=512 -timeout=1 -max_total_time=300

# Deep fuzzing for thorough testing
./build/fuzzer -max_len=8192 -timeout=60 -slow_unit_time_threshold=10

# Memory-focused fuzzing
./build/fuzzer -rss_limit_mb=2048 -malloc_limit_mb=1024
```

### Corpus Management

```console
# Minimize corpus size while maintaining coverage
./build/fuzzer -merge=1 corpus_merged corpus_original

# Remove redundant test cases
./build/fuzzer corpus -minimize_crash=1
```

This comprehensive fuzzing framework provides thorough security testing of the Concordium Ledger application, with particular focus on the critical PLT transaction functionality while ensuring all other operations are also tested for robustness.
