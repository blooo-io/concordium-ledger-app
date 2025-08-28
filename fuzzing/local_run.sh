#!/bin/bash

# FUZZING 101: Local test script for standalone export private key fuzzer

# Clean previous build
rm -rf build

# Build the standalone fuzzer
echo "Building Concordium Export Private Key Fuzzer..."
echo "This is a standalone fuzzer - no external SDK dependencies needed!"
echo ""

cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang
cmake --build build

if ! [ -f ./build/standalone_fuzzer ]; then
    echo "❌ Build failed, please check the output above."
    exit 1
fi

echo "✅ Build successful!"
echo ""

# Create the corpus directory if it doesn't exist
if ! [ -d ./corpus ]; then
    mkdir corpus
    echo "Created corpus directory"
fi

# Create seed inputs specifically for export private key functionality
echo "Creating seed corpus for export private key fuzzing..."
echo "FUZZING 101: Seeds help the fuzzer start with valid-looking inputs"
echo ""

# Seed 1: Identity credential creation (P1=0x00)
python3 -c "
data = b'\\x00'  # p1 = P1_IDENTITY_CREDENTIAL_CREATION
data += b'\\x08'  # lc = 8 bytes (identity provider + identity)
data += b'\\x00\\x00\\x00\\x01'  # identity provider = 1
data += b'\\x00\\x00\\x00\\x05'  # identity = 5
print('Seed 1: Identity credential creation')
open('corpus/identity_cred_creation.bin', 'wb').write(data)
"

# Seed 2: Account creation (P1=0x01) 
python3 -c "
data = b'\\x01'  # p1 = P1_ACCOUNT_CREATION  
data += b'\\x0C'  # lc = 12 bytes (identity provider + identity + account)
data += b'\\x00\\x00\\x00\\x02'  # identity provider = 2
data += b'\\x00\\x00\\x00\\x10'  # identity = 16
data += b'\\x00\\x00\\x00\\x03'  # account = 3
print('Seed 2: Account creation')
open('corpus/account_creation.bin', 'wb').write(data)
"

# Seed 3: ID recovery (P1=0x02)
python3 -c "
data = b'\\x02'  # p1 = P1_ID_RECOVERY
data += b'\\x08'  # lc = 8 bytes  
data += b'\\x00\\x00\\x00\\xFF'  # identity provider = 255
data += b'\\x00\\x00\\x00\\x42'  # identity = 66
print('Seed 3: ID recovery')
open('corpus/id_recovery.bin', 'wb').write(data)
"

# Seed 4: Account credential discovery (P1=0x03)
python3 -c "
data = b'\\x03'  # p1 = P1_ACCOUNT_CREDENTIAL_DISCOVERY
data += b'\\x08'  # lc = 8 bytes
data += b'\\x00\\x00\\x00\\x00'  # identity provider = 0  
data += b'\\x00\\x00\\x00\\x00'  # identity = 0
print('Seed 4: Account credential discovery')
open('corpus/account_cred_discovery.bin', 'wb').write(data)
"

# Seed 5: Creation of ZK proof (P1=0x04)
python3 -c "
data = b'\\x04'  # p1 = P1_CREATION_OF_ZK_PROOF
data += b'\\x0C'  # lc = 12 bytes (needs account parameter)
data += b'\\x00\\x00\\x00\\x07'  # identity provider = 7
data += b'\\x00\\x00\\x00\\x0A'  # identity = 10  
data += b'\\x00\\x00\\x00\\x01'  # account = 1
print('Seed 5: ZK proof creation')
open('corpus/zk_proof_creation.bin', 'wb').write(data)
"

# Seed 6: Edge case - minimal data  
python3 -c "
data = b'\\x00'  # p1 = 0
data += b'\\x01'  # lc = 1 (too small)
data += b'\\xFF'  # minimal data
print('Seed 6: Edge case - minimal data')
open('corpus/minimal_data.bin', 'wb').write(data)
"

# Seed 7: Edge case - invalid p1
python3 -c "
data = b'\\xFF'  # p1 = invalid value
data += b'\\x08'  # lc = 8 bytes
data += b'\\x00' * 8  # data
print('Seed 7: Edge case - invalid p1')
open('corpus/invalid_p1.bin', 'wb').write(data)
"

echo "Created 7 seed files for export private key fuzzing!"
echo ""

# Determine number of jobs (half of available cores)
if command -v nproc >/dev/null 2>&1; then
    ncpus=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
    ncpus=$(sysctl -n hw.ncpu)
else
    ncpus=4  # fallback
fi
jobs=$(($ncpus/2))
if [ $jobs -lt 1 ]; then
    jobs=1
fi

echo "🚀 Starting Export Private Key Fuzzer!"
echo "Target function: handleExportPrivateKeyNewPath"
echo "Using $jobs jobs (half of $ncpus CPUs)"
echo ""
echo "FUZZING 101: The fuzzer will now:"
echo "  • Take our seed inputs and mutate them randomly"
echo "  • Feed thousands of variations to handleExportPrivateKeyNewPath()"
echo "  • Look for crashes, memory errors, infinite loops, etc."
echo "  • If it finds a bug, it saves the crashing input for analysis"
echo ""
echo "Press Ctrl-C when you want to stop and optionally compute coverage"
echo ""

./build/standalone_fuzzer -max_len=1024 -jobs="$jobs" -timeout=10 ./corpus

echo ""
read -p "Would you like to compute coverage (y/n)? " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]
then
    exit 0
fi

# Remove previous artifacts
rm -f default.profdata *.profraw

echo "Running profiling on corpus..."
# Run profiling on the corpus  
./build/standalone_fuzzer -max_len=1024 -runs=0 ./corpus

if ls *.profraw 1> /dev/null 2>&1; then
    echo "Computing coverage..."
    # Compute coverage
    llvm-profdata merge -sparse *.profraw -o default.profdata
    llvm-cov show build/standalone_fuzzer -instr-profile=default.profdata -format=html > coverage_report.html
    llvm-cov report build/standalone_fuzzer -instr-profile=default.profdata
    echo "✅ Coverage report generated: coverage_report.html"
    echo ""
    echo "FUZZING 101: Coverage shows which code lines were executed during fuzzing"
    echo "High coverage = good (we tested most of the code paths)"
else
    echo "⚠️ No profiling data generated. Coverage analysis skipped."
fi

echo ""
echo "🎓 FUZZING COMPLETED! You've successfully:"
echo "  • Built a standalone fuzzer with minimal dependencies" 
echo "  • Created targeted seed inputs for the export private key function"
echo "  • Ran thousands of tests to find potential bugs"
echo "  • Generated coverage analysis to see what code was tested"
echo ""
echo "Next steps: You can now extend this approach to fuzz other Concordium functions!"