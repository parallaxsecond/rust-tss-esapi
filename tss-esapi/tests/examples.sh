#!/usr/bin/env bash

# Copyright 2025 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script builds and tests the examples.
# It can be run inside the container which Dockerfile
# is in the same folder.

set -euf -o pipefail

#################################################
# Change rust toolchain version
#################################################
if [[ ! -z ${RUST_TOOLCHAIN_VERSION:+x} ]]; then
	rustup override set ${RUST_TOOLCHAIN_VERSION}
	# Use the frozen Cargo lock to prevent any drift from MSRV being upgraded
	# underneath our feet.
	cp tests/Cargo.lock.frozen ../Cargo.lock
fi

############################
# Run the TPM SWTPM server #
############################
mkdir /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --pcr-banks sha1,sha256 \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --daemon

####################
# Start tpm2-abrmd #
####################
tpm2-abrmd \
    --logger=stdout \
    --tcti=swtpm: \
    --allow-root \
    --session \
    --flush-all &

#################
# Clear the TPM #
#################
tpm2_startup -c -T tabrmd:bus_type=session

########################
# Declare the examples #
########################
examples=(
    "duplication_secret"
    "duplication"
    "hmac"
    "rsa_oaep"
    "sealed_data_object"
    "symmetric_file_encrypt_decrypt"
)

##########################################
# Environment variables used by examples #
##########################################
export EXAMPLES_INITIAL_DATA_FILE="/tmp/rust-tss-esapi/tss-esapi/examples/symmetric_file_encrypt_decrypt_example.txt"

####################
# Run the examples #
####################
for e in ${examples[@]}; do
    TEST_TCTI=tabrmd:bus_type=session RUST_BACKTRACE=1 RUST_LOG=info cargo run --example ${e}
done
