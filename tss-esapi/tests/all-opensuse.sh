#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

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

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build --features "generate-bindings integration-tests"

#################
# Run the tests #
#################
TEST_TCTI="swtpm:host=localhost,port=2321" RUST_BACKTRACE=1 RUST_LOG=info cargo test --features "generate-bindings integration-tests" --  --test-threads=1 --nocapture

