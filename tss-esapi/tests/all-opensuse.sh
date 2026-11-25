#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

########################################
# Run the TPM SWTPM server for doctest #
########################################
mkdir -p /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --pcr-banks sha1,sha256 \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=unixio,path=/tmp/tpmdir/swtpm.sock.ctrl \
    --server type=unixio,path=/tmp/tpmdir/swtpm.sock \
    --daemon

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build --features "generate-bindings integration-tests serde"

#################
# Run the tests #
#################
TEST_TCTI="swtpm:path=/tmp/tpmdir/swtpm.sock" RUST_BACKTRACE=1 RUST_LOG=info \
    cargo test --all-targets --features "generate-bindings integration-tests serde bundled" -- --test-threads=1 --nocapture

TEST_TCTI="swtpm:path=/tmp/tpmdir/swtpm.sock" RUST_BACKTRACE=1 RUST_LOG=info \
    cargo test --doc --features "generate-bindings integration-tests serde bundled" -- --test-threads=1 --nocapture
