#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes static checks and tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

#################################################
# Generate bindings for non-"standard" versions #
#################################################
if [[ "$TPM2_TSS_VERSION" != "2.3.3" ]]; then
	FEATURES="--features=generate-bindings"
else
	FEATURES=""
fi

#################################
# Run the TPM simulation server #
#################################
tpm_server &
sleep 5
tpm2_startup -c -T mssim

##################
# Execute clippy #
##################
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::cargo

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build $FEATURES

#################
# Run the tests #
#################
TEST_TCTI=mssim: RUST_BACKTRACE=1 RUST_LOG=info cargo test $FEATURES -- --test-threads=1 --nocapture
