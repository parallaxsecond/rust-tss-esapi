#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

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

#################################################
# Generate bindings for non-"standard" versions #
#################################################
if [[ "${TPM2_TSS_VERSION}" != "${TPM2_TSS_BINDINGS_VERSION}" ]]; then
	FEATURES="generate-bindings integration-tests serde"
else
	FEATURES="integration-tests serde"
fi

if [[ ! -z ${TPM2_TSS_PATH:+x} ]]; then
	export LD_LIBRARY_PATH="${TPM2_TSS_PATH}"
fi

#############################################
# Run the TPM simulation server for doctest #
#############################################
mkdir /tmp/tpmdir
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
RUST_BACKTRACE=1 cargo build --features "$FEATURES"

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info \
    cargo test --lib --bins --tests --features "generate-bindings integration-tests serde" -- --nocapture

TEST_TCTI="swtpm:path=/tmp/tpmdir/swtpm.sock" RUST_BACKTRACE=1 RUST_LOG=info \
    cargo test --doc --features "generate-bindings integration-tests serde" -- --test-threads=1 --nocapture
