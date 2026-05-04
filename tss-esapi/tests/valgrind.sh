#!/usr/bin/env bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Script for running valgrind against the set of tests
# Intended for running in the Ubuntu container

set -euf -o pipefail

if [[ ! -z ${RUST_TOOLCHAIN_VERSION:+x} ]]; then
	rustup override set ${RUST_TOOLCHAIN_VERSION}
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

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info \
    cargo valgrind test --all-targets -- --nocapture

TEST_TCTI="swtpm:path=/tmp/tpmdir/swtpm.sock" RUST_BACKTRACE=1 RUST_LOG=info \
    cargo valgrind test --doc -- -- --test-threads=1 --nocapture
