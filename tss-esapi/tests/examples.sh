#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
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

##################
# Build examples #
##################
RUST_BACKTRACE=1 cargo build --examples

#################
# Run the tests #
#################
TEST_TCTI=mssim: RUST_BACKTRACE=1 RUST_LOG=info cargo test --examples -- --test-threads=1 --nocapture