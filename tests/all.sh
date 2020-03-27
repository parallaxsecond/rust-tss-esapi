#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes static checks and tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

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
RUST_BACKTRACE=1 cargo build

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info cargo test -- --test-threads=1 --nocapture

###################
# Stop TPM server #
###################
pkill tpm_server

#############################
# Install nightly toolchain #
#############################
rustup toolchain install nightly

############################
# Install legacy toolchain #
############################
rustup toolchain install 1.38.0

####################
# Verify doc build #
####################
cargo +nightly doc --features docs --verbose --no-deps

########################
# Verify nightly build #
########################
cargo +nightly build

#####################################
# Verify build with legacy compiler #
#####################################
RUST_BACKTRACE=1 cargo +1.38.0 build
