#!/usr/bin/env bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Script for running valgrind against the set of tests
# Intended for running in the Ubuntu container

set -euf -o pipefail

#################################
# Run the TPM simulation server #
#################################
tpm_server &
sleep 5
tpm2_startup -c -T mssim

##########################
# Install cargo-valgrind #
##########################
apt install -y valgrind
cargo install cargo-valgrind

#################
# Run the tests #
#################
TEST_TCTI=mssim: RUST_BACKTRACE=1 RUST_LOG=info cargo valgrind test --  --test-threads=1 --nocapture
