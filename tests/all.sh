#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

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

##############
# Build docs #
##############
cargo doc --no-deps --verbose

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info cargo test -- --test-threads=1 --nocapture

###################
# Stop TPM server #
###################
pkill tpm_server
