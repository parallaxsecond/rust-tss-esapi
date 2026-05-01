#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -euf -o pipefail

#############################
# Install and run tarpaulin #
#############################
cargo install cargo-tarpaulin
cargo tarpaulin --features "integration-tests serde" --tests --out xml --exclude-files="tests/*,../*" -- --nocapture
