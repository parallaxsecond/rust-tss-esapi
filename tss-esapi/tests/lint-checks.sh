#!/usr/bin/env bash

# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes static checks for the tss-esapi crate.

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
# Execute clippy #
##################
LINTS=""
LINTS="$LINTS -D clippy::all"
LINTS="$LINTS -D clippy::cargo"
# clippy::cargo disallows multiple versions of the crate in the tree
# We depend on getrandom which itself will depends on both wit-bindgen 0.46 and 0.51
LINTS="$LINTS -A clippy::multiple-crate-versions"
cargo clippy --all-targets --all-features -- $LINTS
