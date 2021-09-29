#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the `tss-esapi` crate (and its dependencies) for Armv7 and Aarch64
# In order to cross-compile the TSS library we need to also cross-compile OpenSSL

set -euf -o pipefail

OPENSSL_VERSION="OpenSSL_1_1_1j"

cross-compile-openssl() {
    # Prepare directory for cross-compiled OpenSSL files
    mkdir -p /tmp/openssl-$1
    export INSTALL_DIR=/tmp/openssl-$1

    pushd /tmp/openssl
    # Compile and copy files over
    ./Configure $2 shared --prefix=$INSTALL_DIR --openssldir=$INSTALL_DIR/openssl --cross-compile-prefix=$1-
    make clean
    make depend
    make -j$(nproc)
    make install
    popd

    export INSTALL_DIR=
}

cross-compile-tpm2-tss() {
    # Prepare directory for cross-compiled TSS lib
    # `DESTDIR` is used in `make install` below to set the root of the installation paths.
    # The `./configure` script accepts a `--prefix` input variable which sets the same root,
    # but also adds it to the paths in `.pc` files used by `pkg-config`. This prevents the 
    # use of `PKG_CONFIG_SYSROOT_DIR`.
    mkdir -p /tmp/tpm2-tss-$1
    export DESTDIR=/tmp/tpm2-tss-$1
    # Set sysroot to be used by the `pkg-config` wrapper
    export SYSROOT=/tmp/tpm2-tss-$1

    pushd /tpm2-tss
    # Compile and copy files over
    ./configure --build=x86_64-pc-linux-gnu --host=$1 --target=$1 CC=$1-gcc \
        LIBCRYPTO_CFLAGS="-I/tmp/openssl-$1/include" LIBCRYPTO_LIBS="-L/tmp/openssl-$1/lib -lcrypto"
    make clean
    make -j$(nproc)
    make install
    popd

    export DESTDIR=
}

# Download cross-compilers
apt update
apt install -y gcc-multilib
apt install -y gcc-arm-linux-gnueabi
apt install -y gcc-aarch64-linux-gnu

# Download OpenSSL source code
if [ ! -d "/tmp/openssl" ]; then
    pushd /tmp
    git clone https://github.com/openssl/openssl.git --branch $OPENSSL_VERSION
    popd
fi

# Regenerate bindings for x86_64-unknown-linux-gnu
cargo clean
cargo build --features generate-bindings
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/x86_64-unknown-linux-gnu.rs \;

# Allow the `pkg-config` crate to cross-compile
export PKG_CONFIG_ALLOW_CROSS=1
# Make the `pkg-config` crate use our wrapper
export PKG_CONFIG=$(pwd)/../tss-esapi/tests/pkg-config

# Regenerate bindings for aarch64-unknown-linux-gnu
cross-compile-openssl aarch64-linux-gnu linux-generic64
cross-compile-tpm2-tss aarch64-linux-gnu

rustup target add aarch64-unknown-linux-gnu
cargo clean
cargo build --features generate-bindings --target aarch64-unknown-linux-gnu
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/aarch64-unknown-linux-gnu.rs \;

# Regenerate bindings for armv7-unknown-linux-gnueabi
cross-compile-openssl arm-linux-gnueabi linux-generic32
cross-compile-tpm2-tss arm-linux-gnueabi

rustup target add armv7-unknown-linux-gnueabi
cargo clean
cargo build --features generate-bindings --target armv7-unknown-linux-gnueabi
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/arm-unknown-linux-gnueabi.rs \;
