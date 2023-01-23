#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the `tss-esapi` crate (and its dependencies) for Armv7 and Aarch64
# In order to cross-compile the TSS library we need to also cross-compile OpenSSL

set -euf -o pipefail

OPENSSL_GIT="https://github.com/openssl/openssl.git"
OPENSSL_VERSION="OpenSSL_1_1_1j"
JSON_C_GIT="https://github.com/json-c/json-c.git"
JSON_C_VERSION="json-c-0.16-20220414"
CURL_GIT="https://github.com/curl/curl.git"
CURL_VERSION="curl-7_87_0"
TPM2_TSS_GIT="https://github.com/tpm2-software/tpm2-tss.git"
TPM2_TSS_VERSION="3.2.1"

export SYSROOT="/tmp/sysroot"

git_checkout() {
    if [ ! -d "/tmp/$(basename "$1" ".git")" ]; then
	pushd /tmp
	git clone "$1" --branch "$2"
	popd
    fi
}

prepare_sysroot() {
    # Prepare the SYSROOT
    [ -d "$SYSROOT" ] && rm -fr "$SYSROOT"
    mkdir -p "$SYSROOT"

    # Allow the `pkg-config` crate to cross-compile
    export PKG_CONFIG_ALLOW_CROSS=1
    export PKG_CONFIG_PATH="$SYSROOT"/lib/pkgconfig:"$SYSROOT"/share/pkgconfig
    export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
}

cross-compile-openssl() {
    pushd /tmp/openssl
    # Compile and copy files over
    ./Configure $2 shared --prefix="$SYSROOT" --openssldir="$SYSROOT"/openssl --cross-compile-prefix=$1-
    make clean
    make depend
    make -j$(nproc)
    make install
    popd
}

cross-compile-json-c() {
    pushd /tmp/json-c
    rm -fr json-c-build && mkdir json-c-build && cd json-c-build
    cmake -DCMAKE_C_COMPILER=$1-gcc -DCMAKE_INSTALL_PREFIX="$SYSROOT" ..
    cmake --build .
    cmake --install .
    popd
}

cross-compile-curl() {
    pushd /tmp/curl
    [ ! -f configure ] && autoreconf --install
    ./configure --prefix=/ --build=x86_64-pc-linux-gnu --host=$1 --target=$1 CC=$1-gcc --with-openssl
    make clean
    make -j$(nproc)
    make DESTDIR="$SYSROOT" install
    popd
}

cross-compile-tpm2-tss() {
    pushd /tmp/tpm2-tss
    [ ! -f configure ] && ./bootstrap
    ./configure --prefix=/ --build=x86_64-pc-linux-gnu --host=$1 --target=$1 CC=$1-gcc
    make clean
    make -j$(nproc)
    make DESTDIR="$SYSROOT" install
    popd
}

# Download cross-compilers
sudo apt update
sudo apt install -y gcc-multilib
sudo apt install -y gcc-arm-linux-gnueabi
sudo apt install -y gcc-aarch64-linux-gnu

# Download development version for tpm2-tss
sudo apt install -y libtss2-dev

# Download other dependencies
sudo apt install -y autoconf
sudo apt install -y autoconf-archive
sudo apt install -y cmake
sudo apt install -y libclang-dev
sudo apt install -y libtool
sudo apt install -y pkgconf

# Download OpenSSL, tpm2-tss and dependencies source code
git_checkout "$OPENSSL_GIT" "$OPENSSL_VERSION"
git_checkout "$JSON_C_GIT" "$JSON_C_VERSION"
git_checkout "$CURL_GIT" "$CURL_VERSION"
git_checkout "$TPM2_TSS_GIT" "$TPM2_TSS_VERSION"

# Regenerate bindings for x86_64-unknown-linux-gnu
cargo clean
cargo build --features generate-bindings
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/x86_64-unknown-linux-gnu.rs \;

# Clean and prepare SYSROOT
prepare_sysroot

# Regenerate bindings for aarch64-unknown-linux-gnu
cross-compile-openssl aarch64-linux-gnu linux-generic64
cross-compile-json-c aarch64-linux-gnu
cross-compile-curl aarch64-linux-gnu
cross-compile-tpm2-tss aarch64-linux-gnu

rustup target add aarch64-unknown-linux-gnu
cargo clean
cargo build --features generate-bindings --target aarch64-unknown-linux-gnu
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/aarch64-unknown-linux-gnu.rs \;

# Clean and prepare SYSROOT
prepare_sysroot

# Regenerate bindings for armv7-unknown-linux-gnueabi
cross-compile-openssl arm-linux-gnueabi linux-generic32
cross-compile-json-c arm-linux-gnueabi
cross-compile-curl arm-linux-gnueabi
cross-compile-tpm2-tss arm-linux-gnueabi

rustup target add armv7-unknown-linux-gnueabi
cargo clean
cargo build --features generate-bindings --target armv7-unknown-linux-gnueabi
find ../target -name tss_esapi_bindings.rs -exec cp {} ./src/bindings/arm-unknown-linux-gnueabi.rs \;
