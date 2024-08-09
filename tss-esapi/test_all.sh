#!/usr/bin/env bash

set -eux

CARGO="${CARGO:-cargo}"
export TPM2_TSS_PATH="${TPM2_TSS_PATH:-$HOME/tpm2-tss-3.2.2}"

NUM=1
t() {
    echo "TEST ${NUM}"
    ${CARGO} t --no-run --no-default-features --features 'generate-bindings integration-tests serde'
    NUM=$((NUM + 1))
}

DEFAULT=('' '--no-default-features')

for X in "${DEFAULT[@]}" ; do
    t $X --features 'generate-bindings'
    t $X --features 'generate-bindings integration-tests'
    t $X --features 'generate-bindings integration-tests serde'
    t $X --features 'generate-bindings integration-tests serde abstraction'
done
