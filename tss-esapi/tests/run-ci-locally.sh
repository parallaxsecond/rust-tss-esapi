#!/usr/bin/env bash

# Copyright 2026 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Run CI checks locally on Fedora with a swtpm simulator.
# Replicates the CI jobs from .github/workflows/ci.yml without Docker.
#
# Usage: dbus-run-session -- ./tests/run-ci-locally.sh [JOB...]
#
# JOB can be a number, a keyword, or a display name (case-insensitive):
#   1  spelling          "Check spelling"
#   2  formatting        "Check formatting"
#   3  msrv              "MSRV build (1.85.0)"
#   4  build             "Build with generate-bindings"
#   5  clippy-msrv       "Clippy MSRV (1.85.0)"
#   6  clippy-latest     "Clippy latest"
#   7  docs              "Check documentation"
#   8  tests             "Tests with generate-bindings"
#   9  valgrind          "Valgrind tests (1.85.0)"
#   all                  Run all jobs
#   list                 Show available jobs
#
# If no JOB is given, "all" is assumed.
# Multiple jobs can be specified: ./tests/run-ci-locally.sh 5 6 docs
#
# Prerequisites (Fedora):
#   dnf install swtpm swtpm-tools tpm2-abrmd tpm2-tools tpm2-tss-devel \
#               rust clippy cargo llvm llvm-devel clang pkg-config \
#               codespell dbus-daemon

set -euf -o pipefail

##########################
# Check required tools   #
##########################
REQUIRED_CMDS=(
    "cargo:Rust toolchain"
    "rustup:Rust toolchain manager"
    "clippy-driver:Clippy (rustup component add clippy)"
    "rustfmt:rustfmt (rustup component add rustfmt)"
    "pkg-config:pkg-config"
    "clang:Clang/LLVM"
    "swtpm:Software TPM (swtpm)"
    "swtpm_setup:Software TPM setup (swtpm-tools)"
    "tpm2-abrmd:TPM2 Access Broker (tpm2-abrmd)"
    "tpm2_pcrread:TPM2 tools (tpm2-tools)"
)

MISSING=()
for entry in "${REQUIRED_CMDS[@]}"; do
    cmd="${entry%%:*}"
    desc="${entry#*:}"
    if ! command -v "$cmd" &>/dev/null; then
        MISSING+=("  - $cmd ($desc)")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "ERROR: Missing required tools:"
    printf '%s\n' "${MISSING[@]}"
    echo ""
    echo "Install them and try again."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${PROJECT_DIR}/tss-esapi"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

SWTPM_PID=""
ABRMD_PID=""
TPMDIR=""

function cleanup {
    if [[ -n "$ABRMD_PID" ]]; then
        kill "$ABRMD_PID" 2>/dev/null || true
        wait "$ABRMD_PID" 2>/dev/null || true
    fi
    if [[ -n "$SWTPM_PID" ]]; then
        kill "$SWTPM_PID" 2>/dev/null || true
        wait "$SWTPM_PID" 2>/dev/null || true
    fi
    if [[ -n "$TPMDIR" && -d "$TPMDIR" ]]; then
        rm -rf "$TPMDIR"
    fi
}
trap cleanup EXIT

function start_tpm {
    if [[ -n "$SWTPM_PID" ]]; then
        return
    fi

    # Kill leftover processes from previous runs
    pkill -f "swtpm socket.*port=2321" 2>/dev/null || true
    pkill -f "tpm2-abrmd" 2>/dev/null || true
    sleep 1

    TPMDIR=$(mktemp -d)
    swtpm_setup --tpm2 \
        --tpmstate "${TPMDIR}" \
        --createek --decryption --create-ek-cert \
        --create-platform-cert \
        --pcr-banks sha1,sha256 \
        --display

    swtpm socket --tpm2 \
        --tpmstate dir="${TPMDIR}" \
        --flags startup-clear \
        --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 \
        --daemon
    SWTPM_PID=$(pgrep -n swtpm)

    tpm2-abrmd \
        --logger=stdout \
        --tcti=swtpm: \
        --allow-root \
        --session \
        --flush-all &
    ABRMD_PID=$!
    sleep 2
}

function run_job {
    local name="$1"
    shift
    echo ""
    echo -e "${BOLD}======== ${name} ========${RESET}"
    if "$@"; then
        RESULTS+=("${GREEN}PASS${RESET} ${name}")
        ((PASS++)) || true
    else
        RESULTS+=("${RED}FAIL${RESET} ${name}")
        ((FAIL++)) || true
    fi
}

function skip_job {
    local name="$1"
    local reason="$2"
    echo ""
    echo -e "${BOLD}======== ${name} ========${RESET}"
    echo -e "${YELLOW}SKIP: ${reason}${RESET}"
    RESULTS+=("${YELLOW}SKIP${RESET} ${name} (${reason})")
    ((SKIP++)) || true
}

function job_spelling {
    cd "${CRATE_DIR}"
    if codespell --version &>/dev/null; then
        run_job "Check spelling" \
            codespell --ignore-words-list "crate,daa,keypair,AcSend,ser" \
            --skip "*/target,*-sys,${CRATE_DIR}/examples/symmetric_file_encrypt_decrypt_example.txt" \
            "${CRATE_DIR}"
    else
        skip_job "Check spelling" "codespell not installed"
    fi
}

function job_formatting {
    cd "${PROJECT_DIR}"
    run_job "Check formatting" cargo fmt --all -- --check
}

function job_msrv {
    cd "${CRATE_DIR}"
    if rustup toolchain list | grep -q "1.85"; then
        cp tests/Cargo.lock.frozen ../Cargo.lock
        run_job "MSRV build (1.85.0)" cargo +1.85.0 build -p tss-esapi
        rm -f ../Cargo.lock
    else
        skip_job "MSRV build (1.85.0)" "rustup toolchain 1.85.0 not installed (rustup install 1.85.0)"
    fi
}

function job_build {
    cd "${CRATE_DIR}"
    run_job "Build with generate-bindings" \
        cargo build --features generate-bindings
}

function job_clippy_msrv {
    cd "${CRATE_DIR}"
    if rustup toolchain list | grep -q "1.85"; then
        cp tests/Cargo.lock.frozen ../Cargo.lock
        run_job "Clippy MSRV (1.85.0)" \
            cargo +1.85.0 clippy --all-targets --all-features -- -D clippy::all -D clippy::cargo
        rm -f ../Cargo.lock
    else
        skip_job "Clippy MSRV (1.85.0)" "rustup toolchain 1.85.0 not installed"
    fi
}

function job_clippy_latest {
    cd "${CRATE_DIR}"
    run_job "Clippy latest" \
        cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::cargo
}

function job_docs {
    cd "${CRATE_DIR}"
    run_job "Check documentation" \
        env RUSTDOCFLAGS="-Dwarnings" cargo doc --document-private-items --no-deps
}

function job_tests {
    cd "${CRATE_DIR}"
    start_tpm
    run_job "Tests with generate-bindings" \
        env TEST_TCTI=tabrmd:bus_type=session \
            RUST_BACKTRACE=1 RUST_LOG=info \
        cargo test --features generate-bindings -- --test-threads=1 --nocapture
}

function job_valgrind {
    cd "${CRATE_DIR}"
    if ! command -v valgrind &>/dev/null; then
        skip_job "Valgrind tests" "valgrind not installed"
        return
    fi
    if ! cargo valgrind --help &>/dev/null; then
        skip_job "Valgrind tests" "cargo-valgrind not installed (cargo install cargo-valgrind)"
        return
    fi
    start_tpm
    if rustup toolchain list | grep -q "1.85"; then
        cp tests/Cargo.lock.frozen ../Cargo.lock
        run_job "Valgrind tests (1.85.0)" \
            env TEST_TCTI=tabrmd:bus_type=session \
                RUST_BACKTRACE=1 RUST_LOG=info \
            cargo +1.85.0 valgrind test -- --test-threads=1 --nocapture
        rm -f ../Cargo.lock
    else
        skip_job "Valgrind tests (1.85.0)" "rustup toolchain 1.85.0 not installed"
    fi
}

function print_summary {
    echo ""
    echo -e "${BOLD}======== Summary ========${RESET}"
    for r in "${RESULTS[@]}"; do
        echo -e "  $r"
    done
    echo ""
    echo -e "  ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}, ${YELLOW}${SKIP} skipped${RESET}"

    if [[ $FAIL -gt 0 ]]; then
        echo ""
        echo -e "${RED}${BOLD}CI would FAIL${RESET}"
        return 1
    else
        echo ""
        echo -e "${GREEN}${BOLD}CI would PASS${RESET}"
        return 0
    fi
}

# Job registry: NUM:KEYWORD:DISPLAY_NAME:FUNCTION
JOB_REGISTRY=(
    "1:spelling:Check spelling:job_spelling"
    "2:formatting:Check formatting:job_formatting"
    "3:msrv:MSRV build (1.85.0):job_msrv"
    "4:build:Build with generate-bindings:job_build"
    "5:clippy-msrv:Clippy MSRV (1.85.0):job_clippy_msrv"
    "6:clippy-latest:Clippy latest:job_clippy_latest"
    "7:docs:Check documentation:job_docs"
    "8:tests:Tests with generate-bindings:job_tests"
    "9:valgrind:Valgrind tests (1.85.0):job_valgrind"
)

ALL_ORDER=(1 2 3 4 5 6 7 8 9)

function list_jobs {
    echo "Available jobs:"
    for entry in "${JOB_REGISTRY[@]}"; do
        IFS=: read -r num keyword display _func <<< "$entry"
        printf "  %s  %-16s  %s\n" "$num" "$keyword" "\"$display\""
    done
    echo ""
    echo "  all                 Run all jobs"
    echo "  list                Show this list"
}

function resolve_job {
    local input="$1"
    local input_lower
    input_lower=$(echo "$input" | tr '[:upper:]' '[:lower:]')

    for entry in "${JOB_REGISTRY[@]}"; do
        IFS=: read -r num keyword display func <<< "$entry"
        local display_lower
        display_lower=$(echo "$display" | tr '[:upper:]' '[:lower:]')

        if [[ "$input" == "$num" || "$input_lower" == "$keyword" || "$input_lower" == "$display_lower" ]]; then
            echo "$func"
            return 0
        fi
    done
    return 1
}

# Parse arguments
JOBS=("$@")
if [[ ${#JOBS[@]} -eq 0 ]]; then
    JOBS=("all")
fi

for job in "${JOBS[@]}"; do
    if [[ "$job" == "all" ]]; then
        for num in "${ALL_ORDER[@]}"; do
            func=$(resolve_job "$num")
            "$func"
        done
    elif [[ "$job" == "list" || "$job" == "--list" || "$job" == "-l" ]]; then
        list_jobs
        exit 0
    else
        func=$(resolve_job "$job")
        if [[ -n "$func" ]]; then
            "$func"
        else
            echo "Unknown job: $job"
            echo ""
            list_jobs
            exit 1
        fi
    fi
done

print_summary
