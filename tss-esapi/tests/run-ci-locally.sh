#!/usr/bin/env bash

# Copyright 2026 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Run CI checks locally inside a container, mirroring .github/workflows/ci.yml.
# See `./tests/run-ci-locally.sh help` for usage.

set -euf -o pipefail

#################
# Configuration #
#################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROJECT_DIR_IN_CONTAINER="/tmp/rust-tss-esapi"
CRATE_DIR_IN_CONTAINER="${PROJECT_DIR_IN_CONTAINER}/tss-esapi"

DEFAULT_DOCKERFILE="Dockerfile-fedora-full"
DEFAULT_IMAGE_TAG="rust-tss-esapi-fedora:latest"

TSS_ESAPI_MSRV="${TSS_ESAPI_MSRV:-1.85.0}"
TSS_ESAPI_CONTAINER_RUNTIME="${TSS_ESAPI_CONTAINER_RUNTIME:-docker}"
TSS_ESAPI_DOCKERFILE="${TSS_ESAPI_DOCKERFILE:-${SCRIPT_DIR}/${DEFAULT_DOCKERFILE}}"
TSS_ESAPI_IMAGE_TAG="${TSS_ESAPI_IMAGE_TAG:-${DEFAULT_IMAGE_TAG}}"

##############
# CI results #
##############
PASS=0
FAIL=0
RESULTS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

###########
# Helpers #
###########
function in_container {
    "${TSS_ESAPI_CONTAINER_RUNTIME}" run --rm \
        -v "${PROJECT_DIR}:${PROJECT_DIR_IN_CONTAINER}" \
        -w "${CRATE_DIR_IN_CONTAINER}" \
        "${TSS_ESAPI_IMAGE_TAG}" \
        "$@"
}

function in_container_env {
    # Like in_container but takes KEY=VAL env pairs before the command.
    local envs=()
    while [[ $# -gt 0 && "$1" == *"="* ]]; do
        envs+=(-e "$1")
        shift
    done
    "${TSS_ESAPI_CONTAINER_RUNTIME}" run --rm \
        "${envs[@]}" \
        -v "${PROJECT_DIR}:${PROJECT_DIR_IN_CONTAINER}" \
        -w "${CRATE_DIR_IN_CONTAINER}" \
        "${TSS_ESAPI_IMAGE_TAG}" \
        "$@"
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

####################
# Setup functions  #
####################
# Verify the configured runtime and Dockerfile exist on the host.
function preflight {
    if ! command -v "${TSS_ESAPI_CONTAINER_RUNTIME}" &>/dev/null; then
        echo "ERROR: container runtime '${TSS_ESAPI_CONTAINER_RUNTIME}' not found in PATH"
        echo "       (set TSS_ESAPI_CONTAINER_RUNTIME to override)"
        exit 1
    fi
    if [[ ! -f "${TSS_ESAPI_DOCKERFILE}" ]]; then
        echo "ERROR: Dockerfile not found: ${TSS_ESAPI_DOCKERFILE}"
        echo "       (set TSS_ESAPI_DOCKERFILE to override)"
        exit 1
    fi
}

# Build (or rebuild via cache) the image used to run jobs.
function build_image {
    echo -e "${BOLD}Building image ${TSS_ESAPI_IMAGE_TAG} from ${TSS_ESAPI_DOCKERFILE}...${RESET}"
    "${TSS_ESAPI_CONTAINER_RUNTIME}" build \
        -t "${TSS_ESAPI_IMAGE_TAG}" \
        -f "${TSS_ESAPI_DOCKERFILE}" \
        "$(dirname "${TSS_ESAPI_DOCKERFILE}")"
}

# Probe the image once for every binary the jobs depend on. Abort with a
# combined "ERROR: Missing required tools" report if any are absent.
function check_required_tools {
    local required_cmds=(
        "cargo:Rust toolchain"
        "rustup:Rust toolchain manager"
        "rustfmt:rustfmt (rustup component add rustfmt)"
        "clippy-driver:Clippy (rustup component add clippy)"
        "swtpm:Software TPM (swtpm)"
        "swtpm_setup:Software TPM setup (swtpm-tools)"
        "valgrind:Valgrind"
        "cargo-valgrind:cargo-valgrind subcommand (cargo install cargo-valgrind)"
        "codespell:codespell"
        "pkg-config:pkg-config"
        "clang:Clang/LLVM"
    )

    local cmd_names=()
    for entry in "${required_cmds[@]}"; do
        cmd_names+=("${entry%%:*}")
    done

    echo -e "${BOLD}Checking required tools in image...${RESET}"
    local missing
    missing=$(in_container bash -c "
        for cmd in ${cmd_names[*]}; do
            if ! command -v \"\$cmd\" >/dev/null 2>&1; then
                echo \"\$cmd\"
            fi
        done
    " || true)

    if [[ -n "$missing" ]]; then
        echo "ERROR: Missing required tools in image ${TSS_ESAPI_IMAGE_TAG}:"
        while IFS= read -r missing_cmd; do
            for entry in "${required_cmds[@]}"; do
                local cmd="${entry%%:*}"
                local desc="${entry#*:}"
                if [[ "$cmd" == "$missing_cmd" ]]; then
                    echo "  - $cmd ($desc)"
                    break
                fi
            done
        done <<< "$missing"
        echo ""
        echo "Either fix the Dockerfile (${TSS_ESAPI_DOCKERFILE}) or use the default {$DEFAULT_DOCKERFILE}."
        exit 1
    fi
}

# One-shot setup wrapper called before any test job runs.
function ensure_image_ready {
    preflight
    build_image
    check_required_tools
}

###################
# Job definitions #
###################
function job_spelling {
    run_job "Check spelling" \
        in_container codespell \
            --ignore-words-list "crate,daa,keypair,AcSend,ser" \
            --exclude-file examples/symmetric_file_encrypt_decrypt_example.txt
}

function job_formatting {
    run_job "Check formatting" \
        in_container cargo fmt --all -- --check
}

function job_msrv {
    local lockfile="${PROJECT_DIR}/Cargo.lock"
    local backup="${lockfile}.bak"
    cp -p -- "${lockfile}" "${backup}"
    run_job "MSRV build (${TSS_ESAPI_MSRV})" \
        in_container_env RUST_TOOLCHAIN_VERSION="${TSS_ESAPI_MSRV}" \
            bash -c 'rustup override set "${RUST_TOOLCHAIN_VERSION}" \
                && cp tests/Cargo.lock.frozen ../Cargo.lock \
                && cargo build -p tss-esapi'
    mv -- "${backup}" "${lockfile}"
}

function job_build {
    run_job "Build with generate-bindings" \
        in_container cargo build --features generate-bindings
}

function job_clippy_msrv {
    run_job "Clippy MSRV (${TSS_ESAPI_MSRV})" \
        in_container_env RUST_TOOLCHAIN_VERSION="${TSS_ESAPI_MSRV}" \
            ./tests/lint-checks.sh
}

function job_clippy_latest {
    run_job "Clippy latest" \
        in_container ./tests/lint-checks.sh
}

function job_docs {
    run_job "Check documentation" \
        in_container_env RUSTDOCFLAGS=-Dwarnings \
            cargo doc --document-private-items --no-deps
}

function job_tests {
    run_job "Tests with generate-bindings" \
        in_container ./tests/all-fedora.sh
}

function job_valgrind {
    run_job "Valgrind tests (${TSS_ESAPI_MSRV})" \
        in_container_env RUST_TOOLCHAIN_VERSION="${TSS_ESAPI_MSRV}" \
            ./tests/valgrind.sh
}

function print_summary {
    echo ""
    echo -e "${BOLD}======== Summary ========${RESET}"
    for r in "${RESULTS[@]}"; do
        echo -e "  $r"
    done
    echo ""
    echo -e "  ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"

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

################
# Job registry #
################
JOB_REGISTRY=(
    "1:spelling:Check spelling:job_spelling"
    "2:formatting:Check formatting:job_formatting"
    "3:msrv:MSRV build (${TSS_ESAPI_MSRV}):job_msrv"
    "4:build:Build with generate-bindings:job_build"
    "5:clippy-msrv:Clippy MSRV (${TSS_ESAPI_MSRV}):job_clippy_msrv"
    "6:clippy-latest:Clippy latest:job_clippy_latest"
    "7:docs:Check documentation:job_docs"
    "8:tests:Tests with generate-bindings:job_tests"
    "9:valgrind:Valgrind tests (${TSS_ESAPI_MSRV}):job_valgrind"
)

ALL_ORDER=(1 2 3 4 5 6 7 8 9)

function show_help {
    cat <<EOF
Run CI checks locally inside a container, mirroring .github/workflows/ci.yml.

Usage: ./tests/run-ci-locally.sh [JOB...]

If no JOB is given, this help is shown. Use 'all' to run every job.

Available jobs:
EOF
    for entry in "${JOB_REGISTRY[@]}"; do
        IFS=: read -r num keyword display _func <<< "$entry"
        printf "  %s  %-16s  %s\n" "$num" "$keyword" "$display"
    done
    cat <<EOF
  all                  Run all jobs
  help                 Show this help

JOB can be the number, the keyword, or the display name (case-insensitive).
Multiple jobs may be specified, e.g.: ./tests/run-ci-locally.sh 5 6 docs

Environment variables:
  TSS_ESAPI_MSRV               MSRV (default: 1.85.0)
  TSS_ESAPI_CONTAINER_RUNTIME  Docker-compatible container runtime
                               (default: docker; e.g. podman)
  TSS_ESAPI_DOCKERFILE         Path to the Dockerfile to build from
                               (default: ./Dockerfile-fedora-full)
  TSS_ESAPI_IMAGE_TAG          Image tag
                               (default: rust-tss-esapi-fedora:latest)

If the image is missing required tools (rustup, swtpm, valgrind, codespell,
etc.), the script aborts before running any job.

EOF
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

####################
# Argument parsing #
####################
JOBS=("$@")
if [[ ${#JOBS[@]} -eq 0 ]]; then
    JOBS=("help")
fi

# If the user asked for help (alone or alongside other jobs), short-circuit.
# No image setup, no jobs run.
for job in "${JOBS[@]}"; do
    if [[ "$job" == "help" || "$job" == "--help" || "$job" == "-h" ]]; then
        show_help
        exit 0
    fi
done

# Real work: build the image and verify it's complete before running anything.
ensure_image_ready

for job in "${JOBS[@]}"; do
    if [[ "$job" == "all" ]]; then
        for num in "${ALL_ORDER[@]}"; do
            func=$(resolve_job "$num")
            "$func"
        done
    else
        func=$(resolve_job "$job")
        if [[ -n "$func" ]]; then
            "$func"
        else
            echo "Unknown job: $job"
            echo ""
            show_help
            exit 1
        fi
    fi
done

print_summary
