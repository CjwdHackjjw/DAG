#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$PROJECT_ROOT/benchmark"
INSTALL_SYSTEM_DEPS=0
SKIP_BUILD=0
SKIP_RUN=0
USER_INSTALL=1

usage() {
    cat <<'USAGE'
Usage: ./reproduce_local.sh [OPTIONS]

Reproduce the local benchmark experiment for FREE without creating a Python virtual environment.

Options:
  --install-system-deps   Install Ubuntu/Debian system dependencies with apt.
  --system-pip            Install Python packages into the active Python environment instead of using pip --user.
  --skip-build            Skip cargo release build.
  --skip-run              Install dependencies and build, but do not run fab local.
  -h, --help              Show this help message.

Examples:
  ./reproduce_local.sh
  ./reproduce_local.sh --install-system-deps
  ./reproduce_local.sh --system-pip
  ./reproduce_local.sh --skip-build
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-system-deps)
            INSTALL_SYSTEM_DEPS=1
            shift
            ;;
        --system-pip)
            USER_INSTALL=0
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --skip-run)
            SKIP_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

log() {
    printf '\n[reproduce-local] %s\n' "$1"
}

require_command() {
    local command_name="$1"
    local install_hint="$2"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Missing required command: $command_name" >&2
        echo "Install hint: $install_hint" >&2
        exit 1
    fi
}

if [[ "$INSTALL_SYSTEM_DEPS" -eq 1 ]]; then
    log "Installing system dependencies with apt"
    sudo apt update
    sudo apt install -y build-essential clang cmake pkg-config libssl-dev tmux python3 python3-pip
else
    log "Skipping system dependency installation"
    echo "If dependencies are missing, rerun with: ./reproduce_local.sh --install-system-deps"
fi

log "Checking required commands"
require_command python3 "sudo apt install python3 python3-pip"
require_command cargo "Install Rust from https://rustup.rs/"
require_command tmux "sudo apt install tmux"
require_command clang "sudo apt install clang"

log "Preparing pip"
python3 -m pip --version >/dev/null 2>&1 || {
    echo "pip is not available for python3." >&2
    echo "Install it with: sudo apt install python3-pip" >&2
    exit 1
}

if [[ "$USER_INSTALL" -eq 1 ]]; then
    log "Installing Python benchmark dependencies with pip --user"
    python3 -m pip install --user --upgrade pip setuptools wheel
    python3 -m pip install --user -r "$BENCHMARK_DIR/requirements.txt"
    export PATH="$HOME/.local/bin:$PATH"
else
    log "Installing Python benchmark dependencies into the active Python environment"
    python3 -m pip install --upgrade pip setuptools wheel
    python3 -m pip install -r "$BENCHMARK_DIR/requirements.txt"
fi

require_command fab "python3 -m pip install --user -r $BENCHMARK_DIR/requirements.txt"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "Building Rust binaries in release mode"
    cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml"
else
    log "Skipping Rust build"
fi

if [[ "$SKIP_RUN" -eq 1 ]]; then
    log "Environment is ready. Skipping benchmark run by request"
    echo "To run later:"
    echo "  cd $BENCHMARK_DIR"
    echo "  fab local"
    exit 0
fi

log "Running local benchmark"
cd "$BENCHMARK_DIR"
fab local

log "Local benchmark finished"
echo "Check benchmark output above and generated files under $BENCHMARK_DIR if any were produced."
