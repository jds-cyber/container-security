#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$ROOT_DIR/config/config.env"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[ OK ]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

#########################################
# Logging Functions
#########################################

timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

LOG_FILE=""

init_log() {
    mkdir -p "$ROOT_DIR/$LOG_DIR"
    LOG_FILE="$ROOT_DIR/$LOG_DIR/scan-$(date +%Y%m%d_%H%M%S).log"
    touch "$LOG_FILE"
}

log() {
    echo "[$(timestamp)] $1" >> "$LOG_FILE"
}
