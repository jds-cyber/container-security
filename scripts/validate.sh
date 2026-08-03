#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

info "Validating environment..."

if ! docker info >/dev/null 2>&1; then
    error "Docker Desktop is not running."
    exit 1
fi
success "Docker Desktop is running."

if [ ! -S /var/run/docker.sock ]; then
    error "Docker socket not found."
    exit 1
fi
success "Docker socket found."

if [ ! -f "$ROOT_DIR/$CERT_FILE" ]; then
    error "Certificate not found: $ROOT_DIR/$CERT_FILE"
    exit 1
fi
success "Certificate found."

success "Environment validation complete."
