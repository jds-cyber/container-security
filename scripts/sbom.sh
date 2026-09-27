#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/common.sh"

IMAGE="${1:-}"

if [[ -z "$IMAGE" ]]; then
    error "Usage: ./scripts/sbom.sh <docker-image>"
    exit 1
fi

init_log

SCAN_ID=$(date +"%Y-%m-%d_%H%M%S")
SBOM_SCAN_DIR="$ROOT_DIR/$SBOM_DIR/$SCAN_ID"

mkdir -p "$SBOM_SCAN_DIR"

JSON_SBOM="$SBOM_SCAN_DIR/sbom.json"

info "Starting SBOM generation"
log "Starting SBOM generation for image: $IMAGE"

info "Running environment validation..."
"$SCRIPT_DIR/validate.sh" >>"$LOG_FILE" 2>&1

success "Environment validation passed"

info "Generating SBOM..."

docker run --rm \
  -e SSL_CERT_FILE=/tmp/corporate-ca.crt \
  -v "$ROOT_DIR/$CERT_FILE:/tmp/corporate-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  -o json > "$JSON_SBOM"

success "SBOM generation completed"

echo
echo "=========================================="
echo "Container Security Toolkit"
echo "=========================================="
echo "Image : $IMAGE"
echo "SBOM  : $JSON_SBOM"
echo "Log   : $LOG_FILE"
echo "=========================================="

printf '%s\n' "$JSON_SBOM" >&2
