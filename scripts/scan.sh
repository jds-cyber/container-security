#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/common.sh"

IMAGE="${1:-}"

if [[ -z "$IMAGE" ]]; then
    error "Usage: ./scripts/scan.sh <docker-image>"
    exit 1
fi

init_log

SCAN_ID=$(date +"%Y-%m-%d_%H%M%S")
SCAN_DIR="$ROOT_DIR/$REPORT_DIR/$SCAN_ID"

mkdir -p "$SCAN_DIR"

TABLE_REPORT="$SCAN_DIR/report.txt"
JSON_REPORT="$SCAN_DIR/report.json"

info "Starting security scan"
log "Starting scan for image: $IMAGE"

info "Running environment validation..."
"$SCRIPT_DIR/validate.sh" >>"$LOG_FILE" 2>&1

success "Environment validation passed"

info "Updating Grype vulnerability database..."

docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$ROOT_DIR/$CERT_FILE:/tmp/zscaler-root-ca.crt:ro" \
  "$GRYPE_IMAGE" \
  db update >>"$LOG_FILE" 2>&1

success "Database is current"

info "Scanning image..."

docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$ROOT_DIR/$CERT_FILE:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  "docker:$IMAGE" \
  -o table > "$TABLE_REPORT"

docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$ROOT_DIR/$CERT_FILE:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  "docker:$IMAGE" \
  -o json > "$JSON_REPORT"

success "Scan completed"

echo
echo "=========================================="
echo "Container Security Toolkit"
echo "=========================================="
echo "Image   : $IMAGE"
echo "Reports : $SCAN_DIR"
echo "Log     : $LOG_FILE"
echo "=========================================="
