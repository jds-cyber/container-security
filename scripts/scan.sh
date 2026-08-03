#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
init_log
log "Scan started"

IMAGE="$1"

if [ -z "$IMAGE" ]; then
    echo "Usage: $0 <docker-image>"
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="grype-reports"

mkdir -p "$REPORT_DIR"

TABLE_REPORT="${REPORT_DIR}/${IMAGE//[:\/]/_}_${TIMESTAMP}.txt"
JSON_REPORT="${REPORT_DIR}/${IMAGE//[:\/]/_}_${TIMESTAMP}.json"
HTML_REPORT="${REPORT_DIR}/${IMAGE//[:\/]/_}_${TIMESTAMP}.html"

GRYPE_IMAGE="registry.access.redhat.com/hi/grype:latest"

echo "Updating vulnerability database..."

docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$(pwd)/zscaler-root-ca.crt:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  db update

echo "Scanning image: $IMAGE"

# Table output
docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$(pwd)/zscaler-root-ca.crt:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  "$IMAGE" \
  -o table | tee "$TABLE_REPORT"


# JSON output
docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$(pwd)/zscaler-root-ca.crt:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  "$IMAGE" \
  -o json > "$JSON_REPORT"


# HTML output
docker run --rm \
  -e SSL_CERT_FILE=/tmp/zscaler-root-ca.crt \
  -v "$(pwd)/zscaler-root-ca.crt:/tmp/zscaler-root-ca.crt:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$GRYPE_IMAGE" \
  "$IMAGE" \
  -o template \
  -t /opt/grype/templates/html.tmpl > "$HTML_REPORT"


echo ""
echo "===================================="
echo "Reports created:"
echo "------------------------------------"
echo "Table : $TABLE_REPORT"
echo "JSON  : $JSON_REPORT"
echo "HTML  : $HTML_REPORT"
echo "===================================="
