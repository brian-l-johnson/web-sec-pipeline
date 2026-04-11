#!/usr/bin/env sh
# entrypoint.sh — run nuclei against TARGET_URL and write JSONL output.
set -eu

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"

mkdir -p "${OUTPUT_DIR}"

echo "[nuclei-runner] TARGET_URL=${TARGET_URL}"
echo "[nuclei-runner] OUTPUT_DIR=${OUTPUT_DIR}"

# Update templates on first run; ignore failure if offline.
nuclei -update-templates 2>/dev/null || true

echo "[nuclei-runner] Starting scan..."

exec nuclei \
    -u "${TARGET_URL}" \
    -t cves,vulnerabilities,misconfiguration,exposures,default-logins \
    -severity medium,high,critical \
    -json-export "${OUTPUT_DIR}/nuclei.jsonl" \
    -no-interactsh \
    -silent
