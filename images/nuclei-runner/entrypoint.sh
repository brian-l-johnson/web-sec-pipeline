#!/usr/bin/env sh
# entrypoint.sh — run nuclei against TARGET_URL and write JSONL output.
set -eu

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"

TEMPLATES="${NUCLEI_TEMPLATES_PATH:-/nuclei-templates}"

mkdir -p "${OUTPUT_DIR}"

echo "[nuclei-runner] TARGET_URL=${TARGET_URL}"
echo "[nuclei-runner] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[nuclei-runner] TEMPLATES=${TEMPLATES}"

# Verify templates exist — fail fast with a clear message rather than
# the opaque "no templates provided for scan" error.
if [ ! -d "${TEMPLATES}" ] || [ -z "$(ls -A "${TEMPLATES}" 2>/dev/null)" ]; then
    echo "[nuclei-runner] ERROR: templates directory '${TEMPLATES}' is empty or missing" >&2
    exit 1
fi

echo "[nuclei-runner] Starting scan..."

# Use explicit per-directory -t flags (v3 syntax; comma-separated shorthand
# is v2 only and silently produces "no templates provided for scan" in v3).
exec nuclei \
    -u "${TARGET_URL}" \
    -t "${TEMPLATES}/cves/" \
    -t "${TEMPLATES}/vulnerabilities/" \
    -t "${TEMPLATES}/misconfiguration/" \
    -t "${TEMPLATES}/exposures/" \
    -t "${TEMPLATES}/default-logins/" \
    -severity medium,high,critical \
    -ud "${TEMPLATES}" \
    -json-export "${OUTPUT_DIR}/nuclei.jsonl" \
    -no-interactsh \
    -silent
