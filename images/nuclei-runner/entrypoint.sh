#!/usr/bin/env sh
# entrypoint.sh — run nuclei against TARGET_URL and write JSONL output.
set -eu

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"

# Nuclei v3 resolves -t paths relative to $HOME/nuclei-templates/.
# The Dockerfile symlinks $HOME/nuclei-templates -> /nuclei-templates.
TEMPLATES="${HOME}/nuclei-templates"

mkdir -p "${OUTPUT_DIR}"

echo "[nuclei-runner] TARGET_URL=${TARGET_URL}"
echo "[nuclei-runner] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[nuclei-runner] TEMPLATES=${TEMPLATES}"

if [ ! -d "${TEMPLATES}" ] || [ -z "$(ls -A "${TEMPLATES}" 2>/dev/null)" ]; then
    echo "[nuclei-runner] ERROR: templates not found at '${TEMPLATES}'" >&2
    exit 1
fi

echo "[nuclei-runner] Starting scan..."

# Use relative paths — nuclei v3 resolves these against $HOME/nuclei-templates/.
exec nuclei \
    -u "${TARGET_URL}" \
    -t cves \
    -t vulnerabilities \
    -t misconfiguration \
    -t exposures \
    -t default-logins \
    -severity medium,high,critical \
    -json-export "${OUTPUT_DIR}/nuclei.jsonl" \
    -no-interactsh \
    -silent
