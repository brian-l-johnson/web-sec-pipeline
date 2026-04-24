#!/usr/bin/env sh
# entrypoint.sh — run nuclei against TARGET_URL and write JSONL output.
set -eu

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"

TEMPLATES="${HOME}/nuclei-templates"

mkdir -p "${OUTPUT_DIR}"

echo "[nuclei-runner] TARGET_URL=${TARGET_URL}"
echo "[nuclei-runner] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[nuclei-runner] HOME=${HOME}"
echo "[nuclei-runner] TEMPLATES=${TEMPLATES}"
echo "[nuclei-runner] nuclei version: $(nuclei -version 2>&1 | head -1)"

# Dump top-level template directory so we can see the actual structure.
echo "[nuclei-runner] templates top-level:"
ls "${TEMPLATES}/" 2>&1 | head -30 || echo "(ls failed)"

if [ ! -d "${TEMPLATES}" ] || [ -z "$(ls -A "${TEMPLATES}" 2>/dev/null)" ]; then
    echo "[nuclei-runner] ERROR: templates not found at '${TEMPLATES}'" >&2
    exit 1
fi

echo "[nuclei-runner] Starting scan..."

# Use the http/ subtree which covers cves, vulnerabilities, misconfiguration
# etc. in the restructured nuclei-templates layout (templates v9+).
# Fall back to scanning everything if http/ doesn't exist.
if [ -d "${TEMPLATES}/http" ]; then
    TEMPLATE_ARG="-t http"
else
    TEMPLATE_ARG="-t ."
fi

echo "[nuclei-runner] template arg: ${TEMPLATE_ARG}"

exec nuclei \
    -u "${TARGET_URL}" \
    ${TEMPLATE_ARG} \
    -severity medium,high,critical \
    -json-export "${OUTPUT_DIR}/nuclei.jsonl" \
    -no-interactsh \
    -silent
