#!/usr/bin/env sh
# entrypoint.sh — run nuclei against TARGET_URL and write JSONL output.
set -eu

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"

# Strip URL fragment (#...) — fragments are client-side routing only and
# cause HTTP scanners to send malformed or empty requests.
TARGET_URL=$(printf '%s' "${TARGET_URL}" | sed 's/#.*//')

TEMPLATES="${HOME}/nuclei-templates"

mkdir -p "${OUTPUT_DIR}"

echo "[nuclei-runner] TARGET_URL=${TARGET_URL}"
echo "[nuclei-runner] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[nuclei-runner] nuclei version: $(nuclei -version 2>&1 | head -1)"

if [ ! -d "${TEMPLATES}" ] || [ -z "$(ls -A "${TEMPLATES}" 2>/dev/null)" ]; then
    echo "[nuclei-runner] ERROR: templates not found at '${TEMPLATES}'" >&2
    exit 1
fi

# Use http/ subtree (nuclei-templates v9+ layout).
# Fall back to entire templates dir if http/ is absent.
if [ -d "${TEMPLATES}/http" ]; then
    TEMPLATE_ARG="http"
else
    TEMPLATE_ARG="."
fi

echo "[nuclei-runner] Starting scan (templates: ${TEMPLATE_ARG})..."

exec nuclei \
    -u "${TARGET_URL}" \
    -t "${TEMPLATE_ARG}" \
    -severity low,medium,high,critical \
    -json-export "${OUTPUT_DIR}/nuclei.jsonl" \
    -no-interactsh \
    -system-resolvers \
    -stats \
    -v
