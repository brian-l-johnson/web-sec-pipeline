#!/usr/bin/env bash
# entrypoint.sh — substitute env vars into automation plan and launch ZAP.
set -euo pipefail

: "${TARGET_URL:?TARGET_URL env var is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR env var is required}"
SCAN_PROFILE="${SCAN_PROFILE:-passive}"

mkdir -p "${OUTPUT_DIR}"

PLAN="/tmp/automation-plan-${$}.yaml"

# Substitute TARGET_URL and OUTPUT_DIR placeholders.
envsubst '${TARGET_URL} ${OUTPUT_DIR}' < /app/automation-plan.yaml > "${PLAN}"

# For passive-only profiles, remove the activeScan job block so ZAP skips it.
if [[ "${SCAN_PROFILE}" == "passive" ]]; then
    python3 - "${PLAN}" <<'PYEOF'
import sys, yaml

plan_file = sys.argv[1]
with open(plan_file) as f:
    plan = yaml.safe_load(f)

plan["jobs"] = [j for j in plan.get("jobs", []) if j.get("type") != "activeScan"]

with open(plan_file, "w") as f:
    yaml.dump(plan, f, default_flow_style=False)
PYEOF
fi

echo "[zap-runner] TARGET_URL=${TARGET_URL}"
echo "[zap-runner] SCAN_PROFILE=${SCAN_PROFILE}"
echo "[zap-runner] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[zap-runner] Starting ZAP automation framework..."

exec zap.sh -cmd -autorun "${PLAN}"
