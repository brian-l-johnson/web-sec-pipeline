#!/bin/bash
set -e

PROXY_PORT="${PROXY_PORT:-8080}"
API_PORT="${API_PORT:-8090}"
API_KEY="${ZAP_API_KEY:-changeme}"
SESSION_NAME="${ZAP_SESSION:-}"

ARGS=(
  -daemon
  -host 0.0.0.0
  -port "${API_PORT}"
  -config network.localServers.mainProxy.port="${PROXY_PORT}"
  -config api.key="${API_KEY}"
  -config api.addrs.addr.name=".*"
  -config api.addrs.addr.regex=true
  -config connection.dnsTtlSuccessfulQueries=-1
)

# Named session: resume if it exists on the results PVC, else create fresh.
if [ -n "${SESSION_NAME}" ]; then
  SESSION_DIR="${RESULTS_DIR:-/results}/sessions"
  SESSION_FILE="${SESSION_DIR}/${SESSION_NAME}.session"
  mkdir -p "${SESSION_DIR}"
  if [ -f "${SESSION_FILE}" ]; then
    ARGS+=(-newsession "${SESSION_FILE}" -session "${SESSION_FILE}")
  else
    ARGS+=(-newsession "${SESSION_FILE}")
  fi
fi

exec /zap/zap.sh "${ARGS[@]}"
