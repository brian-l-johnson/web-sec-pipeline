FROM ghcr.io/zaproxy/zaproxy:stable

USER root

# envsubst is in gettext-base; jq is handy for debugging report output.
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    gettext-base \
    jq \
 && rm -rf /var/lib/apt/lists/*

COPY automation-plan.yaml /app/automation-plan.yaml
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# ZAP image already drops to a non-root user (zap / uid 1000).
USER zap

ENTRYPOINT ["/app/entrypoint.sh"]
