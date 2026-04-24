FROM projectdiscovery/nuclei:latest

# Download templates at build time so they are always present at runtime.
# Stored at /nuclei-templates (world-readable) so the non-root user can read them.
# This runs as root before we drop privileges.
ENV NUCLEI_TEMPLATES_PATH=/nuclei-templates
RUN nuclei -update-templates -ud /nuclei-templates \
 && chmod -R a+r /nuclei-templates

RUN addgroup -g 1000 scanner && adduser -D -u 1000 -G scanner scanner

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
