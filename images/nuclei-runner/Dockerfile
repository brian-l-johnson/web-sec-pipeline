FROM projectdiscovery/nuclei:latest

# Clone templates at build time so they are always present at runtime.
RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates \
 && chmod -R a+r /nuclei-templates \
 && apk del git

# Create non-root user and symlink templates into their home dir.
# Nuclei v3 resolves -t paths relative to $HOME/nuclei-templates/ so the
# symlink makes the system-wide clone discoverable without -ud tricks.
RUN addgroup -g 1000 scanner \
 && adduser -D -u 1000 -G scanner scanner \
 && mkdir -p /home/scanner \
 && ln -sf /nuclei-templates /home/scanner/nuclei-templates

ENV HOME=/home/scanner

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
