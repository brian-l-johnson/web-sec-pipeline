FROM projectdiscovery/nuclei:latest

# Clone the nuclei-templates repo at build time.
# git clone exits non-zero on failure so the build fails loudly rather than
# silently producing an image with an empty templates directory.
RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates \
 && chmod -R a+r /nuclei-templates \
 && apk del git

ENV NUCLEI_TEMPLATES_PATH=/nuclei-templates

RUN addgroup -g 1000 scanner && adduser -D -u 1000 -G scanner scanner

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
