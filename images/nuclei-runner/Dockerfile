FROM projectdiscovery/nuclei:latest

# nuclei image runs as root by default; create a non-root user.
RUN addgroup -g 1000 scanner && adduser -D -u 1000 -G scanner scanner

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
