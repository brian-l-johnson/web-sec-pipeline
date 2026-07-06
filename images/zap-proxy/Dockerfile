FROM ghcr.io/zaproxy/zaproxy:stable

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 8080 = HTTP proxy port (route browser/httpx traffic through ZAP)
# 8090 = ZAP REST API port
EXPOSE 8080 8090

ENTRYPOINT ["/entrypoint.sh"]
