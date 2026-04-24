FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Install mitmproxy in an isolated venv so its dependency tree cannot
# overwrite or downgrade packages that playwright depends on (greenlet,
# anyio, h2, etc.).  Only mitmdump needs to be on PATH for crawl.py.
RUN python3 -m venv /opt/mitm-venv \
 && /opt/mitm-venv/bin/pip install --no-cache-dir "mitmproxy>=10.4,<12" \
 && ln -sf /opt/mitm-venv/bin/mitmdump /usr/local/bin/mitmdump

COPY har_dump.py crawl.py ./

# The Playwright base image ships with pwuser at UID/GID 1000.
# mitmproxy writes its CA cert to $HOME/.mitmproxy on first run.
RUN mkdir -p /home/pwuser/.mitmproxy \
 && chown -R 1000:1000 /home/pwuser/.mitmproxy /app

ENV HOME=/home/pwuser

USER 1000

ENTRYPOINT ["python3", "/app/crawl.py"]
