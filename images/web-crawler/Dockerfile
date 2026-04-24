FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# python3-venv is not included in the playwright base image on jammy.
RUN apt-get update -q && apt-get install -y --no-install-recommends python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Install mitmproxy in an isolated venv so its dependency tree cannot
# overwrite or downgrade packages that playwright depends on (greenlet,
# anyio, h2, etc.).  Only mitmdump needs to be on PATH for crawl.py.
# Install playwright for the system python3. The base image pre-installs the
# browser binaries but not necessarily the Python package for this interpreter.
RUN pip3 install --no-cache-dir playwright==1.49.0

RUN python3 -m venv /opt/mitm-venv \
 && /opt/mitm-venv/bin/pip install --no-cache-dir "mitmproxy>=10.4,<12" \
 && ln -sf /opt/mitm-venv/bin/mitmdump /usr/local/bin/mitmdump

# Smoke-test: fail the build immediately if playwright can't be imported.
RUN python3 -c "from playwright.sync_api import sync_playwright; print('playwright ok')"

COPY har_dump.py crawl.py ./

# The Playwright base image ships with pwuser at UID/GID 1000.
# mitmproxy writes its CA cert to $HOME/.mitmproxy on first run.
RUN mkdir -p /home/pwuser/.mitmproxy \
 && chown -R 1000:1000 /home/pwuser/.mitmproxy /app

ENV HOME=/home/pwuser

USER 1000

ENTRYPOINT ["python3", "/app/crawl.py"]
