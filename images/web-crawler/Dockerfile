FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Install mitmproxy. Playwright is already in the base image.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY har_dump.py crawl.py ./

# The Playwright base image ships with pwuser at UID/GID 1000.
# mitmproxy writes its CA cert to $HOME/.mitmproxy on first run.
RUN mkdir -p /home/pwuser/.mitmproxy \
 && chown -R 1000:1000 /home/pwuser/.mitmproxy

ENV HOME=/home/pwuser

USER 1000

ENTRYPOINT ["python", "/app/crawl.py"]
