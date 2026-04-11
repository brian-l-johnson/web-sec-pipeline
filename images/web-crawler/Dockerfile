FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Install mitmproxy. Playwright is already in the base image.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY har_dump.py crawl.py ./

# Create a non-root user (UID 1000) for k8s securityContext compatibility.
# mitmproxy writes its CA cert to $HOME/.mitmproxy on first run.
RUN groupadd -g 1000 scanner \
 && useradd -m -u 1000 -g 1000 -d /home/scanner scanner \
 && mkdir -p /home/scanner/.mitmproxy \
 && chown -R 1000:1000 /home/scanner

ENV HOME=/home/scanner

USER 1000

ENTRYPOINT ["python", "/app/crawl.py"]
