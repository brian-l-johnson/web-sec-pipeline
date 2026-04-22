# Web Security Pipeline — Developer Guide

## Environment

Go is installed via MacPorts. The binary is at `/opt/local/bin/go` and is not on the default tool PATH. Always use the full path or prepend to PATH when running Go commands:

```bash
export PATH="/opt/local/bin:$PATH"
/opt/local/bin/go build ./...
```

`swag` and other Go tools installed via `go install` live at `~/go/bin/`.

## Repository Overview

Multi-module Go repository for web application security analysis. Two services under `services/`:

- `services/web-ingestion` — HTTP service that accepts scan submission requests and publishes jobs to NATS (`webapp.submitted`)
- `services/web-coordinator` — Consumes NATS jobs, orchestrates the scan pipeline (crawl → ZAP → Nuclei), stores results in Postgres

Tool wrapper images live under `images/`:

- `images/web-crawler/` — Playwright + mitmproxy; captures authenticated browser session as HAR
- `images/zap-runner/` — OWASP ZAP automation framework runner
- `images/nuclei-runner/` — Nuclei template-based scanner

Each service has its own `go.mod`. There is no top-level Go module.

GitOps manifests (Flux, Kubernetes YAML) live in a **separate repo**: `~/dev/homelab-gitops/`.
The Kubernetes namespace for this pipeline is `web-sec-tools`.

Implementation plan is in `WEB-SEC-PLAN.md`.

---

## Build

```bash
cd services/web-ingestion && go build ./cmd/server
cd services/web-coordinator && go build ./cmd/server
```

## Test

```bash
cd services/web-ingestion && go test ./...
cd services/web-coordinator && go test ./...
```

## Lint

```bash
cd services/web-ingestion && golangci-lint run
cd services/web-coordinator && golangci-lint run
```

## Docker — Services

Build using the service directory as the context (Dockerfiles reference `go.mod`, `migrations/`, etc. at the context root):

```bash
docker build -f services/web-ingestion/Dockerfile  -t web-ingestion:dev  services/web-ingestion/
docker build -f services/web-coordinator/Dockerfile -t web-coordinator:dev services/web-coordinator/
```

## Docker — Tool Wrapper Images

Build from the image-specific directory:

```bash
docker build -f images/web-crawler/Dockerfile  -t web-crawler:dev  images/web-crawler/
docker build -f images/zap-runner/Dockerfile   -t zap-runner:dev   images/zap-runner/
docker build -f images/nuclei-runner/Dockerfile -t nuclei-runner:dev images/nuclei-runner/
```

## Swagger / OpenAPI Docs

Uses [swaggo](https://github.com/swaggo/swag). After adding or modifying any HTTP handler annotations, regenerate docs:

```bash
cd services/web-coordinator && ~/go/bin/swag init -g cmd/server/main.go --output docs
cd services/web-ingestion && ~/go/bin/swag init -g cmd/server/main.go --output docs
```

Commit the updated `docs/` files alongside handler changes.

## GitOps

Kubernetes manifests and Flux Kustomizations are managed in a separate repo:

```
~/dev/homelab-gitops/apps/web-sec-tools/
```

Do not commit Kubernetes YAML to this repo.
