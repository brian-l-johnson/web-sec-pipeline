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
- `images/zap-runner/` — OWASP ZAP automation framework runner (one-shot batch mode)
- `images/zap-proxy/` — OWASP ZAP in persistent proxy/daemon mode with REST API (used by the zap-pentest skill)
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

## Web UI

The coordinator embeds a web UI from `services/web-coordinator/cmd/server/ui/`. Pages are served via Go's `html/template` — **not** as plain static files.

### Template structure

- `ui/nav.html` — defines two named template blocks used by every page:
  - `{{define "nav-css"}}` — nav CSS, injected into each page's `<head>`
  - `{{define "nav"}}` — header markup; receives `ActivePage string` to highlight the correct link
- `ui/index.html`, `ui/job.html`, `ui/targets.html` — full page templates; each includes:
  ```html
  {{template "nav-css" .}}   <!-- inside <style> in <head> -->
  {{template "nav" .}}       <!-- first element of <body> -->
  ```

### Adding a new page

1. Create `ui/<page>.html` with the two template calls above.
2. Add a `case` in the `GET /ui/` handler switch in `cmd/server/main.go`:
   ```go
   case "<page>.html":
       renderUI(w, uiTmpl, "<page>.html", "<active-page-key>")
   ```
3. Add the nav link in `ui/nav.html` with the matching `ActivePage` key:
   ```html
   <a href="/ui/<page>.html"{{if eq .ActivePage "<active-page-key>"}} class="active"{{end}}>Label</a>
   ```

### Template data

`renderUI` passes a `uiPage{ActivePage: "..."}` struct to every template. Currently only `ActivePage` is used but this is the place to add server-side data (version, feature flags, etc.) in future.

### Static assets

Non-HTML files under `ui/` (JS snippets, images) are still served by `http.FileServer` via the `default:` branch of the same switch. There is no separate static file route.

## GitOps

Kubernetes manifests and Flux Kustomizations are managed in a separate repo:

```
~/dev/homelab-gitops/apps/web-sec-tools/
```

Do not commit Kubernetes YAML to this repo.

---

## ZAP Pentest Skill

An interactive security investigation skill lives at `.claude/skills/zap-pentest/`.
It is a **parallel tool** to the automated pipeline — meant for hands-on investigation
sessions, not scheduled batch scans.

### Relationship to the automated pipeline

| Automated pipeline | ZAP pentest skill |
|---|---|
| Triggered by HTTP POST → NATS | Invoked interactively by Claude |
| ZAP runs as a one-shot k8s Job | ZAP runs as a persistent proxy (`zap-proxy` image) |
| Findings stored in `web_findings` DB table | Findings stored in `~/engagements/<name>/findings/` |
| Results visible in coordinator UI | Findings optionally pushed to coordinator via `POST /jobs/{id}/findings` |

### Coordinator integration points

- `GET /targets` — skill reads target config from here to seed engagement.yaml
- `POST /jobs` with `scan_profile: manual` — creates a manual engagement job (no k8s jobs launched)
- `POST /jobs/{id}/findings` — skill pushes discoveries here so they appear in the UI

### Engagement directories

Engagements live **outside the repo** at `~/engagements/<name>/`. Set
`ENGAGEMENTS_ROOT` env var to override. Each engagement needs an
`engagement.yaml` (copy from `.claude/skills/zap-pentest/engagement.template.yaml`).

### ZAP proxy image

```bash
docker build -f images/zap-proxy/Dockerfile -t zap-proxy:dev images/zap-proxy/
docker run -p 8080:8080 -p 8090:8090 \
  -e ZAP_API_KEY=changeme \
  zap-proxy:dev
```

Proxy port: 8080. REST API port: 8090.

### Running the skill

See `.claude/skills/zap-pentest/SKILL.md` for the full workflow.
