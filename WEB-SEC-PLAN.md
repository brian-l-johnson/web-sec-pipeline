# Web Security Analysis Pipeline — Implementation Plan

Each phase is self-contained and ends with a concrete test checkpoint.
Complete and verify each phase before starting the next.

---

## Phase 1 — Database Schema

**What:** Define the Postgres schema for the web-sec-tools pipeline. Two tables:
`web_jobs` and `web_findings`. Write a migration SQL file.

**Files to create:**
```
services/web-coordinator/migrations/001_initial.sql
```

**`web_jobs` columns:**
| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| status | text | pending, running, complete, failed |
| target_url | text | |
| scope | text[] | additional in-scope URLs/patterns |
| auth_config | jsonb | nullable; login form creds, cookie, header token, etc. |
| scan_profile | text | passive, active, full |
| submitted_at | timestamptz | |
| started_at | timestamptz | nullable |
| completed_at | timestamptz | nullable |
| error | text | nullable |
| har_path | text | nullable; path to captured HAR file |
| crawl_status | text | pending, running, complete, failed |
| zap_status | text | pending, running, complete, failed |
| nuclei_status | text | pending, running, complete, failed |

**`web_findings` columns:**
| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| job_id | uuid FK → web_jobs.id | |
| tool | text | zap, nuclei |
| severity | text | info, low, medium, high, critical |
| title | text | |
| url | text | affected URL |
| description | text | nullable |
| evidence | text | nullable; request/response snippet |
| cwe | int | nullable |
| template_id | text | nullable; Nuclei template ID |
| created_at | timestamptz | |

**Test checkpoint:** Apply migration to a local Postgres instance, verify both tables exist with correct types. Connect with psql or a GUI and insert/query a dummy row.

---

## Phase 2 — web-ingestion Service

**What:** HTTP service that accepts scan submission requests, validates them, and publishes to NATS subject `webapp.submitted`. Mirrors the structure of `services/ingestion` in android-re-pipeline.

**Files to create:**
```
services/web-ingestion/
  go.mod                          (module github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion)
  go.sum
  cmd/server/main.go
  internal/api/handlers.go        (POST /scan, GET /health)
  internal/api/handlers_test.go
  internal/queue/publisher.go     (NATS publisher, webapp.submitted subject)
  docs/                           (swag generated)
  Dockerfile
```

**NATS message shape (`webapp.submitted`):**
```json
{
  "job_id": "uuid",
  "target_url": "https://example.com",
  "scope": ["https://example.com/app/*"],
  "auth_config": { "type": "form", "login_url": "...", "username": "...", "password": "..." },
  "scan_profile": "full",
  "submitted_at": "RFC3339"
}
```

`auth_config` is optional. `scan_profile` defaults to `"passive"` if omitted.

**Validation rules:**
- `target_url` must be a valid http/https URL
- `scan_profile` must be one of `passive`, `active`, `full`
- `scope` entries must be valid URL patterns

**Test checkpoint:** Run `go test ./...`. Start the service locally with a NATS server (`docker run -p 4222:4222 nats:alpine -js`) and POST a valid request; verify the NATS message is published. POST an invalid URL; verify 400 response.

---

## Phase 3 — web-coordinator Foundation

**What:** Core coordinator service — NATS consumer, Postgres store layer, k8s Job manager scaffold, HTTP status API. At the end of this phase the coordinator can receive a job, write it to the DB, and expose status via API. Tool execution is stubbed/pending.

**Files to create:**
```
services/web-coordinator/
  go.mod                                (module github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator)
  go.sum
  cmd/server/main.go
  internal/store/store.go               (pgx pool setup)
  internal/store/queries.go             (CRUD for web_jobs, web_findings)
  internal/queue/consumer.go            (NATS consumer, webapp.submitted)
  internal/jobs/manager.go              (k8s Job launcher — create, watch, reconcile)
  internal/pipeline/orchestrator.go     (HandleSubmitted, OnJobComplete, OnJobFailed)
  internal/api/handlers.go              (GET /health, GET /jobs, GET /jobs/:id, GET /jobs/:id/findings, POST /jobs/:id/retrigger)
  internal/api/handlers_test.go
  docs/                                 (swag generated)
  Dockerfile
```

**Orchestration flow at this phase:**
1. NATS message arrives → `HandleSubmitted`
2. Insert `web_jobs` row (status=pending)
3. Launch `crawl` k8s Job (image from `CRAWLER_IMAGE` env var)
4. Set status=running, crawl_status=running
5. Informer fires `OnJobComplete(jobID, "crawl")` → set crawl_status=complete, log "ZAP/Nuclei TODO"
6. `OnJobFailed` → set error, status=failed

**k8s Job labels to use:**
```
web-sec-tools/job-type: scan
web-sec-tools/job-id: <uuid>
web-sec-tools/tool: <crawl|zap|nuclei>
```

**Test checkpoint:** Run `go test ./...`. Deploy to cluster (or run locally with a kubeconfig). Submit a job via web-ingestion. Verify: DB row created, k8s Job launched in `web-sec-tools` namespace, status transitions. The crawler Job will fail (image doesn't exist yet) — verify `OnJobFailed` fires and error is recorded.

---

## Phase 4 — Crawler Image (Playwright + mitmproxy)

**What:** Docker image that drives an authenticated browser session while capturing all traffic as a HAR file. Runs as a k8s Job. mitmproxy runs as a subprocess within the container (not a sidecar) for simpler HAR output control.

**Files to create:**
```
images/web-crawler/
  Dockerfile
  crawl.py          (Playwright entrypoint script)
  har_dump.py       (mitmproxy addon — writes flows to HAR format)
  requirements.txt
```

**Dockerfile approach:**
- Base: `mcr.microsoft.com/playwright/python:v1.x-jammy` (includes Chromium)
- Install mitmproxy via pip
- Copy scripts
- Entrypoint: `python crawl.py`

**`crawl.py` responsibilities:**
- Read config from env vars: `TARGET_URL`, `AUTH_CONFIG` (JSON), `SCOPE`, `OUTPUT_DIR`, `PROXY_PORT` (default 8080)
- Start mitmproxy subprocess: `mitmdump -p $PROXY_PORT -s /app/har_dump.py --set hardump=/output/capture.har`
- Wait for mitmproxy ready (poll port)
- Launch Playwright with `--proxy-server=http://localhost:$PROXY_PORT` and `--ignore-https-errors` (mitmproxy MITM)
- If `AUTH_CONFIG` present: navigate to login URL, fill credentials, submit
- Crawl: follow links within scope, trigger XHR by interacting with the page
- Shutdown mitmproxy (SIGTERM — flushes HAR file)
- Exit 0

**`har_dump.py`:** mitmproxy addon using `HarDumpAddon` pattern — captures request/response pairs to HAR 1.2 format.

**Coordinator change:** After crawl Job completes, update `har_path` in DB from the job's output directory.

**Test checkpoint:** Build image locally and run against a known test site:
```bash
docker run -e TARGET_URL=https://example.com -e OUTPUT_DIR=/output \
  -v /tmp/crawl-out:/output web-crawler:dev
```
Verify `/tmp/crawl-out/capture.har` exists and contains requests. Then run as a k8s Job and verify HAR appears on the PVC.

---

## Phase 5 — ZAP Integration

**What:** After crawl completes, coordinator launches a ZAP k8s Job. ZAP runs in automation mode, passive+active scan, writes a JSON report to the shared PVC. Coordinator parses the report and inserts rows into `web_findings`.

**Files to create:**
```
images/zap-runner/
  Dockerfile              (FROM ghcr.io/zaproxy/zaproxy:stable, add automation plan)
  automation-plan.yaml    (ZAP Automation Framework plan template)
  entrypoint.sh           (substitutes TARGET_URL, OUTPUT_DIR into plan, runs zap.sh)
```

**`automation-plan.yaml` jobs sequence:**
1. `spider` — crawl the target
2. `passiveScan-wait`
3. `activeScan` (only when scan_profile=full; skip for passive)
4. `report` — output `report.json` to OUTPUT_DIR

**Coordinator changes:**
- `OnJobComplete("crawl")` → launch ZAP Job AND Nuclei Job in parallel
- `OnJobComplete("zap")` → call `parseZAPReport()` → insert `web_findings` rows
- ZAP JSON report: parse `site[].alerts[]`, map `riskdesc` → severity, extract `alert`, `uri`, `desc`, `evidence`, `cweid`

**Test checkpoint:** Run ZAP Job manually against a test target (Juice Shop or DVWA). Verify `report.json` is produced. Submit a full pipeline job and verify `web_findings` rows appear with `tool='zap'`.

---

## Phase 6 — Nuclei Integration

**What:** Parallel to ZAP — coordinator launches a Nuclei k8s Job after crawl completes. Nuclei outputs newline-delimited JSON; coordinator parses and stores findings.

**Files to create:**
```
images/nuclei-runner/
  Dockerfile              (FROM projectdiscovery/nuclei:latest, add entrypoint)
  entrypoint.sh           (runs nuclei with correct flags, outputs to /output/nuclei.jsonl)
```

**`entrypoint.sh` invocation:**
```bash
nuclei -u "$TARGET_URL" \
  -t cves,vulnerabilities,misconfiguration,exposures,default-logins \
  -severity medium,high,critical \
  -json-export /output/nuclei.jsonl \
  -no-interactsh
```

**Coordinator changes:**
- `OnJobComplete("nuclei")` → call `parseNucleiReport()` → insert `web_findings` rows
- Nuclei JSONL fields: `info.name` → title, `info.severity` → severity, `matched-at` → url, `info.description` → description, `template-id` → template_id, `info.classification.cwe-id` → cwe

**Completion logic:** job status=complete when crawl=complete AND (zap=complete OR zap=failed) AND (nuclei=complete OR nuclei=failed). One scanner failure must not block the other's results.

**Test checkpoint:** Run Nuclei Job manually against a test target. Submit a full pipeline job and verify both `tool='zap'` and `tool='nuclei'` findings rows appear. Verify `GET /jobs/:id/findings` returns both.

---

## Phase 7 — CI/CD Workflows

**What:** GitHub Actions workflows to build and push all new images on push to main.

**Files to create:**
```
.github/workflows/build-web-ingestion.yml
.github/workflows/build-web-coordinator.yml
.github/workflows/build-web-tools.yml      (matrix: web-crawler, zap-runner, nuclei-runner)
```

Same patterns as android-re-pipeline workflows. Path triggers:
- `build-web-ingestion.yml` → `services/web-ingestion/**`
- `build-web-coordinator.yml` → `services/web-coordinator/**`
- `build-web-tools.yml` → `images/**`

**Image tags:**
- `ghcr.io/brian-l-johnson/web-coordinator:latest` + `:${{ github.sha }}`
- `ghcr.io/brian-l-johnson/web-ingestion:latest` + `:${{ github.sha }}`
- `ghcr.io/brian-l-johnson/web-crawler:latest` + `:${{ github.sha }}`
- `ghcr.io/brian-l-johnson/zap-runner:latest` + `:${{ github.sha }}`
- `ghcr.io/brian-l-johnson/nuclei-runner:latest` + `:${{ github.sha }}`

**Also update** `apps/web-sec-tools/web-coordinator-deployment.yaml` in homelab-gitops to use `zap-runner` and `nuclei-runner` image refs (replacing the upstream image placeholders set in Phase 0).

**Test checkpoint:** Push a trivial change and verify the workflow runs, tests pass, and images appear in GHCR.

---

## Phase 8 — Seal Secrets & Deploy

**What:** Generate and seal the two placeholder secrets, push both repos, verify Flux reconciles, run an end-to-end scan.

**Steps:**
1. Generate a strong password for the `web-coordinator` Postgres role
2. Seal `infrastructure/database/web-coordinator-password-sealed.yaml` (namespace: `database`)
3. Construct the `DATABASE_URL` and seal `apps/web-sec-tools/coordinator-secret-sealed.yaml` (namespace: `web-sec-tools`)
4. Create `ghcr-pull-secret` in `web-sec-tools` namespace (same PAT as re-tools)
5. Push homelab-gitops → Flux reconciles → namespace, NATS, PVCs, services come up
6. Push web-sec-pipeline → CI builds images → coordinator and ingestion deploy

**End-to-end test:**
```bash
curl -X POST https://web-ingestion.apps.blj.wtf/scan \
  -H 'Content-Type: application/json' \
  -d '{"target_url": "http://juice-shop.internal/", "scan_profile": "passive"}'

# Poll status
curl https://web-coordinator.apps.blj.wtf/jobs/<id>

# Check findings after complete
curl https://web-coordinator.apps.blj.wtf/jobs/<id>/findings
```

**Test checkpoint:** Full end-to-end scan completes, findings visible via API, HAR file present on PVC.

---

## Suggested Session Breakdown

| Session | Phase | Expected output |
|---|---|---|
| 1 | Phase 1 | Migration SQL, verified schema |
| 2 | Phase 2 | web-ingestion service, tests passing |
| 3 | Phase 3 | web-coordinator foundation, k8s integration working |
| 4 | Phase 4 | web-crawler image, HAR output verified |
| 5 | Phase 5 | ZAP integration, findings in DB |
| 6 | Phase 6 | Nuclei integration, full pipeline functional |
| 7 | Phase 7 | CI workflows, all images building in GHCR |
| 8 | Phase 8 | Sealed secrets, deployed, end-to-end test passing |
