"""
Web crawler: Playwright drives an authenticated browser session while mitmproxy
captures all traffic to a HAR file.

Environment variables:
  TARGET_URL      Required. Starting URL for the crawl.
  SCOPE           JSON array of in-scope URL patterns (default: target origin only).
                  Patterns ending in /* match any URL under that prefix.
                  Example: '["https://app.example.com/*","https://api.example.com/*"]'
  AUTH_CONFIG     JSON object describing how to authenticate (optional).
                  type=form:   {type, login_url, username, password,
                               username_selector?, password_selector?, submit_selector?}
                  type=cookie: {type, cookies: [{name, value, domain, path?},...]}
                  type=header: {type, headers: {"Authorization": "Bearer ..."}}
  OUTPUT_DIR      Directory to write capture.har (default: /tmp/output).
  PROXY_PORT      mitmproxy listen port (default: 8080).
  MAX_URLS        Max unique URLs to visit (default: 50).
  MAX_DEPTH       Max BFS depth from target_url (default: 3).
  CRAWL_TIMEOUT   Total seconds allowed for the crawl phase (default: 300).
"""
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urljoin, urlparse

_playwright_import_error: str = ""
try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
except Exception as _pw_err:  # broad catch — log the real error in main()
    import traceback as _tb
    _playwright_import_error = (
        f"{type(_pw_err).__name__}: {_pw_err}\n{_tb.format_exc()}"
    )
    sync_playwright = None  # type: ignore[assignment]
    PlaywrightTimeout = Exception  # type: ignore[misc,assignment]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("crawl")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Poll until a TCP connection to host:port succeeds or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    return False


def in_scope(url: str, target_url: str, scope: list) -> bool:
    """Return True if url is within the crawl scope.

    Rules:
    - Non-http/https URLs are always out of scope.
    - If scope is empty, only the same origin as target_url is in scope.
    - Scope entries ending in /* match any URL with that prefix.
    - Other scope entries are treated as URL prefixes.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    if not scope:
        target = urlparse(target_url)
        return parsed.netloc == target.netloc

    for pattern in scope:
        if pattern.endswith("/*"):
            prefix = pattern[:-1]  # strip the trailing *
            if url.startswith(prefix):
                return True
        else:
            if url.startswith(pattern.rstrip("/")):
                return True
    return False


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def do_auth(page, auth_config: dict) -> None:
    """Perform authentication based on auth_config.type."""
    auth_type = auth_config.get("type", "form")

    if auth_type == "form":
        login_url = auth_config.get("login_url")
        if not login_url:
            log.warning("auth_config type=form missing login_url — skipping auth")
            return
        log.info(f"Authenticating via form at {login_url}")
        page.goto(login_url, timeout=30_000)
        page.wait_for_load_state("networkidle", timeout=15_000)

        # Accept multiple common selector patterns as fallback.
        username_sel = auth_config.get(
            "username_selector",
            "input[type='email'], input[name='username'], input[name='user'], input[name='email']",
        )
        password_sel = auth_config.get("password_selector", "input[type='password']")
        submit_sel = auth_config.get(
            "submit_selector", "button[type='submit'], input[type='submit']"
        )

        page.fill(username_sel, auth_config.get("username", ""))
        page.fill(password_sel, auth_config.get("password", ""))
        page.click(submit_sel)
        page.wait_for_load_state("networkidle", timeout=15_000)
        log.info("Form submitted")

    elif auth_type == "cookie":
        cookies = auth_config.get("cookies", [])
        page.context.add_cookies(cookies)
        log.info(f"Injected {len(cookies)} auth cookie(s)")

    elif auth_type == "header":
        # Headers are applied at context level in main(); nothing to do here.
        log.info("Header auth already applied at context level")

    else:
        log.warning(f"Unknown auth type {auth_type!r} — skipping auth")


# ---------------------------------------------------------------------------
# Crawl
# ---------------------------------------------------------------------------

def crawl(page, target_url: str, scope: list, max_urls: int, max_depth: int, timeout_s: float) -> set:
    """BFS crawl from target_url. Returns the set of visited URLs."""
    visited: set = set()
    queue: list = [(target_url, 0)]
    deadline = time.monotonic() + timeout_s

    while queue and len(visited) < max_urls and time.monotonic() < deadline:
        url, depth = queue.pop(0)

        # Normalise: strip fragment.
        url = url.split("#")[0]
        if not url or url in visited:
            continue
        if not in_scope(url, target_url, scope):
            continue

        visited.add(url)
        log.info(f"[{len(visited)}/{max_urls}] depth={depth}  {url}")

        # Retry transient network errors (e.g. ERR_NETWORK_CHANGED while the
        # mitmproxy SSL interception layer finishes initialising).
        for attempt in range(3):
            try:
                page.goto(url, timeout=20_000, wait_until="domcontentloaded")
                # Wait for XHR to settle, but don't block forever on slow SPAs.
                page.wait_for_load_state("networkidle", timeout=8_000)
                break  # success
            except PlaywrightTimeout:
                log.warning(f"Timeout loading {url}")
                break  # don't retry timeouts
            except Exception as exc:
                err_str = str(exc)
                if attempt < 2 and "ERR_NETWORK_CHANGED" in err_str:
                    log.info(f"Transient network error on {url}, retrying ({attempt+1}/2)…")
                    time.sleep(1.5)
                else:
                    log.warning(f"Error loading {url}: {exc}")
                    break

        if depth >= max_depth:
            continue

        # Collect href links.
        try:
            hrefs: list = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
        except Exception:
            hrefs = []

        for href in hrefs:
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            absolute = urljoin(url, href).split("#")[0]
            if absolute not in visited and in_scope(absolute, target_url, scope):
                queue.append((absolute, depth + 1))

        # Light interaction: click tabs / non-submit buttons to surface XHR.
        try:
            page.eval_on_selector_all(
                "[role='tab'], [role='button']:not([type='submit'])",
                """els => {
                    els.slice(0, 8).forEach(el => {
                        try { el.click(); } catch(_) {}
                    });
                }""",
            )
            page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass

    remaining = deadline - time.monotonic()
    if remaining > 0:
        log.info(f"Crawl finished with {remaining:.0f}s remaining")
    else:
        log.info("Crawl stopped: timeout reached")

    return visited


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if sync_playwright is None:
        log.error(
            "playwright is not importable — cannot crawl.\n"
            "Import error details:\n%s\n"
            "Check the Python environment in this container:\n"
            "  python3 -c \"import playwright; print(playwright.__version__)\"\n"
            "  python3 -m pip show playwright",
            _playwright_import_error or "(no details captured)",
        )
        return 1

    target_url = os.environ.get("TARGET_URL", "").strip()
    scope_raw = os.environ.get("SCOPE", "[]").strip()
    auth_raw = os.environ.get("AUTH_CONFIG", "").strip()
    output_dir = os.environ.get("OUTPUT_DIR", "/tmp/output").strip()
    proxy_port = int(os.environ.get("PROXY_PORT", "8080"))
    max_urls = int(os.environ.get("MAX_URLS", "50"))
    max_depth = int(os.environ.get("MAX_DEPTH", "3"))
    crawl_timeout = float(os.environ.get("CRAWL_TIMEOUT", "300"))

    if not target_url:
        log.error("TARGET_URL is required")
        return 1

    scope: list = json.loads(scope_raw) if scope_raw not in ("[]", "") else []
    auth_config: dict | None = json.loads(auth_raw) if auth_raw else None

    os.makedirs(output_dir, exist_ok=True)
    har_path = os.path.join(output_dir, "capture.har")

    log.info(f"Target: {target_url}")
    log.info(f"Scope:  {scope or '(same origin)'}")
    log.info(f"Output: {har_path}")

    # ------------------------------------------------------------------
    # Start mitmproxy
    # ------------------------------------------------------------------
    mitmdump_cmd = [
        "mitmdump",
        "--listen-port", str(proxy_port),
        "-s", "/app/har_dump.py",
        "--set", f"hardump={har_path}",
        "--quiet",
    ]
    log.info(f"Starting mitmproxy on :{proxy_port}...")
    mitm_proc = subprocess.Popen(
        mitmdump_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    if not wait_for_port("127.0.0.1", proxy_port, timeout=30.0):
        stderr = mitm_proc.stderr.read().decode(errors="replace") if mitm_proc.stderr else ""
        log.error(f"mitmproxy failed to start within 30s. stderr: {stderr}")
        mitm_proc.kill()
        return 1
    log.info("mitmproxy ready")
    # Give mitmproxy a moment to fully initialise its SSL interception layer.
    # The port accepts connections immediately but the first CONNECT requests
    # can fail with ERR_NETWORK_CHANGED if the CA cert isn't ready yet.
    time.sleep(1.5)

    # ------------------------------------------------------------------
    # Playwright crawl
    # ------------------------------------------------------------------
    crawl_exit = 0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": f"http://127.0.0.1:{proxy_port}"},
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                extra_http_headers=(
                    auth_config.get("headers", {})
                    if auth_config and auth_config.get("type") == "header"
                    else {}
                ),
            )
            page = context.new_page()

            if auth_config:
                try:
                    do_auth(page, auth_config)
                except Exception as exc:
                    log.warning(f"Auth failed ({exc}) — continuing without auth")

            visited = crawl(page, target_url, scope, max_urls, max_depth, crawl_timeout)
            log.info(f"Crawl complete — visited {len(visited)} URL(s)")

            browser.close()

    except Exception as exc:
        log.error(f"Playwright error: {exc}")
        crawl_exit = 1

    # ------------------------------------------------------------------
    # Shut down mitmproxy — SIGTERM triggers done() which writes the HAR.
    # ------------------------------------------------------------------
    log.info("Stopping mitmproxy...")
    mitm_proc.send_signal(signal.SIGTERM)
    try:
        mitm_proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        log.warning("mitmproxy did not stop within 15s — killing")
        mitm_proc.kill()
        mitm_proc.wait()

    if os.path.exists(har_path):
        size_kb = os.path.getsize(har_path) // 1024
        log.info(f"HAR file written: {har_path} ({size_kb} KB)")
    else:
        log.error(f"HAR file not found at {har_path}")
        crawl_exit = 1

    return crawl_exit


if __name__ == "__main__":
    sys.exit(main())
