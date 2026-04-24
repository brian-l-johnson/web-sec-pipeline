"""
mitmproxy addon: captures all HTTP/HTTPS flows and writes a HAR 1.2 file.

Usage:
    mitmdump -s har_dump.py --set hardump=/path/to/capture.har

The HAR file is written when mitmdump exits (SIGTERM from crawl.py).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

try:
    from mitmproxy import ctx, http
except ImportError:  # allow import without mitmproxy for unit tests
    import types as _types
    ctx = _types.SimpleNamespace(options=_types.SimpleNamespace(hardump=""), log=_types.SimpleNamespace(info=lambda m: None))  # type: ignore[assignment]
    http = None  # type: ignore[assignment]


class HarDump:
    def __init__(self) -> None:
        self.har: dict = {
            "log": {
                "version": "1.2",
                "creator": {"name": "mitmproxy-har", "version": "1.0"},
                "entries": [],
            }
        }

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        # Skip mitmproxy's own internal CA download endpoint.
        if flow.request.pretty_host == "mitm.it":
            return
        self.har["log"]["entries"].append(self._build_entry(flow))

    def done(self) -> None:
        # Read path from env var — more reliable than mitmproxy's option
        # system, where addon-defined --set options can be silently ignored
        # if processed before the addon's load() hook registers them.
        output_path: str = os.environ.get("HARDUMP_PATH", "")
        if not output_path:
            return
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(self.har, fh, indent=2)
        ctx.log.info(
            f"HAR written: {output_path} ({len(self.har['log']['entries'])} entries)"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_entry(self, flow: http.HTTPFlow) -> dict:
        req = flow.request
        resp = flow.response

        started = datetime.fromtimestamp(req.timestamp_start, tz=timezone.utc)

        send_ms = 0.0
        wait_ms = (
            max(0.0, (resp.timestamp_start - req.timestamp_start) * 1000)
            if resp.timestamp_start
            else 0.0
        )
        receive_ms = (
            max(0.0, (resp.timestamp_end - resp.timestamp_start) * 1000)
            if (resp.timestamp_end and resp.timestamp_start)
            else 0.0
        )

        request_body_size = len(req.content) if req.content else 0
        response_body_size = len(resp.content) if resp.content else 0

        request_entry: dict = {
            "method": req.method,
            "url": req.pretty_url,
            "httpVersion": f"HTTP/{req.http_version}",
            "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
            "queryString": [{"name": k, "value": v} for k, v in req.query.items()],
            "cookies": _parse_request_cookies(req.headers.get("cookie", "")),
            "headersSize": -1,
            "bodySize": request_body_size,
        }
        if req.content:
            request_entry["postData"] = {
                "mimeType": req.headers.get("content-type", ""),
                "text": req.get_text(strict=False) or "",
                "params": [],
            }

        response_entry: dict = {
            "status": resp.status_code,
            "statusText": resp.reason or "",
            "httpVersion": f"HTTP/{resp.http_version}",
            "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
            "cookies": [],
            "content": {
                "size": response_body_size,
                "mimeType": resp.headers.get("content-type", "application/octet-stream"),
            },
            "redirectURL": resp.headers.get("location", ""),
            "headersSize": -1,
            "bodySize": response_body_size,
        }

        return {
            "startedDateTime": started.isoformat(),
            "time": send_ms + wait_ms + receive_ms,
            "request": request_entry,
            "response": response_entry,
            "cache": {},
            "timings": {
                "send": send_ms,
                "wait": wait_ms,
                "receive": receive_ms,
            },
        }


def _parse_request_cookies(cookie_header: str) -> list:
    if not cookie_header:
        return []
    cookies = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip()})
    return cookies


addons = [HarDump()]
