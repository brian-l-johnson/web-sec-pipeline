"""
Unit tests for pure helper functions in crawl.py and har_dump.py.
Run with: python -m pytest tests/ -v
These tests do NOT require Playwright, mitmproxy, or Docker.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crawl import in_scope

# ---------------------------------------------------------------------------
# in_scope tests
# ---------------------------------------------------------------------------

TARGET = "https://app.example.com/dashboard"


def test_in_scope_same_origin_no_scope():
    assert in_scope("https://app.example.com/login", TARGET, []) is True


def test_in_scope_different_origin_no_scope():
    assert in_scope("https://evil.com/", TARGET, []) is False


def test_in_scope_non_http_scheme():
    assert in_scope("ftp://app.example.com/file", TARGET, []) is False
    assert in_scope("javascript:void(0)", TARGET, []) is False
    assert in_scope("mailto:user@example.com", TARGET, []) is False


def test_in_scope_wildcard_match():
    scope = ["https://app.example.com/*"]
    assert in_scope("https://app.example.com/login", TARGET, scope) is True
    assert in_scope("https://app.example.com/api/v1/users", TARGET, scope) is True


def test_in_scope_wildcard_no_match_different_host():
    scope = ["https://app.example.com/*"]
    assert in_scope("https://api.example.com/v1/users", TARGET, scope) is False


def test_in_scope_multiple_patterns():
    scope = ["https://app.example.com/*", "https://api.example.com/*"]
    assert in_scope("https://app.example.com/login", TARGET, scope) is True
    assert in_scope("https://api.example.com/v1/data", TARGET, scope) is True
    assert in_scope("https://cdn.example.com/image.png", TARGET, scope) is False


def test_in_scope_prefix_without_wildcard():
    scope = ["https://app.example.com/app"]
    assert in_scope("https://app.example.com/app/settings", TARGET, scope) is True
    assert in_scope("https://app.example.com/other", TARGET, scope) is False


def test_in_scope_empty_url():
    assert in_scope("", TARGET, []) is False


# ---------------------------------------------------------------------------
# har_dump: HarDump._parse_request_cookies test
# ---------------------------------------------------------------------------

def test_parse_request_cookies_single():
    from har_dump import _parse_request_cookies
    result = _parse_request_cookies("session=abc123")
    assert result == [{"name": "session", "value": "abc123"}]


def test_parse_request_cookies_multiple():
    from har_dump import _parse_request_cookies
    result = _parse_request_cookies("session=abc; csrf=xyz")
    assert len(result) == 2
    assert result[0] == {"name": "session", "value": "abc"}
    assert result[1] == {"name": "csrf", "value": "xyz"}


def test_parse_request_cookies_empty():
    from har_dump import _parse_request_cookies
    assert _parse_request_cookies("") == []


def test_parse_request_cookies_value_with_equals():
    from har_dump import _parse_request_cookies
    # Cookie value may contain = (e.g. base64)
    result = _parse_request_cookies("token=abc==")
    assert result[0]["name"] == "token"
    assert result[0]["value"] == "abc=="


# ---------------------------------------------------------------------------
# har_dump: HAR file written on done()
# ---------------------------------------------------------------------------

def test_har_dump_writes_file(monkeypatch, tmp_path):
    """Simulate the HarDump.done() call and verify the file is written."""
    from har_dump import HarDump

    har_path = str(tmp_path / "capture.har")

    # Monkey-patch ctx.options to return our test path.
    class FakeOptions:
        hardump = har_path

    class FakeCtx:
        options = FakeOptions()
        class log:
            @staticmethod
            def info(msg): pass

    import har_dump as hd
    original_ctx = hd.ctx
    hd.ctx = FakeCtx()

    try:
        addon = HarDump()
        # Manually add a fake entry to the HAR log.
        addon.har["log"]["entries"].append({"fake": "entry"})
        addon.done()
    finally:
        hd.ctx = original_ctx

    assert os.path.exists(har_path), "HAR file should be written"
    with open(har_path) as f:
        data = json.load(f)
    assert data["log"]["version"] == "1.2"
    assert len(data["log"]["entries"]) == 1


def test_har_dump_no_path_does_not_write(tmp_path):
    """If hardump option is empty, no file should be written."""
    from har_dump import HarDump

    class FakeOptions:
        hardump = ""

    class FakeCtx:
        options = FakeOptions()

    import har_dump as hd
    original_ctx = hd.ctx
    hd.ctx = FakeCtx()

    try:
        addon = HarDump()
        addon.done()  # should be a no-op
    finally:
        hd.ctx = original_ctx

    # No file should have been written anywhere in tmp_path.
    assert list(tmp_path.iterdir()) == []
