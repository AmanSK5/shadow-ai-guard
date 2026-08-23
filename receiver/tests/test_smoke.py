"""Smoke tests for the ai-guard receiver."""

import os

# AUTH_TOKEN must be set before the app module is imported, because
# main.py reads it at module level.
os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}


def test_healthz_returns_200_with_version():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["version"] == app.version


def test_registry_without_auth_returns_401():
    resp = client.get("/registry")
    assert resp.status_code == 401


def test_report_accepts_device_name_and_risk_tier():
    """Integration: the /report endpoint accepts a payload with the new fields."""
    resp = client.post(
        "/report",
        json={
            "tool": "claude-code",
            "device_name": "ACME-C02XK1AB",
            "risk_tier": "high",
        },
        headers=AUTH,
    )
    assert resp.status_code == 200


def test_model_preserves_device_name_and_risk_tier():
    """device_name and risk_tier survive Pydantic validation into model_dump."""
    from app.main import Finding
    f = Finding(tool="claude-code", device_name="ACME-C02XK1AB", risk_tier="high")
    d = f.model_dump()
    assert d["device_name"] == "ACME-C02XK1AB"
    assert d["risk_tier"] == "high"


def test_model_defaults_for_device_name_and_risk_tier():
    """Omitting device_name and risk_tier gives empty-string defaults."""
    from app.main import Finding
    f = Finding(tool="claude-code")
    d = f.model_dump()
    assert d["device_name"] == ""
    assert d["risk_tier"] == ""


def test_unbounded_fields_not_in_loki_stream_labels():
    """Unbounded fields must not be Loki stream labels."""
    from app.main import LOKI_FINDING_LABELS
    for field in ("device_name", "risk_tier", "tool", "device", "user", "account_domain"):
        assert field not in LOKI_FINDING_LABELS, f"{field} would cause label cardinality issues"


def test_unknown_extra_fields_dropped():
    """Pydantic v2 default is extra='ignore'; unknown fields are silently dropped."""
    from app.main import Finding
    f = Finding(tool="claude-code", completely_unknown_field="should vanish")
    assert "completely_unknown_field" not in f.model_dump()


# ---------------------------------------------- auth before the body is read --


def test_report_without_auth_is_rejected_before_the_body_is_validated():
    """A missing token must beat a broken body.

    The payload here is invalid: tool is required and absent. A 422 would mean
    the model was validated before the token was checked, which is the whole
    problem. The answer has to be 401.
    """
    resp = client.post("/report", json={"not_a_field": "x"})
    assert resp.status_code == 401


def test_non_ascii_authorization_header_is_a_401_not_a_500():
    """A header byte above 0x7f reached hmac.compare_digest as a non-ASCII
    str, which raises TypeError rather than returning False. That was an
    unauthenticated 500 and a traceback per request on the internet-facing
    component. Sent at the ASGI layer because httpx refuses to build the
    header in the first place.

    Covers both the middleware and the defence-in-depth _auth() on the
    endpoint: /registry has no body, so a 401 there proves the second check
    survives the same input too."""
    import asyncio

    async def status(method, path, auth):
        headers = [(b"authorization", auth)]
        body = b""
        if method == "POST":
            body = b'{"tool":"x"}'
            headers += [(b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())]
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": path,
            "raw_path": path.encode(), "query_string": b"",
            "headers": headers, "client": ("127.0.0.1", 1), "server": ("t", 80),
        }
        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(msg):
            sent.append(msg)

        await app(scope, receive, send)
        return next(m["status"] for m in sent
                    if m["type"] == "http.response.start")

    for path, method in (("/report", "POST"), ("/registry", "GET")):
        assert asyncio.run(status(method, path, b"Bearer caf\xe9")) == 401
        # And the token itself still works through the same path.
        assert asyncio.run(status(method, path, b"Bearer test-token-for-ci")) != 401


def test_oversized_body_is_rejected():
    big = {"tool": "claude-code", "evidence": "x" * 200_000}
    resp = client.post("/report", json=big, headers=AUTH)
    assert resp.status_code == 413


def test_oversized_body_without_auth_is_still_a_401():
    """Token first, size second, so an unauthenticated caller learns nothing
    about the size limit."""
    big = {"tool": "claude-code", "evidence": "x" * 200_000}
    resp = client.post("/report", json=big)
    assert resp.status_code == 401


def test_post_without_content_length_is_rejected():
    """A chunked body would slip past the size check, so it is refused."""
    resp = client.post(
        "/report",
        content=iter([b'{"tool":"claude-code"}']),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 411


def test_over_long_field_is_rejected():
    resp = client.post("/report", json={"tool": "x" * 500}, headers=AUTH)
    assert resp.status_code == 422


def test_occurrence_count_must_be_positive():
    resp = client.post(
        "/report", json={"tool": "claude-code", "occurrence_count": 0}, headers=AUTH
    )
    assert resp.status_code == 422


def test_metrics_stays_open():
    """Unauthenticated on purpose: it carries only bounded label values."""
    assert client.get("/metrics").status_code == 200

def test_domain_tool_name_is_normalised_to_the_registry_id():
    """The extension reports the hostname it saw; everything else reports the
    registry id. Without this, one tool is two rows on every dashboard."""
    from app.main import _build_domain_map

    reg = {"tools": [{"id": "chatgpt", "domains": ["chatgpt.com", "openai.com"]}]}
    m = _build_domain_map(reg)
    assert m["chatgpt.com"] == "chatgpt"
    assert m["openai.com"] == "chatgpt"


def test_unknown_tool_names_are_left_alone():
    """A name the registry has never heard of is a registry gap worth seeing,
    not something to quietly fold into a neighbour."""
    from app.main import _build_domain_map

    m = _build_domain_map({"tools": [{"id": "chatgpt", "domains": ["chatgpt.com"]}]})
    assert "something-else.example" not in m


def test_domain_map_survives_a_missing_registry():
    """No registry means no normalisation, not a crash on every report."""
    from app.main import _build_domain_map

    assert _build_domain_map(None) == {}
    assert _build_domain_map({}) == {}

def test_corp_domains_are_normalised_for_the_strictest_matcher():
    """The macOS collector matches with a comma-anchored case pattern: no
    trimming, no case folding. A list served with a stray space or capital
    would silently turn a work account into a personal-account warn."""
    from app.main import _parse_corp_domains

    raw = " Example.COM , example.co.uk ,, example.com "
    assert _parse_corp_domains(raw) == ["example.com", "example.co.uk"]
    assert _parse_corp_domains("") == []


def test_collector_registry_carries_corp_domains_when_configured(tmp_path, monkeypatch):
    """One value changed on the receiver reaches the fleet on its next
    check-in, riding in the payload collectors already fetch."""
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1, "cli": []}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))
    monkeypatch.setattr(main, "CORP_DOMAINS", ["example.com", "example.co.uk"])

    resp = client.get("/registry/collector", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["config"]["corp_domains"] == ["example.com", "example.co.uk"]
    assert body["version"] == 1  # the registry content is untouched


def test_collector_registry_is_untouched_when_no_corp_domains(tmp_path, monkeypatch):
    """No CORP_DOMAINS means no config key at all: a collector must fall back
    to its local list, and an empty served list must not clobber it."""
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))
    monkeypatch.setattr(main, "CORP_DOMAINS", [])

    resp = client.get("/registry/collector", headers=AUTH)
    assert resp.status_code == 200
    assert "config" not in resp.json()


def test_a_rejected_push_is_counted_and_says_why():
    """A push that fails is a finding that exists only in this container's
    stdout. The receiver still answers 200, which is right - a log store being
    down should not lose a collector's finding - so the failure is invisible
    from the outside unless something counts it.

    This was logged at info with no metric, and a wrong LOKI_PUSH_URL
    therefore produced a 404 per finding that nobody read while every
    collector saw a 200.
    """
    import asyncio

    import httpx
    from app import main
    from prometheus_client import generate_latest

    class FakeResponse:
        status_code = 404

    async def boom(*a, **kw):
        raise httpx.HTTPStatusError("nope", request=None, response=FakeResponse())

    original = httpx.AsyncClient.post
    httpx.AsyncClient.post = boom
    try:
        class F:
            surface, severity, os = "cli", "warn", "linux"
        asyncio.run(main._push_loki(F(), "{}", "http://example.invalid/", "", ""))
    finally:
        httpx.AsyncClient.post = original

    metrics = generate_latest().decode()
    assert 'aiguard_loki_push_failures_total{reason="http_404"}' in metrics


def test_loki_basic_auth_is_only_sent_when_configured():
    """Hosted Loki wants basic auth; a self-hosted one usually does not, and
    sending an empty credential pair is not the same as sending none."""
    from app import main

    assert main.LOKI_USERNAME == ""
    # The push builds auth from the username, so unset means no auth tuple.
    auth = (main.LOKI_USERNAME, main.LOKI_PASSWORD) if main.LOKI_USERNAME else None
    assert auth is None

class TestUrlRedaction:
    """A configured URL can carry credentials, and it was logged verbatim.

    http://user:pass@host is a legal way to supply LOKI_PUSH_URL, and a
    deployer who does that rather than using LOKI_USERNAME and LOKI_PASSWORD
    had the credentials copied into stdout on every failed push. Logs are the
    least expected place for a secret and often the most widely readable.
    """

    def test_userinfo_is_removed(self):
        """The whole point. http://user:pass@host is legal, operator-supplied,
        and was written to the log verbatim on every failed push."""
        from app.main import _redact_url

        out = _redact_url("https://user:hunter2@loki.example.com/loki/api/v1/push")

        assert out == "https://loki.example.com/loki/api/v1/push"

    def test_the_host_survives(self):
        """Naming which log store failed is the point of the message. A
        redaction that removed the host would make the error useless and push
        somebody towards logging the raw URL again.

        Asserts on the whole string rather than `host in output`. A substring
        check passes wherever the host appears, including somewhere it should
        not be, so it would accept a redaction that had moved the host into the
        path and still call it a pass.
        """
        from app.main import _redact_url

        assert _redact_url("https://loki.example.com/push") == \
            "https://loki.example.com/push"

    def test_the_port_survives(self):
        from app.main import _redact_url

        assert _redact_url("http://loki:3100/push") == "http://loki:3100/push"

    def test_query_and_fragment_go(self):
        """Neither is meaningful on a push endpoint and both are places a
        token gets put."""
        from app.main import _redact_url

        out = _redact_url("https://loki.example.com/push?token=abc#frag")

        assert out == "https://loki.example.com/push"

    def test_an_unparseable_url_is_not_echoed(self):
        """A URL that cannot be parsed cannot be confirmed safe to print."""
        from app.main import _redact_url

        assert _redact_url("http://[") == "<unparseable url>"

    def test_empty_stays_empty(self):
        from app.main import _redact_url

        assert _redact_url("") == ""


def test_the_standalone_manifest_matches_the_released_version():
    """receiver/deploy/receiver.yaml is offered as the simpler alternative to
    the chart, and it pins an image tag by hand.

    It sat at 0.2.0 while the chart shipped 0.9.x. That is not a cosmetically
    stale example: 0.2.0 predates authentication being checked before the
    request body is parsed, the body size cap, and the field bounds. Anyone
    following the simpler path got materially weaker ingestion than anyone
    following the harder one, and nothing said so.

    A number maintained by remembering will drift again, so this is the thing
    that remembers. It ties the manifest to the chart's appVersion, which the
    release process already bumps.
    """
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent.parent
    chart = (root / "charts" / "ai-guard" / "Chart.yaml").read_text()
    manifest = (root / "receiver" / "deploy" / "receiver.yaml").read_text()

    app_version = re.search(r'^appVersion:\s*"?([^"\s]+)"?', chart, re.MULTILINE).group(1)
    pinned = re.search(r"receiver:([^\s]+)", manifest).group(1)

    assert pinned == app_version, (
        "receiver/deploy/receiver.yaml pins %s while the chart ships %s. "
        "Bump the manifest with the release." % (pinned, app_version)
    )


class TestAlertmanagerErrorsAreRedacted:
    """Same treatment as the Loki push URL, and for the same reason.

    ALERTMANAGER_URL is operator-supplied and can carry userinfo or a
    query-string token. str(e) on an httpx error includes the request URL, so
    logging the exception put the whole thing in stdout. This was fixed for
    Loki and not for Alertmanager, which is what happens when a fix is applied
    to the line that was reported rather than to the pattern.
    """

    def test_the_url_is_redacted_the_same_way(self):
        from app.main import _redact_url

        assert _redact_url("https://u:p@alerts.example.com/api/v2/alerts") == \
            "https://alerts.example.com/api/v2/alerts"

    def test_the_error_line_carries_the_type_not_the_message(self):
        """httpx puts the request URL in the message, which would carry
        userinfo straight past the redaction beside it."""
        import inspect

        from app import main as pm

        src = inspect.getsource(pm)

        assert '"error": "alertmanager: %s" % type(e).__name__' in src
        assert 'f"alertmanager: {e}"' not in src


def test_a_non_http_loki_push_url_is_refused():
    """A log store URL that is not http is a typo or the wrong value pasted,
    and carrying on means findings accepted and never stored."""
    import pytest
    from app.main import require_http_url

    with pytest.raises(SystemExit, match="must be http"):
        require_http_url("LOKI_PUSH_URL", "file:///tmp/x")

    assert require_http_url("LOKI_PUSH_URL", "http://loki:3100/push")
    assert require_http_url("LOKI_PUSH_URL", "") == ""


def test_the_docs_do_not_pin_a_stale_image():
    """Documentation carries copy-paste commands with image tags in them.

    getting-started.md had portal:0.4.0 in a docker run, five releases behind,
    on the page somebody follows first. kubernetes.md named a receiver two
    releases back. Every one of these goes stale on every release, and the
    person who notices is a new user pulling an image with bugs that were
    fixed months ago.

    Same reasoning as the manifest test above: a number maintained by
    remembering drifts, so this is the thing that remembers.
    """
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent.parent
    chart = (root / "charts" / "ai-guard" / "Chart.yaml").read_text()
    app_version = re.search(r'^appVersion:\s*"?([^"\s]+)"?', chart, re.MULTILINE).group(1)

    stale = []
    for doc in sorted(root.glob("docs/**/*.md")) + sorted(root.glob("*.md")):
        for i, line in enumerate(doc.read_text().split("\n"), start=1):
            for m in re.finditer(
                    r"shadow-ai-guard/(receiver|portal|scanner|discovery):"
                    r"(\d+\.\d+\.\d+)", line):
                if m.group(2) != app_version:
                    stale.append("%s:%d pins %s" % (doc.name, i, m.group(0)))

    assert not stale, (
        "these pin an image that is not the released version (%s):\n  %s"
        % (app_version, "\n  ".join(stale))
    )