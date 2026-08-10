"""Exception detail and credentials must not reach an HTTP response.

CodeQL flagged the diagnostics return as information exposure through an
exception (CWE-209, CWE-497). It was right, and it found one of three.

The one it missed was the worst: the 502 raised when Loki cannot be read
interpolated LOKI_URL straight into the response body. LOKI_URL is
operator-supplied and http://user:pass@host is a legal way to supply it, so a
Loki outage would have put a credential in an error page. urllib's own
exception strings are terse and do not carry the URL, which is why nothing
surfaced it.

The endpoints are behind require_auth, but PORTAL_AUTH=none is a supported and
documented mode, so "authenticated only" is not the guarantee it looks like.

What these tests hold to: the response says which Loki and what class of
failure, because a portal that cannot distinguish "Loki is unreachable" from
"the estate is clean" is the exact failure this project exists to catch. The
message behind it goes to the log.
"""

import os

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from app.main import _redact_url
from fastapi import HTTPException

# ─────────────────────────────────────────────
# URL redaction
# ─────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        # The case that matters: credentials in userinfo.
        (
            "http://svcuser:s3cr3t@loki.internal.example.com:3100",
            "http://loki.internal.example.com:3100",
        ),
        # A username with no password still identifies an account.
        (
            "http://svcuser@loki.internal.example.com:3100",
            "http://loki.internal.example.com:3100",
        ),
        # No credentials: the URL should survive intact, because naming which
        # Loki failed is the useful half of the message.
        (
            "http://loki.monitoring.svc.cluster.local:3100",
            "http://loki.monitoring.svc.cluster.local:3100",
        ),
        # Path preserved, query and fragment dropped: neither belongs in an
        # error and a query string can carry anything.
        (
            "https://loki.example.com/prefix?token=abc#frag",
            "https://loki.example.com/prefix",
        ),
        ("", ""),
    ],
)
def test_redact_url(raw, expected):
    assert _redact_url(raw) == expected


def test_a_url_with_no_host_is_not_echoed():
    """Something unparseable as a host must not be passed through verbatim.

    A value that cannot be parsed cannot be confirmed safe to echo, so it is
    replaced rather than trusted.
    """
    assert _redact_url("not-a-url-at-all") == "<redacted>"


def test_password_never_survives_redaction():
    """Belt and braces: assert on the secret, not on the expected output.

    An implementation change that reformats the host would still be caught
    here if it stopped stripping userinfo.
    """
    out = _redact_url("http://user:hunter2@loki.example.com:3100/path")
    assert "hunter2" not in out
    assert "user" not in out
    # Equality rather than a containment check on the host: what survives
    # matters as much as what does not, and asserting the whole result catches
    # a redaction that dropped the port or mangled the path.
    assert out == "http://loki.example.com:3100/path"


# ─────────────────────────────────────────────
# What reaches the caller
# ─────────────────────────────────────────────

def test_loki_failure_names_the_host_and_the_failure_type(monkeypatch):
    """The 502 must stay diagnostic without carrying the exception message."""
    from app import derive
    from app import main as portal_main

    monkeypatch.setattr(
        portal_main, "LOKI_URL", "http://svcuser:s3cr3t@loki.example.com:3100"
    )

    def boom(*a, **kw):
        raise RuntimeError("connection refused to 10.3.1.44 as svcuser/s3cr3t")

    monkeypatch.setattr(derive, "fetch_from_loki", boom)

    with pytest.raises(HTTPException) as exc:
        portal_main._findings(1)

    detail = exc.value.detail
    assert "s3cr3t" not in detail, "credentials must not reach the response"
    assert "svcuser" not in detail
    assert "10.3.1.44" not in detail, "the message body must not be echoed"
    # Compared against what _redact_url produces rather than a hardcoded host,
    # so this stays coupled to the contract instead of to one example URL.
    assert _redact_url(portal_main.LOKI_URL) in detail, \
        "say which Loki, that is the point"
    assert "RuntimeError" in detail, "say what class of failure it was"


def test_loki_last_error_records_the_type_not_the_message(monkeypatch):
    """loki_last_error is served by /api/diagnostics, so it is a response
    field like any other."""
    from app import derive
    from app import main as portal_main

    monkeypatch.setattr(portal_main, "LOKI_URL", "http://loki.example.com:3100")

    def boom(*a, **kw):
        raise RuntimeError("secret detail nobody should see over HTTP")

    monkeypatch.setattr(derive, "fetch_from_loki", boom)

    with pytest.raises(HTTPException):
        portal_main._findings(1)

    assert portal_main._last_loki_error == "RuntimeError"


def test_a_successful_read_clears_the_recorded_error(monkeypatch):
    """A stale error string on a working portal is its own kind of lie."""
    from app import derive
    from app import main as portal_main

    monkeypatch.setattr(portal_main, "LOKI_URL", "http://loki.example.com:3100")
    portal_main._last_loki_error = "RuntimeError"
    monkeypatch.setattr(derive, "fetch_from_loki", lambda *a, **kw: [])

    portal_main._findings(1)

    assert portal_main._last_loki_error == ""


def test_missing_loki_url_still_says_so(monkeypatch):
    """The 503 for unconfigured Loki names a variable, not a value, so it was
    never the problem and must not regress into silence."""
    from app import main as portal_main

    monkeypatch.setattr(portal_main, "LOKI_URL", "")

    with pytest.raises(HTTPException) as exc:
        portal_main._findings(1)

    assert "LOKI_URL" in exc.value.detail
