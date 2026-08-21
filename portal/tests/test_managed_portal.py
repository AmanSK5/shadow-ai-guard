"""Managed mode in the portal: the proxy, the artifacts, the script copies.

Route functions are called directly, like every other test in this suite -
the portal deliberately has no HTTP client dependency (TestClient needs
httpx), and the write path's HTTP wiring is FastAPI dependency defaults
whose behaviour lives in `_admin_forward`, which is tested by name. Config
is monkeypatched onto the module rather than reloaded: every route reads
the globals at call time, and a reload would rebuild the app out from under
the other test files.
"""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import main, managed

PORTAL = Path(__file__).parent.parent
REPO = PORTAL.parent
SCRIPTS = PORTAL / "collector-scripts"


# ------------------------------------------------------- the script copies --


def test_the_script_copies_match_their_sources():
    """Same pattern as the chart's bundled registry: the portal image cannot
    see endpoint/ at build time, so it ships verified copies, and this test
    is the verification. A drifted copy means artifacts deploy an older
    collector than the repo says exists."""
    pairs = [
        ("collector-macos.sh", "endpoint/macos/ai-guard-collector.sh"),
        ("collector-linux.sh", "endpoint/linux/ai-guard-collector.sh"),
        ("collector-windows.ps1", "endpoint/windows/ai-guard-collector.ps1"),
    ]
    for copy, source in pairs:
        assert (SCRIPTS / copy).read_bytes() == (REPO / source).read_bytes(), (
            "portal/collector-scripts/%s no longer matches %s - re-copy it"
            % (copy, source))


def test_every_anchor_matches_its_script_exactly_once():
    """The anchors are the scripts' own fallback syntax. A collector edit
    that reshapes one of those lines must fail here, at build time, rather
    than produce artifacts that quietly bake nothing."""
    for kind, spec in managed.ARTIFACTS.items():
        content = (SCRIPTS / spec["file"]).read_text()
        for anchor, _ in spec["anchors"]:
            assert content.count(anchor) == 1, (
                "%s: anchor not found exactly once: %r" % (kind, anchor))


# ------------------------------------------------------------- generation --


def test_generation_bakes_defaults_not_hardcodes():
    """The substitution targets fallback syntax, so an MDM-supplied value
    still wins. Baking a hardcode instead would make the Jamf parameter a
    lie: set, honoured-looking, and ignored."""
    url, tok = "https://rx.example.com", "aige_TESTTOKEN"

    name, out = managed.generate("collector-macos", str(SCRIPTS), url, tok)
    assert name == "ai-guard-collector.sh"
    assert 'RECEIVER_BASE="${4:-https://rx.example.com}"' in out
    assert 'TOKEN="${5:-aige_TESTTOKEN}"' in out

    _, out = managed.generate("collector-linux", str(SCRIPTS), url, tok)
    assert 'RECEIVER_BASE="${AIGUARD_RECEIVER_BASE:-https://rx.example.com}"' in out
    assert 'TOKEN="${AIGUARD_TOKEN:-aige_TESTTOKEN}"' in out

    name, out = managed.generate("collector-windows", str(SCRIPTS), url, tok)
    assert name == "ai-guard-collector.ps1"
    assert "$ReceiverBase    = 'https://rx.example.com'" in out
    assert "$Token           = 'aige_TESTTOKEN'" in out
    assert "__RECEIVER_TOKEN__" not in out


def test_generation_refuses_values_that_could_escape_their_quoting():
    """The values land inside shell and PowerShell quoting. Anything that
    could break out is refused by name rather than escaped, because both are
    operator configuration and a rejection is a misconfiguration surfaced."""
    for bad in ("https://x.example/'", 'https://x.example/"', "https://x)$(reboot",
                "https://x.example/ payload", "https://x\\y"):
        with pytest.raises(managed.ArtifactError):
            managed.generate("collector-linux", str(SCRIPTS), bad, "aige_ok")
    with pytest.raises(managed.ArtifactError):
        managed.generate("collector-linux", str(SCRIPTS),
                         "https://x.example", "aige_'injected")
    with pytest.raises(managed.ArtifactError):
        managed.generate("nonsense", str(SCRIPTS), "https://x.example", "aige_ok")


# ------------------------------------------------------------- the routes --


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")
    monkeypatch.setattr(main, "COLLECTOR_SCRIPTS_DIR", str(SCRIPTS))


@pytest.fixture
def receiver(monkeypatch, configured):
    """A fake receiver_request that records every call. Canned answers cover
    the routes under test; a test that needs a refusal swaps in its own."""
    calls = []

    def fake(base, method, path, admin_token, body=None):
        calls.append({"base": base, "method": method, "path": path,
                      "token": admin_token, "body": body})
        if path == "/admin/devices":
            return {"devices": [{"id": "d1", "platform": "macos"}]}
        if method == "POST" and path == "/admin/enrollment-tokens":
            return {"id": "tok1", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {"tokens": []}

    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


def http_error(fn, *args, **kw) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        fn(*args, **kw)
    return e.value


def test_unconfigured_managed_routes_say_what_is_missing(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "")
    err = http_error(main._admin_forward, x_admin_token="anything")
    assert err.status_code == 503
    assert "RECEIVER_URL" in err.detail


def test_a_missing_admin_header_is_a_401_that_explains_the_model(configured):
    err = http_error(main._admin_forward, x_admin_token="")
    assert err.status_code == 401
    assert "never stores" in err.detail


def test_the_admin_token_is_forwarded_verbatim(receiver):
    out = main.fleet(_=None, token="the-admin-token")
    assert out["devices"][0]["id"] == "d1"
    assert receiver[0]["token"] == "the-admin-token"
    assert receiver[0]["path"] == "/admin/devices"
    assert receiver[0]["base"] == "http://receiver.internal:8080"


def test_a_receiver_refusal_passes_through_with_its_meaning(monkeypatch, configured):
    """A 401 must reach the operator as "bad token", not as a portal error:
    the receiver is the authorizer and its answer is the answer."""
    def refuse(*a, **kw):
        raise managed.ReceiverError(401, "bad token")
    monkeypatch.setattr(main.managed, "receiver_request", refuse)
    err = http_error(main.fleet, _=None, token="wrong")
    assert err.status_code == 401
    assert err.detail == "bad token"


def test_minting_forwards_note_and_ttl(receiver):
    out = main.mint_enrollment_token(
        main.MintRequest(note="macOS rollout", ttl_days=30), _=None, token="t")
    assert out["token"] == "aige_MINTED"
    assert receiver[0]["body"] == {"note": "macOS rollout", "ttl_days": 30}


def test_mint_bounds_are_enforced_at_the_model():
    """ttl_days=0 must never reach the receiver as a request: the portal's
    model carries the same bounds the receiver enforces, so a bad value is a
    422 at the edge rather than a proxied refusal."""
    with pytest.raises(ValueError):
        main.MintRequest(ttl_days=0)
    with pytest.raises(ValueError):
        main.MintRequest(note="x" * 201)


def test_malformed_ids_never_reach_the_receiver(receiver):
    err = http_error(main.revoke_device, "bad*id", _=None, token="t")
    assert err.status_code == 422
    err = http_error(main.revoke_enrollment_token, "../devices", _=None, token="t")
    assert err.status_code == 422
    assert receiver == []


def test_an_artifact_mints_its_own_token_and_downloads_configured(receiver):
    resp = main.artifact("collector-macos", _=None, token="t")
    assert 'filename="ai-guard-collector.sh"' in resp.headers["content-disposition"]
    assert resp.headers["x-enrollment-token-id"] == "tok1"
    body = resp.body.decode()
    assert 'RECEIVER_BASE="${4:-https://rx.example.com}"' in body
    assert 'TOKEN="${5:-aige_MINTED}"' in body
    # Provenance: the minted token names the artifact it left inside.
    assert receiver[0]["body"]["note"] == "portal artifact: collector-macos"


def test_an_artifact_without_a_public_url_is_refused_before_minting(
        monkeypatch, receiver):
    """The internal RECEIVER_URL baked into a Jamf script would enroll
    nothing, and the refusal has to come before a token is minted for an
    artifact that never existed."""
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "")
    err = http_error(main.artifact, "collector-macos", _=None, token="t")
    assert err.status_code == 503
    assert "RECEIVER_PUBLIC_URL" in err.detail
    assert receiver == []


def test_an_unknown_artifact_is_404_before_minting(receiver):
    err = http_error(main.artifact, "collector-solaris", _=None, token="t")
    assert err.status_code == 404
    assert receiver == []


def test_config_names_which_managed_flag_is_missing(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "http://r.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "")
    assert main.config(_=None)["managed"] == {
        "enabled": True, "artifacts_ready": False}


# --------------------------------------------------------- receiver client --


def test_receiver_errors_carry_the_class_name_not_the_message():
    """The URL and the error text are for the log. An unreachable receiver
    must not echo connection strings into the browser."""
    with pytest.raises(managed.ReceiverError) as e:
        managed.receiver_request("http://127.0.0.1:1", "GET", "/admin/devices", "t")
    assert e.value.status == 502
    assert "127.0.0.1" not in e.value.detail
    assert "could not reach the receiver" in e.value.detail
