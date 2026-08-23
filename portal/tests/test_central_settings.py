"""Central settings and portal-recorded governance, portal side.

The receiver stores and validates; these tests cover what the portal adds:
the per-tool merge (DB wins, file fills gaps, origin labelled), the proxy
routes forwarding exactly what was sent, and the register cache dying when
a decision changes. Same direct-call harness as the rest of the suite.
"""

import os
from datetime import date

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import governance, main, managed


def _request(cookie_token="aigt_s"):
    hs = [(b"host", b"portal")]
    if cookie_token is not None:
        hs.append((b"cookie",
                   ("%s=%s" % (main.SESSION_COOKIE, cookie_token)).encode()))
    return Request({"type": "http", "method": "GET", "path": "/",
                    "scheme": "http", "headers": hs, "query_string": b""})


@pytest.fixture
def login_mode(monkeypatch):
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        if path == "/admin/governance" and method == "GET":
            return {"decisions": [
                {"tool_id": "chatgpt", "status": "approved", "owner": "Security",
                 "review_due": "2027-06-01", "reason": "pilot",
                 "updated_at": "2026-08-23", "updated_by": "aman"}]}
        return {"ok": True}

    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "_session_cache", {})
    return calls


# ------------------------------------------------------- governance merge --


def test_classic_mode_reads_the_file_and_calls_no_receiver(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main.managed, "receiver_request",
                        lambda *a, **k: calls.append(a))
    gov, exceptions, n = main._merged_governance(_request())
    assert gov == {} and n == 0 and calls == []


def test_a_portal_decision_wins_over_the_file_and_says_so(login_mode,
                                                          monkeypatch, tmp_path):
    """DB wins per tool, file fills the gaps - the same rule every setting
    follows - and the record carries its origin so decide() can label it."""
    gov_file = tmp_path / "governance.yaml"
    gov_file.write_text(
        "tools:\n"
        "  chatgpt: {status: not_approved, owner: IT}\n"
        "  claude: {status: reviewing, owner: Legal}\n")
    monkeypatch.setattr(main, "GOVERNANCE_PATH", str(gov_file))

    gov, _exceptions, n = main._merged_governance(_request())
    assert n == 1
    # The DB record displaced the file's chatgpt entirely...
    assert gov["chatgpt"]["status"] == "approved"
    assert gov["chatgpt"]["owner"] == "Security"
    assert gov["chatgpt"]["review_due"] == date(2027, 6, 1)
    assert gov["chatgpt"]["origin"] == "portal"
    # ...and the file still speaks where the DB is silent.
    assert gov["claude"]["status"] == "reviewing"
    assert "origin" not in gov["claude"]

    # decide() labels each source honestly.
    assert governance.decide("chatgpt", gov, False)["source"] == "portal"
    assert governance.decide("claude", gov, False)["source"] == "governance"


def test_an_unreachable_receiver_fails_loud_not_stale(login_mode, monkeypatch):
    """Showing yesterday's decisions as if current is the quiet wrongness
    this project exists to avoid: file-only fallback would do exactly that."""
    def down(base, method, path, token, body=None):
        raise managed.ReceiverError(502, "could not reach the receiver (X)")
    monkeypatch.setattr(main.managed, "receiver_request", down)

    with pytest.raises(HTTPException) as e:
        main._merged_governance(_request())
    assert e.value.status_code == 502
    assert "governance decisions" in e.value.detail


def test_the_merge_forwards_the_requesters_own_session(login_mode):
    main._merged_governance(_request(cookie_token="aigt_mine"))
    assert login_mode[0]["token"] == "aigt_mine"


# ------------------------------------------------------------ proxy routes --


def test_settings_write_forwards_only_what_was_sent(login_mode):
    main.api_settings_write(
        main.SettingsWrite(corp_domains=["Example.com"]), _=None, token="t")
    assert login_mode[0]["method"] == "PUT"
    assert login_mode[0]["path"] == "/admin/settings"
    # Only the provided key rides; normalisation is the receiver's job.
    assert login_mode[0]["body"] == {"corp_domains": ["Example.com"]}


def test_an_explicit_null_rides_through_as_the_delete_it_is(login_mode):
    main.api_settings_write(
        main.SettingsWrite(corp_domains=None), _=None, token="t")
    assert login_mode[0]["body"] == {"corp_domains": None}


def test_an_unknown_settings_key_is_refused_at_the_edge():
    with pytest.raises(ValueError):
        main.SettingsWrite(corp_domain=["typo.com"])


def test_a_governance_write_kills_the_register_cache(login_mode):
    main._cache["register"] = {"value": ["stale"], "at": 9e12, "hours": 168}
    main.api_governance_write(
        main.GovernanceWrite(decisions=[main.DecisionWrite(
            tool_id="chatgpt", status="not_approved")]), _=None, token="t")
    assert "register" not in main._cache
    assert login_mode[0]["method"] == "PUT"
    assert login_mode[0]["path"] == "/admin/governance"
    assert login_mode[0]["body"]["decisions"][0]["tool_id"] == "chatgpt"


def test_password_change_forwards_on_the_callers_session(login_mode):
    main.api_password(main.PasswordWrite(current="old",
                                         new="a-long-enough-password"),
                      _=None, token="aigt_mine")
    assert login_mode[0] == {"method": "POST", "path": "/admin/password",
                             "token": "aigt_mine",
                             "body": {"current": "old",
                                      "new": "a-long-enough-password"}}


def test_the_receiver_client_sends_put_bodies():
    """receiver_request only attached data to POST; a PUT with a silently
    dropped body would reach the receiver as an empty update that changes
    nothing and reports success."""
    import json as _json
    from unittest.mock import patch

    seen = {}

    class _Resp:
        def read(self):
            return b"{}"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        seen["data"] = req.data
        return _Resp()

    with patch.object(managed.urllib.request, "urlopen", fake_urlopen):
        managed.receiver_request("http://r", "PUT", "/admin/settings", "t",
                                 {"corp_domains": ["a.com"]})
    assert _json.loads(seen["data"]) == {"corp_domains": ["a.com"]}


# ---------------------------------------------------------------- the page --


def test_the_page_carries_the_editors():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("gov-edit", "gov-save", "gov-clear", "save-domains",
                   "clear-domains", "save-extid", "change-password",
                   "/api/settings", "/api/governance-decisions",
                   "/api/password", "set in the portal"):
        assert needle in html, needle
