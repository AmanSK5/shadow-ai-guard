"""The portal's half of `aiguardctl upgrade`: proxies that forward and decide
nothing, an approval page owners see, and a tracker that survives the
portal's own restart. SECURITY.md, "Upgrading"."""
import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main

INDEX = (Path(__file__).parent.parent / "app" / "static" / "index.html").read_text()


@pytest.fixture
def login_mode(monkeypatch):
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token, "body": body})
        if path == "/admin/upgrade/plan":
            return {"receiver_version": "0.28.0", "approved": {"by": "aman"}}
        return {"ok": True}
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver:8080")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    return calls


def _req(headers=(), cookie=None):
    hs = [(k.encode(), v.encode()) for k, v in headers]
    if cookie:
        hs.append((b"cookie", ("%s=%s" % (main.SESSION_COOKIE, cookie)).encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "scheme": "http",
                    "headers": hs, "query_string": b""})


def test_the_open_routes_forward_without_a_credential(login_mode):
    main.api_cli_authorize(main.CliAuthorizeWrite(purpose="upgrade", verifier_hash="a" * 64, client="aiguardctl"))
    main.api_cli_token(main.CliTokenWrite(device_code="aigd_" + "x" * 20, verifier="v" * 20))
    assert [(c["method"], c["path"], c["token"]) for c in login_mode] == [
        ("POST", "/admin/cli/authorize", ""), ("POST", "/admin/cli/token", "")]
    assert login_mode[0]["body"]["verifier_hash"] == "a" * 64


def test_the_open_routes_do_not_exist_in_classic_mode(monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    with pytest.raises(HTTPException) as e:
        main.api_cli_authorize(main.CliAuthorizeWrite(purpose="upgrade", verifier_hash="a" * 64))
    assert e.value.status_code == 404


def test_only_an_upgrade_token_reaches_the_run_routes(login_mode):
    """A session cookie is not a substitute: the receiver does not accept
    sessions on the run routes, and the portal does not try."""
    with pytest.raises(HTTPException) as e:
        main._upgrade_bearer(_req(cookie="aigt_session"))
    assert e.value.status_code == 401
    with pytest.raises(HTTPException):
        main._upgrade_bearer(_req(headers=[("authorization", "Bearer aigt_session")]))
    assert main._upgrade_bearer(_req(headers=[("authorization", "Bearer aigu_tok")])) == "aigu_tok"
    main.api_upgrade_run_start(main.UpgradeRunWrite(route="helm", from_version="0.28.0", to_version="0.29.0"), token="aigu_tok")
    main.api_upgrade_run_step("abcdef012345", main.UpgradeStepWrite(step="helm upgrade", status="running"), token="aigu_tok")
    main.api_upgrade_run_finish("abcdef012345", main.UpgradeFinishWrite(outcome="succeeded"), token="aigu_tok")
    paths = [(c["method"], c["path"], c["token"]) for c in login_mode]
    assert paths == [("POST", "/admin/upgrade/runs", "aigu_tok"),
                     ("POST", "/admin/upgrade/runs/abcdef012345/steps", "aigu_tok"),
                     ("POST", "/admin/upgrade/runs/abcdef012345/finish", "aigu_tok")]
    with pytest.raises(HTTPException) as e:
        main.api_upgrade_run_step("not-a-run-id", main.UpgradeStepWrite(step="x", status="done"), token="aigu_tok")
    assert e.value.status_code == 422


def test_the_plan_joins_what_the_portal_knows_to_what_the_receiver_says(login_mode, monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "0.28.0")
    monkeypatch.setattr(main, "_update_state", dict(main._update_state, latest="v0.29.0", url="u"))
    plan = main.api_upgrade_plan(_req(headers=[("authorization", "Bearer aigu_tok")]))
    assert plan["receiver_version"] == "0.28.0" and plan["portal_version"] == "0.28.0"
    assert plan["latest"] == "v0.29.0" and plan["approved"] == {"by": "aman"}
    assert plan["image_repository"] == "ghcr.io/amansk5/shadow-ai-guard"
    assert plan["chart"].startswith("oci://ghcr.io/amansk5/shadow-ai-guard/charts/")
    with pytest.raises(HTTPException) as e:
        main.api_upgrade_plan(_req())
    assert e.value.status_code == 401


def test_the_page_carries_the_approval_view_and_the_tracker():
    assert "'cli-approve'" in INDEX.split("const VIEWS =", 1)[1][:200]
    assert "if (h.startsWith('cli-approve/')) {" in INDEX
    assert "async function cliApprove()" in INDEX
    assert "Only an owner can approve a command" in INDEX
    assert 'data-act="cli-approve"' in INDEX and 'data-act="cli-deny"' in INDEX
    assert "function upgradeTracker()" in INDEX and "function upgradeWatch()" in INDEX
    assert "<b>Portal restarting</b>" in INDEX
    assert "aiguardctl upgrade --portal ${esc(location.origin)}" in INDEX


def test_the_portal_still_runs_nothing():
    src = (main.STATIC.parent / "main.py").read_text()
    for word in ("import subprocess", "os.system(", "os.exec", "import shlex",
                 '"helm ', '"kubectl ', '"docker '):
        assert word not in src, word
