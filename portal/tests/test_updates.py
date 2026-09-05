"""The update check: the portal says a newer release exists and what to run,
the way a self-hosted product does. It never upgrades anything."""
import io
import json
import os

import pytest

os.environ.setdefault("PORTAL_AUTH", "none")

from app import main  # noqa: E402

HTML = (main.STATIC / "index.html").read_text()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _feed(monkeypatch, payload=None, error=None):
    def fake(req, timeout=0):
        assert "ai-guard-portal" in req.get_header("User-agent")
        if error:
            raise error
        return _Resp(json.dumps(payload).encode())
    monkeypatch.setattr(main.urllib.request, "urlopen", fake)


def test_versions_compare_as_numbers_and_dev_is_not_one():
    assert main._parse_version("v0.27.1") == (0, 27, 1)
    assert main._parse_version("0.28.0") == (0, 28, 0)
    assert main._parse_version("v1.2") == (1, 2, 0)
    assert main._parse_version("dev") is None
    assert main._parse_version("") is None


def test_a_newer_release_is_reported_with_its_notes(monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "0.27.1")
    _feed(monkeypatch, {"tag_name": "v0.28.0", "name": "v0.28.0 - the ledger",
                        "html_url": "https://example.test/r", "published_at": "2026-09-06T10:00:00Z",
                        "body": "notes"})
    main._check_update()
    u = main.update_status()
    assert u["available"] is True and u["latest"] == "v0.28.0"
    assert u["name"] == "v0.28.0 - the ledger" and u["notes"] == "notes"
    assert u["error"] == "" and u["checked_at"]


def test_the_same_release_is_up_to_date_and_dev_is_not_compared(monkeypatch):
    _feed(monkeypatch, {"tag_name": "v0.27.1", "html_url": "u"})
    monkeypatch.setattr(main, "APP_VERSION", "0.27.1")
    main._check_update()
    assert main.update_status()["available"] is False
    monkeypatch.setattr(main, "APP_VERSION", "dev")
    u = main.update_status()
    assert u["comparable"] is False and u["available"] is None
    assert u["latest"] == "v0.27.1", "the latest release is still shown"


def test_a_failed_check_says_why_and_keeps_the_last_answer(monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "0.27.1")
    _feed(monkeypatch, {"tag_name": "v0.28.0", "html_url": "u"})
    main._check_update()
    _feed(monkeypatch, error=OSError("no route"))
    main._check_update()
    u = main.update_status()
    assert u["latest"] == "v0.28.0" and u["error"].startswith("OSError")


def test_the_feed_must_carry_a_version_tag(monkeypatch):
    monkeypatch.setattr(main, "_update_state", dict(main._update_state, latest="", error=""))
    _feed(monkeypatch, {"tag_name": "nightly"})
    main._check_update()
    assert main._update_state["latest"] == ""
    assert "ValueError" in main._update_state["error"]


def test_the_route_is_read_from_what_deployed_it(monkeypatch):
    monkeypatch.setattr(main, "DEPLOY_RELEASE", "ai-guard")
    assert main._deploy_route() == "helm"
    monkeypatch.setattr(main, "DEPLOY_RELEASE", "")
    monkeypatch.setattr(main, "DEPLOY_CHART", "")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    assert main._deploy_route() == "kubernetes"
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST")
    assert main._deploy_route() in ("compose", "unknown")


def test_switching_the_check_off_refuses_a_manual_check(monkeypatch):
    monkeypatch.setattr(main, "UPDATE_CHECK", False)
    assert main.update_status()["enabled"] is False
    with pytest.raises(main.HTTPException) as e:
        main.api_update_check(None)
    assert e.value.status_code == 409


def test_the_portal_never_upgrades_anything():
    """Stage one is awareness. No route here runs helm, kubectl or docker,
    and the page only prints commands for a person to run."""
    src = (main.STATIC.parent / "main.py").read_text()
    for word in ("subprocess", "helm upgrade", "docker compose pull"):
        assert word not in src, word
    assert 'data-tour="updates"' in HTML
    assert "How to upgrade on ${esc(route)}" in HTML
    assert "--reuse-values" in HTML
    assert 'data-act="update-check"' in HTML
    assert "t: 'Update available: ' + CFG.update.latest" in HTML
    assert "if (el.getAttribute('data-view')) {" in HTML
