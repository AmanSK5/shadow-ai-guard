"""Portal-side runtime configuration: reading findings from the store the
wizard saved, display preferences from settings, and the connection tests.
Same direct-call harness as the suite."""

import os

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main, managed


def _request(cookie_token="aigt_s"):
    hs = [(b"host", b"portal"),
          (b"cookie", ("%s=%s" % (main.SESSION_COOKIE, cookie_token)).encode())]
    return Request({"type": "http", "method": "GET", "path": "/",
                    "scheme": "http", "headers": hs, "query_string": b""})


@pytest.fixture
def login_mode(monkeypatch):
    calls = []
    answers = {
        "/admin/settings/secrets": {
            "log_store_url": "http://saved-loki:3100",
            "log_store_push_url": "",
            "log_store_username": "u1",
            "log_store_password": "pw1"},
        "/admin/settings": {"settings": {
            "grafana_url": {"value": "https://grafana.saved", "source": "db"},
            "grafana_panels": {"value": "abc:1:Top tools", "source": "db"},
            "grafana_dashboard_uid": {"value": "", "source": "unset"},
            "overview_widgets": {"value": "stat_row", "source": "db"},
            "receiver_public_url": {"value": "https://rx.saved.example",
                                    "source": "db"},
            "log_store_url": {"value": "http://saved-loki:3100",
                              "source": "db"},
        }},
    }

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        return answers.get(path, {"ok": True})

    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    main._invalidate_settings_caches()
    return calls


# --------------------------------------------------------------- log store --


def test_the_saved_store_wins_and_brings_its_own_credentials(login_mode,
                                                             monkeypatch):
    monkeypatch.setattr(main, "LOKI_URL", "http://env-loki:3100")
    monkeypatch.setattr(main, "LOKI_USERNAME", "env-user")
    monkeypatch.setattr(main, "LOKI_PASSWORD", "env-pass")
    assert main._log_store(_request()) == (
        "http://saved-loki:3100", "u1", "pw1", "portal")


def test_no_saved_store_falls_back_to_the_env(login_mode, monkeypatch):
    def fake(base, method, path, token, body=None):
        return {"log_store_url": "", "log_store_push_url": "",
                "log_store_username": "", "log_store_password": ""}
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "LOKI_URL", "http://env-loki:3100")
    url, _, _, source = main._log_store(_request())
    assert (url, source) == ("http://env-loki:3100", "env")


def test_classic_mode_never_calls_the_receiver(login_mode, monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main, "LOKI_URL", "http://env-loki:3100")
    assert main._log_store(None)[3] == "env"
    assert login_mode == []


def test_the_secrets_fetch_is_cached_and_a_write_invalidates(login_mode):
    main._log_store(_request())
    main._log_store(_request())
    secrets_calls = [c for c in login_mode if c["path"] == "/admin/settings/secrets"]
    assert len(secrets_calls) == 1

    # A settings write through the portal makes the cache stale NOW, not
    # in thirty seconds: the saved store must be read on the next page.
    main.api_settings_write(main.SettingsWrite(
        log_store_url="http://other:3100"), _=None, token="t")
    main._log_store(_request())
    secrets_calls = [c for c in login_mode if c["path"] == "/admin/settings/secrets"]
    assert len(secrets_calls) == 2


def test_an_unreachable_receiver_is_loud_not_a_silent_env_fallback(login_mode,
                                                                   monkeypatch):
    """Falling back to env here could read a different store than the
    receiver is writing to, which is the quiet-wrongness failure mode."""
    def down(base, method, path, token, body=None):
        raise managed.ReceiverError(502, "could not reach the receiver (X)")
    monkeypatch.setattr(main.managed, "receiver_request", down)
    with pytest.raises(HTTPException) as e:
        main._log_store(_request())
    assert e.value.status_code == 502


def test_findings_only_sends_the_env_bearer_to_the_env_store(login_mode,
                                                             monkeypatch):
    """LOKI_TOKEN is env configuration; sending it to a portal-saved store
    would leak one store's bearer to another."""
    seen = {}

    def fake_fetch(url, hours, token=None, limit=5000, username=None,
                   password=None):
        seen.update(url=url, token=token, username=username)
        return []
    monkeypatch.setattr(main.derive, "fetch_from_loki", fake_fetch)
    monkeypatch.setattr(main, "LOKI_TOKEN", "env-bearer")

    main._findings(1, _request())
    assert seen["url"] == "http://saved-loki:3100"
    assert seen["token"] is None and seen["username"] == "u1"


# ------------------------------------------------------------------ config --


def test_config_resolves_display_preferences_from_settings(login_mode,
                                                           monkeypatch):
    monkeypatch.setattr(main, "GRAFANA_URL", "https://grafana.env")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.env.example")
    out = main.config(_request(), _=None)
    assert out["grafana_url"] == "https://grafana.saved"
    assert out["grafana_panels"] == [
        {"uid": "abc", "panel_id": "1", "title": "Top tools"}]
    assert out["overview_widgets"] == [{"kind": "stat_row"}]
    assert out["loki_configured"] is True
    assert out["managed"]["artifacts_ready"] is True
    assert out["managed"]["receiver_public_url_default"] == "https://rx.saved.example"


def test_config_in_classic_mode_is_the_env_exactly(monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main, "GRAFANA_URL", "https://grafana.env")
    out = main.config(None, _=None)
    assert out["grafana_url"] == "https://grafana.env"


def test_the_frame_src_follows_the_cached_setting(login_mode, monkeypatch):
    monkeypatch.setattr(main, "GRAFANA_URL", "")
    # Cold cache: nothing to allow yet.
    assert main._frame_src() == ""
    # A config call warms the cache; frames unblock from then on.
    main.config(_request(), _=None)
    assert main._frame_src() == "https://grafana.saved"
    # Env, when set, stays authoritative.
    monkeypatch.setattr(main, "GRAFANA_URL", "https://grafana.env")
    assert main._frame_src() == "https://grafana.env"


def test_artifacts_bake_the_saved_public_url(login_mode, monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.env.example")
    monkeypatch.setattr(main, "COLLECTOR_SCRIPTS_DIR",
                        str(main.Path(__file__).parent.parent / "collector-scripts"))

    def fake(base, method, path, token, body=None):
        if path == "/admin/settings":
            return {"settings": {"receiver_public_url": {
                "value": "https://rx.saved.example", "source": "db"}}}
        return {"id": "t1", "token": "aige_MINTED",
                "expires_at": "2027-01-01T00:00:00+00:00"}
    monkeypatch.setattr(main.managed, "receiver_request", fake)

    resp = main.artifact("collector-macos", _=None, token="t")
    # The exact baked fallback line, not a loose substring: the saved URL
    # must land as the script's default, and the env one must not.
    body = resp.body.decode()
    assert 'RECEIVER_BASE="${4:-https://rx.saved.example}"' in body
    assert 'RECEIVER_BASE="${4:-https://rx.env.example}"' not in body


# ------------------------------------------------------------------- tests --


def _probe_with_saved_url(monkeypatch, saved):
    """The probe reads the SAVED public URL (save first, then probe) - the
    route fetches nothing the request names, by design and for CodeQL."""
    def fake(base, method, path, token, body=None):
        return {"settings": {"receiver_public_url": {
            "value": saved, "source": "db" if saved else "unset"}}}
    monkeypatch.setattr(main.managed, "receiver_request", fake)


def test_the_receiver_url_probe_warns_on_a_dotless_host(login_mode, monkeypatch):
    """The tailscale short-name trap, caught before an artifact bakes it."""
    class _Resp:
        def read(self):
            return b'{"ok": true, "version": "0.9.8"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    import urllib.request as _urlreq
    monkeypatch.setattr(_urlreq, "urlopen", lambda url, timeout=None: _Resp())

    _probe_with_saved_url(monkeypatch, "https://ai-guard")
    out = main.test_receiver_url(_=None, token="t")
    assert out["ok"] is True and out["version"] == "0.9.8"
    assert any("no dot" in w for w in out["warnings"])

    _probe_with_saved_url(monkeypatch, "https://ai-guard.tailfc8950.ts.net")
    out = main.test_receiver_url(_=None, token="t")
    assert out["warnings"] == []


def test_the_probe_with_nothing_saved_falls_back_to_env_then_400(login_mode,
                                                                 monkeypatch):
    _probe_with_saved_url(monkeypatch, "")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "")
    with pytest.raises(HTTPException) as e:
        main.test_receiver_url(_=None, token="t")
    assert e.value.status_code == 400
    assert "save one in Settings" in e.value.detail


def test_the_probe_reports_an_unreachable_host_without_crashing(login_mode,
                                                                monkeypatch):
    import urllib.request as _urlreq

    def boom(url, timeout=None):
        raise OSError("nope")
    monkeypatch.setattr(_urlreq, "urlopen", boom)
    _probe_with_saved_url(monkeypatch, "https://rx.example.com")
    out = main.test_receiver_url(_=None, token="t")
    assert out["ok"] is False
    assert "could not reach" in out["detail"]


def test_the_read_test_hints_at_missing_read_scope(login_mode, monkeypatch):
    def refuse(url, hours, token=None, limit=5000, username=None, password=None):
        import urllib.error
        raise urllib.error.HTTPError(url, 401, "unauthorized", None, None)
    monkeypatch.setattr(main.derive, "fetch_from_loki", refuse)
    out = main.test_log_store_read(_request(), _=None)
    assert out["ok"] is False
    assert "logs:read" in out["hint"]


def test_the_read_test_passes_through_ok(login_mode, monkeypatch):
    monkeypatch.setattr(main.derive, "fetch_from_loki",
                        lambda *a, **kw: [])
    out = main.test_log_store_read(_request(), _=None)
    assert out["ok"] is True and "saved-loki" in out["url"]


def test_the_push_test_is_a_proxy(login_mode):
    main.test_log_store_push(_=None, token="aigt_s")
    assert login_mode[-1] == {"method": "POST",
                              "path": "/admin/test/log-store-push",
                              "token": "aigt_s", "body": None}


def test_the_page_carries_the_new_settings_ui():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("save-setting", "run-test", "log-store-push",
                   "log-store-read", "receiver-url", "wiz-store",
                   "settingRow('log_store_url'",
                   "settingRow('receiver_public_url'",
                   "settingRow('alertmanager_url'",
                   "settingRow('grafana_url'",
                   "settingRow('log_store_password'",
                   "logs:write AND logs:read", "kubectl get svc"):
        assert needle in html, needle


def test_the_inline_script_parses():
    """The whole UI is one inline script: a single syntax error renders a
    blank page with an empty nav and no error anywhere but the console.
    Parse it with node when node is around (it is in CI's extension job and
    on dev machines); skip, not pass, when it is not."""
    import shutil
    import subprocess

    if not shutil.which("node"):
        pytest.skip("node not available")
    html = (main.STATIC / "index.html").read_text()
    # Plain slicing, not a regex: this extracts the page's one known inline
    # block from our own file - it is not a tag filter, and a regex here
    # reads to scanners as one.
    script = html.split("<script>", 1)[1].rsplit("</script>", 1)[0]
    proc = subprocess.run(
        ["node", "-e", "new Function(require('fs').readFileSync(0,'utf8'))"],
        input=script, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-800:]
