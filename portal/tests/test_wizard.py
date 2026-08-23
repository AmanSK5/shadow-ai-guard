"""The onboarding wizard's plumbing: the two generated artifacts, the
registry-tools endpoint, and the wiring that makes a fresh install
deployable from one page. Same direct-call harness as the suite."""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import derive, main, managed

EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


# ------------------------------------------------------- extension policy --


def test_the_extension_policy_bakes_everything_the_extension_reads():
    name, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_TESTTOKEN",
        ["example.com", "example.co.uk"])
    assert name == "ai-guard-extension-policy.plist"
    # The managed-storage schema the extension actually reads
    # (extension/src/background.js, content.js, guard.js).
    assert "<string>https://rx.example.com/report</string>" in out
    assert "<string>aige_TESTTOKEN</string>" in out
    assert "<string>$SERIALNUMBER</string>" in out
    assert "<string>example.com</string>" in out
    assert "<string>example.co.uk</string>" in out
    assert "pasteGuardMode" in out and "classificationMarkings" in out
    # The header names the per-browser upload domains with the real id.
    assert "com.google.Chrome.extensions.%s" % EXT_ID in out
    assert "com.microsoft.Edge.extensions.%s" % EXT_ID in out


def test_the_policy_keys_match_the_shipped_plist_templates():
    """The generated policy and extension/deploy/macos are two spellings of
    one schema; a key drifting in either is an extension that quietly reads
    nothing."""
    shipped = (Path(__file__).parent.parent.parent / "extension" / "deploy"
               / "macos" / "chrome" / "managed-storage.plist").read_text()
    _, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_T", ["example.com"])
    for key in ("reportEndpoint", "authToken", "deviceIdentifier",
                "allowedDomains", "pasteGuardMode", "classificationMarkings"):
        assert "<key>%s</key>" % key in shipped, key
        assert "<key>%s</key>" % key in out, key


def test_no_domains_is_generated_with_a_warning_not_refused():
    """A skipped corp-domains step should not block the download - but the
    file must say what the empty list means."""
    _, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_T", [])
    assert "no corporate domains set" in out


def test_a_malformed_extension_id_is_refused():
    """32 letters a-p or nothing: the shape check doubles as XML safety,
    since the id lands inside an XML comment where '--' would break the
    document."""
    for bad in ("", "short", "z" * 32, "a-b" + "a" * 29, "a" * 33):
        with pytest.raises(managed.ArtifactError):
            managed.generate_extension_policy(
                bad, "https://rx.example.com", "aige_T", [])


def test_hostile_domains_cannot_escape_the_xml():
    with pytest.raises(managed.ArtifactError):
        managed.generate_extension_policy(
            EXT_ID, "https://rx.example.com", "aige_T",
            ["</string><key>authToken</key>"])


# -------------------------------------------------------- scanner cronjob --


def test_the_cronjob_is_valid_yaml_with_the_token_in_a_secret():
    import yaml

    name, out = managed.generate_scanner_cronjob(
        "https://rx.example.com", "aige_TESTTOKEN", "0.9.7")
    assert name == "ai-guard-scanner-cronjob.yaml"
    secret, cron = list(yaml.safe_load_all(out))
    assert secret["kind"] == "Secret"
    assert secret["stringData"]["enrollmentToken"] == "aige_TESTTOKEN"
    assert cron["kind"] == "CronJob"
    c = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    assert c["image"] == "ghcr.io/amansk5/shadow-ai-guard/scanner:0.9.7"
    env = {e["name"]: e for e in c["env"]}
    assert env["RECEIVER_URL"]["value"] == "https://rx.example.com"
    # The token reaches the pod through the Secret, never inline.
    assert env["RECEIVER_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == "ai-guard-scanner"
    assert env["AIGUARD_SCANNER_ID"]["value"] == "scanner"


# ------------------------------------------------------------- the routes --


@pytest.fixture
def receiver(monkeypatch):
    """A fake receiver whose settings carry an extension id and domains."""
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        if path == "/admin/settings":
            return {"settings": {
                "corp_domains": {"value": ["example.com"], "source": "db",
                                 "env": []},
                "extension_id": {"value": EXT_ID, "source": "db"},
                "onboarding_done": {"value": False, "source": "unset"}}}
        if method == "POST" and path == "/admin/enrollment-tokens":
            return {"id": "tok9", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {}

    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


def http_error(fn, *args, **kw) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        fn(*args, **kw)
    return e.value


def test_the_extension_policy_route_reads_settings_then_mints(receiver):
    resp = main.artifact("extension-policy", _=None, token="aigt_s")
    assert 'filename="ai-guard-extension-policy.plist"' in resp.headers["content-disposition"]
    assert resp.headers["x-enrollment-token-id"] == "tok9"
    body = resp.body.decode()
    # The exact plist elements, not loose substrings: the token as the
    # authToken value and the settings-sourced domain inside allowedDomains.
    # (Also what keeps CodeQL from reading a plain "example.com" in body as
    # URL-substring sanitization, which this never was.)
    assert "<string>aige_MINTED</string>" in body
    assert "<string>example.com</string>" in body
    # Settings were read before minting, on the caller's own session.
    assert [c["path"] for c in receiver] == ["/admin/settings",
                                             "/admin/enrollment-tokens"]
    assert receiver[1]["body"]["note"] == "portal artifact: extension-policy"


def test_no_extension_id_refuses_before_minting(receiver, monkeypatch):
    def fake(base, method, path, token, body=None):
        receiver.append({"path": path})
        return {"settings": {"corp_domains": {"value": []},
                             "extension_id": {"value": ""},
                             "onboarding_done": {"value": False}}}
    monkeypatch.setattr(main.managed, "receiver_request", fake)

    err = http_error(main.artifact, "extension-policy", _=None, token="t")
    assert err.status_code == 409
    assert "extension ID" in err.detail
    # No token was minted for an artifact that never existed.
    assert [c["path"] for c in receiver] == ["/admin/settings"]


def test_the_cronjob_route_requires_nothing_from_settings(receiver, monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "0.9.7")
    resp = main.artifact("scanner-cronjob", _=None, token="t")
    assert 'filename="ai-guard-scanner-cronjob.yaml"' in resp.headers["content-disposition"]
    assert "scanner:0.9.7" in resp.body.decode()
    # Settings are read for the public URL, but nothing scanner-specific
    # is required from them.
    assert [c["path"] for c in receiver] == ["/admin/settings",
                                             "/admin/enrollment-tokens"]


def test_a_dev_build_bakes_latest_not_a_nonexistent_image(receiver, monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "dev")
    resp = main.artifact("scanner-cronjob", _=None, token="t")
    assert "scanner:latest" in resp.body.decode()


def test_unknown_kinds_are_still_404(receiver):
    assert http_error(main.artifact, "collector-solaris", _=None,
                      token="t").status_code == 404


def test_registry_tools_needs_no_findings(monkeypatch, tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "tools:\n"
        "  - id: chatgpt\n    name: ChatGPT\n    vendor: OpenAI\n"
        "  - id: claude\n    name: Claude\n    vendor: Anthropic\n"
        "    approved: true\n")
    monkeypatch.setattr(main, "REGISTRY_PATH", str(reg))
    out = main.registry_tools(None, _=None)
    assert out["tools"] == [
        {"id": "chatgpt", "name": "ChatGPT", "vendor": "OpenAI",
         "approved": False, "custom": False},
        {"id": "claude", "name": "Claude", "vendor": "Anthropic",
         "approved": True, "custom": False}]


def test_the_setup_rows_offer_the_extension_policy_once():
    """The accounts row carries the artifact; the paste-guard row must not,
    because it is the same extension and a second button minting a second
    token for one deployment is a trap."""
    all_rows = [r for g in derive.status_from([])["groups"]
                for r in g["sources"]]
    arts = {r["source"]: r["artifact"] for r in all_rows}
    assert arts["browser_extension"] == "extension-policy"
    assert arts["paste_guard"] == ""
    assert arts["collector-macos"] == "collector-macos"


# ---------------------------------------------------------------- the page --


def test_the_page_carries_the_wizard():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("wiz-approve", "wiz-notapprove", "wiz-finish",
                   "/api/registry-tools", "onboarding_done", "'wizard'",
                   "scanner-cronjob", "extension-policy"):
        assert needle in html, needle


def test_the_register_carries_the_watchlist_decisions():
    """The wizard's baseline table was the only place to record a decision
    about a tool nothing has observed yet, and the wizard is a door you
    walk through once. The register's watchlist section is the standing
    version, and Settings can reopen the wizard."""
    html = (main.STATIC / "index.html").read_text()
    for needle in ("watchlistBlock", "wl-toggle", "open-wizard",
                   "known, not observed",
                   "run the setup wizard again"):
        assert needle in html, needle


def test_the_page_carries_the_tool_registry_view():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("registryView", "reg-add", "reg-save", "reg-delete",
                   "reg-suggest", "reg-adv", "'registry'", "Tool registry",
                   "/api/registry-entries", "add to registry"):
        assert needle in html, needle


def test_the_js_category_list_matches_the_schema():
    """REG_CATEGORIES is a hand-mirror of registry/schema.json's category
    enum; a value added to one and not the other makes the form refuse (or
    omit) a category the receiver accepts."""
    import json

    schema = json.loads(
        (Path(__file__).parent.parent.parent / "registry" / "schema.json")
        .read_text())
    enum = schema["properties"]["tools"]["items"]["properties"]["category"]["enum"]
    html = (main.STATIC / "index.html").read_text()
    start = html.index("REG_CATEGORIES = [")
    js_list = html[start:html.index("];", start)]
    for value in enum:
        assert "'%s'" % value in js_list, value
