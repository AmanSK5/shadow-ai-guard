"""The extension artifact matrix: one policy story, four downloads.

The paste guard is the extension, and its settings (mode, markings) are
central Settings baked into every generated artifact - so the properties
under test are: the settings actually land in the files; absent settings
fall back to the documented defaults (warn, the five markings); an
explicitly saved empty markings list is honoured as a choice; Firefox
artifacts are gated on the gecko id and the SIGNED .xpi URL because
without them the policy is a no-op; and nothing that could escape its
quoting context can be embedded.
"""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import main, managed

SCRIPTS = Path(__file__).parent.parent / "collector-scripts"


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")
    monkeypatch.setattr(main, "COLLECTOR_SCRIPTS_DIR", str(SCRIPTS))


def _receiver_with(settings):
    def fake(base, method, path, admin_token, body=None):
        if path == "/admin/settings":
            return {"settings": settings}
        if method == "POST" and path == "/admin/enrollment-tokens":
            return {"id": "tok1", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {}
    return fake


BASE_SETTINGS = {
    "extension_id": {"value": "a" * 32, "source": "db"},
    "firefox_extension_id": {"value": "ai-guard@corp.example", "source": "db"},
    "extension_update_url": {"value": "https://files.corp.example/updates.xml",
                             "source": "db"},
    "extension_xpi_url": {"value": "https://files.corp.example/ai-guard.xpi",
                          "source": "db"},
    "corp_domains": {"value": ["corp.example"], "source": "db"},
}


@pytest.fixture
def receiver(monkeypatch, configured):
    def install(extra=None):
        settings = {**BASE_SETTINGS, **(extra or {})}
        monkeypatch.setattr(main.managed, "receiver_request",
                            _receiver_with(settings))
    install()
    return install


def _body(kind):
    return main.artifact(kind, _=None, token="t").body.decode()


# ------------------------------------------------- settings land in files --


def test_defaults_when_nothing_is_saved(receiver):
    plist = _body("extension-policy")
    assert "<string>warn</string>" in plist
    for m in managed.DEFAULT_MARKINGS:
        assert m in plist


def test_saved_mode_and_markings_reach_all_four_artifacts(receiver):
    receiver({"paste_guard_mode": {"value": "block", "source": "db"},
              "classification_markings": {"value": ["Top Secret"],
                                          "source": "db"}})
    plist = _body("extension-policy")
    assert "<string>block</string>" in plist
    assert "Top Secret" in plist and "Client Confidential" not in plist

    ff = _body("firefox-policy")
    assert "<key>ai-guard@corp.example</key>" in ff
    assert "<string>block</string>" in ff and "Top Secret" in ff
    assert "https://files.corp.example/ai-guard.xpi" in ff

    win = _body("extension-windows")
    assert "$PasteGuardMode = 'block'" in win
    assert "$ClassificationMarkings = @('Top Secret')" in win
    assert "$ExtensionId = '%s'" % ("a" * 32) in win
    assert "$UpdatesXml  = 'https://files.corp.example/updates.xml'" in win
    assert "$AuthToken   = 'aige_MINTED'" in win

    ffwin = _body("firefox-windows")
    assert "$GeckoId   = 'ai-guard@corp.example'" in ffwin
    assert "$XpiUrl    = 'https://files.corp.example/ai-guard.xpi'" in ffwin
    assert "$AllowedDomains = @('corp.example')" in ffwin


def test_an_explicitly_empty_markings_list_is_a_choice_not_a_fallback(receiver):
    receiver({"classification_markings": {"value": [], "source": "db"}})
    plist = _body("extension-policy")
    assert "Client Confidential" not in plist


# --------------------------------------------------------------- the gates --


def test_firefox_artifacts_are_gated_on_the_gecko_id(receiver):
    receiver({"firefox_extension_id": {"value": "", "source": "unset"}})
    for kind in ("firefox-policy", "firefox-windows"):
        with pytest.raises(HTTPException) as e:
            main.artifact(kind, _=None, token="t")
        assert e.value.status_code == 409
        assert "gecko" in e.value.detail


def test_firefox_artifacts_are_gated_on_the_signed_xpi(receiver):
    receiver({"extension_xpi_url": {"value": "", "source": "unset"}})
    with pytest.raises(HTTPException) as e:
        main.artifact("firefox-policy", _=None, token="t")
    assert e.value.status_code == 409
    assert "signed" in e.value.detail


def test_the_windows_chromium_script_is_gated_on_the_update_url(receiver):
    receiver({"extension_update_url": {"value": "", "source": "unset"}})
    with pytest.raises(HTTPException) as e:
        main.artifact("extension-windows", _=None, token="t")
    assert e.value.status_code == 409
    assert "update URL" in e.value.detail


# ------------------------------------------------------------ embeddability --


def test_a_marking_that_could_escape_its_quoting_is_refused():
    for bad in ("it's secret", 'say "no"', "a`b", "a$b", "a<b>"):
        with pytest.raises(managed.ArtifactError):
            managed._checked_markings([bad])


def test_markings_with_spaces_are_legitimate():
    assert managed._checked_markings(["Commercial in Confidence"]) == [
        "Commercial in Confidence"]


def test_a_quote_in_a_powershell_value_cannot_break_out():
    # Defence in depth behind the refusal: if it were ever loosened, the
    # doubled quote keeps the literal a literal.
    assert managed._ps_str("it's") == "'it''s'"


def test_an_empty_domain_list_bakes_an_empty_array_not_the_placeholder(receiver):
    receiver({"corp_domains": {"value": [], "source": "unset"}})
    win = _body("firefox-windows")
    assert "$AllowedDomains = @()" in win
    assert "@('example.com')" not in win
