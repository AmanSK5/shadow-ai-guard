"""The extension setup guide's server half: source zip, update manifests,
hosting probes.

The properties: the source download is the shipped source with exactly one
change (the receiver origin), because a second silent difference would make
"pack what you downloaded" a lie; the update manifests are generated from
Settings and carry the bundled source's version, since a version mismatch
is the failure browsers report as nothing at all; none of these downloads
mints an enrollment token, because they carry no credential and a minted-
but-unused token reads as a rollout that never happened; and the probes
catch the two hosted-file failures that answer 200 and still break every
machine - a manifest describing some other id, and an unsigned .xpi.
"""

import io
import json
import os
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import main, managed

PORTAL = Path(__file__).parent.parent
SRC = PORTAL / "extension-src"
BUNDLED_VERSION = managed.extension_version(str(SRC))


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")
    monkeypatch.setattr(main, "EXTENSION_SRC_DIR", str(SRC))


def _receiver_with(settings, minted):
    def fake(base, method, path, admin_token, body=None):
        if path == "/admin/settings":
            return {"settings": settings}
        if method == "POST" and path == "/admin/enrollment-tokens":
            minted.append(body)
            return {"id": "tok1", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {}
    return fake


BASE_SETTINGS = {
    "extension_id": {"value": "a" * 32, "source": "db"},
    "firefox_extension_id": {"value": "ai-guard@corp.example", "source": "db"},
    "extension_crx_url": {"value": "https://files.corp.example/ai-guard.crx",
                          "source": "db"},
    "extension_update_url": {"value": "https://files.corp.example/updates.xml",
                             "source": "db"},
    "extension_xpi_url": {"value": "https://files.corp.example/ai-guard.xpi",
                          "source": "db"},
}


@pytest.fixture
def receiver(monkeypatch, configured):
    minted = []

    def install(extra=None, drop=()):
        settings = {k: v for k, v in {**BASE_SETTINGS, **(extra or {})}.items()
                    if k not in drop}
        monkeypatch.setattr(main.managed, "receiver_request",
                            _receiver_with(settings, minted))
    install()
    return install, minted


# ------------------------------------------------------------- source zip --


def test_the_zip_is_the_source_with_exactly_one_change(receiver):
    resp = main.artifact("extension-source", _=None, token="t")
    z = zipfile.ZipFile(io.BytesIO(resp.body))
    names = {n.rsplit("/", 1)[1] for n in z.namelist()}
    assert names == set(managed.EXTENSION_SOURCE_FILES)

    manifest = z.read("ai-guard-extension/manifest.json").decode()
    assert '"https://rx.example.com/*"' in manifest
    assert "ai-guard.example.com" not in manifest
    for name in managed.EXTENSION_SOURCE_FILES:
        if name == "manifest.json":
            continue
        assert (z.read("ai-guard-extension/" + name)
                == (SRC / name).read_bytes()), name


def test_the_origin_is_the_origin_not_the_whole_url(configured):
    """A receiver URL saved with a path must not put the path into
    host_permissions - a match pattern with a path component narrows the
    permission and the report POST dies on CORS."""
    _, content = managed.generate_extension_source(
        str(SRC), "https://rx.example.com/some/path")
    manifest = zipfile.ZipFile(io.BytesIO(content)).read(
        "ai-guard-extension/manifest.json").decode()
    assert '"https://rx.example.com/*"' in manifest


def test_two_downloads_are_the_same_bytes(configured):
    a = managed.generate_extension_source(str(SRC), "https://rx.example.com")
    b = managed.generate_extension_source(str(SRC), "https://rx.example.com")
    assert a == b


def test_a_reshaped_manifest_fails_loudly(tmp_path):
    """Same contract as the collector-script anchors: if the shipped
    manifest no longer contains the placeholder exactly once, generation
    must refuse rather than serve a zip that reports nowhere."""
    for name in managed.EXTENSION_SOURCE_FILES:
        (tmp_path / name).write_bytes((SRC / name).read_bytes())
    (tmp_path / "manifest.json").write_text("{\"host_permissions\": []}")
    with pytest.raises(managed.ArtifactError, match="anchor"):
        managed.generate_extension_source(str(tmp_path), "https://rx.example.com")


# -------------------------------------------------------- update manifests --


def test_updates_xml_carries_the_settings_and_the_bundled_version(receiver):
    resp = main.artifact("extension-updates-xml", _=None, token="t")
    root = ET.fromstring(resp.body.decode())
    ns = "{http://www.google.com/update2/response}"
    app = root.find(ns + "app")
    assert app.get("appid") == "a" * 32
    check = app.find(ns + "updatecheck")
    assert check.get("codebase") == "https://files.corp.example/ai-guard.crx"
    assert check.get("version") == BUNDLED_VERSION


def test_firefox_updates_json_is_keyed_on_the_gecko_id(receiver):
    resp = main.artifact("firefox-updates-json", _=None, token="t")
    body = json.loads(resp.body.decode())
    (update,) = body["addons"]["ai-guard@corp.example"]["updates"]
    assert update == {"version": BUNDLED_VERSION,
                      "update_link": "https://files.corp.example/ai-guard.xpi"}


def test_each_manifest_names_the_setting_it_is_missing(receiver):
    install, _ = receiver
    for kind, missing, said in (
            ("extension-updates-xml", "extension_id", "extension ID"),
            ("extension-updates-xml", "extension_crx_url", ".crx URL"),
            ("firefox-updates-json", "firefox_extension_id", "gecko id"),
            ("firefox-updates-json", "extension_xpi_url", ".xpi URL")):
        install(drop=(missing,))
        with pytest.raises(HTTPException) as e:
            main.artifact(kind, _=None, token="t")
        assert e.value.status_code == 409
        assert said in e.value.detail


def test_an_id_that_is_not_an_id_is_refused(configured):
    with pytest.raises(managed.ArtifactError, match="Chromium extension id"):
        managed.generate_updates_xml("not-an-id", "https://x.example/e.crx",
                                     "1.0.0")


def test_a_gecko_id_that_could_escape_json_is_refused(configured):
    with pytest.raises(managed.ArtifactError):
        managed.generate_firefox_updates_json(
            'ai"guard@corp.example', "https://x.example/e.xpi", "1.0.0")


# ------------------------------------------------------------- no minting --


def test_the_hosting_downloads_mint_nothing(receiver):
    """A collector artifact mints (that is its credential); these carry
    none, so a token minted for one would sit in the list looking like a
    rollout that never happened."""
    _, minted = receiver
    for kind in main.TOKENLESS_ARTIFACTS:
        main.artifact(kind, _=None, token="t")
    assert minted == []
    main.artifact("scanner-cronjob", _=None, token="t")
    assert len(minted) == 1  # the control: minting still works


# ----------------------------------------------------------------- probes --


def _updates_xml(appid, version):
    return ("<?xml version='1.0' encoding='UTF-8'?>"
            "<gupdate xmlns='http://www.google.com/update2/response'"
            " protocol='2.0'><app appid='%s'><updatecheck"
            " codebase='https://h/e.crx' version='%s' /></app></gupdate>"
            % (appid, version)).encode()


def _hosted(monkeypatch, body, ctype="application/xml"):
    monkeypatch.setattr(main, "_fetch_hosted",
                        lambda url, cap: (200, ctype, body[:cap]))


def test_the_updates_probe_accepts_a_matching_manifest(receiver, monkeypatch):
    _hosted(monkeypatch, _updates_xml("a" * 32, BUNDLED_VERSION))
    out = main.test_extension_updates(_=None, token="t")
    assert out["ok"] and not out["warnings"]


def test_the_updates_probe_catches_somebody_elses_manifest(receiver, monkeypatch):
    """The failure that looks fine everywhere: the URL answers 200, the XML
    parses, and every browser polls it forever without installing anything,
    because it describes a different extension."""
    _hosted(monkeypatch, _updates_xml("b" * 32, BUNDLED_VERSION))
    out = main.test_extension_updates(_=None, token="t")
    assert not out["ok"]
    assert "b" * 32 in out["detail"]


def test_the_updates_probe_warns_on_a_version_behind_the_bundle(receiver, monkeypatch):
    _hosted(monkeypatch, _updates_xml("a" * 32, "0.0.1"))
    out = main.test_extension_updates(_=None, token="t")
    assert out["ok"] and any("0.0.1" in w for w in out["warnings"])


def test_the_updates_probe_says_when_the_answer_is_not_xml(receiver, monkeypatch):
    _hosted(monkeypatch, b"<html>bucket listing</html")
    out = main.test_extension_updates(_=None, token="t")
    assert not out["ok"]


def test_the_updates_probe_requires_a_saved_url(receiver, monkeypatch):
    install, _ = receiver
    install(drop=("extension_update_url",))
    with pytest.raises(HTTPException) as e:
        main.test_extension_updates(_=None, token="t")
    assert e.value.status_code == 400


def _xpi(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    return buf.getvalue()


def test_the_xpi_probe_accepts_a_signed_file(receiver, monkeypatch):
    _hosted(monkeypatch, _xpi(["manifest.json", "META-INF/mozilla.rsa"]),
            "application/x-xpinstall")
    out = main.test_extension_xpi(_=None, token="t")
    assert out["ok"] and not out["warnings"]


def test_the_xpi_probe_catches_the_unsigned_build(receiver, monkeypatch):
    """The trap the probe exists for: your own build and the signed one are
    both valid zips at valid URLs, and Firefox refuses one of them on every
    machine in the fleet."""
    _hosted(monkeypatch, _xpi(["manifest.json"]), "application/x-xpinstall")
    out = main.test_extension_xpi(_=None, token="t")
    assert not out["ok"]
    assert "mozilla.rsa" in out["detail"]


def test_the_xpi_probe_warns_on_the_wrong_content_type(receiver, monkeypatch):
    _hosted(monkeypatch, _xpi(["manifest.json", "META-INF/mozilla.rsa"]),
            "text/plain")
    out = main.test_extension_xpi(_=None, token="t")
    assert out["ok"] and any("content type" in w or "text/plain" in w
                             for w in out["warnings"])


def test_the_xpi_probe_says_when_the_file_is_not_a_zip(receiver, monkeypatch):
    _hosted(monkeypatch, b"not a zip", "application/x-xpinstall")
    out = main.test_extension_xpi(_=None, token="t")
    assert not out["ok"]
