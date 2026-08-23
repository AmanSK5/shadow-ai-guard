"""Central settings and portal-recorded governance decisions.

Precedence under test is the managed-mode promise: a portal-saved value
wins over the environment, clearing it falls back, and classic mode never
consults a DB that does not exist. Same harness shape as test_managed.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}
ADMIN = {"Authorization": "Bearer admin-test-token"}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    from app import main

    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    return st


@pytest.fixture
def collector_registry(tmp_path, monkeypatch):
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))


def _served_domains():
    reg = client.get("/registry/collector", headers=AUTH).json()
    return (reg.get("config") or {}).get("corp_domains")


# ------------------------------------------------------------ mode gating --


def test_settings_routes_do_not_exist_in_classic_mode():
    assert client.get("/admin/settings", headers=ADMIN).status_code == 404
    assert client.put("/admin/settings", headers=ADMIN, json={}).status_code == 404
    assert client.get("/admin/governance", headers=ADMIN).status_code == 404


def test_settings_require_admin(managed):
    assert client.get("/admin/settings").status_code == 401
    assert client.get("/admin/settings", headers=AUTH).status_code == 401


# -------------------------------------------------------------- settings --


def test_a_saved_value_names_its_source_and_shadows_the_env(managed, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "CORP_DOMAINS", ["fromenv.com"])
    out = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert out["corp_domains"] == {"value": ["fromenv.com"], "source": "env",
                                  "env": ["fromenv.com"]}

    resp = client.put("/admin/settings", headers=ADMIN,
                      json={"corp_domains": ["Portal.Com", " portal.com "]})
    assert resp.status_code == 200
    cd = resp.json()["settings"]["corp_domains"]
    # Normalised exactly as the env path normalises: trimmed, lowered,
    # deduplicated - and the response still names what it is shadowing.
    assert cd == {"value": ["portal.com"], "source": "db", "env": ["fromenv.com"]}


def test_the_fleet_hears_the_saved_list_not_the_env(managed, monkeypatch,
                                                    collector_registry):
    from app import main

    monkeypatch.setattr(main, "CORP_DOMAINS", ["fromenv.com"])
    assert _served_domains() == ["fromenv.com"]

    client.put("/admin/settings", headers=ADMIN,
               json={"corp_domains": ["portal.com"]})
    assert _served_domains() == ["portal.com"]


def test_an_explicit_empty_list_means_none_not_fall_back(managed, monkeypatch,
                                                         collector_registry):
    """An operator who saved an empty list said "none"; resurrecting the env
    value would undo the very thing they removed."""
    from app import main

    monkeypatch.setattr(main, "CORP_DOMAINS", ["fromenv.com"])
    client.put("/admin/settings", headers=ADMIN, json={"corp_domains": []})
    assert _served_domains() is None
    out = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert out["corp_domains"]["value"] == [] and out["corp_domains"]["source"] == "db"


def test_clearing_a_setting_falls_back_to_the_env(managed, monkeypatch,
                                                  collector_registry):
    from app import main

    monkeypatch.setattr(main, "CORP_DOMAINS", ["fromenv.com"])
    client.put("/admin/settings", headers=ADMIN,
               json={"corp_domains": ["portal.com"]})
    resp = client.put("/admin/settings", headers=ADMIN,
                      json={"corp_domains": None})
    assert resp.json()["settings"]["corp_domains"]["source"] == "env"
    assert _served_domains() == ["fromenv.com"]


def test_classic_serving_is_untouched(monkeypatch, collector_registry):
    """No DB exists in classic mode, and the env path must behave exactly
    as it did before settings existed."""
    from app import main

    monkeypatch.setattr(main, "CORP_DOMAINS", ["fromenv.com"])
    assert _served_domains() == ["fromenv.com"]


def test_an_unknown_key_is_refused_by_name(managed):
    resp = client.put("/admin/settings", headers=ADMIN,
                      json={"corp_domain": ["typo.com"]})
    assert resp.status_code == 422


def test_a_partial_update_leaves_other_keys_alone(managed):
    client.put("/admin/settings", headers=ADMIN,
               json={"corp_domains": ["a.com"], "extension_id": "abcdef"})
    out = client.put("/admin/settings", headers=ADMIN,
                     json={"onboarding_done": True}).json()["settings"]
    assert out["corp_domains"]["value"] == ["a.com"]
    assert out["extension_id"] == {"value": "abcdef", "source": "db"}
    assert out["onboarding_done"] == {"value": True, "source": "db"}


def test_extension_id_rejects_whitespace_and_empties_delete(managed):
    assert client.put("/admin/settings", headers=ADMIN,
                      json={"extension_id": "has space"}).status_code == 422
    client.put("/admin/settings", headers=ADMIN, json={"extension_id": "abc"})
    out = client.put("/admin/settings", headers=ADMIN,
                     json={"extension_id": ""}).json()["settings"]
    assert out["extension_id"] == {"value": "", "source": "unset"}


def test_writes_are_stamped_with_who(managed):
    """A session write carries the username; the API credential is "api"."""
    from app import main

    # An account and a session, no monkeypatched shortcuts.
    st = managed
    st.create_admin("aman", "a-long-enough-password")
    token = st.login("aman", "a-long-enough-password")["token"]

    client.put("/admin/settings", headers={"Authorization": f"Bearer {token}"},
               json={"corp_domains": ["a.com"]})
    client.put("/admin/settings", headers=ADMIN, json={"extension_id": "abc"})
    rows = {r["key"]: r["updated_by"] for r in st._db.execute(
        "SELECT key, updated_by FROM settings")}
    assert rows == {"corp_domains": "aman", "extension_id": "api"}


# ------------------------------------------------------------- governance --


def _decide(**kw):
    return {"tool_id": "chatgpt", "status": "not_approved", **kw}


def test_governance_decision_lifecycle(managed):
    resp = client.put("/admin/governance", headers=ADMIN, json={
        "decisions": [_decide(status="approved", owner="Security",
                              review_due="2027-06-01", reason="pilot")]})
    assert resp.status_code == 200
    (d,) = resp.json()["decisions"]
    assert d["tool_id"] == "chatgpt" and d["status"] == "approved"
    assert d["owner"] == "Security" and d["updated_by"] == "api"

    resp = client.put("/admin/governance", headers=ADMIN,
                      json={"delete": ["chatgpt"]})
    assert resp.json()["decisions"] == []


def test_an_approval_without_a_review_date_is_refused(managed):
    """The file validator's rule, enforced on the write path too: an
    approval with no expiry is the one that outlives its maker."""
    resp = client.put("/admin/governance", headers=ADMIN, json={
        "decisions": [_decide(status="approved")]})
    assert resp.status_code == 422
    assert "review_due" in resp.json()["detail"]


def test_validation_refuses_the_batch_before_writing_any_of_it(managed):
    resp = client.put("/admin/governance", headers=ADMIN, json={
        "decisions": [_decide(), _decide(tool_id="x", status="banned")]})
    assert resp.status_code == 422
    # The valid first entry must not have been applied.
    assert client.get("/admin/governance", headers=ADMIN).json()["decisions"] == []


def test_bad_dates_and_ids_are_422(managed):
    assert client.put("/admin/governance", headers=ADMIN, json={
        "decisions": [_decide(review_due="junk")]}).status_code == 422
    assert client.put("/admin/governance", headers=ADMIN, json={
        "decisions": [_decide(tool_id="bad id")]}).status_code == 422
    assert client.put("/admin/governance", headers=ADMIN, json={
        "delete": ["../etc"]}).status_code == 422


def test_a_database_from_before_settings_gains_the_tables(tmp_path):
    """The homelab's state.db predates these tables; opening it must add
    them and keep every existing row."""
    import sqlite3

    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    # The pre-0.9.7 schema: no settings, no governance_decisions.
    db.executescript("""
      CREATE TABLE enrollment_tokens (id TEXT PRIMARY KEY, token_hash BLOB
        NOT NULL UNIQUE, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT
        NULL, expires_at TEXT NOT NULL, revoked_at TEXT);
      INSERT INTO enrollment_tokens VALUES
        ('t1', X'00', '', '2026-01-01', '2027-01-01', NULL);
    """)
    db.commit()
    db.close()

    st = state_mod.State(str(path))
    assert st.get_settings() == {}
    assert st.list_decisions() == []
    assert st.list_tokens()[0]["id"] == "t1"


# ------------------------------------- paste guard and extension delivery --
# Settings baked into the portal's extension artifacts. The receiver only
# stores and validates; what warrants tests is the validation - a mode
# outside the enum or a marking that could carry control characters must
# never reach an artifact generator.


def test_paste_guard_mode_is_an_enum(managed):
    ok = client.put("/admin/settings", headers=ADMIN,
                    json={"paste_guard_mode": "block"})
    assert ok.status_code == 200
    got = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert got["paste_guard_mode"] == {"value": "block", "source": "db"}
    bad = client.put("/admin/settings", headers=ADMIN,
                     json={"paste_guard_mode": "loud"})
    assert bad.status_code == 422
    assert "off, warn, block" in bad.json()["detail"]


def test_markings_store_as_a_list_and_empty_is_a_choice(managed):
    client.put("/admin/settings", headers=ADMIN,
               json={"classification_markings": [" Top Secret ", "", "Internal"]})
    got = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert got["classification_markings"] == {
        "value": ["Top Secret", "Internal"], "source": "db"}
    # An explicit empty list is stored (no markings, on purpose); null
    # deletes and the source goes back to unset.
    client.put("/admin/settings", headers=ADMIN,
               json={"classification_markings": []})
    got = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert got["classification_markings"] == {"value": [], "source": "db"}
    client.put("/admin/settings", headers=ADMIN,
               json={"classification_markings": None})
    got = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert got["classification_markings"]["source"] == "unset"


def test_a_marking_with_control_characters_is_refused(managed):
    bad = client.put("/admin/settings", headers=ADMIN,
                     json={"classification_markings": ["a\nb"]})
    assert bad.status_code == 422


def test_the_firefox_id_refuses_whitespace(managed):
    ok = client.put("/admin/settings", headers=ADMIN,
                    json={"firefox_extension_id": "ai-guard@corp.example"})
    assert ok.status_code == 200
    bad = client.put("/admin/settings", headers=ADMIN,
                     json={"firefox_extension_id": "ai guard@x"})
    assert bad.status_code == 422


def test_the_delivery_urls_must_be_urls(managed):
    for key in ("extension_update_url", "extension_xpi_url"):
        bad = client.put("/admin/settings", headers=ADMIN, json={key: "files/x"})
        assert bad.status_code == 422, key
        ok = client.put("/admin/settings", headers=ADMIN,
                        json={key: "https://files.corp.example/x"})
        assert ok.status_code == 200, key
