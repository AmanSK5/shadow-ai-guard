"""The identity map as portal-managed state.

It was the last piece of configuration that still needed kubectl: the
portal generated the proposal and could not accept the corrected version
back, so the loop ended at a ConfigMap. Same harness shape as the other
managed-mode suites.
"""

import json
import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)

ADMIN = {"Authorization": "Bearer admin-test-token"}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    from app import main

    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    return st


@pytest.fixture
def viewer(managed):
    managed.create_admin("admin", "a-long-password")
    managed.create_user("watcher", "another-long-pass", "viewer", by="admin")
    return {"Authorization": "Bearer " + managed.login(
        "watcher", "another-long-pass")["token"]}


ROWS = [{"key": "C02XXXX", "identity": "jo.bloggs"},
        {"key": "jo.bloggs", "identity": "Jo Bloggs"}]


def test_routes_do_not_exist_in_classic_mode():
    assert client.get("/admin/identity-map", headers=ADMIN).status_code == 404


def test_round_trip_and_wholesale_replace(managed):
    r = client.put("/admin/identity-map", headers=ADMIN,
                   json={"entries": ROWS})
    assert r.json() == {"ok": True, "count": 2}
    got = client.get("/admin/identity-map", headers=ADMIN).json()["entries"]
    assert [(e["key"], e["identity"]) for e in got] == [
        ("C02XXXX", "jo.bloggs"), ("jo.bloggs", "Jo Bloggs")]
    assert got[0]["updated_by"] == "api"

    # An operator edits this list in a spreadsheet, so a save is the whole
    # map: a row dropped from the file is dropped from the map.
    client.put("/admin/identity-map", headers=ADMIN,
               json={"entries": [ROWS[0]]})
    got = client.get("/admin/identity-map", headers=ADMIN).json()["entries"]
    assert [e["key"] for e in got] == ["C02XXXX"]


def test_an_empty_map_clears_it(managed):
    client.put("/admin/identity-map", headers=ADMIN, json={"entries": ROWS})
    client.put("/admin/identity-map", headers=ADMIN, json={"entries": []})
    assert client.get("/admin/identity-map",
                      headers=ADMIN).json()["entries"] == []


def test_values_that_cannot_survive_the_csv_round_trip_are_refused(managed):
    for bad in ({"key": "a,b", "identity": "x"},
                {"key": "ok", "identity": 'say "hi"'},
                {"key": "ok", "identity": "x # comment"},
                # Interior, not trailing: surrounding whitespace is
                # trimmed on the way in, which is what an operator
                # pasting from a spreadsheet needs.
                {"key": "ok\nbad", "identity": "x"}):
        r = client.put("/admin/identity-map", headers=ADMIN,
                       json={"entries": [bad]})
        assert r.status_code == 422, bad
    r = client.put("/admin/identity-map", headers=ADMIN, json={"entries": [
        {"key": "SAME", "identity": "a"}, {"key": "same", "identity": "b"}]})
    assert r.status_code == 422 and "duplicate" in r.json()["detail"]
    # A refused batch changes nothing.
    assert client.get("/admin/identity-map",
                      headers=ADMIN).json()["entries"] == []


def test_a_viewer_reads_it_and_cannot_write_it(managed, viewer):
    """The portal renders these names on every page that attributes a
    device, so withholding the map from a viewer would make the pages
    wrong rather than private. Writing is another matter."""
    client.put("/admin/identity-map", headers=ADMIN, json={"entries": ROWS})
    assert client.get("/admin/identity-map",
                      headers=viewer).status_code == 200
    assert client.put("/admin/identity-map", headers=viewer,
                      json={"entries": []}).status_code == 403


def test_the_audit_trail_records_the_change_and_not_the_people(managed):
    client.put("/admin/identity-map", headers=ADMIN, json={"entries": ROWS})
    events = json.dumps(client.get("/admin/events", headers=ADMIN).json())
    assert "identity_map_replaced" in events
    # Counts, never names: this table is nothing but people.
    assert "jo.bloggs" not in events and "Jo Bloggs" not in events
