"""The account email mapping, and the preferences an account owns.

Two things arrive together because both are groundwork for a portal that
knows who is looking at it: an address for an identity provider to map
onto later, and somewhere for one person's view of the pages to live.

The properties under test: an address is optional, normalised, and unique
across accounts; only an admin may set one, and clearing it works; a
viewer reads and writes its own preferences and can reach nobody else's;
preferences are bounded; deleting an account takes its preferences with
it; and a database written before either existed gains both on open.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

API_ADMIN = {"Authorization": "Bearer admin-test-token"}
PASSWORD = "a-long-enough-password"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    yield st


def _session(managed, username, password=PASSWORD):
    return {"Authorization": "Bearer " + managed.login(username,
                                                       password)["token"]}


# ------------------------------------------------------------- the address --

def test_an_account_needs_no_address(managed):
    """The break-glass account is created before anyone has decided how
    sign-in will work, so a required address would block the one account
    that exists for when everything else is broken."""
    user = managed.create_user("nobody", PASSWORD, "admin", by="test")
    assert user["email"] == ""
    assert managed.list_users()[0]["email"] is None


def test_an_address_is_stored_lowercased_and_stripped(managed):
    user = managed.create_user("someone", PASSWORD, "admin", by="test",
                               email="  Someone.Else@Example.COM ")
    assert user["email"] == "someone.else@example.com"


def test_two_accounts_cannot_share_an_address(managed):
    """A provider mapping that resolves two ways is not a mapping."""
    managed.create_user("first", PASSWORD, "admin", by="test",
                        email="shared@example.com")
    with pytest.raises(state_mod.AuthError) as e:
        managed.create_user("second", PASSWORD, "viewer", by="test",
                            email="SHARED@example.com")
    assert e.value.status == 409


def test_a_malformed_address_is_refused(managed):
    for bad in ("no-at-sign", "no@domain", "two@@example.com",
                "spaces in@example.com", "x@" + "y" * 300 + ".com"):
        with pytest.raises(state_mod.AuthError) as e:
            managed.create_user("u" + str(len(bad)), PASSWORD, "admin",
                                by="test", email=bad)
        assert e.value.status == 422, bad


def test_an_admin_sets_and_clears_an_address(managed):
    managed.create_admin("root", PASSWORD)
    uid = managed.list_users()[0]["id"]
    r = client.post(f"/admin/users/{uid}/email",
                    json={"email": "Root@Example.com"}, headers=API_ADMIN)
    assert r.status_code == 200
    assert r.json()["email"] == "root@example.com"

    r = client.post(f"/admin/users/{uid}/email", json={"email": ""},
                    headers=API_ADMIN)
    assert r.status_code == 200
    assert managed.list_users()[0]["email"] is None


def test_a_viewer_cannot_set_an_address(managed):
    """An account that could rewrite its own mapping could point somebody
    else's federated sign-in at itself."""
    managed.create_admin("root", PASSWORD)
    managed.create_user("reader", PASSWORD, "viewer", by="test")
    uid = [u for u in managed.list_users() if u["username"] == "reader"][0]["id"]
    r = client.post(f"/admin/users/{uid}/email",
                    json={"email": "reader@example.com"},
                    headers=_session(managed, "reader"))
    assert r.status_code == 403


def test_setting_an_address_records_that_it_was_set_not_what_it_is(managed):
    """The audit trail says who has a mapping. It is not a staff directory."""
    managed.create_admin("root", PASSWORD)
    uid = managed.list_users()[0]["id"]
    client.post(f"/admin/users/{uid}/email",
                json={"email": "root@example.com"}, headers=API_ADMIN)
    events = client.get("/admin/events", headers=API_ADMIN).json()["events"]
    setting = [e for e in events if e["kind"] == "user_email_set"]
    assert setting and setting[0]["detail"]["email_set"] is True
    assert "root@example.com" not in str(events)


# --------------------------------------------------------- the preferences --

def test_a_viewer_owns_its_own_preferences(managed):
    """The one authenticated write a read-only account makes: choosing a
    chart type changes what one person sees, never what a page reports."""
    managed.create_admin("root", PASSWORD)
    managed.create_user("reader", PASSWORD, "viewer", by="test")
    h = _session(managed, "reader")

    r = client.put("/admin/preferences",
                   json={"preferences": {"overview.layout": "[1,2,3]"}},
                   headers=h)
    assert r.status_code == 200
    assert client.get("/admin/preferences",
                      headers=h).json()["preferences"] == {
                          "overview.layout": "[1,2,3]"}


def test_preferences_are_per_account(managed):
    managed.create_admin("root", PASSWORD)
    managed.create_user("reader", PASSWORD, "viewer", by="test")
    client.put("/admin/preferences",
               json={"preferences": {"tour.seen": "yes"}},
               headers=_session(managed, "reader"))
    assert client.get("/admin/preferences",
                      headers=_session(managed, "root")
                      ).json()["preferences"] == {}


def test_a_write_merges_rather_than_replaces(managed):
    """One page saves its own key without carrying every other page's."""
    managed.create_admin("root", PASSWORD)
    h = _session(managed, "root")
    client.put("/admin/preferences",
               json={"preferences": {"a": "1", "b": "2"}}, headers=h)
    r = client.put("/admin/preferences", json={"preferences": {"b": "3"}},
                   headers=h)
    assert r.json()["preferences"] == {"a": "1", "b": "3"}


def test_null_deletes_a_key(managed):
    """Back to whatever the portal's default becomes later, rather than a
    stored copy of today's."""
    managed.create_admin("root", PASSWORD)
    h = _session(managed, "root")
    client.put("/admin/preferences", json={"preferences": {"a": "1"}},
               headers=h)
    r = client.put("/admin/preferences", json={"preferences": {"a": None}},
                   headers=h)
    assert r.json()["preferences"] == {}


def test_preferences_are_bounded(managed):
    """These rows are the one place an authenticated viewer writes freely."""
    managed.create_admin("root", PASSWORD)
    h = _session(managed, "root")

    too_long = {"a": "x" * (state_mod.MAX_PREFERENCE_VALUE + 1)}
    assert client.put("/admin/preferences", json={"preferences": too_long},
                      headers=h).status_code == 422

    many = {f"k{i}": "v" for i in range(state_mod.MAX_PREFERENCE_KEYS + 1)}
    assert client.put("/admin/preferences", json={"preferences": many},
                      headers=h).status_code == 422

    assert client.put("/admin/preferences",
                      json={"preferences": {"Bad Key": "v"}},
                      headers=h).status_code == 422


def test_the_api_credential_has_no_preferences(managed):
    """It is automation and break-glass, not a person with a portal open,
    and several operators may hold it."""
    managed.create_admin("root", PASSWORD)
    assert client.get("/admin/preferences",
                      headers=API_ADMIN).status_code == 409


def test_deleting_an_account_takes_its_preferences(managed):
    managed.create_admin("root", PASSWORD)
    managed.create_user("reader", PASSWORD, "viewer", by="test")
    uid = [u for u in managed.list_users()
           if u["username"] == "reader"][0]["id"]
    client.put("/admin/preferences", json={"preferences": {"a": "1"}},
               headers=_session(managed, "reader"))
    managed.delete_user(uid, by="test")
    with pytest.raises(state_mod.AuthError):
        managed.set_preferences(uid, {"a": "1"})
    assert managed.get_preferences(uid) == {}


# ------------------------------------------------------------- the upgrade --

def test_a_database_written_before_either_gains_both(tmp_path):
    """CREATE TABLE IF NOT EXISTS leaves the existing rows alone, so an
    upgrade keeps its accounts and gains the column and the table."""
    import sqlite3

    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE admin_users ("
        " id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
        " password_hash TEXT NOT NULL, created_at TEXT NOT NULL,"
        " last_login_at TEXT);"
        "INSERT INTO admin_users VALUES ('a' * 16, 'existing', 'x', 'now',"
        " NULL);")
    db.commit()
    db.close()

    st = state_mod.State(path)
    users = st.list_users()
    assert [u["username"] for u in users] == ["existing"]
    # Accounts predate roles as well as addresses, and both defaults hold.
    assert users[0]["role"] == "admin"
    assert users[0]["email"] is None
    assert st.set_preferences(users[0]["id"], {"a": "1"}) == {"a": "1"}
