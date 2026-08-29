"""The account-email and preferences proxies.

Same direct-call harness as the rest of the suite. The receiver owns
storage, validation and the role gate, so what the portal must hold is
thin and worth stating exactly: each route forwards the right verb to the
right receiver path with the operator's own session, and the preferences
routes carry no account id at all - a forwarded session is one account,
which is what keeps a layout from being addressable by anyone else.
"""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest

from app import main

INDEX = (Path(__file__).parent.parent / "app" / "static"
         / "index.html").read_text()


@pytest.fixture
def receiver_spy(monkeypatch):
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        return {"ok": True}

    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver:8080")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


class _Req:
    cookies = {"aiguard_session": "aigt_test"}


def test_the_email_route_forwards_the_right_verb_and_path(receiver_spy):
    token = main._admin_forward(_Req())
    uid = "0123456789abcdef"

    main.api_users_email(uid, main.UserEmailWrite(email="someone@example.com"),
                         token=token)

    assert receiver_spy[-1]["method"] == "POST"
    assert receiver_spy[-1]["path"] == "/admin/users/%s/email" % uid
    assert receiver_spy[-1]["body"] == {"email": "someone@example.com"}
    assert receiver_spy[-1]["token"] == token


def test_a_malformed_user_id_never_reaches_the_receiver(receiver_spy):
    token = main._admin_forward(_Req())
    with pytest.raises(Exception):
        main.api_users_email("not-a-uid", main.UserEmailWrite(email=""),
                             token=token)
    assert receiver_spy == []


def test_creating_an_account_carries_the_address(receiver_spy):
    token = main._admin_forward(_Req())
    main.api_users_create(
        main.UserCreate(username="someone", password="a-long-enough-password",
                        role="viewer", email="someone@example.com"),
        token=token)
    assert receiver_spy[-1]["body"]["email"] == "someone@example.com"


def test_an_unset_address_is_not_sent_at_all(receiver_spy):
    """The receiver forbids unknown fields, so a key always sent is a key
    that breaks account creation against a receiver too old to know it -
    a call that worked before this feature existed."""
    token = main._admin_forward(_Req())
    main.api_users_create(
        main.UserCreate(username="someone", password="a-long-enough-password",
                        role="viewer"),
        token=token)
    assert "email" not in receiver_spy[-1]["body"]
    assert receiver_spy[-1]["body"]["username"] == "someone"


def test_the_preferences_routes_pass_no_account_id(receiver_spy):
    """A forwarded session is one account. There is no id to pass, which is
    what stops one person asking for another's."""
    token = main._admin_forward(_Req())

    main.api_preferences(token=token)
    assert receiver_spy[-1]["method"] == "GET"
    assert receiver_spy[-1]["path"] == "/admin/preferences"

    main.api_preferences_write(
        main.PreferencesWrite(preferences={"overview.layout": "[1,2]"}),
        token=token)
    assert receiver_spy[-1]["method"] == "PUT"
    assert receiver_spy[-1]["path"] == "/admin/preferences"
    assert receiver_spy[-1]["body"] == {
        "preferences": {"overview.layout": "[1,2]"}}


def test_a_null_preference_survives_the_relay(receiver_spy):
    """None means delete, and a proxy that dropped it would silently turn a
    reset into a no-op."""
    token = main._admin_forward(_Req())
    main.api_preferences_write(
        main.PreferencesWrite(preferences={"overview.layout": None}),
        token=token)
    assert receiver_spy[-1]["body"] == {"preferences": {"overview.layout": None}}


def test_the_role_route_forwards_the_right_verb_and_path(receiver_spy):
    token = main._admin_forward(_Req())
    uid = "0123456789abcdef"

    main.api_users_role(uid, main.UserRoleWrite(role="admin"), token=token)

    assert receiver_spy[-1]["method"] == "POST"
    assert receiver_spy[-1]["path"] == "/admin/users/%s/role" % uid
    assert receiver_spy[-1]["body"] == {"role": "admin"}


def test_the_role_route_refuses_a_malformed_id_locally(receiver_spy):
    token = main._admin_forward(_Req())
    with pytest.raises(Exception):
        main.api_users_role("../../admin", main.UserRoleWrite(role="admin"),
                            token=token)
    assert receiver_spy == []


def test_the_accounts_table_ships_the_role_control():
    """A route with no control in front of it is a route nobody uses."""
    assert "data-role-for" in INDEX
    assert "async function userRole" in INDEX


def test_a_viewer_sees_the_role_as_text_not_a_control():
    """The select is rendered only for an account that could use it - a
    read-only account offered a dropdown that always 403s is a worse page
    than one that shows the role plainly."""
    cell = INDEX.split("data-role-for")[0]
    assert "${viewer" in cell.rsplit("<td>", 1)[-1]

