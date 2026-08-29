"""The account-email and preferences proxies.

Same direct-call harness as the rest of the suite. The receiver owns
storage, validation and the role gate, so what the portal must hold is
thin and worth stating exactly: each route forwards the right verb to the
right receiver path with the operator's own session, and the preferences
routes carry no account id at all - a forwarded session is one account,
which is what keeps a layout from being addressable by anyone else.
"""

import os

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest

from app import main


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


def test_an_address_is_optional_on_create(receiver_spy):
    """A local account has never needed one, and still does not."""
    token = main._admin_forward(_Req())
    main.api_users_create(
        main.UserCreate(username="someone", password="a-long-enough-password",
                        role="viewer"),
        token=token)
    assert receiver_spy[-1]["body"]["email"] == ""


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
