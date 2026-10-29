# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Calls that send mail wait for the mail server.

The receiver sends before it answers and allows a relay 15 seconds a step,
so a slow relay outlasted the portal's 10: Test mail said the receiver could
not be reached while the message went, and "invite everybody" reported a
failure for people it had invited.
"""

import os
import urllib.request

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest

from app import main, managed


@pytest.fixture
def receiver_spy(monkeypatch):
    calls = []

    def fake(base, method, path, token, body=None, **kw):
        calls.append({"method": method, "path": path, "timeout": kw.get("timeout")})
        return {"ok": True}

    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver:8080")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


class _Req:
    cookies = {"aiguard_session": "aigt_test"}


def test_every_call_that_sends_mail_waits_for_it(receiver_spy):
    token = main._admin_forward(_Req())
    main.api_users_invite(main.InviteWrite(), token=token)
    main.api_test_mail(main.MailTestWrite(to="someone@example.com"), token=token)
    main.api_users_create(main.UserCreate(username="someone", password="x" * 12, role="viewer",
                                          email="someone@example.com"), token=token)
    assert [c["path"] for c in receiver_spy] == ["/admin/users/invite", "/admin/test/mail", "/admin/users"]
    assert all(c["timeout"] == managed.MAIL_TIMEOUT_SECONDS for c in receiver_spy)
    assert managed.MAIL_TIMEOUT_SECONDS > 3 * 15, "shorter than one slow relay's three steps"


def test_calls_that_send_nothing_keep_the_default(receiver_spy):
    main.api_users(token=main._admin_forward(_Req()))
    assert receiver_spy[-1]["timeout"] is None


def test_the_timeout_reaches_the_socket(monkeypatch):
    seen = []

    def urlopen(req, timeout=None):
        seen.append(timeout)
        raise OSError("stop here")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    for kw in ({}, {"timeout": managed.MAIL_TIMEOUT_SECONDS}):
        with pytest.raises(managed.ReceiverError):
            managed.receiver_request("http://r", "POST", "/admin/test/mail", "t", {}, **kw)
    assert seen == [managed.TIMEOUT_SECONDS, managed.MAIL_TIMEOUT_SECONDS]
