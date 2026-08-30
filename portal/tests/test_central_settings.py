"""Central settings and portal-recorded governance, portal side.

The receiver stores and validates; these tests cover what the portal adds:
the per-tool merge (DB wins, file fills gaps, origin labelled), the proxy
routes forwarding exactly what was sent, and the register cache dying when
a decision changes. Same direct-call harness as the rest of the suite.
"""

import os
from datetime import date

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import governance, main, managed


def _request(cookie_token="aigt_s"):
    hs = [(b"host", b"portal")]
    if cookie_token is not None:
        hs.append((b"cookie",
                   ("%s=%s" % (main.SESSION_COOKIE, cookie_token)).encode()))
    return Request({"type": "http", "method": "GET", "path": "/",
                    "scheme": "http", "headers": hs, "query_string": b""})


@pytest.fixture
def login_mode(monkeypatch):
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        if path == "/admin/governance" and method == "GET":
            return {"decisions": [
                {"tool_id": "chatgpt", "status": "approved", "owner": "Security",
                 "review_due": "2027-06-01", "reason": "pilot",
                 "updated_at": "2026-08-23", "updated_by": "aman"}]}
        return {"ok": True}

    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "_session_cache", {})
    return calls


# ------------------------------------------------------- governance merge --


def test_classic_mode_reads_the_file_and_calls_no_receiver(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main.managed, "receiver_request",
                        lambda *a, **k: calls.append(a))
    gov, exceptions, n = main._merged_governance(_request())
    assert gov == {} and n == 0 and calls == []


def test_a_portal_decision_wins_over_the_file_and_says_so(login_mode,
                                                          monkeypatch, tmp_path):
    """DB wins per tool, file fills the gaps - the same rule every setting
    follows - and the record carries its origin so decide() can label it."""
    gov_file = tmp_path / "governance.yaml"
    gov_file.write_text(
        "tools:\n"
        "  chatgpt: {status: not_approved, owner: IT}\n"
        "  claude: {status: reviewing, owner: Legal}\n")
    monkeypatch.setattr(main, "GOVERNANCE_PATH", str(gov_file))

    gov, _exceptions, n = main._merged_governance(_request())
    assert n == 1
    # The DB record displaced the file's chatgpt entirely...
    assert gov["chatgpt"]["status"] == "approved"
    assert gov["chatgpt"]["owner"] == "Security"
    assert gov["chatgpt"]["review_due"] == date(2027, 6, 1)
    assert gov["chatgpt"]["origin"] == "portal"
    # ...and the file still speaks where the DB is silent.
    assert gov["claude"]["status"] == "reviewing"
    assert "origin" not in gov["claude"]

    # decide() labels each source honestly.
    assert governance.decide("chatgpt", gov, False)["source"] == "portal"
    assert governance.decide("claude", gov, False)["source"] == "governance"


def test_an_unreachable_receiver_fails_loud_not_stale(login_mode, monkeypatch):
    """Showing yesterday's decisions as if current is the quiet wrongness
    this project exists to avoid: file-only fallback would do exactly that."""
    def down(base, method, path, token, body=None):
        raise managed.ReceiverError(502, "could not reach the receiver (X)")
    monkeypatch.setattr(main.managed, "receiver_request", down)

    with pytest.raises(HTTPException) as e:
        main._merged_governance(_request())
    assert e.value.status_code == 502
    assert "governance decisions" in e.value.detail


def test_the_merge_forwards_the_requesters_own_session(login_mode):
    main._merged_governance(_request(cookie_token="aigt_mine"))
    assert login_mode[0]["token"] == "aigt_mine"


# ------------------------------------------------------------ proxy routes --


def test_settings_write_forwards_only_what_was_sent(login_mode):
    main.api_settings_write(
        main.SettingsWrite(corp_domains=["Example.com"]), _=None, token="t")
    assert login_mode[0]["method"] == "PUT"
    assert login_mode[0]["path"] == "/admin/settings"
    # Only the provided key rides; normalisation is the receiver's job.
    assert login_mode[0]["body"] == {"corp_domains": ["Example.com"]}


def test_an_explicit_null_rides_through_as_the_delete_it_is(login_mode):
    main.api_settings_write(
        main.SettingsWrite(corp_domains=None), _=None, token="t")
    assert login_mode[0]["body"] == {"corp_domains": None}


def test_an_unknown_settings_key_is_refused_at_the_edge():
    with pytest.raises(ValueError):
        main.SettingsWrite(corp_domain=["typo.com"])


def test_a_governance_write_kills_the_register_cache(login_mode):
    main._cache["register"] = {"value": ["stale"], "at": 9e12, "hours": 168}
    main.api_governance_write(
        main.GovernanceWrite(decisions=[main.DecisionWrite(
            tool_id="chatgpt", status="not_approved")]), _=None, token="t")
    assert "register" not in main._cache
    assert login_mode[0]["method"] == "PUT"
    assert login_mode[0]["path"] == "/admin/governance"
    assert login_mode[0]["body"]["decisions"][0]["tool_id"] == "chatgpt"


def test_password_change_forwards_on_the_callers_session(login_mode):
    main.api_password(main.PasswordWrite(current="old",
                                         new="a-long-enough-password"),
                      _=None, token="aigt_mine")
    assert login_mode[0] == {"method": "POST", "path": "/admin/password",
                             "token": "aigt_mine",
                             "body": {"current": "old",
                                      "new": "a-long-enough-password"}}


def test_the_receiver_client_sends_put_bodies():
    """receiver_request only attached data to POST; a PUT with a silently
    dropped body would reach the receiver as an empty update that changes
    nothing and reports success."""
    import json as _json
    from unittest.mock import patch

    seen = {}

    class _Resp:
        def read(self):
            return b"{}"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        seen["data"] = req.data
        return _Resp()

    with patch.object(managed.urllib.request, "urlopen", fake_urlopen):
        managed.receiver_request("http://r", "PUT", "/admin/settings", "t",
                                 {"corp_domains": ["a.com"]})
    assert _json.loads(seen["data"]) == {"corp_domains": ["a.com"]}


# ---------------------------------------------------------------- the page --


def test_the_page_carries_the_editors():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("gov-edit", "gov-save", "gov-clear", "save-domains",
                   "clear-domains", "save-extid", "change-password",
                   "/api/settings", "/api/governance-decisions",
                   "/api/password", "set in the portal"):
        assert needle in html, needle


def test_the_settings_tabs_share_one_save_and_secrets_keep_their_own():
    """The Fleet tab alone carried eight Save buttons, one per field, and
    the four extension-hosting URLs - only meaningful together - were four
    separate round trips.

    A SECRET is deliberately left out of the batch. Its box renders blank by
    design and blank means CLEAR, so sweeping the secrets into a batch would
    wipe every one of them the moment somebody edited an unrelated field on
    the same tab."""
    html = (main.STATIC / "index.html").read_text()
    # The batch is opt-in per call site, and a secret refuses it.
    assert "function settingRow(key, label, placeholder, note, batch) {" in html
    assert "const batched = batch && !secret;" in html
    # Dirty is measured against the value the field was RENDERED with.
    assert "const sDirty = () => Array.from(app.querySelectorAll('[data-sfield]'))" in html
    assert "data-sinit=" in html
    # The bar and the one save it drives.
    assert 'data-act="settings-save-all"' in html
    assert 'data-act="settings-discard"' in html
    # The two list shapes the settings API takes.
    assert 'data-slist="csv"' in html and 'data-slist="lines"' in html
    # A failed save must NOT re-render: a render redraws every field from
    # SETTINGS and would throw away the several edits that just failed.
    assert "const err = document.getElementById('setbar-err');" in html
    # The wizard and the extension guide pass no batch and keep their own
    # per-field saves - each of their steps gates on its value being stored.
    assert 'data-act="save-domains"' in html
    assert 'data-act="save-extid"' in html
    assert "${batch ? '' : '<button class=\"mini\" data-act=\"save-markings\">Save</button>'}" in html


def test_getting_started_has_its_own_tab():
    """"Run the setup wizard again" and "Take the tour again" sat at the
    bottom of the Account tab, under the accounts table and single sign-on -
    nowhere anybody would look, since neither has anything to do with
    accounts. The first UX pass found the tour re-entry 1,002 pixels down an
    1,105-pixel page."""
    html = (main.STATIC / "index.html").read_text()
    assert "['start', 'Getting started']" in html
    assert "function gettingStarted()" in html
    assert "else if (SETTAB === 'start') body = gettingStarted();" in html


def test_the_fleet_tab_is_renamed_but_keeps_its_id():
    """"Fleet" also names a whole nav section - enrolled devices and
    enrollment tokens - and two different things called Fleet in one product
    is a coin toss every time somebody says it. The id stays so existing
    #settings/fleet links, and the tour step that targets this tab, still
    land."""
    html = (main.STATIC / "index.html").read_text()
    assert "['fleet', 'Detection & paste guard']" in html
    assert "{view: 'settings', tab: 'fleet', sel: '#set-domains'," in html


def test_your_own_password_lives_in_the_account_menu():
    """Changing your own password is not an administrative setting, and
    Settings > Account is about OTHER people's accounts and single sign-on. It
    matters most for a viewer: that tab is read-only for them, so their
    password was the one editable field on it, three blocks down.

    The menu sits outside #app, where the delegated data-act listeners never
    reach - so it carries its own."""
    html = (main.STATIC / "index.html").read_text()
    assert 'id="usermenu"' in html
    assert "function umClose()" in html
    assert "e.target.closest('#usermenu [data-act]')" in html
    assert 'data-act="open-password"' in html
    # Gone from the administrative tab.
    account = html.split("function accountSettings()")[1].split("\nfunction ")[0]
    assert "set-curpass" not in account


def test_the_password_form_is_a_modal_and_not_the_menu_itself():
    """The menu offers an ITEM; the form is a dialog. A menu closes on any
    click outside it and on Escape, and umClose() would take half-typed
    fields with it - and a password manager rarely offers to save from a
    panel that disappears on blur.

    The dialog is outside #app for the same reason the menu is, so it needs
    its own listener, and the result is reported INTO the dialog: SETMSG only
    ever renders on Settings, and telling a page the person is not looking at
    is the same as not telling them."""
    html = (main.STATIC / "index.html").read_text()
    assert '<dialog id="pwdlg"' in html
    assert "dlg.showModal()" in html
    assert 'id="pw-msg"' in html
    assert "document.getElementById('pwdlg').addEventListener('click'" in html
    # Every field is cleared on the way out. Escape is closed by hand rather
    # than left to the dialog element: measured in Chrome 151, main world, it
    # closes itself but fires neither 'cancel' nor 'close', so the listener
    # would never run and a typed password would sit in the field behind a
    # dismissed dialog.
    # And it takes the keystroke outright: the drawer's Escape handler is a
    # later window listener, and by the time it runs pwHide() has already made
    # pwIsOpen() false - so one Escape would dismiss the modal AND the drawer
    # sitting open behind it.
    assert "if (pwIsOpen()) { pwHide(); e.stopImmediatePropagation(); return; }" in html
    assert "document.getElementById('pwdlg').addEventListener('close', pwWipe)" in html
    # Signing out takes the dialog with it.
    assert "pwHide(); }" in html


def test_the_new_password_is_typed_twice():
    """Without a confirm field a typo is not discovered until the next
    sign-in - by which time every other session has been signed out with the
    old password. The mismatch is answered here rather than by the receiver,
    which never sees the second copy and would report the typo as whichever
    password was sent being wrong."""
    html = (main.STATIC / "index.html").read_text()
    assert 'id="set-confpass"' in html
    assert "if (nw !== _val('set-confpass'))" in html
    assert "The two new passwords do not match." in html


def test_the_primary_button_submits_the_form_and_carries_no_act():
    """Enter in any field has to do what the button does. The button is
    therefore the form's submit - and it deliberately carries no data-act,
    because a click would otherwise both submit AND delegate, changing the
    password twice."""
    html = (main.STATIC / "index.html").read_text()
    dlg = html.split('<dialog id="pwdlg"')[1].split("</dialog>")[0]
    assert 'id="pw-submit"' in dlg and 'type="submit"' in dlg
    assert "data-act" not in dlg.split('id="pw-submit"')[1].split(">")[0]
    assert 'data-act="close-password"' in dlg
    assert "document.getElementById('pwform').addEventListener('submit'" in html
