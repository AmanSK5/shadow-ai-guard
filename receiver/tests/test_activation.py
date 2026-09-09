# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Activation keys: what is accepted, what is refused, and what comes back.

The properties that matter commercially are all negative ones - a key
nobody issued must not work, and an edited key must not work - so most of
this file forges things. The positive half checks the two promises made to
an operator instead: the check needs no network, and the key they typed is
never handed back to a browser.
"""

import base64
import json
import os
from datetime import date

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import activation
from app import main
from app import state as state_mod
from app.main import app
from tests.ed25519_signer import public_key, sign

client = TestClient(app)

# The publisher, for this file. Nothing here uses the key compiled into
# the module: a test that signed with the real private key would need the
# real private key to exist somewhere a test can reach it.
SEED = b"a test publisher's signing seed."


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint(seed: bytes = SEED, **overrides) -> str:
    claims = {"v": 1, "id": "NYX-0001", "org": "Acme Group Ltd",
              "plan": "enterprise", "issued": "2026-01-01",
              "expires": "2099-01-01", "devices": 2500}
    claims.update(overrides)
    for k in [k for k, v in claims.items() if v is None]:
        del claims[k]
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True,
                         ensure_ascii=False).encode()
    return "nyxl_%s.%s" % (_b64url(payload), _b64url(sign(seed, payload)))


@pytest.fixture(autouse=True)
def publisher(monkeypatch):
    monkeypatch.setenv("ACTIVATION_PUBLIC_KEY",
                       base64.b64encode(public_key(SEED)).decode())


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    return st


def _session(managed, username="root", password="a-long-enough-password"):
    return {"Authorization": "Bearer " + managed.login(username, password)["token"]}


@pytest.fixture
def owner(managed):
    managed.create_admin("root", "a-long-enough-password")
    return _session(managed)


@pytest.fixture
def admin(managed, owner):
    managed.create_user("second", "a-long-enough-password", "admin", by="test")
    return _session(managed, "second")


@pytest.fixture
def viewer(managed, owner):
    managed.create_user("auditor", "a-long-enough-password", "viewer", by="test")
    return _session(managed, "auditor")


# ------------------------------------------------------------ the format --

def test_a_genuine_key_reads_back_what_it_says():
    c = activation.describe(mint(), today=date(2026, 6, 1))
    assert c["state"] == "active"
    assert c["org"] == "Acme Group Ltd"
    assert c["id"] == "NYX-0001"
    assert c["plan"] == "enterprise"
    assert c["devices"] == 2500
    assert c["expires"] == "2099-01-01"


def test_a_key_from_another_publisher_is_refused():
    forged = mint(seed=b"somebody else's signing seed....")
    with pytest.raises(activation.ActivationError) as e:
        activation.parse(forged)
    assert "not issued for this software" in str(e.value)


def test_editing_the_claims_breaks_the_signature():
    """The whole scheme in one test: the claims are readable on purpose, so
    the thing that has to hold is that reading them is all anyone can do."""
    key = mint(devices=10)
    body = key[len("nyxl_"):]
    claims_raw, sig_raw = body.split(".")
    padded = claims_raw + "=" * (-len(claims_raw) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    assert claims["devices"] == 10           # plainly readable
    claims["devices"] = 100000
    swapped = _b64url(json.dumps(claims, separators=(",", ":"),
                                 sort_keys=True).encode())
    with pytest.raises(activation.ActivationError):
        activation.parse("nyxl_%s.%s" % (swapped, sig_raw))


def test_an_expired_key_is_genuine_and_says_so():
    """Expired is not forged. An operator renewing has to be able to see
    what ran out and when."""
    c = activation.describe(mint(expires="2026-01-31"), today=date(2026, 3, 1))
    assert c["state"] == "expired"
    assert c["days_left"] == -29
    assert c["org"] == "Acme Group Ltd"


def test_the_last_day_is_still_active():
    c = activation.describe(mint(expires="2026-03-01"), today=date(2026, 3, 1))
    assert c["state"] == "active" and c["days_left"] == 0


@pytest.mark.parametrize("bad,says", [
    ("", "no key"),
    ("   ", "no key"),
    ("nyxe_9f3c2a1b", "starts with nyxl_"),
    ("nyxl_notbase64!!", "damaged"),
    ("nyxl_" + "a" * 20, "damaged"),
    ("nyxl_" + "a" * 5000, "too long"),
])
def test_what_is_not_a_key_says_what_to_do_about_it(bad, says):
    with pytest.raises(activation.ActivationError) as e:
        activation.parse(bad)
    assert says in str(e.value)


def test_a_signed_key_this_release_cannot_read_asks_for_an_upgrade():
    with pytest.raises(activation.ActivationError) as e:
        activation.parse(mint(v=2))
    assert "newer release" in str(e.value)


@pytest.mark.parametrize("overrides", [
    {"org": None}, {"id": None}, {"expires": None}, {"plan": None},
    {"expires": "next Tuesday"}, {"issued": "2026-13-40"},
    {"plan": "unlimited"}, {"devices": "lots"}, {"id": "NYX 0001 & co"},
])
def test_a_signed_key_that_is_incomplete_is_still_refused(overrides):
    """Signed by the right publisher and still not a key: the signature
    says who wrote it, not that what they wrote makes sense."""
    with pytest.raises(activation.ActivationError):
        activation.parse(mint(**overrides))


def test_the_fingerprint_identifies_a_key_without_being_one():
    key = mint()
    fp = activation.fingerprint(key)
    assert fp == activation.fingerprint(" " + key + "\n")
    assert fp != activation.fingerprint(mint(id="NYX-0002"))
    assert len(fp) == 14 and fp.count("-") == 2
    assert fp not in key


def test_checking_a_key_makes_no_network_call(monkeypatch):
    """The promise the whole format exists to keep."""
    import socket

    def refuse(*a, **k):
        raise AssertionError("activation tried to reach the network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert activation.describe(mint())["state"] == "active"


# --------------------------------------------------------- the endpoints --

def test_a_deployment_with_no_key_says_so(managed, owner):
    assert client.get("/admin/activation", headers=owner).json() == {"state": "none"}


def test_an_owner_activates_and_the_key_never_comes_back(managed, owner):
    key = mint()
    r = client.put("/admin/activation", headers=owner, json={"key": key})
    assert r.status_code == 200 and r.json()["org"] == "Acme Group Ltd"

    got = client.get("/admin/activation", headers=owner)
    body = got.text
    assert got.json()["state"] == "active"
    assert got.json()["fingerprint"] == activation.fingerprint(key)
    assert key not in body and key[10:40] not in body

    # Nor through the settings route, which echoes everything else.
    assert "activation" not in client.get("/admin/settings", headers=owner).text


def test_a_forged_key_is_refused_and_nothing_is_stored(managed, owner):
    forged = mint(seed=b"somebody else's signing seed....")
    r = client.put("/admin/activation", headers=owner, json={"key": forged})
    assert r.status_code == 422
    assert "not issued for this software" in r.json()["detail"]
    assert client.get("/admin/activation", headers=owner).json() == {"state": "none"}


def test_only_an_owner_may_activate(managed, owner, admin, viewer):
    key = mint()
    assert client.put("/admin/activation", headers=viewer,
                      json={"key": key}).status_code == 403
    assert client.put("/admin/activation", headers=admin,
                      json={"key": key}).status_code == 403
    assert client.put("/admin/activation", headers=owner,
                      json={"key": key}).status_code == 200
    # Reading it is not the owner's alone: an admin supporting the
    # deployment needs to see when the subscription runs out.
    assert client.get("/admin/activation", headers=viewer).json()["state"] == "active"


def test_clearing_goes_back_to_the_open_edition(managed, owner):
    client.put("/admin/activation", headers=owner, json={"key": mint()})
    r = client.put("/admin/activation", headers=owner, json={"key": ""})
    assert r.status_code == 200 and r.json() == {"state": "none"}
    assert client.get("/admin/activation", headers=owner).json() == {"state": "none"}


def test_activating_is_recorded_with_who_did_it_and_not_what(managed, owner):
    client.put("/admin/activation", headers=owner, json={"key": mint()})
    events = managed.list_events(20)
    setting = [e for e in events if e["kind"] == "setting_changed"
               and e["detail"].get("key") == "activation_key"]
    assert setting and setting[0]["detail"]["by"] == "root"
    assert "nyxl_" not in json.dumps(events)


def test_a_key_the_running_release_cannot_verify_is_reported_not_hidden(
        managed, owner, monkeypatch):
    """What a publisher key rotation looks like from inside a deployment
    that has not taken the release carrying the new one."""
    client.put("/admin/activation", headers=owner, json={"key": mint()})
    monkeypatch.setenv("ACTIVATION_PUBLIC_KEY",
                       base64.b64encode(public_key(b"a rotated signing seed..." + b"." * 7)).decode())
    got = client.get("/admin/activation", headers=owner).json()
    assert got["state"] == "invalid"
    assert "not issued for this software" in got["error"]
    assert got["fingerprint"]


def test_an_expired_key_is_stored_and_shown_as_expired(managed, owner):
    r = client.put("/admin/activation", headers=owner,
                   json={"key": mint(expires="2020-01-01")})
    assert r.status_code == 200 and r.json()["state"] == "expired"
    assert client.get("/admin/activation", headers=owner).json()["state"] == "expired"


def test_an_unknown_field_is_refused_rather_than_ignored(managed, owner):
    r = client.put("/admin/activation", headers=owner,
                   json={"key": mint(), "seats": 5})
    assert r.status_code == 422
