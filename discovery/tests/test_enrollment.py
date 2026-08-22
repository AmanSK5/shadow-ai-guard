"""Managed mode: RECEIVER_TOKEN may be an enrollment token, and discovery -
which only ever reads the registry - enrolls as a scanner first and reads it
with its own credential. Mirrors scanner/receiver_reporter.py; the copy is
deliberate (discovery imports nothing from the scanner package), so the
behaviour is pinned here on its own.
"""

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import discover


class FakeReceiver:
    def __init__(self):
        self.requests = []
        self.live = set()
        self.issued = 0
        self.enroll_status = 200

    def handler(self, request):
        self.requests.append(request)
        bearer = request.headers.get("authorization", "").removeprefix("Bearer ")
        if request.url.path == "/enroll":
            if not bearer.startswith("aige_"):
                return httpx.Response(401, json={"detail": "bad token"})
            if self.enroll_status != 200:
                return httpx.Response(self.enroll_status, json={"detail": "refused"})
            self.issued += 1
            self.live.add(f"aigd_{self.issued}")
            return httpx.Response(200, json={"device_id": "d1",
                                             "device_token": f"aigd_{self.issued}"})
        if bearer in self.live or bearer == "shared":
            return httpx.Response(200, json={"tools": []})
        return httpx.Response(401, json={"detail": "bad token"})


@pytest.fixture
def receiver(monkeypatch):
    rx = FakeReceiver()
    transport = httpx.MockTransport(rx.handler)
    real = httpx.Client
    monkeypatch.setattr(discover.httpx, "post",
                        lambda url, **kw: real(transport=transport).post(url, **kw))
    monkeypatch.setattr(discover.httpx, "get",
                        lambda url, **kw: real(transport=transport).get(url, **kw))
    monkeypatch.setattr(discover, "RECEIVER_URL", "https://r.example")
    monkeypatch.setattr(discover.socket, "gethostname", lambda: "discovery-pod")
    return rx


def test_a_shared_token_is_used_as_is(receiver):
    assert discover.resolve_credential("https://r.example", "shared", "discovery", "") == "shared"
    assert receiver.requests == []


def test_an_enrollment_token_enrolls_as_a_scanner_and_reads_the_registry(receiver):
    cred = discover.resolve_credential("https://r.example", "aige_x", "discovery", "")
    assert cred == "aigd_1"
    assert discover.fetch_registry(cred) == {"tools": []}
    enroll, read = receiver.requests
    assert json.loads(enroll.content) == {"platform": "scanner", "serial": "discovery",
                                          "hostname": "discovery-pod",
                                          "agent_version": discover.AGENT_VERSION}
    assert read.headers["authorization"] == "Bearer aigd_1"
    assert read.headers["x-aiguard-agent-version"] == discover.AGENT_VERSION


def test_a_state_dir_keeps_the_credential_between_runs(receiver, tmp_path):
    a = discover.resolve_credential("https://r.example", "aige_x", "discovery", str(tmp_path))
    b = discover.resolve_credential("https://r.example", "aige_x", "discovery", str(tmp_path))
    assert a == b and receiver.issued == 1
    assert (tmp_path / "device.cred").stat().st_mode & 0o777 == 0o600


def test_a_refused_enrollment_exits_and_names_the_status(receiver):
    receiver.enroll_status = 401
    with pytest.raises(SystemExit) as e:
        discover.resolve_credential("https://r.example", "aige_x", "discovery", "")
    assert "HTTP 401" in str(e.value) and "refused" in str(e.value)


def test_an_unreadable_stored_credential_exits_with_a_name(receiver, tmp_path):
    cred = tmp_path / "device.cred"
    cred.write_text("aigd_stored")
    cred.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as e:
            discover.resolve_credential("https://r.example", "aige_x", "discovery", str(tmp_path))
        assert "cannot read" in str(e.value)
    finally:
        cred.chmod(0o600)


def test_a_revoked_credential_exits_loudly_and_never_reenrolls(receiver):
    with pytest.raises(SystemExit) as e:
        discover.fetch_registry("aigd_revoked")
    assert "revoked" in str(e.value)
    assert all(r.url.path != "/enroll" for r in receiver.requests)
