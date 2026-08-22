"""Managed mode: RECEIVER_TOKEN may be an enrollment token.

The prefix is the switch, as for the collectors and the extension. The run
exchanges it once for a device credential, keeps it when a state dir is
given, uses it for the registry fetch and every report, and is loud and
fatal when the receiver refuses - an enrollment token cannot report, so a
scan that carried on would look like a clean estate.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import receiver_reporter as rr
from ai_guard.registry import Registry


class FakeReceiver:
    """Records every request; enrolls anyone with an aige_ bearer."""

    def __init__(self, enroll_status=200):
        self.requests = []
        self.enroll_status = enroll_status
        self.issued = 0
        self.live = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
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
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, json={"detail": "bad token"})


@pytest.fixture
def receiver(monkeypatch):
    rx = FakeReceiver()
    transport = httpx.MockTransport(rx.handler)
    real_client = httpx.Client
    # Route module-level httpx.post/get and Client() through the fake.
    monkeypatch.setattr(httpx, "post", lambda url, **kw: real_client(transport=transport).post(url, **kw))
    monkeypatch.setattr(httpx, "get", lambda url, **kw: real_client(transport=transport).get(url, **kw))
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(transport=transport, **kw))
    return rx


def test_a_shared_token_is_used_as_is(receiver):
    assert rr.resolve_credential("https://r.example", "shared", "scanner", state_dir="") == "shared"
    assert receiver.requests == []


def test_an_enrollment_token_is_exchanged_for_a_device_credential(receiver, monkeypatch):
    monkeypatch.setattr(rr.socket, "gethostname", lambda: "scanner-pod-1")
    cred = rr.resolve_credential("https://r.example/", "aige_x", "nightly", state_dir="")
    assert cred == "aigd_1"
    (req,) = receiver.requests
    assert req.url == "https://r.example/enroll"
    assert req.headers["authorization"] == "Bearer aige_x"
    import json
    body = json.loads(req.content)
    assert body == {"platform": "scanner", "serial": "nightly",
                    "hostname": "scanner-pod-1", "agent_version": rr.AGENT_VERSION}


def test_a_state_dir_keeps_the_credential_between_runs(receiver, tmp_path):
    first = rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir=str(tmp_path))
    second = rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir=str(tmp_path))
    assert first == second == "aigd_1"
    assert receiver.issued == 1, "the second run read device.cred instead of enrolling"
    cred_file = tmp_path / "device.cred"
    assert cred_file.read_text() == "aigd_1"
    assert (cred_file.stat().st_mode & 0o777) == 0o600


def test_without_a_state_dir_every_run_enrolls(receiver):
    rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir="")
    rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir="")
    assert receiver.issued == 2  # the receiver reissues in place; one fleet row


def test_a_refused_enrollment_is_fatal_and_names_the_status(receiver):
    receiver.enroll_status = 401
    with pytest.raises(rr.EnrollmentError) as e:
        rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir="")
    assert "HTTP 401" in str(e.value) and "refused" in str(e.value)


def test_an_unreadable_stored_credential_is_named_not_a_traceback(receiver, tmp_path):
    cred = tmp_path / "device.cred"
    cred.write_text("aigd_stored")
    cred.chmod(0o000)
    try:
        with pytest.raises(rr.EnrollmentError) as e:
            rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir=str(tmp_path))
        assert "cannot read" in str(e.value)
    finally:
        cred.chmod(0o600)


def test_a_registry_fetch_refused_on_a_device_credential_is_visible(receiver):
    """The entrypoint turns this into exit 1. Without it a revoked scanner
    would scan against the bundled registry, find nothing, and exit 0."""
    reg = Registry(url="https://r.example/registry", token="aigd_revoked")
    assert reg.fetch_status == 401
    assert reg.source.startswith("bundled")


def test_an_unwritable_state_dir_is_fatal(receiver, tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        with pytest.raises(rr.EnrollmentError) as e:
            rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir=str(ro))
        assert "refusing to scan" in str(e.value)
    finally:
        ro.chmod(0o700)


def test_the_resolved_credential_reaches_the_registry_and_every_report(receiver):
    """The same bearer for both requests. A credential that can report but
    not fetch the registry would scan against nothing."""
    from ai_guard.scanners.base import DetectionSource, Finding
    from ai_guard.registry import AIService

    cred = rr.resolve_credential("https://r.example", "aige_x", "scanner", state_dir="")
    # Registry() falls back to the bundled copy if the fetch fails; what is
    # asserted here is the request it made, not the JSON it got back.
    Registry(url="https://r.example/registry", token=cred)
    reporter = rr.ReceiverReporter(url="https://r.example", token=cred)
    svc = AIService(name="ChatGPT", vendor="OpenAI", category="chat", risk_tier="high",
                    id="chatgpt")
    finding = Finding(service=svc, source=DetectionSource.JAMF_APP, risk_tier="high", detail="present",
                      device_name="C02TEST")
    sent, failed = reporter.send([finding])
    assert (sent, failed) == (1, 0)

    paths = [r.url.path for r in receiver.requests]
    assert paths == ["/enroll", "/registry", "/report"]
    for r in receiver.requests[1:]:
        assert r.headers["authorization"] == "Bearer aigd_1"
        assert r.headers["x-aiguard-agent-version"] == rr.AGENT_VERSION


def test_a_revoked_credential_fails_the_report_and_says_why(receiver, caplog):
    from ai_guard.scanners.base import DetectionSource, Finding
    from ai_guard.registry import AIService

    reporter = rr.ReceiverReporter(url="https://r.example", token="aigd_revoked")
    svc = AIService(name="ChatGPT", vendor="OpenAI", category="chat", risk_tier="high",
                    id="chatgpt")
    finding = Finding(service=svc, source=DetectionSource.JAMF_APP, risk_tier="high", detail="present",
                      device_name="C02TEST")
    sent, failed = reporter.send([finding, finding])
    assert (sent, failed) == (0, 2)
    revoked = [r for r in caplog.records if "revoked" in r.getMessage()]
    assert len(revoked) == 1, "said once, not per finding"
    assert not any(r.url.path == "/enroll" for r in receiver.requests), "never re-enrolls on its own"
