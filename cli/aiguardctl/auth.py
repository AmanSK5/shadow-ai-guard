"""Borrowing the portal's sign-in. The command generates a verifier it keeps
in memory, asks the receiver (through the portal) for a grant with the
verifier's hash, opens the approval page for the person, and polls until an
owner has decided. It never sees a password and never learns whether
sign-in is federated; the browser handles that. SECURITY.md, "Upgrading"."""
from __future__ import annotations

import hashlib
import secrets
import time
import webbrowser

from . import __version__, api


class Denied(Exception):
    pass


def authorize(portal: str, say, open_browser=webbrowser.open,
              sleep=time.sleep, poll=api.request) -> str:
    """Returns an upgrade token, or raises Denied / api.ApiError."""
    verifier = secrets.token_urlsafe(32)
    grant = poll(portal, "POST", "/api/cli/authorize", {
        "purpose": "upgrade",
        "verifier_hash": hashlib.sha256(verifier.encode()).hexdigest(),
        "client": "aiguardctl %s" % __version__})
    url = portal.rstrip("/") + grant["approve_path"]
    say("")
    say("  Approve this upgrade in the portal as an owner.")
    say("  Compare the code on the page with this one:  %s" % grant["user_code"])
    say("  Opening %s" % url)
    say("")
    try:
        open_browser(url)
    except Exception:  # noqa: BLE001 - a headless machine just gets the link
        pass
    interval = max(1, int(grant.get("interval", 3)))
    deadline = time.time() + int(grant.get("expires_in", 600))
    while time.time() < deadline:
        sleep(interval)
        try:
            out = poll(portal, "POST", "/api/cli/token", {
                "device_code": grant["device_code"], "verifier": verifier})
        except api.ApiError as e:
            if e.status == 428:
                continue
            if e.status == 429:
                interval += 1
                continue
            if e.status == 403:
                raise Denied("the owner denied this request") from None
            if e.status == 410:
                raise Denied("the request expired before it was approved") from None
            raise
        return out["token"]
    raise Denied("no decision arrived before the request expired")
