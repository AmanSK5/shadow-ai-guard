# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Activation keys: what one is, and how this deployment checks one.

Shadow AI Guard is the open edition and stays whole without any of this.
Nothing here switches a feature on or off, and no code path in this
repository asks whether a key is present before doing its job. What an
activation key does is name a subscription to the enterprise edition, which
ships as private images: it identifies the organisation, states the term
and the limits, and doubles as the credential that pulls those images. This
module exists so the portal can tell an operator whether the key they were
issued is genuine, what it says, and what to run next - on their own
machine, which is where every deployment change in this project happens.

Three properties are deliberate.

Offline. The key carries its own claims and an Ed25519 signature over them.
Checking it needs the publisher's public key, which is compiled in below,
and nothing else - no outbound request at activation, at boot, or ever. A
deployment that is airgapped, or whose vendor has gone quiet, keeps working
exactly as it did the day before.

Readable. The claims are plain JSON, so the operator can see what they were
sold without a tool. The signature stops it being edited, not read; a key
is a statement about an agreement, not a secret about the software.

Verified where it is stored. The receiver holds settings and holds this,
and refuses to store a key it cannot verify. A portal that verified and
then wrote would leave the write path as the real gate.
"""

import base64
import binascii
import hashlib
import json
import os
import re
from datetime import date, datetime, timezone

from . import ed25519

# The publisher's Ed25519 public key. Public by nature: it verifies
# signatures and makes none, so shipping it in a public repository is what
# it is for. ACTIVATION_PUBLIC_KEY overrides it, which is how a test issues
# its own keys and how a key rotation reaches a deployment that has not
# taken a new image yet.
_DEFAULT_PUBLIC_KEY = "FHWkKrwWNLyubMhj6asRZGaW/80gKbaDj2zhonmPcmQ="

PREFIX = "nyxl_"

# Long enough for any real key, short enough that the parser is never handed
# a megabyte to base64-decode.
MAX_LENGTH = 4000

_PLANS = ("enterprise", "trial")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# Why a key was refused, and the sentence an operator is shown for it.
#
# The two are separate on purpose. CodeQL flagged the first version of this
# module for exposing exception detail in a response, and it was right in
# the way it was right about the portal's Loki errors (see
# portal/tests/test_error_disclosure.py): a response must carry the class of
# failure, and the detail behind it belongs in the log. Nothing here is
# built from a caught exception or from anything the key itself contains -
# every refusal an operator sees is one of the constants below, chosen by
# code.
#
# They still say what to do about it rather than which check failed, because
# someone holding a key that does not work needs to know whether to look for
# a typo or to email support.
REFUSALS = {
    "empty": "no key was given",
    "too_long": "this is too long to be an activation key",
    "not_a_key": "an activation key starts with %s. This looks like "
                 "something else - an enrollment token, perhaps." % "nyxl_",
    "damaged": "this key is damaged - it is not the shape a key has. Paste "
               "it again, whole.",
    "not_ours": "this key was not issued for this software, or it has been "
                "altered since it was issued. Check you pasted all of it; if "
                "you did, ask for it to be reissued.",
    "unreadable": "this key is signed but unreadable",
    "too_new": "this key needs a newer release than the one running here. "
               "Upgrade, then activate.",
    "incomplete": "this key is signed, but it does not state everything a "
                  "key has to state. Ask for it to be reissued.",
    "unknown_plan": "this key is for a plan this release does not know "
                    "about. Upgrade, then activate.",
    "publisher_key": "this deployment's ACTIVATION_PUBLIC_KEY is not a "
                     "32-byte Ed25519 public key, so no key can be checked "
                     "until it is corrected or removed.",
}


class ActivationError(ValueError):
    """The key is not usable. Carries the code, not a message to echo.

    Raised inside this module and caught inside it: check() is the only
    thing callers use, and it hands back a constant from REFUSALS. An
    exception object never reaches a response.
    """

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def public_key() -> bytes:
    raw = (os.environ.get("ACTIVATION_PUBLIC_KEY") or _DEFAULT_PUBLIC_KEY).strip()
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise ActivationError("publisher_key")
    if len(key) != 32:
        raise ActivationError("publisher_key")
    return key


def _b64url(raw: str) -> bytes:
    # The encoder strips padding because a key is something people paste
    # into a chat window, and "=" at the end of one invites a truncation.
    pad = "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw + pad)
    except (binascii.Error, ValueError):
        raise ActivationError("damaged")


def fingerprint(key: str) -> str:
    """A short, stable name for a key, safe to say out loud.

    Support needs to agree with an operator about which key is installed
    without either of them sending it anywhere, and the key is also a
    registry credential, so it is never displayed. This is a hash of it.
    """
    digest = hashlib.sha256(key.strip().encode()).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 12, 4))


def parse(key: str) -> dict:
    """The claims in a key, once its signature has been checked.

    Raises ActivationError for anything that is not a genuine key. Expiry
    is NOT checked here: an expired key is genuine and its claims are worth
    showing, and conflating "forged" with "ran out" is how an operator
    spends an afternoon on the wrong problem. See describe().
    """
    key = (key or "").strip()
    if not key:
        raise ActivationError("empty")
    if len(key) > MAX_LENGTH:
        raise ActivationError("too_long")
    if not key.startswith(PREFIX):
        raise ActivationError("not_a_key")
    body = key[len(PREFIX):]
    if body.count(".") != 1:
        raise ActivationError("damaged")
    claims_raw, sig_raw = body.split(".")
    signed = _b64url(claims_raw)
    signature = _b64url(sig_raw)
    if not ed25519.verify(public_key(), signed, signature):
        raise ActivationError("not_ours")
    try:
        claims = json.loads(signed.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ActivationError("unreadable")
    if not isinstance(claims, dict):
        raise ActivationError("unreadable")
    # Version first: a v2 key may mean something different by every field
    # below, so guessing at it is worse than saying the software is old.
    if claims.get("v") != 1:
        raise ActivationError("too_new")
    for field in ("id", "org", "plan", "issued", "expires"):
        if not isinstance(claims.get(field), str) or not claims[field].strip():
            raise ActivationError("incomplete")
    if not _ID_RE.match(claims["id"]):
        raise ActivationError("incomplete")
    if claims["plan"] not in _PLANS:
        # The plan is not echoed. It is publisher-signed rather than
        # attacker-chosen, but a response that quotes a field out of the
        # key is the shape this module is not allowed to have.
        raise ActivationError("unknown_plan")
    for field in ("issued", "expires"):
        if not _DATE_RE.match(claims[field]) or not _as_date(claims[field]):
            raise ActivationError("incomplete")
    devices = claims.get("devices")
    if devices is not None and (not isinstance(devices, int)
                                or isinstance(devices, bool) or devices < 0):
        raise ActivationError("incomplete")
    return claims


def _as_date(text: str):
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def check(key: str, today: date | None = None) -> dict:
    """What the portal shows about a key. Never raises for a bad one.

    A key that does not verify is an ordinary answer, not an exceptional
    one - somebody mistyping a key is the common case, not a fault - so
    this returns the same shape either way and callers have no exception to
    catch. That is also what keeps exception detail out of every response
    built from it: "reason" is a constant from REFUSALS, chosen by code.

    Never returns the key. Every caller of this is on a path to a browser,
    and the key is the registry credential; the fingerprint is what a
    person needs to identify it and all they get.
    """
    today = today or datetime.now(timezone.utc).date()
    try:
        claims = parse(key)
    except ActivationError as e:
        return {"state": "invalid", "code": e.code,
                "reason": REFUSALS.get(e.code, REFUSALS["damaged"]),
                "fingerprint": fingerprint(key)}
    expires = _as_date(claims["expires"])
    days_left = (expires - today).days
    return {
        "state": "active" if days_left >= 0 else "expired",
        "id": claims["id"],
        "org": claims["org"],
        "plan": claims["plan"],
        "devices": claims.get("devices"),
        "issued": claims["issued"],
        "expires": claims["expires"],
        "days_left": days_left,
        "registry": (claims.get("registry") or "").strip(),
        "fingerprint": fingerprint(key),
    }
