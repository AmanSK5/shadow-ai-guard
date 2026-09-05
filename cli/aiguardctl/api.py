"""Talking to the portal. Standard library only; JSON in, JSON out; the
token lives in this process and is sent only as a bearer header to the
portal's upgrade routes."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__

TIMEOUT = 15


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def request(portal: str, method: str, path: str, body: dict | None = None,
            token: str = "") -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json",
               "Accept": "application/json",
               "User-Agent": "aiguardctl/%s" % __version__}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(portal.rstrip("/") + path, data=data,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}").get("detail") or e.reason
        except Exception:  # noqa: BLE001 - the status is the story
            detail = e.reason
        raise ApiError(e.code, str(detail)) from None
    except urllib.error.URLError as e:
        raise ApiError(0, "could not reach %s: %s" % (portal, e.reason)) from None
