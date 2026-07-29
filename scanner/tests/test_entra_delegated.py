"""Delegated access detection.

The interesting cases are all about not repeating the mistake the sign-in
scan made: counting the wrong events, and turning volume into meaning.
"""

import json

from ai_guard.scanners.entra import _looks_like_service_account, _oauth_scopes


class _Svc:
    def __init__(self, name, vendor="", risk_tier="medium"):
        self.name = name
        self.vendor = vendor
        self.risk_tier = risk_tier


def _entry(scopes=None, **kw):
    e = {
        "userPrincipalName": "someone@example.com",
        "appDisplayName": "Example AI",
        "appId": "app-1",
        "createdDateTime": "2026-07-29T17:39:09Z",
        "status": {"errorCode": 0},
        "clientCredentialType": "clientSecret",
        "resourceDisplayName": "Microsoft Graph",
    }
    if scopes is not None:
        e["authenticationProcessingDetails"] = [
            {"key": "Is Legacy Store Used", "value": "0"},
            {"key": "Oauth Scope Info", "value": json.dumps(scopes)},
        ]
    e.update(kw)
    return e


def test_scopes_are_extracted_from_processing_details():
    entry = _entry(["Calendars.Read", "openid", "User.Read"])
    assert _oauth_scopes(entry) == ["Calendars.Read", "openid", "User.Read"]


def test_missing_processing_details_gives_no_scopes():
    assert _oauth_scopes(_entry()) == []


def test_malformed_scope_value_gives_no_scopes():
    """Graph returns the scope list as a JSON string. If that ever stops being
    valid JSON, the finding should lose its scopes, not raise."""
    entry = _entry([])
    entry["authenticationProcessingDetails"] = [
        {"key": "Oauth Scope Info", "value": "not json"}
    ]
    assert _oauth_scopes(entry) == []


def test_processing_details_not_a_list_is_tolerated():
    entry = _entry()
    entry["authenticationProcessingDetails"] = None
    assert _oauth_scopes(entry) == []


def test_service_account_matches_on_service_name():
    assert _looks_like_service_account("exampleai@corp.com", _Svc("Example AI"))


def test_service_account_matches_on_vendor():
    assert _looks_like_service_account("acme@corp.com", _Svc("Some Tool", vendor="Acme"))


def test_a_person_is_not_a_service_account():
    assert not _looks_like_service_account(
        "michael.smith@corp.com", _Svc("Example AI", vendor="Example")
    )


def test_partial_name_overlap_is_not_a_service_account():
    """exampleaidan is a person whose name starts like the service. Substring
    matching here would label them a bot, so the check is exact."""
    assert not _looks_like_service_account("example.aidan@corp.com", _Svc("Example AI"))


def test_empty_upn_is_not_a_service_account():
    assert not _looks_like_service_account("", _Svc("Example AI"))