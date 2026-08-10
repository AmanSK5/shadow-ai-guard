"""SentinelOne reports device identity as the hardware serial.

Deep Visibility events carry the computer name and nothing else, so findings
used to be keyed on it. The endpoint collectors and the browser extension both
report serials. The same machine therefore arrived twice, once as C02XK1ABCDEF
from its collector and once as JANES-MBP from the scanner, and a fleet of about
65 counted 73 devices.

jamf.py had done this correctly since it was written and says why in its module
docstring. This is the same rule applied to the other two sources.

The serial comes from the Agents call the scanner already makes for the user
map, so this costs no extra API calls.
"""

import asyncio

from ai_guard.config import ScannerConfig
from ai_guard.scanners.sentinelone import SentinelOneScanner


class FakeRegistry:
    services = []


AGENTS = [
    {
        "computerName": "JANES-MBP",
        "lastLoggedInUserName": "jane",
        "serialNumber": "C02XK1ABCDEF",
    },
    {
        "computerName": "LAPTOP-01",
        "lastLoggedInUserName": "sam",
        "serialNumber": "PF2ABCDE",
    },
]


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeClient:
    """Returns one page of agents, then no cursor."""

    def __init__(self, agents):
        self.agents = agents
        self.calls = 0

    async def get(self, url, params=None):
        self.calls += 1
        return FakeResponse({"data": self.agents, "pagination": {}})


def _scanner():
    return SentinelOneScanner(FakeRegistry(), ScannerConfig(enabled=True))


def test_agents_call_yields_both_maps():
    scanner = _scanner()
    users, serials = asyncio.run(
        scanner._build_endpoint_user_map(FakeClient(AGENTS))
    )

    assert users == {"JANES-MBP": "jane", "LAPTOP-01": "sam"}
    assert serials == {
        "JANES-MBP": "C02XK1ABCDEF",
        "LAPTOP-01": "PF2ABCDE",
    }


def test_both_maps_come_from_one_call():
    """The serial must not cost a second pass over the agent inventory."""
    scanner = _scanner()
    client = FakeClient(AGENTS)
    asyncio.run(scanner._build_endpoint_user_map(client))

    assert client.calls == 1


def test_device_id_returns_the_serial():
    scanner = _scanner()
    scanner._endpoint_serials = {"JANES-MBP": "C02XK1ABCDEF"}

    assert scanner._device_id("JANES-MBP") == "C02XK1ABCDEF"


def test_unknown_endpoint_falls_back_to_the_computer_name():
    """A finding that joins imperfectly beats one with no device at all.

    The agents call filters on isActive, so an endpoint whose agent has gone
    quiet is absent from the map while its DV events are still in the lookback
    window.
    """
    scanner = _scanner()
    scanner._endpoint_serials = {}

    assert scanner._device_id("RETIRED-LAPTOP") == "RETIRED-LAPTOP"


def test_empty_endpoint_name_passes_through():
    scanner = _scanner()
    assert scanner._device_id("") == ""


def test_agent_with_no_serial_is_absent_rather_than_blank():
    """A blank serial must not become the device identity.

    Every agent missing a serial would collapse to one device called "".
    """
    scanner = _scanner()
    agents = [
        {
            "computerName": "NO-SERIAL",
            "lastLoggedInUserName": "sam",
            "serialNumber": "   ",
        },
        {
            "computerName": "NULL-SERIAL",
            "lastLoggedInUserName": "sam",
            "serialNumber": None,
        },
    ]
    users, serials = asyncio.run(
        scanner._build_endpoint_user_map(FakeClient(agents))
    )

    assert serials == {}
    assert users == {"NO-SERIAL": "sam", "NULL-SERIAL": "sam"}
    assert scanner._device_id("NO-SERIAL") == "NO-SERIAL"


def test_serial_is_recorded_even_when_the_user_is_unknown():
    """The two maps are independent. An agent with no logged in user still
    has a serial worth keying on."""
    scanner = _scanner()
    agents = [
        {
            "computerName": "KIOSK-01",
            "lastLoggedInUserName": "",
            "serialNumber": "PF9ZZZZZ",
        }
    ]
    users, serials = asyncio.run(
        scanner._build_endpoint_user_map(FakeClient(agents))
    )

    assert users == {}
    assert serials == {"KIOSK-01": "PF9ZZZZZ"}
