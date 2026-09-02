"""A process name is matched in every shape the platforms report it in.

`is_allowed_process` was an exact lowercase set lookup against a list written
in mac/Linux form, so "OneDrive" never matched the "onedrive.exe" SentinelOne
actually reports and no Windows browser matched anything at all. Two things
followed: the Microsoft-noise filter never fired on Windows, so Office apps
resolving the Copilot endpoints were reported as AI usage; and the bridge scan
raised a high-risk finding on every chrome.exe that touched api.github.com.

The second half is attribution. A stub resolver is the querying process for
every lookup its machine makes, so naming it says only "this device resolved
it" - the same non-answer as the agent version string is_unattributable
already refused, and it has to be refused the same way.
"""

import pytest

from ai_guard.registry import normalise_process
from ai_guard.scanners.sentinelone import is_unattributable


@pytest.mark.parametrize("reported,expected", [
    ("OneDrive", "onedrive"),
    ("onedrive.exe", "onedrive"),
    ("ONEDRIVE.EXE", "onedrive"),
    ("chrome.exe", "chrome"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome"),
    ("/Applications/Firefox.app/Contents/MacOS/firefox", "firefox"),
    ("Google Chrome Helper", "google chrome"),
    ("Google Chrome Helper (Renderer)", "google chrome"),
    ("Google Chrome Helper (GPU)", "google chrome"),
    ("Claude Helper", "claude"),
    ("", ""),
    ("   ", ""),
])
def test_a_name_reduces_to_the_form_the_allowlist_is_written_in(reported, expected):
    assert normalise_process(reported) == expected


class _Reg:
    """Just the allowlist half of Registry, loaded the way Registry loads it."""

    def __init__(self, entries):
        self.allowed_processes = {normalise_process(p) for p in entries} - {""}
        from ai_guard.registry import Registry
        self.BROWSER_NAMES = Registry.BROWSER_NAMES

    is_allowed_process = None


def _allowed(entries, name):
    from ai_guard.registry import Registry
    r = _Reg(entries)
    return Registry.is_allowed_process(r, name)


@pytest.mark.parametrize("name", [
    "onedrive.exe", "outlook.exe", "excel.exe", "powerpnt.exe",
    "chrome.exe", "msedge.exe", "Google Chrome Helper (Renderer)",
])
def test_the_shapes_that_used_to_fall_through_are_allowed(name):
    """Every one of these was reported to an operator as an unaccountable
    process reaching a model."""
    entries = ["chrome", "Google Chrome", "msedge", "OneDrive", "Outlook",
               "Excel", "PowerPnt"]
    assert _allowed(entries, name) is True


def test_an_empty_name_is_not_allowed_by_an_empty_allowlist_entry():
    """A blank entry in the list would normalise to "" and match every
    process with no name, allowing everything unattributed through."""
    assert _allowed(["chrome", ""], "") is False


@pytest.mark.parametrize("proc", [
    "systemd-resolved", "systemd-executor", "mDNSResponder", "dnsmasq",
    "svchost.exe", "unbound", "nscd",
])
def test_a_resolver_or_service_host_names_nothing(proc):
    assert is_unattributable(proc) is True


@pytest.mark.parametrize("proc", ["", "2.1.204", "24.1"])
def test_the_cases_it_already_refused_are_still_refused(proc):
    assert is_unattributable(proc) is True


@pytest.mark.parametrize("proc", ["curl", "python3", "node", "Claude Helper"])
def test_a_real_client_is_still_attributable(proc):
    """The signal this all exists to keep: a script with a key in it."""
    assert is_unattributable(proc) is False


@pytest.mark.parametrize("reported,expected", [
    ("OneDrive.Sync.Service.exe", ["onedrive.sync.service", "onedrive.sync", "onedrive"]),
    ("Microsoft.Notes.exe", ["microsoft.notes", "microsoft"]),
    ("SearchHost.exe", ["searchhost"]),
])
def test_a_dotted_name_offers_its_shorter_prefixes(reported, expected):
    """A Windows service names itself in dotted components and only the
    leading one is the product, so "OneDrive.Sync.Service.exe" never matched
    the "OneDrive" already on the allowlist."""
    from ai_guard.registry import process_stems
    assert process_stems(reported) == expected


def test_a_prefix_does_not_allowlist_everything_a_vendor_ships():
    """The shorter prefixes are offered longest-first so a specific entry
    always wins, and the bare vendor component only matches if somebody
    actually put a bare vendor name on the list. Nobody should."""
    entries = ["Microsoft.Notes", "OneDrive"]
    assert _allowed(entries, "Microsoft.Notes.exe") is True
    assert _allowed(entries, "OneDrive.Sync.Service.exe") is True
    # Same vendor, different product, not listed: must not inherit.
    assert _allowed(entries, "Microsoft.Telemetry.exe") is False


@pytest.mark.parametrize("proc", [
    "backgroundTaskHost.exe", "taskhostw.exe", "rundll32.exe", "dllhost.exe",
])
def test_a_generic_task_host_names_nothing(proc):
    """Windows runs scheduled and background work inside these, so the name
    is whatever they were told to run - the same non-answer as svchost."""
    assert is_unattributable(proc) is True


@pytest.mark.parametrize("proc", ["Update.exe", "Updater.exe", "Squirrel.exe"])
def test_a_squirrel_updater_names_the_framework_not_the_app(proc):
    """Squirrel ships its updater as Update.exe inside every app that uses
    it, so the name says an application updated itself and not which one.
    An allowlist entry would wrongly read as "this program is fine"."""
    assert is_unattributable(proc) is True


# ---- the rule that replaces a maintained list of shell process names -------

def test_a_browser_is_recognised_in_every_shape():
    """The one process that must stay visible on a backend domain: somebody
    using a model in a browser is the ordinary case, and it is the only
    non-background thing that reaches these hosts."""
    from ai_guard.registry import Registry
    r = _Reg([])
    for n in ["chrome.exe", "Google Chrome Helper (Renderer)", "msedge.exe",
              "firefox", r"C:\Program Files\Google\Chrome\chrome.exe"]:
        assert Registry.is_browser_process(r, n) is True, n
    for n in ["SearchHost.exe", "curl", "OneDrive.Sync.Service.exe", ""]:
        assert Registry.is_browser_process(r, n) is False, n
