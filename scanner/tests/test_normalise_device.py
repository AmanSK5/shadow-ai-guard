"""Tests for normalise_device in receiver_reporter.py.

Covers the bug where the no-prefix branch returned a bare str instead of
a tuple, which caused the call-site unpack to fail for any hostname that
wasn't exactly two characters long.
"""

import os
import sys
from pathlib import Path

# receiver_reporter.py lives at scanner/ (outside the ai_guard package).
# Add that directory so the import resolves regardless of working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


@pytest.fixture(autouse=True)
def _clear_prefix(monkeypatch):
    """Ensure AIGUARD_DEVICE_PREFIX is unset for all tests by default."""
    monkeypatch.delenv("AIGUARD_DEVICE_PREFIX", raising=False)


def _fresh_import():
    """Import normalise_device after env is set, bypassing module cache.

    receiver_reporter reads AIGUARD_DEVICE_PREFIX at import time, so we
    need to reload the module to pick up the test environment.
    """
    import importlib
    import receiver_reporter as mod

    importlib.reload(mod)
    return mod.normalise_device


class TestNoPrefixConfigured:
    """AIGUARD_DEVICE_PREFIX is unset (the common case)."""

    def test_normal_hostname_returns_tuple(self):
        normalise_device = _fresh_import()
        result = normalise_device("workstation-01")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result == ("workstation-01", "workstation-01")

    def test_two_char_hostname(self):
        normalise_device = _fresh_import()
        result = normalise_device("AB")
        assert isinstance(result, tuple)
        assert result == ("AB", "AB")

    def test_none_returns_empty_tuple(self):
        normalise_device = _fresh_import()
        result = normalise_device(None)
        assert result == ("", "")

    def test_empty_string_returns_empty_tuple(self):
        normalise_device = _fresh_import()
        result = normalise_device("")
        assert result == ("", "")

    def test_whitespace_stripped(self):
        normalise_device = _fresh_import()
        result = normalise_device("  host-01  ")
        assert result == ("host-01", "host-01")

    def test_call_site_unpack_works(self):
        """The actual usage pattern from ReceiverReporter.payload()."""
        normalise_device = _fresh_import()
        device, device_name = normalise_device("workstation-01")
        assert device == "workstation-01"
        assert device_name == "workstation-01"


class TestWithPrefix:
    """AIGUARD_DEVICE_PREFIX is set."""

    def test_matching_prefix_extracts_serial(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()
        result = normalise_device("ACME-C02XK1ABCDEF")
        assert isinstance(result, tuple)
        assert result == ("C02XK1ABCDEF", "ACME-C02XK1ABCDEF")

    def test_non_matching_returns_hostname_twice(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()
        result = normalise_device("other-host-01")
        assert isinstance(result, tuple)
        assert result == ("other-host-01", "other-host-01")

    def test_none_with_prefix_set(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()
        result = normalise_device(None)
        assert result == ("", "")


class TestPrefixLengthAndDigits:
    """The rule that decides whether something is a serial or a hostname.

    It was originally eight characters or more, and that was wrong in both
    directions. Dell service tags are seven, so most of a Windows fleet went
    unnormalised and every one of those machines counted twice: once as
    ACME-XYZ4A21 from the scanner and once as XYZ4A21 from the collector. And
    length alone would happily strip ACME-SERVER down to SERVER, turning a
    domain controller's hostname into something that looks like a serial.

    Six or more characters, and at least one digit. A serial essentially
    always contains a digit; a word essentially never does.
    """

    def test_a_seven_character_service_tag_is_stripped(self, monkeypatch):
        """The regression. Dell service tags are seven characters, and the
        eight-character minimum silently skipped all of them."""
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("ACME-XYZ4A21") == ("XYZ4A21", "ACME-XYZ4A21")

    def test_a_serial_starting_with_a_digit_is_stripped(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("ACME-1ABC234") == ("1ABC234", "ACME-1ABC234")

    def test_a_word_is_not_a_serial(self, monkeypatch):
        """ACME-SERVER stripped to SERVER would put a hostname in the field
        every other source fills with a hardware serial, and two machines
        called SERVER on different fleets would merge into one."""
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("ACME-SERVER") == ("ACME-SERVER", "ACME-SERVER")

    def test_a_short_asset_number_is_not_a_serial(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("ACME-DC01") == ("ACME-DC01", "ACME-DC01")

    def test_the_prefix_without_a_separator_is_left_alone(self, monkeypatch):
        """ACME015 is a machine named after the fleet, not a prefixed serial."""
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("ACME015") == ("ACME015", "ACME015")


class TestSeveralPrefixes:
    """A fleet can have more than one convention.

    Windows and macOS are often enrolled by different tools, and a single
    prefix normalises half an estate while leaving the other half duplicated,
    which reads as a partial fix and is harder to spot than no fix at all.
    """

    def test_either_prefix_is_stripped(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME,ACM")
        normalise_device = _fresh_import()

        assert normalise_device("ACME-XYZ4A21") == ("XYZ4A21", "ACME-XYZ4A21")
        assert normalise_device("ACM-YJXCWNR42G") == ("YJXCWNR42G", "ACM-YJXCWNR42G")

    def test_whitespace_around_a_prefix_is_ignored(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME, ACM ")
        normalise_device = _fresh_import()

        assert normalise_device("ACM-YJXCWNR42G") == ("YJXCWNR42G", "ACM-YJXCWNR42G")

    def test_an_unlisted_prefix_is_left_alone(self, monkeypatch):
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME")
        normalise_device = _fresh_import()

        assert normalise_device("OTHER-XYZ4A21") == ("OTHER-XYZ4A21", "OTHER-XYZ4A21")

    def test_an_empty_entry_does_not_match_everything(self, monkeypatch):
        """"ACME," has a trailing empty element. An empty alternation branch
        would match any string and strip every hostname in the estate."""
        monkeypatch.setenv("AIGUARD_DEVICE_PREFIX", "ACME,")
        normalise_device = _fresh_import()

        assert normalise_device("random-host-99") == ("random-host-99", "random-host-99")