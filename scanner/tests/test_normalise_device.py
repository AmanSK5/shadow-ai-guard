"""Tests for normalise_device in receiver_reporter.py.

Covers the bug where the no-prefix branch returned a bare str instead of
a tuple, which caused the call-site unpack to fail for any hostname that
wasn't exactly two characters long.
"""

import os

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
