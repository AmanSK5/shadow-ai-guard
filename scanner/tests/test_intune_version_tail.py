"""The version suffix is stripped from the end, not consumed to it.

_VERSION_TAIL used to be `\\s+v?\\d[\\d.+_-]*.*$`. The `.*$` swallowed everything
after the first digit-led token, so any display name shaped `<word> <digits>
<words>` collapsed to its first word.

Measured against 985 detectedApps display names from a real tenant, that folded
31 localisations of Microsoft 365 onto the single key "microsoft", plus 12
Visual C++ redistributables, 6 .NET SDKs and 3 SQL Server LocalDBs. Nothing was
misattributed to an AI tool at the time, because no registry entry happened to
claim those keys. But "Microsoft 365 Copilot" normalises to "microsoft" under
the old pattern, and adding an exe_name for it would have attributed every
Office install on the estate to Copilot.

A looser fix requiring groups of three or more digits was also tried and
rejected: it left 20% of the disagreements intact because three-digit version
segments still matched.

The names below are all real shapes from that inventory. They are vendor
product names, not anything belonging to a particular deployment.
"""

import pytest

from ai_guard.scanners.intune import _normalise_app_name


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Versions still come off, in every form Intune produces.
        ("LM Studio 0.3.20", "lm studio"),
        ("LM Studio 0.4.20+1", "lm studio"),
        ("LM Studio 0.3.20-beta", "lm studio"),
        ("Cursor v1.2.3", "cursor"),
        # A trailing parenthetical is part of the version suffix. This is the
        # common Windows shape and the reason a stricter end-anchored pattern
        # is not enough on its own.
        ("Notion 3.0 (x64)", "notion"),
        ("Python 3.12.3 (64-bit)", "python"),
        ("7-Zip 24.07 (x64)", "7-zip"),
        ("TortoiseGit 2.17.0.2 (64 bit)", "tortoisegit"),
        ("ChatGPT 1.2024.021 (Machine - MSI)", "chatgpt"),
        # Package ids and suffixes are unaffected by this change.
        ("ChatGPT.exe", "chatgpt"),
        ("Claude.app", "claude"),
        ("Exafunction.Windsurf", "windsurf"),
        ("Microsoft.Copilot", "copilot"),
        ("Claude", "claude"),
        ("", ""),
    ],
)
def test_version_suffixes_are_still_stripped(raw, expected):
    assert _normalise_app_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # The 31-name case. Every localisation of Microsoft 365 used to become
        # "microsoft".
        "Microsoft 365 Apps for business - en-us",
        "Microsoft 365 - en-us",
        # Words after a digit-led token are part of the name, not the version.
        "Microsoft SQL Server 2019 LocalDB",
        "Microsoft ODBC Driver 17 for SQL Server",
        "CanoScan LiDE 400 Scanner Driver",
        "IIS 10.0 Express",
        "Microsoft Visual Studio 2010 Tools for Office Runtime (x64)",
        # An unrelated app whose name begins with a tool name must not collapse
        # onto that tool. This is the false positive the change exists to stop.
        "Cursor 2024 Backup Utility",
        "Copilot 2 Helper Service",
        "Claude 3 Sync Agent",
    ],
)
def test_names_that_are_not_versioned_stay_whole(raw):
    assert _normalise_app_name(raw) == raw.strip().lower()


def test_a_leading_digit_is_not_a_version():
    """The pattern needs whitespace before the digit.

    Otherwise 1Password normalises to the empty string and matches either
    everything or nothing, depending which side of the comparison it lands on.
    """
    assert _normalise_app_name("1Password") == "1password"


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Stripping the version leaves a dangling separator behind.
        (
            "Microsoft Windows Desktop Runtime - 6.0.25 (x64)",
            "microsoft windows desktop runtime",
        ),
        (
            "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.51.36231",
            "microsoft visual c++ 2015-2022 redistributable (x86)",
        ),
        (
            "Azul Zulu JDK 21.42.19 (21.0.7), 64-bit",
            "azul zulu jdk 21.42.19 (21.0.7)",
        ),
    ],
)
def test_trailing_separators_are_removed(raw, expected):
    """A key ending in punctuation matches nothing and reads as a bug."""
    assert _normalise_app_name(raw) == expected


def test_every_version_of_one_product_shares_a_key():
    """The point of stripping the version at all.

    Ten Windows Desktop Runtime versions were installed across the tenant. They
    are one product and should key as one, which is the behaviour that must
    survive making the pattern stricter.
    """
    versions = [
        "Microsoft Windows Desktop Runtime - 6.0.25 (x64)",
        "Microsoft Windows Desktop Runtime - 8.0.11 (x64)",
        "Microsoft Windows Desktop Runtime - 8.0.16 (x86)",
        "Microsoft Windows Desktop Runtime - 9.0.18 (x64)",
    ]
    assert len({_normalise_app_name(v) for v in versions}) == 1


def test_distinct_products_do_not_share_a_key():
    """The complement, and the actual regression.

    Under the old pattern these four all became "microsoft".
    """
    products = [
        "Microsoft 365 Apps for business - en-us",
        "Microsoft SQL Server 2019 LocalDB",
        "Microsoft ODBC Driver 17 for SQL Server",
        "Microsoft Visual Studio 2010 Tools for Office Runtime (x64)",
    ]
    assert len({_normalise_app_name(p) for p in products}) == len(products)
