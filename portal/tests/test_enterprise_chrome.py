"""The enterprise shell: one named stylesheet behind the page-auth boundary,
and chrome that reports what the last read said rather than a fixed word.

Static assertions against the page source, like the rest of the suite: the
portal has no HTTP client dependency and the page is one file."""
from app import main

HTML = (main.STATIC / "index.html").read_text()
CSS = (main.STATIC / "enterprise.css").read_text()


def test_the_stylesheet_is_one_named_route_behind_page_auth():
    """Like the logo: a fixed path, never a caller-supplied one, and the same
    credentials that protect the document protect its presentation."""
    route = next(r for r in main.app.routes if getattr(r, "path", "") == "/enterprise.css")
    deps = [d.call for d in route.dependant.dependencies]
    assert main.require_page_auth in deps
    assert not any(getattr(r, "path", "").startswith("/static") for r in main.app.routes)
    resp = main.enterprise_css(None)
    assert str(resp.path) == str(main.STATIC / "enterprise.css")
    assert resp.media_type == "text/css"
    assert '<link rel="stylesheet" href="/enterprise.css">' in HTML


def test_pinned_destinations_are_stored_as_a_string():
    """A preference value is a string on both the portal and receiver models.
    An array was accepted by the browser copy and refused by the receiver
    with a 422 the client never reads, so pins vanished on reload in the one
    mode where preferences follow the person."""
    assert "prefSet(NAV_PIN_KEY, JSON.stringify(next))" in HTML
    assert "raw = JSON.parse(raw)" in HTML
    assert "prefSet(NAV_PIN_KEY, next)" not in HTML
    # The model this guards against regressing.
    assert main.PreferencesWrite.model_fields["preferences"].annotation == dict[str, str | None]


def test_the_estate_chrome_carries_no_fixed_claim():
    """'Managed estate · Production' and 'Monitoring active' were markup. A
    classic-mode portal with nothing reporting said both. They now come from
    the config the page already gates on and the status read it already
    makes, after every load."""
    for fixed in ("<span>Production</span>", "</i> Production<",
                  "<span>Monitoring active</span>", 'title="The portal is receiving estate data"'):
        assert fixed not in HTML, fixed
    assert "function showEstate()" in HTML
    assert "render();\n  showFreshness();\n  showEstate();" in HTML
    for word in ("'Monitoring active'", "'No sources reporting'", "'Data unavailable'",
                 "'Managed estate' : 'Standalone portal'"):
        assert word in HTML, word
    for cls in (".estate-dot.off", ".estate-dot.warn", ".trust-state.off", ".trust-state.warn"):
        assert cls in CSS, cls


def test_the_health_count_only_counts_checks_that_run():
    """'3/3 core checks passing' counted a literal true for the application
    row. The page rendering is the whole of that evidence, so it is a fact
    on the card, not a check in the score."""
    assert "const checks = [logFresh, !!r.registry_loaded];" in HTML
    assert "const checks = [true," not in HTML


def test_settings_no_longer_reads_diagnostics_it_does_not_render():
    """System health owns that read now; the Settings view had kept the fetch
    from when diagnostics were a tab there."""
    body = HTML.split("async function settings() {", 1)[1].split("\nasync function", 1)[0]
    assert "/api/diagnostics" not in body


def test_the_account_button_survives_a_phone_width():
    """Sign-out and change-password live only in the account menu now, so the
    button that opens it cannot be hidden with the rest of the top-bar
    detail at the narrowest width - only its label is."""
    narrow = CSS.split("@media(max-width:560px){", 1)[1].split("\n}", 1)[0]
    assert "#whowrap" not in narrow
    # Under an id, or the plain .account-copy{display:block} declared later
    # in the file wins the tie and the label stays.
    assert ".topbar #who .account-copy,.topbar #who .account-chevron{display:none}" in narrow


def test_the_estate_control_takes_the_organisations_name():
    """An admin names the estate once, under Settings and in the wizard;
    the control beneath the logo, the narrow top bar and the sign-in card
    all say it, and the fallback stays what the portal is."""
    assert main.SettingsWrite.model_fields["org_name"].annotation == (str | None)
    assert "const org = ((AUTH && AUTH.org_name) || '').trim();" in HTML
    assert "const name = org || kind;" in HTML
    assert "settingRow('org_name', 'Organisation name', 'Acme Ltd'," in HTML
    assert "function orgSettings()" in HTML
    assert "body = orgSettings() + mailSettings() + alertingSettings();" in HTML
    assert "<h4>Name the estate</h4>" in HTML
    assert "Sign in to ${esc(org)}." in HTML
    assert "if (key === 'org_name' && AUTH) { AUTH.org_name = val.trim(); showEstate(); }" in HTML


def test_the_pin_button_does_not_wear_the_current_page_marker():
    """nav button.on:before is the bar that marks the page you are on. The
    pin button is a nav button too, and while it said .on for 'pinned' it
    grew the same bar beside its star."""
    assert "class=\"nav-pin ${isPinned ? 'pinned' : ''}\"" in HTML
    assert ".nav-pin.on" not in CSS
    assert ".nav-pin.pinned" in CSS
