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


def test_export_pdf_is_reachable_from_every_page_that_offers_it():
    """The Overview and Evidence centre buttons carry data-act=evidence-print.
    The handler sat in budgetAction, which managedAction only enters for
    acts starting with b-, so both buttons did nothing."""
    head = HTML.split("async function managedAction(act, el) {", 1)[1][:600]
    assert "if (act === 'evidence-print') { window.print(); return; }" in head
    assert "if (act.startsWith('b-')) return budgetAction(act, el);" in head
    assert HTML.count('data-act="evidence-print"') == 2


def test_the_reporting_window_is_a_control_sent_on_every_read_that_takes_one():
    """Six reads accept hours and cache per window; the page sends the chosen
    window on each of them and on the two downloads, and labels derive from
    the same value, so no page reports a different 'now'."""
    assert "let HOURS = null;" in HTML
    assert "const hq = sep => HOURS ? (sep || '?') + 'hours=' + HOURS : '';" in HTML
    assert "fetch('/api/graph' + q + hq(q ? '&' : '?'))" in HTML
    assert HTML.count("fetch('/api/status' + hq())") == 1
    assert HTML.count("fetch('/api/paste-guard' + hq())") == 2
    assert HTML.count("fetch('/api/agentic' + hq())") == 2
    assert HTML.count("fetch('/api/register' + hq())") == 2
    assert HTML.count("fetch('/api/evidence' + hq())") == 1
    assert "href=\"/api/register?fmt=csv${hq('&')}\"" in HTML
    assert "href=\"/api/evidence?download=true${hq('&')}\"" in HTML
    assert "CFG.lookback_hours || 168" not in HTML.split("const hoursNow", 1)[1]
    assert "<select data-window" in HTML
    assert "const el = e.target.closest('[data-window]');" in HTML
    assert "[2160, '90 days']" in HTML  # the server's ceiling, le=24*90


def test_the_search_box_is_a_finder_everywhere():
    """It filtered the views that call match() and did nothing on the rest,
    which reads as broken. It still filters those, says so, and on every
    view offers pages, tools, devices, people and MCP servers to jump to."""
    assert 'id="qresults"' in HTML
    assert "function qMatches()" in HTML and "function qResults()" in HTML
    assert "render(); qResults(); };" in HTML
    for kind in ("'page'", "'tool'", "'device'", "'person'", "'mcp'"):
        assert "kind: " + kind in HTML, kind
    assert "#qresults{position:absolute" in CSS


def test_one_divider_under_the_pinned_list():
    assert ".nav-pinned+.nav-area-block{border-top:0}" in CSS


def test_the_posture_headline_needs_a_source_to_have_reported():
    """"Monitoring healthy" was derived from open personal accounts and
    coverage gaps alone, so a fleet nobody heard from showed healthy with
    100% coverage. It now needs the same status read the top-bar badge uses
    to show at least one source reporting."""
    assert "const silent = !S || !S.reporting;" in HTML
    assert "silent ? 'Nothing reporting' : attention ? 'Needs attention' : 'Monitoring healthy'" in HTML
    assert ".overview-executive.silent" in CSS


def test_every_time_label_follows_the_chosen_window():
    """A week hard-coded into a label under a 24-hour window is a lie."""
    body = HTML.split("</style>", 1)[1]
    assert "first seen this week" not in body
    assert "from=now-7d" not in body
    assert "'One bar per day for the last ' + fmtWindow(hoursNow())" in HTML
    assert "'&from=now-' + hoursNow() + 'h&to=now&kiosk'" in HTML


def test_system_health_is_called_that_everywhere_a_person_reads():
    assert '<span class="tenant-chev" aria-hidden="true">System health</span>' in HTML
    assert 'aria-label="Open System health">' in HTML
    assert "managed-estate switcher" not in HTML


def test_a_printed_page_says_which_estate_window_and_when():
    assert "stamp.className = 'print-head';" in HTML
    assert ".print-head{display:none}" in CSS
    assert ".print-head{display:block!important" in CSS
    assert "main#app .evidence-actions,main#app .view-meta" in CSS
