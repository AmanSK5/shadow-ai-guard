"""The guided tour: what it points at, and what tears it down.

The suite's usual direct-call harness cannot drive a walkthrough that
lives in the browser, so what is held here is the part that rots. A tour
is a second description of the portal, written beside it and read by
nobody until somebody new signs in - so a step that points at a view
which was renamed, or an element that stopped being rendered, is wrong
for exactly as long as it takes a new colleague to find it. These read
the page's own NAV and markup and refuse a step that no longer lands.
"""

import os
import re
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

INDEX = (Path(__file__).parent.parent / "app" / "static"
         / "index.html").read_text()

# The tour definitions, from `const TOURS = {` to the line that closes it.
TOURS = INDEX.split("const TOURS = {", 1)[1].split("\n};", 1)[0]


def _nav_views() -> set:
    """Every view id the sidebar can reach, read from NAV itself."""
    nav = INDEX.split("const NAV = [", 1)[1].split("\n];", 1)[0]
    return set(re.findall(r"\['([a-z-]+)',", nav))


def test_every_step_points_at_a_view_that_exists():
    """A renamed view leaves the tour navigating to a blank page, and the
    person it was written for is the one who finds out."""
    # System health is intentionally reached from the estate control rather
    # than a sidebar destination, but is still a real tour view.
    known = _nav_views() | {"diagnostics"}
    assert known, "NAV did not parse; this test is guarding nothing"
    used = set(re.findall(r"view: '([a-z-]+)'", TOURS))
    assert used, "no steps parsed; this test is guarding nothing"
    assert used <= known, f"tour steps point at unknown views: {used - known}"


def test_the_tour_points_at_the_current_navigation_model():
    """The sidebar moved from a flat section list to expandable work areas.
    The tour has to describe that model rather than retain a hidden dependency
    on the old data-s navigation buttons."""
    assert 'sel: \'[data-area="discovery"]\'' in TOURS
    assert 'data-area="${area.id}"' in INDEX


def test_every_hooked_element_is_still_rendered():
    """data-tour hooks exist only for the tour, so nothing else fails when
    one is dropped from a view being rewritten."""
    for hook in set(re.findall(r"""sel: '\[data-tour="([a-z]+)"\]'""", TOURS)):
        assert f'data-tour="{hook}"' in INDEX, f"nothing renders data-tour={hook}"


def test_every_id_target_is_still_rendered():
    for el in set(re.findall(r"sel: '#([a-z-]+)'", TOURS)):
        assert f'id="{el}"' in INDEX, f"nothing renders #{el}"


def test_every_class_target_is_still_rendered():
    """The summary cards are semantic tour targets. A visual redesign that
    removes one should fail here rather than leave an un-aimed tour card."""
    for cls in set(re.findall(r"sel: '\\.([a-z-]+)'", TOURS)):
        assert f'class="{cls}' in INDEX or f' {cls}"' in INDEX, \
            f"nothing renders .{cls}"


def test_the_tour_covers_the_current_operating_path():
    """The tour is an orientation, not a page-by-page inventory. It must
    cover the current executive, discovery, governance, evidence, settings
    and system-health journey for both roles."""
    expected = {"overview", "setup", "devices", "personal", "register",
                "iso", "budget", "agentic", "fleet", "settings", "diagnostics"}
    for role in ("admin", "viewer"):
        block = TOURS.split(role + ": [", 1)[1].split("\n  ],", 1)[0]
        reached = set(re.findall(r"view: '([a-z-]+)'", block))
        missing = expected - reached
        assert not missing, f"{role} tour never reaches: {sorted(missing)}"


def test_both_roles_walk_the_same_number_of_steps():
    """The two tours are deliberately separate copy - a viewer is told who
    to ask where an admin is told what to change - but they describe one
    product. A step added to one and forgotten in the other is how the
    read-only account ends up with a shorter, quietly different tool."""
    counts = {}
    for role in ("admin", "viewer"):
        block = TOURS.split(role + ": [", 1)[1].split("\n  ],", 1)[0]
        counts[role] = block.count("{title:") + block.count("{view:")
    assert counts["admin"] == counts["viewer"], counts
    assert counts["admin"] >= 10, f"steps went missing: {counts}"


def test_both_roles_have_a_tour():
    """An admin and a viewer are looking at different products, and a
    missing role would silently fall back to the other one's."""
    assert re.search(r"^  admin: \[", TOURS, re.M)
    assert re.search(r"^  viewer: \[", TOURS, re.M)


def test_the_tour_is_torn_down_when_the_session_goes():
    """It outlived its session once: the overlay sat on the login screen
    with a stale card over the sign-in button, which reads as a portal
    that failed to load."""
    show_login = INDEX.split("function showLogin(msg) {", 1)[1][:800]
    assert "tourAbort()" in show_login


def test_finishing_the_wizard_offers_rather_than_springs():
    """A first-run deployment opens on the wizard and the tour holds off;
    finishing it is the moment orientation becomes useful, and somebody
    who has just worked through it has earned a question."""
    finish = INDEX.split("if (act === 'wiz-finish') {", 1)[1].split(
        "\n  }", 1)[0]
    assert "TOUR_AFTER_WIZARD" in finish
    assert "TOURTRIED = true" in finish, \
        "without claiming the attempt, the tour races the offer"


def test_the_wizard_still_takes_precedence_on_a_first_run():
    maybe = INDEX.split("async function maybeTour() {", 1)[1].split(
        "\n}", 1)[0]
    assert "view === 'wizard'" in maybe


def test_progress_is_kept_per_role():
    """Which is what makes a role change detectable without asking: the
    other role's key is present and this one's is not."""
    assert "'tour.seen.' + tourRole()" in INDEX
    assert "TOUR_ROLE_CHANGED" in INDEX
    # Both roles are read, whichever store they come from - the point is
    # that one role's progress never answers for the other's.
    progress = INDEX.split("async function tourProgress() {", 1)[1].split(
        "\n}", 1)[0]
    for role in ("admin", "viewer"):
        assert f"tour.seen.{role}" in progress


def test_every_step_carries_a_way_forward():
    """The click steps had none, so a click that would not land left
    leaving as the only way on."""
    card = INDEX.split(
        "const last = TOUR.i === TOUR.steps.length - 1;", 1)[1].split(
            "card.classList.remove", 1)[0]
    assert 'data-tour-act="next"' in card
    # The old shape suppressed the whole button on a click step. It now
    # only picks the button's class, so match the suppression itself
    # rather than the expression, which legitimately still appears.
    assert "st.click ? '' : `<button" not in card, \
        "a step that asks for a click must still offer next"
    assert "st.click ? '' : 'pri'" in card, \
        "next should be secondary on a click step, not absent"
    assert "'End tour'" in card, "the way out has to say what it does"


def test_a_described_control_cannot_be_used_during_the_tour():
    """The shade and the ring both pass clicks through, deliberately, so a
    step that asks somebody to press a real control can let them. The cost
    was that every spotlighted control stayed fully live: Edit opened the
    arranger behind the card, the corporate domains field took typing in
    the middle of a walkthrough, and Refresh reloaded the page on the last
    step. inert rather than pointer-events, because the keyboard reaches a
    focusable field whatever the mouse is allowed to do."""
    assert "if (el && !st.click) { el.inert = true; TOUR.inert = el; }" in INDEX


def test_the_frozen_control_is_always_released():
    """#refresh and the account menu live outside #app and survive every
    render, so a step that froze one and never released it would leave the
    topbar dead for the rest of the session - long after the tour ended."""
    assert "function tourRelease()" in INDEX
    end = INDEX.split("async function tourEnd(", 1)[1][:300]
    assert "tourRelease()" in end, "ending the tour has to release it"
    abort = INDEX.split("function tourAbort()", 1)[1][:300]
    assert "tourRelease()" in abort, "a session going away has to release it"
    show = INDEX.split("async function tourShow()", 1)[1][:1400]
    assert "tourRelease()" in show, "each step has to release the last one"


def test_leaving_the_tour_early_says_where_it_lives():
    """Somebody who ends the tour on step two never reaches the last step,
    which is the only place that says the tour can be taken again."""
    assert '<dialog id="tourdlg"' in INDEX
    assert "if (!done) tourDoneShow();" in INDEX
    assert "Settings &rsaquo; Getting started" in INDEX


def test_the_tour_reaches_every_section_of_the_nav():
    """The tour is the only description of the whole product, and a section
    it never visits is one a new colleague does not know exists. Budget and
    Fleet went missing from the first enterprise tour for exactly that
    reason. Sections are the NAV list the work areas are built from; a
    section counts as reached when one of its views is a step."""
    nav = INDEX.split("const NAV = [", 1)[1].split("\n];", 1)[0]
    sections = {}
    for sec in re.finditer(r"\{id:'([a-z]+)'.*?items:\[(.*?)\]\}", nav, re.S):
        sections[sec.group(1)] = set(re.findall(r"\['([a-z-]+)'", sec.group(2)))
    assert len(sections) >= 8, sections
    for role in ("admin", "viewer"):
        block = TOURS.split(role + ": [", 1)[1].split("\n  ],", 1)[0]
        reached = set(re.findall(r"view: '([a-z-]+)'", block))
        missing = sorted(sid for sid, views in sections.items() if not views & reached)
        assert not missing, f"{role} tour never reaches: {missing}"


def test_a_step_that_only_applies_in_login_mode_says_so():
    """The account control exists only when somebody signed in. A tour that
    pointed at it on a no-login deployment dimmed the page to frame nothing;
    the step now carries its own condition and tourStart filters on it."""
    assert "sel: '#who', when: () => !!(AUTH && AUTH.mode === 'login' && AUTH.username)" in TOURS
    assert "TOURS[role].filter(st => !st.when || st.when())" in INDEX
