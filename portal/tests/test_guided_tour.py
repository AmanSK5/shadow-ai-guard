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
    known = _nav_views()
    assert known, "NAV did not parse; this test is guarding nothing"
    used = set(re.findall(r"view: '([a-z-]+)'", TOURS))
    assert used, "no steps parsed; this test is guarding nothing"
    assert used <= known, f"tour steps point at unknown views: {used - known}"


def test_every_nav_target_is_a_real_section():
    """The click steps drive the sidebar, so they carry section ids rather
    than view ids - a different list, and just as easy to rename."""
    nav = INDEX.split("const NAV = [", 1)[1].split("\n];", 1)[0]
    sections = set(re.findall(r"\{id:'([a-z]+)'", nav))
    assert sections, "NAV sections did not parse"
    used = set(re.findall(r"""sel: '\[data-s="([a-z]+)"\]'""", TOURS))
    assert used, "no nav steps parsed"
    assert used <= sections, f"unknown nav sections: {used - sections}"


def test_every_hooked_element_is_still_rendered():
    """data-tour hooks exist only for the tour, so nothing else fails when
    one is dropped from a view being rewritten."""
    for hook in set(re.findall(r"""sel: '\[data-tour="([a-z]+)"\]'""", TOURS)):
        assert f'data-tour="{hook}"' in INDEX, f"nothing renders data-tour={hook}"


def test_every_id_target_is_still_rendered():
    for el in set(re.findall(r"sel: '#([a-z-]+)'", TOURS)):
        assert f'id="{el}"' in INDEX, f"nothing renders #{el}"


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
    for role in ("admin", "viewer"):
        assert f"p['tour.seen.{role}']" in INDEX


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
    assert "'end tour'" in card, "the way out has to say what it does"
