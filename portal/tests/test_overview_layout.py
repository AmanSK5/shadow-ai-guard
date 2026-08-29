"""Arranging the overview: what each person keeps, and what they cannot.

A saved layout is a second copy of a list the deployment also owns, which
is the whole risk: an arrangement saved today must not decide what a
deployment shows a year from now. These hold the merge rules that keep a
saved order from becoming a filter on widgets nobody had yet.
"""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

INDEX = (Path(__file__).parent.parent / "app" / "static"
         / "index.html").read_text()

PICK = INDEX.split("function overviewWidgets() {", 1)[1].split("\n}", 1)[0]
DRAW = INDEX.split("function overview() {", 1)[1].split("\nfunction ", 1)[0]


def test_a_widget_the_saved_order_never_mentioned_still_appears():
    """The deployment's list stays the source of what CAN appear. Without
    this, turning a widget on would be invisible to everyone who had ever
    saved an arrangement - which is everyone who used the feature."""
    assert "by.forEach(w => out.push(w))" in PICK


def test_a_saved_layout_cannot_resurrect_a_widget_that_is_gone():
    """The order is walked against the live list, never the other way."""
    assert "if (by.has(k))" in PICK
    assert "hidden.filter(k => out.some(w => wKey(w) === k))" in PICK


def test_an_unparseable_layout_is_ignored_rather_than_fatal():
    """It is one JSON string in a preferences row; a bad one must cost a
    default layout, not the page."""
    assert "catch (e)" in PICK and "JSON.parse(pref('overview.layout'" in PICK


def test_reset_deletes_rather_than_storing_todays_default():
    """A stored copy of the default stops tracking the default."""
    reset = INDEX.split("if (act === 'ov-reset') {", 1)[1].split("\n  }", 1)[0]
    assert "prefSet('overview.layout', null)" in reset


def test_the_grid_span_is_lifted_onto_the_wrapper():
    """The width class lives on the widget's own card, which is no longer
    the grid's direct child - every card sized to its content instead of
    tiling."""
    assert "(w4|w6|w12)" in DRAW


def test_the_arrangement_controls_ride_the_tab_row():
    """Not a line of copy under the heading explaining what a button does
    - the button explains itself once it is open, and the affordance
    belongs with the page furniture."""
    assert "function overviewTools()" in INDEX
    assert "view === 'overview' && !OVEDIT ? overviewTools()" in INDEX
    assert "Your own arrangement" not in INDEX
    # And it stands down while arranging: the edit toolbar is the control
    # surface then.
    tools = INDEX.split("function overviewTools() {", 1)[1].split("\n}", 1)[0]
    assert "data-act=\"ov-edit\"" in tools


def test_arranging_your_own_view_cannot_change_anyone_elses():
    """Which widgets a deployment offers is already a Settings control -
    checkboxes, a save, a page somebody went to on purpose. A one-click
    copy of it inside a personal layout editor, a button away from
    "cancel", is the same power with none of the deliberation: four admins
    and one misclick decides what ten people see."""
    assert "ov-default" not in INDEX
    assert "data-act=\"ov-save\"" in DRAW


def test_hiding_is_not_deleting():
    """Hidden widgets stay in the saved order and come back."""
    assert "data-act=\"ov-showall\"" in INDEX
    show = INDEX.split("if (act === 'ov-showall') {", 1)[1].split("\n  }", 1)[0]
    assert "hidden: []" in show


def test_a_cards_own_controls_step_aside_while_arranging():
    """The form switch sits exactly where the hide button needs to be."""
    assert ".editing .wform { display: none; }" in INDEX


# ---- sizes -----------------------------------------------------------

SIZES = INDEX.split("const WIDGET_SIZES = {", 1)[1].split("\n};", 1)[0]


def _sizes() -> dict:
    import re as _re
    return {k: _re.findall(r"'(w\d+)'", v)
            for k, v in _re.findall(r"^  ([a-z_]+): \[(.*?)\],", SIZES, _re.M)}


def test_every_offered_size_is_a_real_grid_width():
    """The three widths the grid actually has. A fourth would be a class
    with no CSS behind it, which sizes the card to its content."""
    for kind, sizes in _sizes().items():
        assert sizes, kind
        assert set(sizes) <= {"w4", "w6", "w12"}, kind


def test_the_widgets_kept_off_the_smallest_size_are_the_ones_that_break():
    """Established by rendering each of them at 328px and looking. The
    review queue's Add to registry / Dismiss buttons overflow the card
    with Dismiss clipped mid-word, and a four-column table of people
    wraps every date onto three lines. Everything else holds, including
    the KPI row, which simply wraps to two columns."""
    narrow = {k for k, v in _sizes().items() if "w4" in v}
    assert "recent_personal_accounts" not in narrow
    assert "review_queue" not in narrow
    assert "grafana" not in narrow, "a cross-origin frame cannot be checked"
    assert narrow == {"stat_row", "top_tools", "activity_trend",
                      "budget_spend", "detection_coverage", "source_health",
                      "paste_guard"}


def test_a_saved_size_the_widget_no_longer_offers_falls_back():
    """Sizes get withdrawn when a widget's content changes; a stored one
    must not size a card to something nobody checked it at."""
    assert "can.indexOf(sizes[k]) >= 0 ? sizes[k]" in DRAW


def test_the_bar_label_column_stops_growing_on_a_wide_card():
    """At full width 34% is 330px of gap between a six-letter name and its
    bar."""
    css = INDEX.split(".barrow .bl {", 1)[1].split("}", 1)[0]
    assert "max-width: 190px" in css


def test_the_trend_chart_fills_its_card_at_any_size():
    """A fixed height with the default preserveAspectRatio scales the
    whole chart uniformly and centres it, so a large card got a small
    chart with empty margins either side."""
    trend = INDEX.split("function trendChart(", 1)[1].split("\nconst WIDGETS", 1)[0]
    assert 'preserveAspectRatio="none"' in trend
    # Which distorts everything that is not a stroked path, so the labels
    # live outside the SVG and the strokes are told not to scale.
    assert "<text" not in trend
    assert "vector-effect: non-scaling-stroke" in INDEX
    # And it keeps the class its fills come from - without it the
    # transparent hit areas render as a black box over the plot.
    assert '<svg class="chart"' in trend


def test_a_slot_is_a_column_that_can_hold_more_than_one_card():
    """Three goes at the same problem. Cards at their own height leave
    ragged row bottoms; cards stretched to the row fill it but hollow the
    short one out - the spend tile beside the review queue became 480px of
    border around 200px of content, which reads as a card that failed to
    load. Neither is fixable on its own, because the real cause is one
    short card being asked to fill a tall row alone.

    A slot is a column instead. Rows stay flush, and a card that would be
    stretched too far gets a second card stacked under it rather than
    growing to cover the gap."""
    col = INDEX.split(".gitem { display: flex;", 1)[1].split("}", 1)[0]
    assert "flex-direction: column" in col
    # The excess lands on the last card, so a stack grows downwards from a
    # fixed top rather than every card in it stretching a little.
    assert ".gcard:last-child { flex: 1 1 auto; }" in INDEX


def test_stacking_is_a_drag_and_only_unstacking_is_a_button():
    """A button could only ever stack a card with the one before it. A
    drop onto any card stacks with that one, which is the same gesture
    people already use to move a card - and it takes a control away
    rather than adding one."""
    assert "data-act=\"w-unstack\"" in DRAW
    assert "w-stack" not in INDEX.replace("w-unstack", "")
    assert "function dropZone(" in INDEX


def test_a_drop_beside_a_stack_never_lands_inside_it():
    """The anchor is the column, not the card under the pointer: without
    that, dropping on the lower half of a stack's head inserts between it
    and its own followers, and they silently join the new card instead."""
    drop = INDEX.split("app.addEventListener('drop', e => {", 1)[1].split(
        "\n});", 1)[0]
    assert "colKeys(it)" in drop
    assert "rest[0]" in drop and "rest[rest.length - 1]" in drop


def test_lifting_the_head_of_a_stack_promotes_the_next_card():
    """Otherwise its followers attach themselves to whatever column
    happened to precede them."""
    drop = INDEX.split("app.addEventListener('drop', e => {", 1)[1].split(
        "\n});", 1)[0]
    # From the DRAGGED card's column. Reading the drop target's promoted
    # nothing, and the orphaned follower joined whatever column it landed
    # beside instead.
    assert "fromCol[0] === from && fromCol.length > 1" in drop
    assert "colKeys(fromCard)" in drop


def test_a_stacked_card_is_not_offered_a_width():
    """The column takes its width from the card at its head, so a width on
    a stacked card would be a control that does nothing."""
    assert "(!isStacked && can.length > 1)" in DRAW


def test_the_card_is_the_drag_unit_not_the_column():
    """Dragging a whole column would make a stack impossible to undo by
    dragging."""
    assert ".gcard[draggable]" in INDEX
    assert ".gitem[draggable]" not in INDEX


def test_a_stack_of_a_widget_that_is_gone_is_dropped():
    assert "stacked.filter(k => out.some(w => wKey(w) === k))" in PICK


def test_the_headline_tiles_fit_one_row():
    """Seven tiles into six tracks left five empty cells on a second row,
    which in edit mode reads as a card that failed to fill its slot."""
    assert "repeat(auto-fit,minmax(120px,1fr))" in INDEX


def test_the_headline_row_has_no_stray_top_margin():
    """It is a <dl>, and the rule only ever set margin-bottom - so the
    browser's own 1em top margin sat above it, unasked for, everywhere. It
    is also where the edit controls ended up, outside the outlined card,
    which is what made them look clipped."""
    css = INDEX.split(".stats{", 1)[1].split("}", 1)[0]
    assert "margin:0 0 20px" in css


def test_a_card_with_no_title_gets_a_strip_for_its_controls():
    """Every other card has a title row for them to sit in. Without this
    they land on top of a tile, or in whatever margin happens to be
    above."""
    assert ".editing .gcard.notitle > .stats { margin-top: 38px; }" in INDEX


def test_the_outline_is_drawn_on_the_card_not_the_widget_inside_it():
    """The wrapper holds the controls, so outlining the widget drew a box
    that excluded them - on a card whose controls sit in a strip above the
    content, they landed outside the card they belong to. For every other
    card the two boxes are the same, so nothing else moves."""
    assert ".editing .gcard { outline: 1px dashed var(--bd);" in INDEX
    assert ".editing .gcard > .wcard, .editing .gcard > .stats {\n  outline:" \
        not in INDEX


def test_a_titleless_card_is_named_while_arranging():
    """Every other card has an <h3> for the edit controls to sit beside.
    Without one they float in a strip attached to nothing, which reads as
    a control that has come loose rather than one belonging to the card
    under it."""
    assert "const WIDGET_TITLES = {stat_row: 'Headline numbers'};" in INDEX
    assert "editing && !titled" in DRAW
    assert "body.indexOf('<h3') >= 0" in DRAW


def test_the_strip_clears_the_outline_above_and_the_content_below():
    """A 23px control in a 28px strip left its bottom edge a pixel INSIDE
    the first tile - touching the widget it sits above. 38px holds it with
    11px to the outline and 7px to the tile."""
    assert ".editing .gcard.notitle > .stats { margin-top: 38px; }" in INDEX
    assert ".gcard.notitle .gtools { top: 8px; }" in INDEX


def test_every_card_insets_its_controls_the_same():
    """Tuning the inset per card so each aligns with its own content puts
    them at different offsets - tiles run to the card edge, a titled
    card's content sits inside 17px of padding - and the control clusters
    then fail to line up with each other down the page, which is the
    alignment somebody actually reads."""
    assert "gcard${titled ? '' : ' notitle'}" in DRAW
    # Only the vertical is tuned for the titleless case; the horizontal
    # comes from the shared rule.
    assert "right: 0" not in INDEX.split(".gcard.notitle .gtools {", 1)[1] \
        .split("}", 1)[0]
