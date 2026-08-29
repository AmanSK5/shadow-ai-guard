"""Widget forms, and the charts they draw.

A form picker is the one feature here whose failure mode is a confident
picture of the wrong thing, so what these hold is the restraint: only
widgets whose data has a second honest reading may offer a choice, and
the default is always the form the widget already had.

The chart code itself is hand-written SVG - this portal ships no external
script and a chart library would be the first - so the properties worth
pinning are the ones a rewrite would quietly drop.
"""

import os
import re
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

from app import main

INDEX = (Path(__file__).parent.parent / "app" / "static"
         / "index.html").read_text()

FORMS = INDEX.split("const WIDGET_FORMS = {", 1)[1].split("\n};", 1)[0]


def _forms() -> dict:
    out = {}
    for kind, body in re.findall(r"^  ([a-z_]+): \[(.*?)\],", FORMS, re.M):
        out[kind] = re.findall(r"'([a-z]+)'", body)
    return out


def test_only_widgets_with_a_second_reading_offer_one():
    """The restraint is the feature. A row of headline numbers is a row of
    headline numbers; a list of recent findings is a log. Offering a
    picker on those would make misleading charts of the estate the main
    thing this shipped."""
    assert set(_forms()) == {"top_tools", "detection_coverage"}


def test_no_widget_offers_a_pie():
    """Pie is part-to-whole with two or three slices. Tools compared by
    device count is magnitude across seven, and coverage is a ratio
    against a limit - neither is a pie, and drawing one would be harder
    to read than what these already were."""
    for forms in _forms().values():
        assert "pie" not in forms
        assert "donut" not in forms


def test_the_default_is_the_form_the_widget_already_had():
    """Nobody's overview changes shape because this shipped."""
    assert _forms()["top_tools"][0] == "table"
    assert _forms()["detection_coverage"][0] == "dots"


def test_every_offered_form_is_actually_drawn():
    """A form in the list with no branch behind it is a button that
    silently does nothing."""
    for kind, forms in _forms().items():
        for form in forms[1:]:
            assert f"widgetForm('{kind}') === '{form}'" in INDEX, \
                f"{kind} offers {form} with nothing drawing it"


def test_an_unknown_saved_form_falls_back():
    """Forms get renamed and dropped; a stale preference must not blank a
    card on somebody who has not signed in since."""
    fn = INDEX.split("function widgetForm(kind) {", 1)[1].split("\n}", 1)[0]
    assert "indexOf(saved) >= 0 ? saved : forms[0]" in fn


def test_the_new_trend_widget_is_registered_both_sides():
    """The catalogue is what Settings offers and what the parser accepts;
    a widget drawn but unregistered is one the server calls an error."""
    assert "activity_trend" in main.KNOWN_WIDGETS
    assert "activity_trend: () =>" in INDEX


def test_charts_use_their_own_colour_tokens():
    """--acc is interface chrome and sits below the chroma floor a fill
    needs: it reads grey once it is an area rather than a 1px border."""
    assert "--chart:#0a7ea4" in INDEX, "light chart token missing"
    assert "--chart:#2b9ec4" in INDEX, "dark chart token missing"
    # Its own step per mode, not one value flipped for both.
    assert INDEX.count("--chart:#") == 2


def test_two_series_carry_a_legend():
    """Identity is never colour alone."""
    trend = INDEX.split("function trendChart(", 1)[1].split("\n}", 1)[0]
    assert 'class="clegend"' in trend
    assert trend.count("<span><i") == 2


def test_a_bar_is_rounded_only_at_its_data_end():
    """Rounding the baseline end as well detaches the bar from the edge it
    is measured from."""
    css = INDEX.split(".barrow .bf {", 1)[1].split("}", 1)[0]
    assert "border-radius: 2px 4px 4px 2px" in css


def test_a_bar_row_opens_the_same_thing_its_table_row_does():
    """Switching how a widget draws must not take a way in with it."""
    fn = INDEX.split("function barRows(", 1)[1].split("\n}", 1)[0]
    assert 'data-open="${esc(open)}"' in fn
    assert "barRows(rows.map" in INDEX and "'devices', 'tool')" in INDEX


def test_the_bars_keep_one_left_edge():
    """A label column sized to the longest name moves the edge the bars
    are compared against."""
    css = INDEX.split(".barrow .bl {", 1)[1].split("}", 1)[0]
    assert "flex: 0 0 34%" in css


def test_tooltips_are_written_as_text_not_markup():
    """Tool names come from findings, and the one thing this page will
    not do is let a finding's own text become part of a program."""
    fn = INDEX.split("function tipShow(", 1)[1].split("\n}", 1)[0]
    assert "textContent" in fn
    assert "innerHTML" not in fn


def test_the_meter_fill_can_actually_render():
    """A span inside the track is inline, and an inline box takes neither
    a percentage width nor a percentage height - every meter drew as an
    empty track whatever the ratio was."""
    css = INDEX.split(".meterrow .fill {", 1)[1].split("}", 1)[0]
    assert "display: block" in css
