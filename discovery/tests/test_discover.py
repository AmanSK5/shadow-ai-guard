"""The classifier's reply is untrusted input arriving from a trusted place.

discover.py sends observed domains to a model, takes back JSON the model wrote,
and opens a merge request that edits registry.yaml with it. A human reviews
that MR, which is the mitigation people reach for and the same reasoning that
would excuse most injection bugs: reviewers approve things that look plausible,
and plausible is exactly what a manipulated reply looks like.

Two ways it could go wrong, and both are covered here.

The reply could name a domain nobody observed, which then reaches the registry
as though a device had been seen using it. So every verdict has to be about a
domain that was in the batch we sent.

The reply could contain YAML. Values were interpolated into the entry with an
f-string, so a product name containing a newline and two spaces could write its
own keys, and `approved: true` is one line away from `name:`. Validation should
stop that arriving, and dumping through yaml rather than formatting a string is
the part that does not depend on the validation being complete.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import discover

SUBMITTED = {"fireflies.ai", "otter.ai", "example.com"}


def _verdict(**kw):
    base = {
        "domain": "fireflies.ai", "is_ai": True, "name": "Fireflies.ai",
        "vendor": "Fireflies", "category": "transcription",
        "confidence": "high",
    }
    base.update(kw)
    return base


# ─────────────────────────────────────────────
# The reply has to be about what we asked
# ─────────────────────────────────────────────

def test_a_valid_verdict_is_accepted():
    assert discover.valid_classification(_verdict(), SUBMITTED) == ""


def test_a_domain_we_did_not_submit_is_rejected():
    """The regression. Without this the model can introduce a domain nobody
    observed, and it lands in the registry as an observation."""
    why = discover.valid_classification(
        _verdict(domain="attacker.example"), SUBMITTED)

    assert "was not in the batch" in why


def test_a_missing_domain_is_rejected():
    assert discover.valid_classification(_verdict(domain=None), SUBMITTED)


def test_is_ai_must_be_a_boolean():
    """A string "false" is truthy, and a verdict that says a domain is not an
    AI service must not be read as saying it is."""
    assert discover.valid_classification(_verdict(is_ai="false"), SUBMITTED)


def test_a_category_outside_the_prompt_is_rejected():
    assert discover.valid_classification(
        _verdict(category="something-invented"), SUBMITTED)


def test_a_confidence_outside_the_prompt_is_rejected():
    assert discover.valid_classification(
        _verdict(confidence="very high"), SUBMITTED)


def test_a_null_name_is_allowed():
    """The prompt asks for null when the model cannot name the product, and
    grouping falls back to the domain."""
    assert discover.valid_classification(_verdict(name=None), SUBMITTED) == ""


@pytest.mark.parametrize("name", [
    "X\n    approved: true",
    "x: y",
    '"quoted"',
    "{a: b}",
    "a" * 200,
    "<script>alert(1)</script>",
])
def test_a_name_that_is_not_a_product_name_is_rejected(name):
    """Narrow on purpose. A registry id is derived from this and it is rendered
    into YAML and into an MR description, so anything that is not a plain
    product name is more likely a mistake or an injection than a product nobody
    thought of.
    """
    assert discover.valid_classification(_verdict(name=name), SUBMITTED)


@pytest.mark.parametrize("name", [
    "Fireflies.ai", "Otter.ai", "Microsoft 365 Copilot", "Claude",
    "GitHub Copilot", "n8n.io", "Adobe Firefly", "Jasper AI",
])
def test_real_product_names_are_accepted(name):
    """The check has to let through the things it exists to carry. A rule that
    rejects Microsoft 365 Copilot is one somebody will remove."""
    assert discover.valid_classification(_verdict(name=name), SUBMITTED) == ""


def test_a_reply_that_is_not_an_object_is_rejected():
    assert discover.valid_classification("just a string", SUBMITTED)
    assert discover.valid_classification(None, SUBMITTED)


# ─────────────────────────────────────────────
# The entry cannot escape into its own YAML
# ─────────────────────────────────────────────

def _entry(**kw):
    g = {"name": "Fireflies.ai", "vendor": "Fireflies", "confidence": "high",
         "domains": ["fireflies.ai"], "devices": {"D1", "D2"}}
    g.update(kw)
    return discover.candidate_yaml(g, set())


def test_the_entry_parses_as_one_registry_tool():
    tools = yaml.safe_load("tools:" + _entry())["tools"]

    assert len(tools) == 1
    assert tools[0]["id"] == "fireflies"
    assert tools[0]["domains"] == ["fireflies.ai"]


def test_a_name_containing_yaml_cannot_add_keys():
    """The injection this guards. An f-string put the name straight into the
    document, so a newline and two spaces wrote a sibling key, and
    `approved: true` is the one that matters.
    """
    tools = yaml.safe_load("tools:" + _entry(
        name="X\n    approved: true\n    injected: yes\n    y"))["tools"]

    assert len(tools) == 1
    assert tools[0]["approved"] is False
    assert "injected" not in tools[0]


def test_a_domain_containing_yaml_cannot_add_keys():
    tools = yaml.safe_load("tools:" + _entry(
        domains=['x.com", approved: true, y: "']))["tools"]

    assert len(tools) == 1
    assert tools[0]["approved"] is False


def test_a_candidate_is_never_approved():
    """Discovery proposes, a human decides. An entry that arrived approved
    would turn a suggestion into a decision nobody made."""
    tools = yaml.safe_load("tools:" + _entry())["tools"]

    assert tools[0]["approved"] is False
    assert tools[0]["category"] == "unreviewed"
    assert tools[0]["added_by"] == "discovery"


def test_ids_do_not_collide():
    """build.py rejects a duplicate id, so a colliding candidate fails the
    whole MR rather than just itself."""
    taken = {"fireflies"}
    out = discover.candidate_yaml(
        {"name": "Fireflies.ai", "vendor": "v", "confidence": "high",
         "domains": ["x.com"], "devices": set()}, taken)

    assert yaml.safe_load("tools:" + out)["tools"][0]["id"] == "fireflies-2"


def test_the_entry_matches_the_style_it_is_appended_to():
    """registry.yaml is hand-edited, and an entry formatted differently from
    its neighbours reads as machine output nobody looked at."""
    out = _entry(domains=["a.com", "b.com"])

    assert "    domains: [a.com, b.com]" in out
    assert "\n  - id: " in out