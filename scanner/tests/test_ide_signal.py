"""Installed versus used, for products that are an editor first.

Cursor and Windsurf/Devin Desktop are VS Code forks. Finding one on a laptop
proves an editor is installed; it does not prove anyone sent code to a model.
Every other tool in the registry has no purpose except its AI, so presence is
use and nothing about it changes - the tests here pin both halves, because
the risk of this feature is not that it under-reports IDE forks, it is that
it quietly starts under-reporting everything else.
"""

from ai_guard.registry import AIService
from ai_guard.scanners.base import (DetectionSource, Finding, classify_signal)

IDE = AIService(
    name="Windsurf / Devin (Cognition)", vendor="Cognition", category="coding",
    risk_tier="high", id="codeium",
    domains=["windsurf.com", "server.codeium.com", "api.devin.ai"],
    form="ide", inference_domains=["server.codeium.com", "api.devin.ai"],
)
# No form: an assistant whose only reason to exist is the model.
PLAIN = AIService(
    name="Claude", vendor="Anthropic", category="assistant", risk_tier="high",
    id="claude", domains=["claude.ai"],
)


def test_the_completion_backend_is_use_and_the_marketing_host_is_not():
    """The distinction the whole feature rests on. An editor reaches its
    update, licence and telemetry hosts on launch with the AI untouched, so
    a hit there proves the product exists and nothing more."""
    assert IDE.domain_signal("server.codeium.com") == "active"
    assert IDE.domain_signal("api.devin.ai") == "active"
    assert IDE.domain_signal("windsurf.com") == "ambient"
    assert IDE.domain_signal("codeium.com") == "ambient"


def test_a_subdomain_of_an_inference_host_still_counts():
    assert IDE.domain_signal("eu.api.devin.ai") == "active"
    # But a lookalike suffix must not: notdevin.ai is not devin.ai.
    assert IDE.domain_signal("xapi.devin.ai.evil.example") == "ambient"


def test_inventory_of_an_editor_is_installed_not_used():
    for src in (DetectionSource.INTUNE_APP, DetectionSource.JAMF_APP):
        assert classify_signal(IDE, src) == "ambient", src


def test_an_account_or_an_mcp_config_is_use_even_for_an_editor():
    """These are not "the binary exists" - they are someone having signed in
    or wired an agent up, which no amount of merely having an editor does."""
    for src in (DetectionSource.MCP_SCAN, DetectionSource.ENTRA_SIGN_IN,
                DetectionSource.EXCHANGE_EMAIL):
        assert classify_signal(IDE, src) == "active", src


def test_nothing_changes_for_a_tool_that_is_only_an_ai():
    """The regression that would matter: a Claude desktop app or an Otter
    extension has no non-AI use, so every source stays active for it."""
    for src in (DetectionSource.INTUNE_APP, DetectionSource.JAMF_APP,
                DetectionSource.SENTINELONE_DNS, DetectionSource.MCP_SCAN):
        assert classify_signal(PLAIN, src, "claude.ai") == "active", src


def test_an_editor_with_no_inference_domains_recorded_never_claims_use():
    """The honest default. If we cannot tell a fork's telemetry from its
    completions we do not get to call a DNS hit evidence of use - an
    over-claimed inference domain turns "the app opened" into "someone used
    AI", which is the failure this feature exists to remove."""
    unknown = AIService(name="Some Fork", vendor="x", category="coding",
                        risk_tier="medium", domains=["fork.example"],
                        form="ide")
    assert unknown.domain_signal("fork.example") == "ambient"
    assert classify_signal(unknown, DetectionSource.SENTINELONE_DNS,
                           "fork.example") == "ambient"


def test_a_bridge_target_has_no_form_and_is_always_use():
    """Bridge findings carry a BridgeTarget, not an AIService: a non-browser
    process holding a token is use by definition, and getattr must not turn
    the missing attribute into a crash."""
    class BridgeTargetLike:
        name = "Atlassian"

    assert classify_signal(BridgeTargetLike(),
                           DetectionSource.SENTINELONE_BRIDGE) == "active"


def test_the_finding_default_keeps_an_unconverted_scanner_honest():
    """A scanner that never sets the field reports what it always reported."""
    assert Finding(service=PLAIN, source=DetectionSource.MCP_SCAN,
                   risk_tier="high").signal == "active"
