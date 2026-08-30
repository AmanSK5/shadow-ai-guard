"""The onboarding wizard's plumbing: the two generated artifacts, the
registry-tools endpoint, and the wiring that makes a fresh install
deployable from one page. Same direct-call harness as the suite."""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import derive, main, managed

EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


# ------------------------------------------------------- extension policy --


def test_the_extension_policy_bakes_everything_the_extension_reads():
    name, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_TESTTOKEN",
        ["example.com", "example.co.uk"])
    assert name == "ai-guard-extension-policy.plist"
    # The managed-storage schema the extension actually reads
    # (extension/src/background.js, content.js, guard.js).
    assert "<string>https://rx.example.com/report</string>" in out
    assert "<string>aige_TESTTOKEN</string>" in out
    assert "<string>$SERIALNUMBER</string>" in out
    assert "<string>example.com</string>" in out
    assert "<string>example.co.uk</string>" in out
    assert "pasteGuardMode" in out and "classificationMarkings" in out
    # The header names the per-browser upload domains with the real id.
    assert "com.google.Chrome.extensions.%s" % EXT_ID in out
    assert "com.microsoft.Edge.extensions.%s" % EXT_ID in out


def test_the_policy_keys_match_the_shipped_plist_templates():
    """The generated policy and extension/deploy/macos are two spellings of
    one schema; a key drifting in either is an extension that quietly reads
    nothing."""
    shipped = (Path(__file__).parent.parent.parent / "extension" / "deploy"
               / "macos" / "chrome" / "managed-storage.plist").read_text()
    _, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_T", ["example.com"])
    for key in ("reportEndpoint", "authToken", "deviceIdentifier",
                "allowedDomains", "pasteGuardMode", "classificationMarkings"):
        assert "<key>%s</key>" % key in shipped, key
        assert "<key>%s</key>" % key in out, key


def test_no_domains_is_generated_with_a_warning_not_refused():
    """A skipped corp-domains step should not block the download - but the
    file must say what the empty list means."""
    _, out = managed.generate_extension_policy(
        EXT_ID, "https://rx.example.com", "aige_T", [])
    assert "no corporate domains set" in out


def test_a_malformed_extension_id_is_refused():
    """32 letters a-p or nothing: the shape check doubles as XML safety,
    since the id lands inside an XML comment where '--' would break the
    document."""
    for bad in ("", "short", "z" * 32, "a-b" + "a" * 29, "a" * 33):
        with pytest.raises(managed.ArtifactError):
            managed.generate_extension_policy(
                bad, "https://rx.example.com", "aige_T", [])


def test_hostile_domains_cannot_escape_the_xml():
    with pytest.raises(managed.ArtifactError):
        managed.generate_extension_policy(
            EXT_ID, "https://rx.example.com", "aige_T",
            ["</string><key>authToken</key>"])


# -------------------------------------------------------- scanner cronjob --


def test_the_cronjob_is_valid_yaml_with_the_token_in_a_secret():
    import yaml

    name, out = managed.generate_scanner_cronjob(
        "https://rx.example.com", "aige_TESTTOKEN", "0.9.7")
    assert name == "ai-guard-scanner-cronjob.yaml"
    secret, cron = list(yaml.safe_load_all(out))
    assert secret["kind"] == "Secret"
    assert secret["stringData"]["enrollmentToken"] == "aige_TESTTOKEN"
    assert cron["kind"] == "CronJob"
    c = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    assert c["image"] == "ghcr.io/amansk5/shadow-ai-guard/scanner:0.9.7"
    env = {e["name"]: e for e in c["env"]}
    assert env["RECEIVER_URL"]["value"] == "https://rx.example.com"
    # The token reaches the pod through the Secret, never inline.
    assert env["RECEIVER_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == "ai-guard-scanner"
    assert env["AIGUARD_SCANNER_ID"]["value"] == "scanner"


# ------------------------------------------------------------- the routes --


@pytest.fixture
def receiver(monkeypatch):
    """A fake receiver whose settings carry an extension id and domains."""
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        if path == "/admin/settings":
            return {"settings": {
                "corp_domains": {"value": ["example.com"], "source": "db",
                                 "env": []},
                "extension_id": {"value": EXT_ID, "source": "db"},
                "onboarding_done": {"value": False, "source": "unset"}}}
        if method == "POST" and path == "/admin/enrollment-tokens":
            return {"id": "tok9", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {}

    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


def http_error(fn, *args, **kw) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        fn(*args, **kw)
    return e.value


def test_the_extension_policy_route_reads_settings_then_mints(receiver):
    resp = main.artifact("extension-policy", _=None, token="aigt_s")
    assert 'filename="ai-guard-extension-policy.plist"' in resp.headers["content-disposition"]
    assert resp.headers["x-enrollment-token-id"] == "tok9"
    body = resp.body.decode()
    # The exact plist elements, not loose substrings: the token as the
    # authToken value and the settings-sourced domain inside allowedDomains.
    # (Also what keeps CodeQL from reading a plain "example.com" in body as
    # URL-substring sanitization, which this never was.)
    assert "<string>aige_MINTED</string>" in body
    assert "<string>example.com</string>" in body
    # Settings were read before minting, on the caller's own session.
    assert [c["path"] for c in receiver] == ["/admin/settings",
                                             "/admin/enrollment-tokens"]
    assert receiver[1]["body"]["note"] == "portal artifact: extension-policy"


def test_no_extension_id_refuses_before_minting(receiver, monkeypatch):
    def fake(base, method, path, token, body=None):
        receiver.append({"path": path})
        return {"settings": {"corp_domains": {"value": []},
                             "extension_id": {"value": ""},
                             "onboarding_done": {"value": False}}}
    monkeypatch.setattr(main.managed, "receiver_request", fake)

    err = http_error(main.artifact, "extension-policy", _=None, token="t")
    assert err.status_code == 409
    assert "extension ID" in err.detail
    # No token was minted for an artifact that never existed.
    assert [c["path"] for c in receiver] == ["/admin/settings"]


def test_the_cronjob_route_requires_nothing_from_settings(receiver, monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "0.9.7")
    resp = main.artifact("scanner-cronjob", _=None, token="t")
    assert 'filename="ai-guard-scanner-cronjob.yaml"' in resp.headers["content-disposition"]
    assert "scanner:0.9.7" in resp.body.decode()
    # Settings are read for the public URL, but nothing scanner-specific
    # is required from them.
    assert [c["path"] for c in receiver] == ["/admin/settings",
                                             "/admin/enrollment-tokens"]


def test_a_dev_build_bakes_latest_not_a_nonexistent_image(receiver, monkeypatch):
    monkeypatch.setattr(main, "APP_VERSION", "dev")
    resp = main.artifact("scanner-cronjob", _=None, token="t")
    assert "scanner:latest" in resp.body.decode()


def test_unknown_kinds_are_still_404(receiver):
    assert http_error(main.artifact, "collector-solaris", _=None,
                      token="t").status_code == 404


def test_registry_tools_needs_no_findings(monkeypatch, tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "tools:\n"
        "  - id: chatgpt\n    name: ChatGPT\n    vendor: OpenAI\n"
        "  - id: claude\n    name: Claude\n    vendor: Anthropic\n"
        "    approved: true\n")
    monkeypatch.setattr(main, "REGISTRY_PATH", str(reg))
    out = main.registry_tools(None, _=None)
    assert out["tools"] == [
        {"id": "chatgpt", "name": "ChatGPT", "vendor": "OpenAI",
         "approved": False, "license_group": "", "custom": False},
        {"id": "claude", "name": "Claude", "vendor": "Anthropic",
         "approved": True, "license_group": "", "custom": False}]


def test_the_setup_rows_offer_the_extension_policy_once():
    """The accounts row carries the artifact; the paste-guard row must not,
    because it is the same extension and a second button minting a second
    token for one deployment is a trap."""
    all_rows = [r for g in derive.status_from([])["groups"]
                for r in g["sources"]]
    arts = {r["source"]: r["artifact"] for r in all_rows}
    assert arts["browser_extension"] == "extension-policy"
    assert arts["paste_guard"] == ""
    assert arts["collector-macos"] == "collector-macos"


# ---------------------------------------------------------------- the page --


def test_the_page_carries_the_wizard():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("wiz-approve", "wiz-notapprove", "wiz-finish",
                   "/api/registry-tools", "onboarding_done", "'wizard'",
                   "scanner-cronjob", "extension-policy"):
        assert needle in html, needle


def test_the_register_carries_the_watchlist_decisions():
    """The wizard's baseline table was the only place to record a decision
    about a tool nothing has observed yet, and the wizard is a door you
    walk through once. The register's watchlist section is the standing
    version, and Settings can reopen the wizard."""
    html = (main.STATIC / "index.html").read_text()
    for needle in ("watchlistBlock", "wl-toggle", "open-wizard",
                   "known, not observed",
                   "Run the setup wizard again"):
        assert needle in html, needle


def test_the_page_carries_the_tool_registry_view():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("registryView", "reg-add", "reg-save", "reg-delete",
                   "reg-suggest", "reg-adv", "'registry'", "Tool registry",
                   "/api/registry-entries", "add to registry"):
        assert needle in html, needle


def test_defining_a_tool_proposes_rather_than_asks():
    """Nineteen flat fields became a three-step wizard, because the operator
    does not know a tool's bundle id or CLI binary - working that out is what
    they run the platform for. Discovery only sees DNS
    (_CANDIDATE_KINDS = domain, mcp_server) and collectors report only what
    already matches the registry, so the estate cannot answer it either.

    So proposals are DERIVED and offered UNTICKED, and where each one came
    from is on screen beside it. A wrong identifier is worse than a missing
    one: a blank leaves a tool unseen on a surface, a wrong one hangs somebody
    else's findings on it."""
    html = (main.STATIC / "index.html").read_text()
    for needle in ("function rwDerive(", "function rwOpen(", "function rwEntry(",
                   "rw-step", "rw-tick", "rw-add",
                   "seen in your estate", "derived from the name",
                   "already saved", "you added"):
        assert needle in html, needle
    # Derived guesses are never on by default; evidence and saved values are.
    assert "why: 'derived', conf: 'low', on: false" in html
    # The four fields registry/schema.json requires are always written. vendor
    # was conditional, which produced an entry the receiver refused - found by
    # saving one, not by reading the code.
    assert "const e = {id: RW.editing || RW.id, name: RW.name, vendor: RW.vendor};" in html
    assert "const rwReady = () => !!(RW.name && RW.vendor && (RW.editing || RW.id));" in html
    # Typing has to reach the Next button, or the wizard cannot be walked at
    # all: nothing else re-renders while a field has focus.
    assert "function rwLive()" in html
    assert "matches('#rw-name,#rw-vendor,#rw-id')" in html
    # The JSON escape hatch survives the rewrite.
    assert "reg-adv" in html and "re-json" in html


def test_the_review_queue_button_lands_in_the_wizard():
    """cand-add already opened the same form the Tool registry did, so making
    that form a wizard puts the review queue's own button into it. What
    discovery saw rides along as evidence - the one thing on the identifier
    step that is not a guess."""
    html = (main.STATIC / "index.html").read_text()
    assert "if (act === 'cand-add')" in html
    assert "evidence: {kind: c.kind" in html
    # An entry being edited arrives already confirmed, not re-proposed.
    assert "function rwFromEntry(" in html
    assert "why: 'saved', conf: 'high', on: true" in html


def test_the_js_category_list_matches_the_schema():
    """REG_CATEGORIES is a hand-mirror of registry/schema.json's category
    enum; a value added to one and not the other makes the form refuse (or
    omit) a category the receiver accepts."""
    import json

    schema = json.loads(
        (Path(__file__).parent.parent.parent / "registry" / "schema.json")
        .read_text())
    enum = schema["properties"]["tools"]["items"]["properties"]["category"]["enum"]
    html = (main.STATIC / "index.html").read_text()
    start = html.index("REG_CATEGORIES = [")
    js_list = html[start:html.index("];", start)]
    for value in enum:
        assert "'%s'" % value in js_list, value


def test_every_setup_doc_reference_is_a_real_file():
    """The Setup view renders these as GitHub links pinned to the running
    release. A renamed or moved doc becomes a 404 on every deployment's
    Setup page, so the paths are held to the repo here."""
    from app.derive import status_from

    repo = Path(__file__).parent.parent.parent
    docs = {r["doc"] for g in status_from([])["groups"] for r in g["sources"]}
    for d in sorted(docs):
        assert (repo / d).is_file(), d


def test_the_page_carries_the_review_queue():
    html = (main.STATIC / "index.html").read_text()
    for needle in ("review_queue", "Awaiting a decision", "new today",
                   "docUrl", "github.com/AmanSK5/shadow-ai-guard/blob/"):
        assert needle in html, needle


def test_the_extension_setup_owns_its_delivery_values():
    """The same seven values were editable in Settings > Fleet AND in the
    extension setup - two editors for one value, and neither screen mentioned
    the other. The sign-on wizard has never done that: it owns its fields and
    Settings shows a state and a door.

    A field belongs in Settings if it is meaningful on its own. Corporate
    domains and the paste guard pass that - flipping warn to block is a
    Tuesday decision, not a repack. The pack-host-sign values do not: they
    only mean anything as the output of that sequence."""
    html = (main.STATIC / "index.html").read_text()
    # Settings no longer edits any of them.
    assert 'id="set-extid"' not in html.split("function fleetSettings()")[1] \
        .split("function connectionSettings()")[0]
    for gone in ("extensionDeliveryFields",):
        assert gone not in html, gone
    # It shows their state and a way in instead.
    assert "function extStatusRows(mode)" in html
    assert 'data-act="ext-open"' in html
    # The status block suppresses paste guard mode in Settings, where the
    # field itself sits three rows above; the setup wizard's step 5 keeps it,
    # having no field of its own.
    assert "${extStatusRows(true)}" in html
    assert "${extStatusRows()}" in html


def test_the_extension_setup_wears_the_rail_and_infers_the_early_steps():
    """Steps 1 and 2 are a download and a pack, both on the operator's own
    machine, so neither saves anything the rail could read back. They are
    inferred from the extension id on step 3: you cannot know a 32-letter
    Chromium id without having packed the thing that produced it. Evidence,
    rather than a tick somebody presses to say they did it."""
    html = (main.STATIC / "index.html").read_text()
    assert "packed - the id proves it" in html
    assert "downloaded - the id proves it" in html
    assert 'data-act="ext-page"' in html and "ssrail" in html
    # The numbered pill row is gone.
    assert "${i + 1} · ${t}" not in html


def test_the_hosting_step_says_where_not_just_how():
    """"Any static host will do" is not an answer if you have never hosted a
    file deliberately. The named options are the missing half - and a
    container registry, which is where build output often goes, is the one
    thing that cannot serve these."""
    html = (main.STATIC / "index.html").read_text()
    for needle in ("AWS S3", "Azure Blob Storage", "Google Cloud Storage",
                   "artifact repository", "not a container registry"):
        assert needle in html, needle
    # The S3 gotcha the extension README documents, where it is needed.
    assert "arn:aws:s3:::your-bucket/*" in html


def test_a_long_command_cannot_widen_the_wizard_past_its_card():
    """Steps 2 and 5 carry shell commands too long to wrap. Both a grid item
    and a flex item default to min-width:auto, which means neither shrinks
    below its widest child - so one unbreakable line pushed the whole panel
    wider than the card, and .ssow's overflow:hidden then cut off the Copy
    buttons and Back/Next entirely. Scrolling right did not reach them,
    because the clipping was the card's rather than the page's.

    min-width:0 in both places lets the column shrink and the pre's own
    overflow-x finally engage."""
    html = (main.STATIC / "index.html").read_text()
    assert ".ssmain{padding:22px 24px;min-width:0}" in html
    assert "flex:1;min-width:0;font-size:12px" in html


def test_the_first_run_wizard_is_one_step_at_a_time():
    """Seven numbered sections rendered on one page - the only wizard that
    never became one, and the first thing a new deployment sees."""
    html = (main.STATIC / "index.html").read_text()
    assert "let WIZSTEP = 1;" in html
    assert "const WIZ_STEPS = [" in html
    assert 'data-act="wiz-step"' in html
    # managedAction takes (act, el) and has no `key` in scope. Borrowing the
    # name threw a silent ReferenceError and every rail click did nothing -
    # the wizard looked rendered and was simply inert.
    assert "const n = parseInt(el ? el.getAttribute('data-key') : '', 10);" in html


def test_the_rail_says_what_each_step_costs_to_skip():
    """A first-run wizard that only counts steps says how far down the page
    you are. Corporate domains is marked required not because the platform
    refuses to run without it, but because it runs WRONG - every account reads
    as personal, and the Overview headline, the Personal accounts page and the
    ISO evidence all inherit that. Once the required steps are in, the summary
    says so, because the moment it starts working is worth naming."""
    html = (main.STATIC / "index.html").read_text()
    for needle in ("required", "recommended", "optional",
                   "You can deploy now", "Start collecting", "Make it useful",
                   "every account reads as personal",
                   "nothing can deploy without it"):
        assert needle in html, needle


def test_the_first_two_steps_say_where_to_look_not_just_what_to_type():
    """"The one a laptop on someone's kitchen table can resolve" told an
    operator what the address is FOR, not how to find the one they have. And
    "Loki-compatible" left open whether Loki itself was required.

    The ingest-versus-query distinction is the trap worth naming: a store that
    accepts Loki writes but answers queries in its own language will take every
    finding and then show an empty portal."""
    html = (main.STATIC / "index.html").read_text()
    assert "kitchen table" not in html
    for needle in ("kubectl get ingress -A", "tailscale status",
                   "Grafana Cloud Logs", "/loki/api/v1/query_range",
                   "advertise Loki-compatible"):
        assert needle in html, needle


def test_the_extension_setup_offers_the_way_back_it_actually_owes_you():
    """It is reachable from the first-run wizard's step 5 and from Settings,
    and the way out differs: somebody mid-setup wants to land back on step 5,
    somebody who came from Settings has no setup to return to. The last step
    used to offer "Back to the setup wizard" to everybody, including people
    who had never been there.

    EXTFROM is cleared by every other navigation, so the offer cannot outlive
    the journey that earned it. And it appears once per screen - the last step
    showed it twice, as both the escape and the primary, until the escape was
    dropped there."""
    html = (main.STATIC / "index.html").read_text()
    assert "let EXTFROM = '';" in html
    assert "EXTFROM = view === 'wizard' ? 'wizard' : '';" in html
    assert "if (act === 'ext-back-to-setup')" in html
    # Returning lands on the step that sent you, not the top of the wizard.
    assert "WIZSTEP = 5;" in html
    # Cleared on every other route out.
    assert "view = h.view; detail = null; EXTFROM = '';" in html
    # One exit per screen.
    assert "${EXTPAGE === 6 ? '' : EXTFROM === 'wizard'" in html


def test_the_first_account_created_goes_to_the_wizard_not_the_tour():
    """The wizard otherwise opens only on a bare fragment, so that an
    operator who navigated somewhere on purpose is not dragged back to it.
    The very first sign-in has no such intent to respect: a tab still
    carrying #settings/start from before the volume was wiped skipped the
    wizard entirely, and maybeTour() then handed a brand new deployment the
    walkthrough instead of the setup it had not done."""
    html = (main.STATIC / "index.html").read_text()
    assert "if (act === 'do-setup') FIRSTRUN = true;" in html
    assert "const first = FIRSTRUN;" in html
    assert "FIRSTRUN = false;" in html
    assert "(first || !location.hash || location.hash === '#wizard')" in html


def test_skipping_the_wizard_says_where_it_went():
    """Skip and Finish wrote the same thing, so skipping retired the wizard
    for good without a word about it - and the two required steps are the
    ones whose absence makes the deployment run WRONG rather than not run.
    Skip is now its own action, and it asks first."""
    html = (main.STATIC / "index.html").read_text()
    # The button is Skip only while a required step is outstanding.
    assert "canGo ? 'wiz-finish' : 'wiz-skip'" in html
    assert "if (act === 'wiz-skip') { skipShow(); return; }" in html
    assert '<dialog id="skipdlg"' in html
    assert "Settings &rsaquo; Getting started" in html
    # Confirming does exactly what finishing does, rather than a second copy
    # of it that can drift.
    assert "await managedAction('wiz-finish')" in html


def test_the_skip_dialog_owns_escape_like_the_other_one():
    """Same trap as the password modal: the drawer's Escape handler is a
    later window listener, so guarding it on live state alone let one
    keystroke dismiss the dialog AND whatever was open behind it."""
    html = (main.STATIC / "index.html").read_text()
    assert "if (skipIsOpen()) { skipHide(); e.stopImmediatePropagation(); return; }" in html
    assert "pwIsOpen() || skipIsOpen()" in html


def test_a_viewer_can_leave_the_wizard():
    """Finish and Skip both write onboarding_done, and the receiver refuses
    the write from a read-only account - so the only way out of a wizard a
    viewer can reach from Settings answered 'this account is read-only' and
    left them on it. The nav was the only escape.

    Nothing is being saved either way, so for a viewer leaving is
    navigation: one button, no write, no refusal to report."""
    html = (main.STATIC / "index.html").read_text()
    assert "const wizRO = AUTH && AUTH.role === 'viewer';" in html
    assert "if (act === 'wiz-close') {" in html
    # BOTH exits are role-aware: the footer button, and the one step 7
    # shows in place of Next. Missing either leaves a viewer stuck on that
    # step instead of on the wizard, which is the same trap in one place.
    assert html.count("wizRO ? 'wiz-close'") == 2
    assert html.count("${wizRO ? 'wiz-close' : 'wiz-finish'}") == 1
    # And it lands back on the tab the button that opens the wizard is on.
    close = html.split("if (act === 'wiz-close') {", 1)[1][:400]
    assert "SETTAB = 'start'" in close
    assert "mfetch" not in close, "a viewer's exit must not attempt a write"
