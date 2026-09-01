"""Registry loader and indexer.

Loads the AI service registry and builds lookup indexes so scanner modules can
efficiently match their data against known AI services.

Two sources, one shape internally:

  * The receiver's /registry endpoint (AIGUARD_REGISTRY_URL). This is the
    monorepo registry.yaml, published as a ConfigMap by CI. Merging a discovery
    MR therefore reaches every scanner on its next run, with no image rebuild.

  * The bundled ai_services.yaml, used when no URL is set (a laptop run) or
    when the fetch fails. A network blip should not mean a missed scan. It is
    generated from registry.yaml by registry/build.py and never hand-edited;
    CI fails if the committed copy has drifted, because a stale fallback means
    reduced coverage with only a log line to say so.

The two files use different shapes. `tools:` has flattened identifier fields,
`services:` has nested desktop_apps/browser_extensions. _normalise converts
the first into the second so everything below it can stay the same.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

REGISTRY_PATH = Path(__file__).parent / "ai_services.yaml"

# Strict pattern for domain entries: alphanumeric, dots, hyphens, optional wildcard prefix.
_DOMAIN_RE = re.compile(r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")


@dataclass
class AIService:
    """A single AI service from the registry."""

    name: str
    vendor: str
    category: str  # chatbot | copilot | embedded | api | agent
    risk_tier: str  # high | medium | low

    # The registry id is the label used downstream: Loki streams, Prometheus
    # `tool=` labels, the dashboard's Top Tools panel. Every surface must agree
    # on it, or one tool splits into several rows ("Otter" vs "otter").
    # Empty when loaded from the bundled ai_services.yaml, which has no ids.
    id: str = ""

    # Sanctioned in your organisation. Presence of an unapproved tool is reportable;
    # presence of an approved one is inventory.
    approved: bool = False

    domains: list[str] = field(default_factory=list)
    entra_app_ids: list[str] = field(default_factory=list)
    email_domains: list[str] = field(default_factory=list)
    desktop_apps: dict = field(default_factory=dict)
    browser_extensions: dict = field(default_factory=dict)
    mcp_identifiers: list[str] = field(default_factory=list)

    # "ide" marks a product that is an editor first and bundles AI second -
    # a VS Code fork. Finding it installed proves an editor is installed,
    # which is not the same claim as someone having used a model. Empty for
    # every other shape, where presence does imply use.
    form: str = ""
    # The subset of `domains` reached only when a model actually runs. The
    # rest of `domains` is reached on launch anyway (telemetry, updates,
    # licence), so for an `ide` the two mean different things.
    inference_domains: list[str] = field(default_factory=list)
    notes: str = ""

    def domain_signal(self, host: str) -> str:
        """What a DNS or network hit on `host` proves about this tool.

        "active" - a model ran. "ambient" - the product is present, and
        nothing more. Only an `ide` can produce "ambient" from a domain: for
        everything else the domain IS the product, so any hit is use.

        An `ide` with no inference_domains recorded returns "ambient" for
        every host, which is the honest answer - we cannot tell its
        telemetry from its completions, so we do not claim it is use.
        """
        if self.form != "ide":
            return "active"
        h = (host or "").lower().strip(".")
        for d in self.inference_domains:
            d = d.lower()
            if h == d or h.endswith("." + d):
                return "active"
        return "ambient"

    @property
    def label(self) -> str:
        """The tool label to report. Prefers the id; falls back to the name."""
        return self.id or self.name


@dataclass
class BridgeTarget:
    """A SaaS service that should only be accessed by browsers.

    If a non-browser process connects to these domains, it indicates
    an MCP bridge, API key integration, or unauthorised automation.
    """

    name: str
    domains: list[str] = field(default_factory=list)
    notes: str = ""


class Registry:
    """Indexed registry of known AI services.

    Builds reverse-lookup dicts so scanners can do O(1) matching
    instead of iterating the full service list per event.
    """

    def __init__(self, path: Optional[Path] = None, url: Optional[str] = None,
                 token: Optional[str] = None):
        self.path = path or REGISTRY_PATH

        # When set, the registry is fetched from the receiver rather than read
        # from disk. Pass url="" explicitly to force the bundled copy.
        self.url = url if url is not None else os.environ.get("AIGUARD_REGISTRY_URL", "")
        # The bearer for that fetch. The entrypoint passes the credential it
        # resolved for the run (a device credential in managed mode); the CLI
        # and older callers fall back to the environment as before.
        self.token = token if token is not None else os.environ.get("RECEIVER_TOKEN", "")

        # Which source actually supplied the data. Worth logging: otherwise a
        # silently failing fetch means scanning against a stale registry for
        # weeks without noticing.
        self.source = "bundled"
        # The HTTP status of a failed fetch, when the failure was an HTTP
        # status at all. The entrypoint reads it: a 401 on a device
        # credential means the credential was revoked, which must not be
        # absorbed into a quiet bundled-registry fallback.
        self.fetch_status: Optional[int] = None

        self.services: list[AIService] = []
        self.bridge_targets: list[BridgeTarget] = []
        self.allowed_processes: set[str] = set()
        self.discover_exclude_domains: set[str] = set()

        # Reverse-lookup indexes
        self._by_domain: dict[str, AIService] = {}
        self._by_entra_app_id: dict[str, AIService] = {}
        self._by_email_domain: dict[str, AIService] = {}
        self._by_desktop_app: dict[str, AIService] = {}
        self._by_browser_ext: dict[str, AIService] = {}
        self._by_mcp_id: dict[str, AIService] = {}
        self._bridge_domain_to_target: dict[str, BridgeTarget] = {}

        self._load()

    def _fetch(self) -> dict:
        """Fetch the registry from the receiver.

        JSON is a subset of YAML, so the same parser reads both. Any failure
        falls back to the bundled copy rather than scanning against nothing.
        """
        import httpx

        headers = {}
        if self.token:
            from ai_guard import __version__

            # The version rides on the registry read as on every report, so a
            # managed-mode receiver's inventory knows what a scanner runs even
            # on a run that finds nothing to report.
            headers = {"Authorization": f"Bearer {self.token}",
                       "X-AiGuard-Agent-Version": __version__}
        try:
            response = httpx.get(self.url, headers=headers, timeout=15)
            response.raise_for_status()
            data = yaml.safe_load(response.text)
            self.source = self.url
            return data
        except Exception as e:  # noqa: BLE001 - any failure means fall back
            self.fetch_status = getattr(getattr(e, "response", None), "status_code", None)
            logger.warning(
                "Using bundled registry fallback; detection coverage may be reduced"
            )
            logger.debug("Registry fetch failed: %s", e)
            self.source = "bundled (fetch failed)"
            return yaml.safe_load(self.path.read_text())

    @staticmethod
    def _normalise(data: dict) -> dict:
        """Accept either registry shape, return the `services:` shape.

        The monorepo registry.yaml uses `tools:` with flattened identifier
        fields (bundle_ids, app_names, exe_names, extension_ids, email_senders).
        The bundled ai_services.yaml uses `services:` with nested dicts. Convert
        the former so the rest of this class never has to care which it got.

        Nothing is dropped: a tool with no desktop identifiers simply gets empty
        lists, exactly as a hand-written service entry would.
        """
        if "services" in data:
            return data

        services = []
        for tool in data.get("tools", []):
            services.append(
                {
                    "id": tool["id"],
                    "name": tool["name"],
                    "vendor": tool.get("vendor", ""),
                    "category": tool.get("category", ""),
                    "risk_tier": tool.get("risk_tier", "medium"),
                    "approved": tool.get("approved", False),
                    "domains": tool.get("domains", []),
                    "entra_app_ids": tool.get("entra_app_ids", []),
                    "email_domains": tool.get("email_senders", []),
                    "desktop_apps": {
                        # Bundle ids and .app names both match Jamf inventory;
                        # exe names match Intune's discovered apps.
                        "macos": tool.get("bundle_ids", []) + tool.get("app_names", []),
                        "windows": tool.get("exe_names", []),
                    },
                    "browser_extensions": {
                        browser: ids
                        for browser, ids in (tool.get("extension_ids") or {}).items()
                        if browser in ("chrome", "edge")
                    },
                    "mcp_identifiers": tool.get("mcp_identifiers", []),
                    "form": tool.get("form", ""),
                    "inference_domains": tool.get("inference_domains", []),
                    "notes": tool.get("notes", ""),
                }
            )

        normalised = dict(data)
        normalised["services"] = services
        return normalised

    def _load(self) -> None:
        raw = self._fetch() if self.url else yaml.safe_load(self.path.read_text())
        data = self._normalise(raw)

        for entry in data.get("services", []):
            svc = AIService(
                id=entry.get("id", ""),
                approved=entry.get("approved", False),
                name=entry["name"],
                vendor=entry["vendor"],
                category=entry["category"],
                risk_tier=entry.get("risk_tier", "medium"),
                domains=entry.get("domains", []),
                entra_app_ids=entry.get("entra_app_ids", []),
                email_domains=entry.get("email_domains", []),
                desktop_apps=entry.get("desktop_apps", {}),
                browser_extensions=entry.get("browser_extensions", {}),
                mcp_identifiers=entry.get("mcp_identifiers", []),
                form=entry.get("form", ""),
                inference_domains=entry.get("inference_domains", []),
                notes=entry.get("notes", ""),
            )
            self.services.append(svc)
            self._index(svc)

        # Load bridge targets
        for entry in data.get("bridge_targets", []):
            target = BridgeTarget(
                name=entry["name"],
                domains=entry.get("domains", []),
                notes=entry.get("notes", ""),
            )
            self.bridge_targets.append(target)
            for domain in target.domains:
                if not self._validate_domain(domain):
                    logger.warning(
                        "Skipping invalid bridge domain %r in target %s",
                        domain, target.name,
                    )
                    continue
                self._bridge_domain_to_target[domain.lower()] = target

        # Load allowed process names (browsers, native apps, system processes)
        self.allowed_processes = set(
            p.lower() for p in data.get("allowed_processes", [])
        )

        # Load discover exclusion domains
        self.discover_exclude_domains = set(
            d.lower() for d in data.get("discover_exclude_domains", [])
        )

    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Reject domains that contain characters unsafe for query interpolation."""
        return bool(_DOMAIN_RE.match(domain))

    def _index(self, svc: AIService) -> None:
        for domain in svc.domains:
            if not self._validate_domain(domain):
                logger.warning(
                    "Skipping invalid domain %r in service %s — "
                    "does not match expected pattern",
                    domain, svc.name,
                )
                continue
            self._by_domain[domain.lower()] = svc

        for app_id in svc.entra_app_ids:
            self._by_entra_app_id[app_id.lower()] = svc

        for email_domain in svc.email_domains:
            self._by_email_domain[email_domain.lower()] = svc

        for platform_apps in svc.desktop_apps.values():
            for app_name in platform_apps:
                self._by_desktop_app[app_name.lower()] = svc

        for browser_exts in svc.browser_extensions.values():
            for ext_id in browser_exts:
                self._by_browser_ext[ext_id.lower()] = svc

        for mcp_id in svc.mcp_identifiers:
            self._by_mcp_id[mcp_id.lower()] = svc

    def match_domain(self, domain: str) -> Optional[AIService]:
        """Match a domain or subdomain against the registry."""
        domain = domain.lower().strip(".")
        # Exact match first
        if domain in self._by_domain:
            return self._by_domain[domain]
        # Try parent domains (e.g. "foo.chat.openai.com" -> "chat.openai.com")
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._by_domain:
                return self._by_domain[parent]
        return None

    def match_entra_app_id(self, app_id: str) -> Optional[AIService]:
        return self._by_entra_app_id.get(app_id.lower())

    def match_email_domain(self, sender_domain: str) -> Optional[AIService]:
        return self._by_email_domain.get(sender_domain.lower())

    def match_desktop_app(self, app_name: str) -> Optional[AIService]:
        return self._by_desktop_app.get(app_name.lower())

    def match_browser_extension(self, ext_id: str) -> Optional[AIService]:
        return self._by_browser_ext.get(ext_id.lower())

    def match_mcp_identifier(self, mcp_id: str) -> Optional[AIService]:
        return self._by_mcp_id.get(mcp_id.lower())

    def match_bridge_domain(self, domain: str) -> Optional[BridgeTarget]:
        """Match a domain against bridge targets."""
        domain = domain.lower().strip(".")
        # Exact match
        if domain in self._bridge_domain_to_target:
            return self._bridge_domain_to_target[domain]
        # Try parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._bridge_domain_to_target:
                return self._bridge_domain_to_target[parent]
        # Check wildcard entries (e.g. "*.atlassian.net")
        for pattern, target in self._bridge_domain_to_target.items():
            if pattern.startswith("*.") and domain.endswith(pattern[1:]):
                return target
        return None

    def is_allowed_process(self, process_name: str) -> bool:
        """Check if a process is a known browser, native app, or system process."""
        return process_name.lower() in self.allowed_processes

    @property
    def all_domains(self) -> set[str]:
        return set(self._by_domain.keys())

    @property
    def all_bridge_domains(self) -> set[str]:
        """All bridge target domains (excluding wildcard entries)."""
        return set(
            d for d in self._bridge_domain_to_target.keys()
            if not d.startswith("*.")
        )

    @property
    def all_email_domains(self) -> set[str]:
        return set(self._by_email_domain.keys())

    @property
    def stats(self) -> dict:
        return {
            "source": self.source,
            "total_services": len(self.services),
            "indexed_domains": len(self._by_domain),
            "indexed_entra_apps": len(self._by_entra_app_id),
            "indexed_email_domains": len(self._by_email_domain),
            "indexed_desktop_apps": len(self._by_desktop_app),
            "indexed_browser_extensions": len(self._by_browser_ext),
            "indexed_mcp_identifiers": len(self._by_mcp_id),
            "bridge_targets": len(self.bridge_targets),
            "bridge_domains": len(self._bridge_domain_to_target),
        }