"""Report generator.

Takes findings from all scanner modules and produces unified output:
  - Terminal (rich tables)
  - JSON (machine-readable, for pipelines)
  - CSV (for evidence/compliance)
  - Confluence (wiki markup for Confluence pages)
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ai_guard.scanners.base import Finding, ScanResult, occurrence_unit


RISK_COLORS = {
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

RISK_EMOJI = {
    "high": "[red]HIGH[/red]",
    "medium": "[yellow]MED[/yellow]",
    "low": "[green]LOW[/green]",
}


class ReportGenerator:
    def __init__(self, results: list[ScanResult], output_format: str = "terminal"):
        self.results = results
        self.output_format = output_format
        self.all_findings = self._collect_findings()

    def _collect_findings(self) -> list[Finding]:
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def generate(self, output_path: Optional[str] = None) -> None:
        if self.output_format == "json":
            self._generate_json(output_path)
        elif self.output_format == "csv":
            self._generate_csv(output_path)
        elif self.output_format == "confluence":
            self._generate_confluence(output_path)
        else:
            self._generate_terminal()

    def _generate_terminal(self) -> None:
        console = Console()

        # Header
        console.print()
        console.print(
            Panel.fit(
                "[bold]AI Guard — Shadow AI Discovery Report[/bold]\n"
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Scanners run: {len(self.results)} | "
                f"Total findings: {len(self.all_findings)}\n"
                "[dim]CONFIDENTIAL — Contains employee names and device identifiers[/dim]",
                border_style="blue",
            )
        )

        # Scanner status summary
        console.print("\n[bold]Scanner Status[/bold]")
        status_table = Table(show_header=True, header_style="bold")
        status_table.add_column("Scanner")
        status_table.add_column("Status")
        status_table.add_column("Findings")
        status_table.add_column("Duration")

        for result in self.results:
            if result.skipped_reason:
                status = f"[dim]Skipped: {result.skipped_reason}[/dim]"
            elif result.errors:
                status = f"[red]Errors: {len(result.errors)}[/red]"
            else:
                status = "[green]OK[/green]"

            status_table.add_row(
                result.scanner_name,
                status,
                str(result.finding_count),
                f"{result.duration_seconds:.1f}s",
            )

        console.print(status_table)

        if not self.all_findings:
            console.print("\n[green]No AI tool usage detected.[/green]\n")
            return

        # Findings by user
        console.print("\n[bold]Findings by User[/bold]")
        by_user = defaultdict(list)
        no_user = []
        for f in self.all_findings:
            if f.user_upn:
                by_user[f.user_upn].append(f)
            else:
                no_user.append(f)

        for upn in sorted(by_user.keys()):
            user_findings = by_user[upn]
            console.print(f"\n  [bold]{upn}[/bold]")

            for f in sorted(user_findings, key=lambda x: x.risk_tier, reverse=True):
                risk = RISK_EMOJI.get(f.risk_tier, f.risk_tier)
                line = f"    {risk} {f.service.name} — {f.detail}"
                if f.first_seen and f.last_seen:
                    start = f.first_seen.strftime("%b %Y")
                    end = f.last_seen.strftime("%b %Y")
                    line += f" ({start} — {end})" if start != end else f" ({start})"
                console.print(line)

        if no_user:
            console.print("\n  [bold]Unattributed[/bold]")
            for f in no_user:
                risk = RISK_EMOJI.get(f.risk_tier, f.risk_tier)
                line = f"    {risk} {f.service.name} — {f.detail}"
                if f.first_seen and f.last_seen:
                    start = f.first_seen.strftime("%b %Y")
                    end = f.last_seen.strftime("%b %Y")
                    line += f" ({start} — {end})" if start != end else f" ({start})"
                console.print(line)

        # Findings by service
        console.print("\n[bold]Findings by Service[/bold]")
        by_service = defaultdict(list)
        for f in self.all_findings:
            by_service[f.service.name].append(f)

        svc_table = Table(show_header=True, header_style="bold")
        svc_table.add_column("Service")
        svc_table.add_column("Vendor")
        svc_table.add_column("Risk")
        svc_table.add_column("Users")
        svc_table.add_column("Endpoints")
        svc_table.add_column("Sources")

        for svc_name in sorted(by_service.keys()):
            svc_findings = by_service[svc_name]
            first = svc_findings[0]
            users = set(f.user_upn for f in svc_findings if f.user_upn)
            endpoints = set(f.device_name for f in svc_findings if f.device_name)
            sources = set(f.source.value for f in svc_findings)
            risk_color = RISK_COLORS.get(first.risk_tier, "white")

            svc_table.add_row(
                svc_name,
                first.service.vendor,
                Text(first.risk_tier.upper(), style=risk_color),
                str(len(users)) if users else "-",
                str(len(endpoints)) if endpoints else "-",
                ", ".join(sorted(sources)),
            )

        console.print(svc_table)
        console.print(
            "[dim]SentinelOne results are deduplicated by endpoint — "
            "each row represents a unique user/endpoint, not event volume.[/dim]"
        )

        # ─────────────────────────────────────────────
        # Actionable Summary
        # ─────────────────────────────────────────────
        console.print("\n[bold]Action Required[/bold]")

        # 1. Blocked tool violations
        blocked = [
            f for f in self.all_findings
            if f.user_upn and "[BLOCKED]" in f.detail
        ]
        if blocked:
            console.print("\n  [bold red]Blocked Tool Violations[/bold red]")
            seen_blocked = set()
            for f in blocked:
                key = (f.user_upn, f.service.name)
                if key in seen_blocked:
                    continue
                seen_blocked.add(key)
                process = f.raw_evidence.get("process", "browser")
                console.print(
                    f"    [red]•[/red] [bold]{f.user_upn}[/bold] is using "
                    f"[red]{f.service.name}[/red] via {process}"
                )
            console.print(
                "    [dim]Action: Review with users — these tools are on "
                "the organisation's blocked list.[/dim]"
            )

        # 2. Bridge connections (non-browser processes hitting SaaS APIs)
        bridges = [
            f for f in self.all_findings
            if f.source.value == "sentinelone_bridge" and f.user_upn
        ]
        if bridges:
            console.print("\n  [bold yellow]SaaS Bridge Connections[/bold yellow]")
            seen_bridges = set()
            for f in bridges:
                process = f.raw_evidence.get("process_name", "unknown")
                target = f.raw_evidence.get("bridge_target", f.service.name)
                key = (f.user_upn, process, target)
                if key in seen_bridges:
                    continue
                seen_bridges.add(key)
                console.print(
                    f"    [yellow]•[/yellow] [bold]{f.user_upn}[/bold] has "
                    f"[yellow]{process}[/yellow] connecting to "
                    f"[bold]{target}[/bold]"
                )
            console.print(
                "    [dim]Action: Investigate — a non-browser application is "
                "accessing your SaaS tools, possibly via an API key or "
                "MCP integration. Review whether this is authorised.[/dim]"
            )

        # 3. Shadow AI usage via desktop apps (not browsers)
        desktop_ai = [
            f for f in self.all_findings
            if f.source.value == "sentinelone_dns"
            and f.user_upn
            and "[BLOCKED]" not in f.detail
        ]
        # Filter to findings where process is an AI desktop app, not a browser
        ai_app_processes = {
            "claude", "claude.exe", "chatgpt", "chatgpt.exe",
            "copilot.exe", "copilot", "cursor", "cursor.exe",
            "windsurf", "windsurf.exe",
            "ollama", "ollama.exe",
            "code helper", "code helper (renderer)",
            "code", "code.exe",
        }
        desktop_ai_real = []
        for f in desktop_ai:
            process = (f.raw_evidence.get("process", "") or "").lower()
            if process in ai_app_processes:
                desktop_ai_real.append(f)

        if desktop_ai_real:
            console.print("\n  [bold]AI Desktop App Usage[/bold]")
            seen_desktop = set()
            for f in desktop_ai_real:
                process = f.raw_evidence.get("process", "unknown")
                key = (f.user_upn, f.service.name, process)
                if key in seen_desktop:
                    continue
                seen_desktop.add(key)
                console.print(
                    f"    • [bold]{f.user_upn}[/bold] is using "
                    f"[bold]{f.service.name}[/bold] via the "
                    f"[bold]{process}[/bold] desktop app"
                )
            console.print(
                "    [dim]Action: Review — these users have AI desktop "
                "applications installed and actively making API calls. "
                "Verify this aligns with your AI usage policy.[/dim]"
            )

        if not blocked and not bridges and not desktop_ai_real:
            console.print("  [green]No actions required.[/green]")

        # Errors
        all_errors = [e for r in self.results for e in r.errors]
        if all_errors:
            console.print("\n[bold red]Errors[/bold red]")
            for error in all_errors:
                console.print(f"  [red]• {error}[/red]")

        console.print()

    def _generate_confluence(self, output_path: Optional[str] = None) -> None:
        lines: list[str] = []

        risk_markup = {
            "high": "{color:red}HIGH{color}",
            "medium": "{color:#ff8b00}MEDIUM{color}",
            "low": "{color:green}LOW{color}",
        }

        # Header
        lines.append("h1. AI Guard — Shadow AI Discovery Report")
        lines.append("")
        lines.append(
            f"*Generated:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"*Scanners run:* {len(self.results)} | "
            f"*Total findings:* {len(self.all_findings)}"
        )
        lines.append("_CONFIDENTIAL — Contains employee names and device identifiers_")
        lines.append("")

        # Scanner status table
        lines.append("h2. Scanner Status")
        lines.append("|| Scanner || Status || Findings || Duration ||")
        for result in self.results:
            if result.skipped_reason:
                status = f"Skipped: {result.skipped_reason}"
            elif result.errors:
                status = f"{{color:red}}Errors: {len(result.errors)}{{color}}"
            else:
                status = "{color:green}OK{color}"
            lines.append(
                f"| {result.scanner_name} | {status} "
                f"| {result.finding_count} | {result.duration_seconds:.1f}s |"
            )
        lines.append("")

        if not self.all_findings:
            lines.append("{color:green}No AI tool usage detected.{color}")
            output = "\n".join(lines)
            if output_path:
                self._write_secure_file(output_path, output)
            else:
                print(output)
            return

        # Findings by user
        lines.append("h2. Findings by User")
        by_user: dict[str, list[Finding]] = defaultdict(list)
        no_user: list[Finding] = []
        for f in self.all_findings:
            if f.user_upn:
                by_user[f.user_upn].append(f)
            else:
                no_user.append(f)

        for upn in sorted(by_user.keys()):
            user_findings = by_user[upn]
            lines.append(f"h3. {upn}")
            for f in sorted(user_findings, key=lambda x: x.risk_tier, reverse=True):
                risk = risk_markup.get(f.risk_tier, f.risk_tier)
                entry = f"* {risk} *{f.service.name}* — {f.detail}"
                if f.first_seen and f.last_seen:
                    start = f.first_seen.strftime("%b %Y")
                    end = f.last_seen.strftime("%b %Y")
                    entry += f" ({start} — {end})" if start != end else f" ({start})"
                lines.append(entry)

        if no_user:
            lines.append("h3. Unattributed")
            for f in no_user:
                risk = risk_markup.get(f.risk_tier, f.risk_tier)
                entry = f"* {risk} *{f.service.name}* — {f.detail}"
                if f.first_seen and f.last_seen:
                    start = f.first_seen.strftime("%b %Y")
                    end = f.last_seen.strftime("%b %Y")
                    entry += f" ({start} — {end})" if start != end else f" ({start})"
                lines.append(entry)

        lines.append("")

        # Findings by service table
        lines.append("h2. Findings by Service")
        lines.append("|| Service || Vendor || Risk || Users || Endpoints || Sources ||")

        by_service: dict[str, list[Finding]] = defaultdict(list)
        for f in self.all_findings:
            by_service[f.service.name].append(f)

        for svc_name in sorted(by_service.keys()):
            svc_findings = by_service[svc_name]
            first = svc_findings[0]
            users = set(f.user_upn for f in svc_findings if f.user_upn)
            endpoints = set(f.device_name for f in svc_findings if f.device_name)
            sources = set(f.source.value for f in svc_findings)
            risk = risk_markup.get(first.risk_tier, first.risk_tier.upper())
            lines.append(
                f"| {svc_name} | {first.service.vendor} | {risk} "
                f"| {len(users) if users else '-'} "
                f"| {len(endpoints) if endpoints else '-'} "
                f"| {', '.join(sorted(sources))} |"
            )

        lines.append("")
        lines.append(
            "_SentinelOne results are deduplicated by endpoint — "
            "each row represents a unique user/endpoint, not event volume._"
        )
        lines.append("")

        # Action required
        lines.append("h2. Action Required")

        action_sections: list[str] = []

        # Blocked tool violations
        blocked = [f for f in self.all_findings if f.user_upn and "[BLOCKED]" in f.detail]
        if blocked:
            section = ["{panel:title=Blocked Tool Violations|borderColor=red}"]
            seen: set[tuple[str | None, str]] = set()
            for f in blocked:
                key = (f.user_upn, f.service.name)
                if key in seen:
                    continue
                seen.add(key)
                process = f.raw_evidence.get("process", "browser")
                section.append(
                    f"* {{color:red}}(!){{color}} *{f.user_upn}* is using "
                    f"{{color:red}}{f.service.name}{{color}} via {process}"
                )
            section.append("")
            section.append(
                "_Action: Review with users — these tools are on "
                "the organisation's blocked list._"
            )
            section.append("{panel}")
            action_sections.append("\n".join(section))

        # Bridge connections
        bridges = [
            f for f in self.all_findings
            if f.source.value == "sentinelone_bridge" and f.user_upn
        ]
        if bridges:
            section = ["{panel:title=SaaS Bridge Connections|borderColor=#ff8b00}"]
            seen_bridges: set[tuple[str | None, str, str]] = set()
            for f in bridges:
                process = f.raw_evidence.get("process_name", "unknown")
                target = f.raw_evidence.get("bridge_target", f.service.name)
                key = (f.user_upn, process, target)
                if key in seen_bridges:
                    continue
                seen_bridges.add(key)
                section.append(
                    f"* {{color:#ff8b00}}(!){{color}} *{f.user_upn}* has "
                    f"{{color:#ff8b00}}{process}{{color}} connecting to *{target}*"
                )
            section.append("")
            section.append(
                "_Action: Investigate — a non-browser application is "
                "accessing your SaaS tools, possibly via an API key or "
                "MCP integration. Review whether this is authorised._"
            )
            section.append("{panel}")
            action_sections.append("\n".join(section))

        # Desktop AI apps
        desktop_ai = [
            f for f in self.all_findings
            if f.source.value == "sentinelone_dns"
            and f.user_upn
            and "[BLOCKED]" not in f.detail
        ]
        ai_app_processes = {
            "claude", "claude.exe", "chatgpt", "chatgpt.exe",
            "copilot.exe", "copilot", "cursor", "cursor.exe",
            "windsurf", "windsurf.exe",
            "ollama", "ollama.exe",
            "code helper", "code helper (renderer)",
            "code", "code.exe",
        }
        desktop_ai_real = [
            f for f in desktop_ai
            if (f.raw_evidence.get("process", "") or "").lower() in ai_app_processes
        ]
        if desktop_ai_real:
            section = ["{panel:title=AI Desktop App Usage}"]
            seen_desktop: set[tuple[str | None, str, str]] = set()
            for f in desktop_ai_real:
                process = f.raw_evidence.get("process", "unknown")
                key = (f.user_upn, f.service.name, process)
                if key in seen_desktop:
                    continue
                seen_desktop.add(key)
                section.append(
                    f"* *{f.user_upn}* is using *{f.service.name}* "
                    f"via the *{process}* desktop app"
                )
            section.append("")
            section.append(
                "_Action: Review — these users have AI desktop "
                "applications installed and actively making API calls. "
                "Verify this aligns with your AI usage policy._"
            )
            section.append("{panel}")
            action_sections.append("\n".join(section))

        if action_sections:
            lines.append("\n".join(action_sections))
        else:
            lines.append("{color:green}No actions required.{color}")

        lines.append("")

        # Errors
        all_errors = [e for r in self.results for e in r.errors]
        if all_errors:
            lines.append("h2. Errors")
            for error in self._sanitize_errors(all_errors):
                lines.append(f"* {{color:red}}{error}{{color}}")
            lines.append("")

        output = "\n".join(lines)
        if output_path:
            self._write_secure_file(output_path, output)
        else:
            print(output)

    def _generate_json(self, output_path: Optional[str] = None) -> None:
        data = {
            "classification": "CONFIDENTIAL — Contains employee names and device identifiers",
            "generated_at": datetime.now().isoformat(),
            "scanner_results": [
                {
                    "scanner": r.scanner_name,
                    "finding_count": r.finding_count,
                    "errors": self._sanitize_errors(r.errors),
                    "skipped": r.skipped_reason,
                    "duration_seconds": r.duration_seconds,
                }
                for r in self.results
            ],
            "note": "Each entry is one user/endpoint, not one per event. occurrence_count carries how many, in the unit named by occurrence_unit (sign-ins, devices, signup emails); it is 1 for sources that do not aggregate.",
            "findings": [
                {
                    "service": f.service.name,
                    "vendor": f.service.vendor,
                    "category": f.service.category,
                    "risk_tier": f.risk_tier,
                    "source": f.source.value,
                    "user_upn": f.user_upn,
                    "device_name": f.device_name,
                    "detail": f.detail,
                    "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                    "occurrence_count": f.occurrence_count,
                    "occurrence_unit": occurrence_unit(f.source),
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                    "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                }
                for f in self.all_findings
            ],
        }

        output = json.dumps(data, indent=2)
        if output_path:
            self._write_secure_file(output_path, output)
        else:
            print(output)

    def _generate_csv(self, output_path: Optional[str] = None) -> None:
        import csv
        import io

        headers = [
            "service", "vendor", "category", "risk_tier", "source",
            "user_upn", "device_name", "detail",
            "occurrence_count", "occurrence_unit",
            "first_seen", "last_seen",
        ]

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=headers)
        writer.writeheader()

        for f in self.all_findings:
            writer.writerow({
                "service": f.service.name,
                "vendor": f.service.vendor,
                "category": f.service.category,
                "risk_tier": f.risk_tier,
                "source": f.source.value,
                "user_upn": f.user_upn or "",
                "device_name": f.device_name or "",
                "detail": f.detail,
                "occurrence_count": f.occurrence_count,
                "occurrence_unit": occurrence_unit(f.source),
                "first_seen": f.first_seen.isoformat() if f.first_seen else "",
                "last_seen": f.last_seen.isoformat() if f.last_seen else "",
            })

        output = buffer.getvalue()
        if output_path:
            self._write_secure_file(output_path, output)
        else:
            print(output)

    @staticmethod
    def _write_secure_file(path: str, content: str) -> None:
        """Write output file with restricted permissions (owner-only)."""
        import stat
        with open(path, "w") as f:
            f.write(content)
        try:
            Path(path).chmod(stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, AttributeError):
            pass

    @staticmethod
    def _sanitize_errors(errors: list[str]) -> list[str]:
        """Remove full API URLs from error messages to avoid leaking
        internal hostnames and instance identifiers in reports."""
        import re
        sanitized = []
        for error in errors:
            # Strip full URLs, keep just the status code and path
            cleaned = re.sub(
                r"https?://[^/]+(/[^\s'\"]*)",
                r"<redacted>\1",
                error,
            )
            sanitized.append(cleaned)
        return sanitized