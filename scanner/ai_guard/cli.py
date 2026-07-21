"""CLI entry point for ai-guard.

Usage:
    ai-guard scan                    Run all enabled scanners
    ai-guard scan --scanner entra    Run a specific scanner
    ai-guard mcp-scan <config>       Standalone MCP security assessment
    ai-guard registry                Show loaded AI service registry
    ai-guard discover                Keyword DNS sweep for unknown AI tools
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ai_guard import __version__
from ai_guard.config import Config
from ai_guard.registry import Registry
from ai_guard.report import ReportGenerator
from ai_guard.utils.audit import log_mcp_scan, log_scan_complete, log_scan_start


console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to policy config YAML (default: ./policy.yaml)",
)
@click.option(
    "--env-file", "-e",
    type=click.Path(),
    default=".env",
    show_default=True,
    help="Path to .env file for API credentials.",
)
@click.pass_context
def main(ctx, config, env_file):
    """AI Guard — Shadow AI discovery and MCP security scanner."""
    # Auto-load .env file if it exists
    env_path = Path(env_file)
    if env_path.exists():
        # Check file permissions before loading
        from ai_guard.utils.auth import check_env_file_permissions
        perm_warning = check_env_file_permissions(str(env_path))
        if perm_warning:
            console.print(f"[yellow]{perm_warning}[/yellow]")

        load_dotenv(env_path, override=False)
        console.print(f"[dim]Loaded credentials from {env_path}[/dim]")
    elif env_file != ".env":
        # Only warn if they explicitly specified a non-default path
        console.print(f"[yellow]Env file not found: {env_path}[/yellow]")
    ctx.ensure_object(dict)

    if config:
        ctx.obj["config"] = Config.from_file(Path(config))
    else:
        # Try default locations
        for default_path in [Path("policy.yaml"), Path("ai-guard.yaml")]:
            if default_path.exists():
                ctx.obj["config"] = Config.from_file(default_path)
                break
        else:
            ctx.obj["config"] = Config.default()

    ctx.obj["registry"] = Registry()


@main.command()
@click.option(
    "--scanner", "-s",
    multiple=True,
    help="Run specific scanner(s) only. Can be repeated.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "json", "csv", "confluence"]),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path (for json/csv).",
)
@click.option(
    "--demo",
    is_flag=True,
    default=False,
    help="Run with synthetic fixture data (no API calls).",
)
@click.pass_context
def scan(ctx, scanner, output_format, output, demo):
    """Run shadow AI discovery scanners."""
    registry: Registry = ctx.obj["registry"]

    if demo:
        config = _load_demo_config()
        ctx.obj["config"] = config
    else:
        config = ctx.obj["config"]

    from ai_guard.scanners import ALL_SCANNERS

    # Demo mode: use fixture scanners
    if demo:
        from ai_guard.scanners.demo import load_demo_scanners

        console.print("\n[bold yellow]Running in demo mode — all data is synthetic.[/bold yellow]\n")
        console.print(f"[bold]AI Guard v{__version__}[/bold]")
        console.print(f"Registry: {registry.stats['total_services']} AI services indexed")

        demo_scanners = load_demo_scanners(registry)
        scanner_names = [s.name for s in demo_scanners]
        console.print(f"Scanners: {', '.join(scanner_names)}\n")

        log_scan_start(scanners=scanner_names, config_path="demo")

        results = []
        for scanner_instance in demo_scanners:
            ok, msg = scanner_instance.check_prerequisites()
            if not ok:
                console.print(f"  [yellow]⏭ {scanner_instance.name}: {msg}[/yellow]")
                from ai_guard.scanners.base import ScanResult
                results.append(ScanResult(scanner_name=scanner_instance.name, skipped_reason=msg))
                continue

            console.print(f"  [blue]⟳ {scanner_instance.name}: scanning...[/blue]", end="")
            result = asyncio.run(scanner_instance.scan())
            results.append(result)
            console.print(f"\r  [green]✓ {scanner_instance.name}: {result.finding_count} findings ({result.duration_seconds:.1f}s)[/green]")

    else:
        # Determine which scanners to run
        if scanner:
            scanner_names = list(scanner)
        else:
            scanner_names = [
                name for name, sconf in config.scanners.items()
                if sconf.enabled
            ]

        if not scanner_names:
            console.print(
                "[yellow]No scanners enabled. "
                "Enable scanners in policy.yaml or use --scanner flag.[/yellow]\n"
                "Available scanners: " + ", ".join(ALL_SCANNERS.keys())
            )
            sys.exit(1)

        log_scan_start(scanners=scanner_names, config_path=str(ctx.parent.params.get("config") or "default"))

        console.print(f"\n[bold]AI Guard v{__version__}[/bold]")
        console.print(f"Registry: {registry.stats['total_services']} AI services indexed")
        console.print(f"Scanners: {', '.join(scanner_names)}\n")

        results = []

        for name in scanner_names:
            if name not in ALL_SCANNERS:
                console.print(f"[red]Unknown scanner: {name}[/red]")
                continue

            scanner_cls = ALL_SCANNERS[name]
            scanner_config = config.scanners.get(name, config.scanners.get(name))

            if not scanner_config:
                from ai_guard.config import ScannerConfig
                scanner_config = ScannerConfig(enabled=True)

            scanner_instance = scanner_cls(registry=registry, config=scanner_config)

            # Check prerequisites
            ok, msg = scanner_instance.check_prerequisites()
            if not ok:
                console.print(f"  [yellow]⏭ {name}: {msg}[/yellow]")
                from ai_guard.scanners.base import ScanResult
                results.append(ScanResult(scanner_name=name, skipped_reason=msg))
                continue

            console.print(f"  [blue]⟳ {name}: scanning...[/blue]", end="")

            result = asyncio.run(scanner_instance.scan())
            results.append(result)

            if result.errors:
                console.print(f"\r  [red]✗ {name}: {result.finding_count} findings, {len(result.errors)} error(s)[/red]")
            else:
                console.print(f"\r  [green]✓ {name}: {result.finding_count} findings ({result.duration_seconds:.1f}s)[/green]")

    # Apply policy overrides to risk tiers
    for result in results:
        for finding in result.findings:
            override = config.policy.risk_overrides.get(finding.service.name)
            if override:
                finding.risk_tier = override

            if finding.service.name in config.policy.approved_services:
                finding.detail = f"[APPROVED] {finding.detail}"

            if finding.service.name in config.policy.blocked_services:
                finding.risk_tier = "high"
                finding.detail = f"[BLOCKED] {finding.detail}"

    # Generate report
    report = ReportGenerator(
        results=results,
        output_format=output_format,
    )
    report.generate(output_path=output)

    # Audit trail
    total_duration = sum(r.duration_seconds for r in results)
    log_scan_complete(
        scanners=scanner_names,
        finding_counts={r.scanner_name: r.finding_count for r in results},
        error_counts={r.scanner_name: len(r.errors) for r in results if r.errors},
        duration_seconds=total_duration,
        output_path=output,
    )


@main.command("mcp-scan")
@click.argument("config_path", type=click.Path(exists=True))
@click.pass_context
def mcp_scan(ctx, config_path):
    """Standalone MCP server security assessment."""
    registry: Registry = ctx.obj["registry"]

    log_mcp_scan(config_path=config_path)

    from ai_guard.config import ScannerConfig
    from ai_guard.scanners.mcp import MCPScanner, RiskLevel, Verdict

    scanner = MCPScanner(
        registry=registry,
        config=ScannerConfig(enabled=True),
    )

    assessment = scanner.assess_from_file(Path(config_path))

    # Display assessment
    verdict_colors = {
        Verdict.BLOCK: "red",
        Verdict.ALLOW_WITH_CONDITIONS: "yellow",
        Verdict.ALLOW: "green",
    }

    console.print(f"\n[bold]MCP Security Assessment: {assessment.server_name}[/bold]")
    console.print(f"Description: {assessment.server_description}")
    console.print(f"Auth method: {assessment.auth_method}")
    console.print(f"Tools: {assessment.tool_count} total ({len(assessment.read_tools)} read, {len(assessment.write_tools)} write)")

    if assessment.oauth_scopes:
        console.print(f"OAuth scopes: {', '.join(assessment.oauth_scopes)}")

    color = verdict_colors.get(assessment.verdict, "white")
    console.print(f"\n[bold {color}]Verdict: {assessment.verdict.value.upper()}[/bold {color}]")

    if assessment.risks:
        console.print(f"\n[bold]Risks ({len(assessment.risks)})[/bold]")

        risk_table = Table(show_header=True, header_style="bold")
        risk_table.add_column("Level")
        risk_table.add_column("Category")
        risk_table.add_column("Risk")
        risk_table.add_column("Recommendation")

        level_colors = {
            RiskLevel.CRITICAL: "red bold",
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.INFO: "dim",
        }

        for risk in sorted(assessment.risks, key=lambda r: list(RiskLevel).index(r.level)):
            style = level_colors.get(risk.level, "white")
            risk_table.add_row(
                Text(risk.level.value.upper(), style=style),
                risk.category,
                f"{risk.title}\n{risk.detail}",
                risk.recommendation,
            )

        console.print(risk_table)
    else:
        console.print("\n[green]No risks identified.[/green]")

    console.print()


@main.command()
@click.pass_context
def registry(ctx):
    """Display the loaded AI service registry."""
    reg: Registry = ctx.obj["registry"]

    console.print(f"\n[bold]AI Service Registry[/bold]")
    console.print(f"Services: {reg.stats['total_services']}")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Service")
    table.add_column("Vendor")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Domains")
    table.add_column("Detection Methods")

    for svc in sorted(reg.services, key=lambda s: (s.risk_tier, s.name)):
        methods = []
        if svc.domains:
            methods.append("DNS")
        if svc.entra_app_ids:
            methods.append("Entra")
        if svc.email_domains:
            methods.append("Email")
        if svc.desktop_apps.get("windows") or svc.desktop_apps.get("macos"):
            methods.append("App")
        if any(svc.browser_extensions.values()):
            methods.append("Ext")
        if svc.mcp_identifiers:
            methods.append("MCP")

        risk_color = RISK_COLORS.get(svc.risk_tier, "white")

        table.add_row(
            svc.name,
            svc.vendor,
            svc.category,
            Text(svc.risk_tier.upper(), style=risk_color),
            ", ".join(svc.domains[:2]) + ("..." if len(svc.domains) > 2 else ""),
            ", ".join(methods),
        )

    console.print(table)
    console.print()


@main.command()
@click.pass_context
def init(ctx):
    """Set up AI Guard in the current directory.

    Creates .env from template (with restricted permissions) and copies
    the default policy.yaml.
    """
    import shutil

    package_dir = Path(__file__).parent.parent

    # Create .env from template
    env_file = Path(".env")
    env_example = package_dir / ".env.example"

    if env_file.exists():
        console.print("[yellow].env already exists — skipping[/yellow]")
        # Still check permissions on existing file
        _secure_env_file(env_file)
    elif env_example.exists():
        shutil.copy(env_example, env_file)
        _secure_env_file(env_file)
        console.print("[green]Created .env with restricted permissions (600) — fill in your API credentials[/green]")
    else:
        console.print("[yellow].env.example not found in package — create .env manually[/yellow]")

    # Copy policy.yaml if not present
    policy_file = Path("policy.yaml")
    policy_template = package_dir / "policy.yaml"

    if policy_file.exists():
        console.print("[yellow]policy.yaml already exists — skipping[/yellow]")
    elif policy_template.exists():
        shutil.copy(policy_template, policy_file)
        console.print("[green]Created policy.yaml — edit to enable scanners and set your policy[/green]")

    console.print(
        "\n[bold]Next steps:[/bold]\n"
        "  1. Edit .env with your API credentials\n"
        "  2. Edit policy.yaml to enable scanners and set blocked/approved services\n"
        "  3. Run: ai-guard scan\n"
    )


def _secure_env_file(path: Path) -> None:
    """Set .env file to owner-only read/write (chmod 600)."""
    try:
        import stat
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, AttributeError):
        pass  # Windows or permission error — skip


@main.command()
@click.option(
    "--lookback", "-l",
    type=int,
    default=14,
    show_default=True,
    help="Days of DNS history to search (max 14).",
)
@click.pass_context
def discover(ctx, lookback):
    """Keyword DNS sweep to find unknown AI tools.

    Queries SentinelOne Deep Visibility for DNS lookups containing
    common AI-related keywords, then filters out domains already in
    the registry and common false positives. What remains is a list
    of potentially unknown AI tools, grouped by observation frequency.

    Requires AIGUARD_S1_BASE_URL and AIGUARD_S1_API_TOKEN.
    """
    from ai_guard.discover import AI_KEYWORDS, run_discover
    from ai_guard.utils.auth import AuthError, SentinelOneAuth

    registry: Registry = ctx.obj["registry"]

    # Authenticate
    try:
        auth = SentinelOneAuth.from_env("AIGUARD_S1")
    except AuthError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]AI Guard — Discovery Sweep[/bold]")
    console.print(f"Keywords: {', '.join(AI_KEYWORDS)}")
    console.print(f"Lookback: {lookback} days")
    console.print(f"Registry: {registry.stats['total_services']} known services ({registry.stats['indexed_domains']} domains filtered)\n")
    console.print("[blue]Running keyword DNS sweep via SentinelOne Deep Visibility...[/blue]")
    console.print("[dim]This may take several minutes due to API rate limits.[/dim]\n")

    domain_counts, errors = asyncio.run(
        run_discover(auth=auth, registry=registry, lookback_days=lookback)
    )

    # Show errors if any
    if errors:
        console.print(f"[yellow]Encountered {len(errors)} error(s):[/yellow]")
        for err in errors:
            console.print(f"  [dim]{err}[/dim]")
        console.print()

    # Display results
    if not domain_counts:
        console.print("[green]No unknown AI-related domains found.[/green]\n")
        return

    console.print(f"[bold]Potentially unknown AI-related domains ({len(domain_counts)} unique):[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Domain", style="cyan")
    table.add_column("Hits", justify="right")

    for domain, count in domain_counts.most_common():
        table.add_row(domain, str(count))

    console.print(table)
    console.print(
        f"\n[dim]These domains matched AI keywords but are not in the registry.\n"
        f"Review and add confirmed AI services to ai_services.yaml.[/dim]\n"
    )


RISK_COLORS = {
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


def _load_demo_config() -> Config:
    """Load the demo policy file bundled with the project."""
    demo_policy = Path(__file__).parent.parent / "policies" / "demo.yaml"
    if demo_policy.exists():
        return Config.from_file(demo_policy)
    # Fallback: default config with ChatGPT blocked, Copilot approved
    from ai_guard.config import PolicyConfig
    return Config(
        scanners={},
        policy=PolicyConfig(
            blocked_services=["ChatGPT"],
            approved_services=["GitHub Copilot"],
        ),
    )


if __name__ == "__main__":
    main()
