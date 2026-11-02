import json
import os
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .adapters import OPTIONAL, REGISTRY, validate_nuclei_templates
from .engine import get_scan, list_scans, load_config, plan, run_scan
from .reporting import render_report

app = typer.Typer(help="RedForge VAPT Engine")
tools_app = typer.Typer()
scans_app = typer.Typer()
app.add_typer(tools_app, name="tools")
app.add_typer(scans_app, name="scans")
console = Console()


@app.command()
def doctor():
    """Check dependencies and scanner availability."""
    table = Table("Component", "Status")
    for name, adapter in REGISTRY.items():
        if not adapter.available():
            status = "unavailable"
        elif name == "nuclei" and not os.environ.get("REDFORGE_NUCLEI_SAFE_TEMPLATES"):
            status = "installed; safe templates not configured"
        elif name == "nuclei":
            try:
                validate_nuclei_templates(os.environ["REDFORGE_NUCLEI_SAFE_TEMPLATES"])
                status = "ready"
            except (ValueError, OSError, yaml.YAMLError) as exc:
                status = f"unconfigured: {exc}"
        elif name == "semgrep" and not os.environ.get("REDFORGE_SEMGREP_RULES"):
            status = "installed; local rules not configured"
        else:
            status = "ready"
        table.add_row(name, status)
    for name in OPTIONAL:
        table.add_row(name, "planned")
    table.add_row("database", os.environ.get("REDFORGE_DATABASE_URL", "sqlite:///./redforge.db"))
    console.print(table)


@tools_app.command("list")
def tools_list():
    doctor()


@app.command()
def scan(
    config: Path = typer.Option(..., exists=True, readable=True),
    profile: str = typer.Option("passive"),
    report: str = typer.Option("html,json"),
    dry_run: bool = typer.Option(False),
    fixture_dir: Path | None = typer.Option(None, help="Offline fixture directory; no scanner process runs"),
):
    """Validate scope, execute permitted scanners, and generate reports."""
    try:
        engagement = load_config(config)
        actions = plan(engagement, profile, fixture=fixture_dir is not None)
        console.print_json(json.dumps({"engagement": engagement.id, "profile": profile, "mode": "fixture" if fixture_dir else "live", "actions": actions}))
        if dry_run:
            return
        scan_id, status, statuses = run_scan(engagement, profile, fixture_dir=fixture_dir)
        formats = [item.strip() for item in report.split(",") if item.strip()]
        paths = [str(render_report(scan_id, fmt)) for fmt in formats]
        console.print_json(json.dumps({"scan_id": scan_id, "status": status, "tools": statuses, "reports": paths}))
        if status == "failed":
            raise typer.Exit(2)
        if status == "partial":
            raise typer.Exit(3)
    except (ValueError, TypeError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@scans_app.command("list")
def scans_list():
    console.print_json(json.dumps(list_scans()))


@scans_app.command("status")
def scans_status(scan_id: str):
    try:
        console.print_json(json.dumps(get_scan(scan_id)))
    except KeyError:
        raise typer.Exit(1) from None


@app.command("report")
def report_command(scan_id: str, format: str = typer.Option("html")):
    try:
        console.print(str(render_report(scan_id, format)))
    except (KeyError, ValueError, RuntimeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    uvicorn.run("redforge_vapt.api:app", host=host, port=port)


if __name__ == "__main__":
    app()
