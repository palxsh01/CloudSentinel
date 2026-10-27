"""Formats findings. Never talks to AWS."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table

from .models import Severity

COLOURS = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan"}
TEMPLATES = Path(__file__).resolve().parent / "templates"


def _counts(findings):
    """{"HIGH": n, "MEDIUM": n, "LOW": n}, highest severity first."""
    return {s.name: sum(f.severity is s for f in findings) for s in reversed(Severity)}


def _document(findings, errors, account_id):
    """The plain-data report that the JSON and HTML outputs share."""
    return {
        "account": account_id or "unknown",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": _counts(findings),
        "findings": [{**asdict(f), "severity": f.severity.name} for f in findings],
        "errors": [{"check_id": c, "message": m} for c, m in errors],
    }


def as_json(findings, errors=(), account_id=None):
    return json.dumps(_document(findings, errors, account_id), indent=2)


def as_html(findings, errors=(), account_id=None):
    # Autoescape matters: bucket, user and policy names come from the scanned
    # account and must not be able to inject markup into the report.
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    return env.get_template("report.html.j2").render(**_document(findings, errors, account_id))


def terminal(findings, errors=(), account_id=None, console=None):
    console = console or Console()
    console.print(f"\n[bold]CloudSentinel scan report[/bold] — account: {account_id or 'unknown'}")

    if not findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(show_lines=False, header_style="bold")
        for column in ("Severity", "Check", "Resource", "Detail"):
            table.add_column(column, overflow="fold")
        for f in findings:
            table.add_row(
                f"[{COLOURS[f.severity]}]{f.severity.name}[/]",
                f.check_id,
                f.resource,
                f.detail,
            )
        console.print(table)

        summary = ", ".join(f"{n} {name.title()}" for name, n in _counts(findings).items() if n)
        plural = "" if len(findings) == 1 else "s"
        console.print(f"{len(findings)} finding{plural}: {summary}")

    for check_id, message in errors:
        console.print(f"[yellow]![/yellow] {check_id} could not run: {message}")
