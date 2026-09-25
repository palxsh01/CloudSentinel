"""Formats findings. Never talks to AWS."""

from rich.console import Console
from rich.table import Table

from .models import Severity

COLOURS = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan"}


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

        counts = {s: sum(f.severity is s for f in findings) for s in reversed(Severity)}
        summary = ", ".join(f"{n} {s.name.title()}" for s, n in counts.items() if n)
        plural = "" if len(findings) == 1 else "s"
        console.print(f"{len(findings)} finding{plural}: {summary}")

    for check_id, message in errors:
        console.print(f"[yellow]![/yellow] {check_id} could not run: {message}")
