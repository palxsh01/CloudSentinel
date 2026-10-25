"""CLI entrypoint."""

from pathlib import Path

import click

from .aws_client import AWS
from .models import Severity
from . import report, runner


@click.group()
def cli():
    """CloudSentinel — read-only AWS security scanner."""


@cli.command()
@click.option("--service", type=click.Choice(["s3", "iam", "ec2", "cloudtrail"]))
@click.option("--profile", help="AWS profile name.")
@click.option("--region", help="AWS region.")
@click.option("--output", type=click.Choice(["terminal", "json", "html"]), default="terminal", show_default=True)
@click.option("--file", "path", type=click.Path(dir_okay=False), help="Write the json/html report here instead of stdout.")
def scan(service, profile, region, output, path):
    """Scan an AWS account for security misconfigurations.

    Exits 1 when any HIGH finding is present, so a CI step fails on it.
    """
    if path and output == "terminal":
        raise click.UsageError("--file needs --output json or html")
    aws = AWS(profile=profile, region=region)
    findings, errors = runner.run(aws, service=service)

    if output == "terminal":
        report.terminal(findings, errors, account_id=aws.account_id)
    else:
        render = report.as_json if output == "json" else report.as_html
        text = render(findings, errors, account_id=aws.account_id)
        if path:
            Path(path).write_text(text)
            click.echo(f"Wrote {output} report to {path}", err=True)
        else:
            click.echo(text)
        # Keep check failures visible even when the report goes to a file.
        for check_id, message in errors:
            click.echo(f"! {check_id} could not run: {message}", err=True)

    if any(f.severity is Severity.HIGH for f in findings):
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
