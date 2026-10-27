"""CLI entrypoint."""

from contextlib import nullcontext
from pathlib import Path

import click
from botocore.exceptions import BotoCoreError, ClientError

from .aws_client import AWS
from .models import Severity
from . import report, runner
from .checks import REGISTRY


@click.group()
def cli():
    """CloudSentinel — read-only AWS security scanner."""


@cli.command()
@click.option("--service", type=click.Choice(["s3", "iam", "ec2", "cloudtrail"]), help="Run only this service's checks (default: all 14).")
@click.option("--profile", help="AWS profile name (default: boto3's usual credential chain).")
@click.option("--region", help="Session region. EC2/CloudTrail still sweep every enabled region.")
@click.option("--output", type=click.Choice(["terminal", "json", "html"]), default="terminal", show_default=True)
@click.option("--file", "path", type=click.Path(dir_okay=False), help="Write the json/html report here instead of stdout.")
@click.option("--demo", is_flag=True, help="Scan a mocked account with every issue planted (moto). No AWS login or cost.")
def scan(service, profile, region, output, path, demo):
    """Scan an AWS account for security misconfigurations.

    Exits 1 when any HIGH finding is present, so a CI step fails on it.
    """
    if path and output == "terminal":
        raise click.UsageError("--file needs --output json or html")
    if demo and (profile or region):
        raise click.UsageError("--demo can't be combined with --profile or --region")
    if demo:
        from .demo import account  # imported here so real scans never load moto
        click.echo("Demo: scanning a mocked AWS account (moto) with every issue planted. Nothing real is touched.", err=True)
        session = account()
    else:
        session = nullcontext(AWS(profile=profile, region=region))
    with session as aws:
        # Check the login before any scanning, so a missing or expired login is one
        # clear line instead of a traceback (or 14 identical check failures).
        try:
            account_id = aws.account_id
        except (BotoCoreError, ClientError) as exc:
            click.echo(f"Error: no AWS account is logged in. Please log in first (e.g. `aws login`).\n  Reason: {exc}", err=True)
            raise SystemExit(2)
        findings, errors = runner.run(aws, service=service)

        if output == "terminal":
            report.terminal(findings, errors, account_id=account_id)
        else:
            render = report.as_json if output == "json" else report.as_html
            text = render(findings, errors, account_id=account_id)
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


GUIDE = """
Running a real scan
  1. Log in to AWS. Any of these works:
       aws login                        (or: aws sso login --profile <name>)
       export AWS_PROFILE=<name>
       export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
  2. Give that identity only iam/scanner-readonly-policy.json (30 read-only
     actions). The scanner never changes anything in the account.
  3. Run it:
       cs scan
  If no login is found, cs prints one line saying so and exits 2.

Running a demo scan (mocked with moto, no AWS account or cost)
       cs scan --demo
  This plants one issue per check in a fake in-memory account and runs the
  real scan on it: 14 findings (7 High, 4 Medium, 3 Low). --service, --output
  and --file work as usual; --profile and --region don't apply.

Examples
  cs scan                                      full scan, terminal table
  cs scan --service s3                         only the 4 S3 checks
  cs scan --output json --file findings.json   JSON report to a file
  cs scan --output html --file report.html     HTML report to a file
  cs scan --profile audit --region eu-west-1   named profile and region
  cs scan --demo --service iam --output json   demo, IAM checks only, as JSON

Exit codes
  0  no HIGH findings
  1  at least one HIGH finding (makes a CI step fail)
  2  not logged in to AWS, or bad usage

"""


@cli.command("help")
@click.pass_context
def help_(ctx):
    """Show every command and option, and how to run a real or demo scan."""
    root = ctx.parent
    click.echo(cli.get_help(root))
    click.echo("\n" + "=" * 70 + "\n")
    with click.Context(scan, info_name="scan", parent=root) as sub:
        click.echo(scan.get_help(sub))
    click.echo(GUIDE.rstrip("\n") + f"\n\nChecks ({len(REGISTRY)})")
    for check_id, _service, severity, title, _fix in sorted(fn.meta for fn in REGISTRY):
        click.echo(f"  {check_id:<6} {severity.name:<6}  {title}")


if __name__ == "__main__":
    cli()
