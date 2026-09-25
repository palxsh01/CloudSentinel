"""CLI entrypoint."""

import click

from .aws_client import AWS
from . import report, runner


@click.group()
def cli():
    """CloudSentinel — read-only AWS security scanner."""


@cli.command()
@click.option("--service", type=click.Choice(["s3", "iam", "ec2", "cloudtrail"]))
@click.option("--profile", help="AWS profile name.")
@click.option("--region", help="AWS region.")
def scan(service, profile, region):
    """Scan an AWS account for security misconfigurations."""
    aws = AWS(profile=profile, region=region)
    findings, errors = runner.run(aws, service=service)
    report.terminal(findings, errors, account_id=aws.account_id)


if __name__ == "__main__":
    cli()
