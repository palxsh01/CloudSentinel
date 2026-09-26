"""Whole pipeline: registry -> runner -> reporter, against a mocked account.

Stands in for the real-account validation in Phase 8 until an AWS account
exists. As checks are added, extend the `planted` fixture so this test
keeps asserting that every implemented check fires.
"""

from datetime import timedelta

import pytest
from rich.console import Console

from scanner import report, runner
from scanner.checks import REGISTRY
from scanner.checks import iam as iam_checks
from scanner.models import Severity
from tests.conftest import (
    fake_root_row,
    make_bucket,
    make_policy,
    make_security_group,
    make_user,
    make_volume,
)

IMPLEMENTED = {
    *("S3.1", "S3.2", "S3.3", "S3.4"),
    *("IAM.1", "IAM.2", "IAM.3", "IAM.4"),
    *("EC2.1", "EC2.2", "EC2.3"),
}


INSECURE_BUCKET = "cloudsentinel-public-bucket"
HARDENED_BUCKET = "cloudsentinel-hardened-bucket"


INSECURE_USER = "cloudsentinel-no-mfa"
HARDENED_USER = "cloudsentinel-mfa"


@pytest.fixture
def planted(aws, monkeypatch):
    """Plant every misconfiguration, plus a hardened twin of each resource.

    Returns the set of resources the scan must flag — and nothing else.
    """
    # Fails every S3 check.
    make_bucket(aws, INSECURE_BUCKET, public_acl=True)
    # Passes every S3 check — the false-positive control. Logs to itself so no
    # second, unhardened sink bucket is needed.
    make_bucket(
        aws, HARDENED_BUCKET, encrypted=True, versioning="Enabled", log_to=HARDENED_BUCKET
    )

    # IAM.1 + IAM.3: console without MFA, holding a key that will be 91 days old.
    stale_key = make_user(aws, INSECURE_USER, console=True, access_key=True)
    make_user(aws, HARDENED_USER, console=True, mfa=True)
    admin_policy = make_policy(aws, "cloudsentinel-admin", {"Effect": "Allow", "Action": "*", "Resource": "*"})
    make_policy(aws, "cloudsentinel-scoped", {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    later = iam_checks._now() + timedelta(days=91)
    monkeypatch.setattr(iam_checks, "_now", lambda: later)
    # IAM.4: root signed in two days before that moved clock.
    fake_root_row(aws, monkeypatch, password_last_used=(later - timedelta(days=2)).isoformat())

    # EC2.1 + EC2.2: one group exposing SSH and MySQL. The hardened twin is
    # world-open only on HTTPS, with SSH limited to an office range.
    open_group = make_security_group(
        aws, "cloudsentinel-open", ("tcp", 22, 22, "0.0.0.0/0"), ("tcp", 3306, 3306, "0.0.0.0/0")
    )
    make_security_group(
        aws, "cloudsentinel-web", ("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 22, 22, "203.0.113.0/24")
    )
    # EC2.3
    plain_volume = make_volume(aws)
    make_volume(aws, encrypted=True)

    return {
        INSECURE_BUCKET,
        INSECURE_USER,
        stale_key,
        admin_policy,
        "<root_account>",
        f"{open_group} (cloudsentinel-open)",
        plain_volume,
    }


def test_every_registered_check_is_expected_here():
    """Fails when a check is added without extending this test."""
    assert {fn.meta[0] for fn in REGISTRY} == IMPLEMENTED


def test_scan_catches_every_planted_issue(aws, planted):
    findings, errors = runner.run(aws)

    assert errors == []
    assert {f.check_id for f in findings} == IMPLEMENTED, "false negative: a planted issue was missed"
    assert {f.resource for f in findings} == planted, "false positive on a hardened resource"


def test_findings_sort_highest_severity_first(aws, planted):
    findings, _ = runner.run(aws)
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), reverse=True
    )
    assert findings[0].severity is Severity.HIGH


def test_service_filter_runs_only_that_service(aws, planted):
    for service in ("s3", "iam", "ec2"):
        findings, _ = runner.run(aws, service=service)
        assert findings and {f.service for f in findings} == {service}
    assert runner.run(aws, service="cloudtrail")[0] == []


def test_a_broken_check_is_reported_without_killing_the_scan(aws, planted, monkeypatch):

    def exploding(_aws):
        raise RuntimeError("boom")
        yield  # pragma: no cover - makes this a generator

    exploding.meta = ("X.1", "s3", Severity.LOW, "Exploding check", "n/a")
    monkeypatch.setattr(runner, "REGISTRY", [*REGISTRY, exploding])

    findings, errors = runner.run(aws)
    assert errors == [("X.1", "RuntimeError: boom")]
    assert {f.check_id for f in findings} == IMPLEMENTED


def test_demo_renders_the_terminal_report(aws, planted, capsys):
    """Run with `pytest -s -k demo` to eyeball the real output."""
    findings, errors = runner.run(aws)
    report.terminal(findings, errors, account_id="123456789012", console=Console(width=100))

    out = capsys.readouterr().out
    print(out)
    assert "HIGH" in out and "S3.1" in out and INSECURE_BUCKET in out
    assert "11 findings: 6 High, 3 Medium, 2 Low" in out
