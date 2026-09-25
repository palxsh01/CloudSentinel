"""Whole pipeline: registry -> runner -> reporter, against a mocked account.

Stands in for the real-account validation in Phase 8 until an AWS account
exists. As checks are added, extend `plant_misconfigurations` so this test
keeps asserting that every implemented check fires.
"""

from rich.console import Console

from scanner import report, runner
from scanner.checks import REGISTRY
from scanner.models import Severity
from tests.conftest import make_bucket

IMPLEMENTED = {"S3.1", "S3.2", "S3.3", "S3.4"}


INSECURE_BUCKET = "cloudsentinel-public-bucket"
HARDENED_BUCKET = "cloudsentinel-hardened-bucket"


def plant_misconfigurations(aws):
    # Fails every S3 check.
    make_bucket(aws, INSECURE_BUCKET, public_acl=True)
    # Passes every S3 check — the false-positive control. Logs to itself so no
    # second, unhardened sink bucket is needed.
    make_bucket(
        aws, HARDENED_BUCKET, encrypted=True, versioning="Enabled", log_to=HARDENED_BUCKET
    )


def test_every_registered_check_is_expected_here():
    """Fails when a check is added without extending this test."""
    assert {fn.meta[0] for fn in REGISTRY} == IMPLEMENTED


def test_scan_catches_every_planted_issue(aws):
    plant_misconfigurations(aws)
    findings, errors = runner.run(aws)

    assert errors == []
    assert {f.check_id for f in findings} == IMPLEMENTED, "false negative: a planted issue was missed"
    assert {f.resource for f in findings} == {INSECURE_BUCKET}, "false positive on hardened bucket"


def test_findings_sort_highest_severity_first(aws):
    plant_misconfigurations(aws)
    findings, _ = runner.run(aws)
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), reverse=True
    )
    assert findings[0].severity is Severity.HIGH


def test_service_filter_runs_only_that_service(aws):
    plant_misconfigurations(aws)
    assert runner.run(aws, service="s3")[0]
    assert runner.run(aws, service="iam")[0] == []


def test_a_broken_check_is_reported_without_killing_the_scan(aws, monkeypatch):
    plant_misconfigurations(aws)

    def exploding(_aws):
        raise RuntimeError("boom")
        yield  # pragma: no cover - makes this a generator

    exploding.meta = ("X.1", "s3", Severity.LOW, "Exploding check", "n/a")
    monkeypatch.setattr(runner, "REGISTRY", [*REGISTRY, exploding])

    findings, errors = runner.run(aws)
    assert errors == [("X.1", "RuntimeError: boom")]
    assert {f.check_id for f in findings} == IMPLEMENTED


def test_demo_renders_the_terminal_report(aws, capsys):
    """Run with `pytest -s -k demo` to eyeball the real output."""
    plant_misconfigurations(aws)
    findings, errors = runner.run(aws)
    report.terminal(findings, errors, account_id="123456789012", console=Console(width=100))

    out = capsys.readouterr().out
    print(out)
    assert "HIGH" in out and "S3.1" in out and INSECURE_BUCKET in out
    assert "4 findings: 1 High, 1 Medium, 2 Low" in out
