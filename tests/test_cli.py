"""The CLI: output modes, --file, --service and the exit code."""

import json

from click.testing import CliRunner

from scanner import report, runner
from scanner.checks import REGISTRY
from scanner.main import cli
from scanner.models import Finding, Severity
from tests.conftest import make_bucket

ACCOUNT = "123456789012"  # moto's fixed account id


def scan(*args):
    return CliRunner().invoke(cli, ["scan", "--service", "s3", *args])


def test_json_output(aws):
    make_bucket(aws, "public-bucket", public_acl=True)
    result = scan("--output", "json")

    doc = json.loads(result.stdout)
    assert doc["account"] == ACCOUNT
    assert {f["check_id"] for f in doc["findings"]} == {"S3.1", "S3.2", "S3.3", "S3.4"}
    assert doc["summary"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 2}
    assert doc["findings"][0]["severity"] == "HIGH" and doc["errors"] == []


def test_html_output_to_file(aws, tmp_path):
    make_bucket(aws, "public-bucket", public_acl=True)
    out = tmp_path / "report.html"
    result = scan("--output", "html", "--file", str(out))

    assert result.stdout == ""
    html = out.read_text()
    assert "S3.1" in html and "public-bucket" in html and ACCOUNT in html
    assert "4 findings" in html


def test_terminal_output_runs_only_the_chosen_service(aws):
    make_bucket(aws, "public-bucket", public_acl=True)
    result = scan()
    assert "S3.1" in result.stdout and "4 findings" in result.stdout
    assert not any(cid in result.stdout for cid in ("IAM.", "EC2.", "CT."))


def test_exit_code_is_1_only_when_a_high_finding_exists(aws):
    make_bucket(aws, "private-bucket")  # MEDIUM/LOW findings only
    assert scan().exit_code == 0
    make_bucket(aws, "public-bucket", public_acl=True)
    assert scan().exit_code == 1
    assert scan("--output", "json").exit_code == 1


def test_file_without_a_report_format_is_a_usage_error(aws, tmp_path):
    result = scan("--file", str(tmp_path / "x"))
    assert result.exit_code == 2 and "--file needs" in result.stderr


def test_failed_checks_reach_stderr_and_the_report(aws, monkeypatch):
    def exploding(_aws):
        raise RuntimeError("boom")
        yield  # pragma: no cover

    exploding.meta = ("X.1", "s3", Severity.LOW, "Exploding check", "n/a")
    monkeypatch.setattr(runner, "REGISTRY", [*REGISTRY, exploding])
    result = scan("--output", "json")

    assert "X.1 could not run: RuntimeError: boom" in result.stderr
    assert json.loads(result.stdout)["errors"] == [{"check_id": "X.1", "message": "RuntimeError: boom"}]


def test_html_escapes_resource_names():
    hostile = Finding("S3.1", "s3", Severity.HIGH, "t", "<script>alert(1)</script>", "d", "r")
    html = report.as_html([hostile], account_id=ACCOUNT)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
