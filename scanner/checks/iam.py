"""IAM checks (IAM.1–IAM.4)."""

import csv
import io
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from ..models import Severity
from .base import check

KEY_MAX_AGE = timedelta(days=90)
ROOT_WINDOW = timedelta(days=30)


def _now():
    # One seam so tests can move the clock instead of backdating AWS objects.
    return datetime.now(timezone.utc)


def _paginate(aws, operation, key, **kwargs):
    for page in aws.iam.get_paginator(operation).paginate(**kwargs):
        yield from page[key]


def _as_list(value):
    """IAM policy fields may be a single value or a list of them."""
    return value if isinstance(value, list) else [value]


@check(
    "IAM.1",
    "iam",
    Severity.HIGH,
    "Console user without MFA",
    "Enable an MFA device for the user, or remove their console password if "
    "they only need programmatic access.",
)
def console_users_without_mfa(aws):
    for user in _paginate(aws, "list_users", "Users"):
        name = user["UserName"]
        try:
            aws.iam.get_login_profile(UserName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                continue  # no console password, so MFA on sign-in is moot
            raise
        if not aws.iam.list_mfa_devices(UserName=name)["MFADevices"]:
            yield name, "console password set, no MFA device"


@check(
    "IAM.2",
    "iam",
    Severity.HIGH,
    "Policy grants full admin (*:*)",
    "Replace the wildcard statement with the specific actions and resources "
    "the principal needs.",
)
def wildcard_policies(aws):
    # ponytail: customer-managed policies only. Inline user/group/role policies
    # can also hold *:*; add list_*_policies + get_*_policy walks if needed.
    for policy in _paginate(aws, "list_policies", "Policies", Scope="Local"):
        document = aws.iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )["PolicyVersion"]["Document"]
        for stmt in _as_list(document.get("Statement", [])):
            if (
                stmt.get("Effect") == "Allow"
                and "*" in _as_list(stmt.get("Action", []))
                and "*" in _as_list(stmt.get("Resource", []))
            ):
                yield policy["Arn"], "allows Action '*' on Resource '*'"
                break


@check(
    "IAM.3",
    "iam",
    Severity.MEDIUM,
    "Access key older than 90 days",
    "Create a new access key, move workloads to it, then deactivate and "
    "delete the old one.",
)
def stale_access_keys(aws):
    now = _now()
    for user in _paginate(aws, "list_users", "Users"):
        for key in aws.iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
            age = now - key["CreateDate"]
            # An inactive key can't authenticate, so its age isn't a risk.
            if key["Status"] == "Active" and age > KEY_MAX_AGE:
                yield key["AccessKeyId"], f"{user['UserName']}'s key is {age.days} days old"


def _credential_report(aws):
    # GenerateCredentialReport only builds a report of existing data — it does
    # not change account configuration, and AWS's read-only SecurityAudit
    # policy grants it. Generation is async; a recent report is reused.
    for attempt in range(10):  # backs off 0s, 1s, 2s ... (~45s worst case)
        if aws.iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(attempt)
    content = aws.iam.get_credential_report()["Content"].decode()
    return list(csv.DictReader(io.StringIO(content)))


def _parse_date(value):
    try:
        return datetime.fromisoformat(value)
    except ValueError:  # "N/A", "no_information", "not_supported"
        return None


@check(
    "IAM.4",
    "iam",
    Severity.HIGH,
    "Root account used recently",
    "Stop using the root account for daily work: create an admin IAM user or "
    "role, delete root access keys, and enable root MFA.",
)
def recent_root_usage(aws):
    now = _now()
    for row in _credential_report(aws):
        if row["user"] != "<root_account>":
            continue
        used = {
            "console sign-in": _parse_date(row["password_last_used"]),
            "access key 1": _parse_date(row["access_key_1_last_used_date"]),
            "access key 2": _parse_date(row["access_key_2_last_used_date"]),
        }
        recent = [
            f"{how} {(now - when).days}d ago"
            for how, when in used.items()
            if when and now - when <= ROOT_WINDOW
        ]
        if recent:
            yield "<root_account>", "root used via " + ", ".join(recent)
