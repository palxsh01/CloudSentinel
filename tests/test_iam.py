import json
from datetime import timedelta

from scanner.checks import iam as iam_checks
from scanner.checks.iam import (
    console_users_without_mfa,
    recent_root_usage,
    stale_access_keys,
    wildcard_policies,
)
from tests.conftest import fake_root_row, make_policy, make_user

ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}


# --- IAM.1 console user without MFA -------------------------------------------


def test_console_user_without_mfa_is_flagged(aws):
    make_user(aws, "alice", console=True)
    assert dict(console_users_without_mfa(aws)) == {"alice": "console password set, no MFA device"}


def test_console_user_with_mfa_is_not_flagged(aws):
    make_user(aws, "bob", console=True, mfa=True)
    assert dict(console_users_without_mfa(aws)) == {}


def test_programmatic_only_user_is_not_flagged(aws):
    make_user(aws, "ci-bot", access_key=True)
    assert dict(console_users_without_mfa(aws)) == {}


# --- IAM.2 wildcard policies --------------------------------------------------


def test_star_star_policy_is_flagged(aws):
    arn = make_policy(aws, "god-mode", ADMIN)
    assert set(dict(wildcard_policies(aws))) == {arn}


def test_wildcard_inside_lists_is_flagged(aws):
    arn = make_policy(aws, "sneaky", {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]})
    assert set(dict(wildcard_policies(aws))) == {arn}


def test_single_statement_object_is_flagged(aws):
    # IAM accepts "Statement": {...} without the list wrapper.
    arn = aws.iam.create_policy(
        PolicyName="bare", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": ADMIN})
    )["Policy"]["Arn"]
    assert set(dict(wildcard_policies(aws))) == {arn}


def test_scoped_policies_are_not_flagged(aws):
    make_policy(aws, "read-bucket", {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    make_policy(aws, "all-actions-one-bucket", {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"})
    make_policy(aws, "any-resource-one-action", {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"})
    make_policy(aws, "deny-everything", {**ADMIN, "Effect": "Deny"})
    assert dict(wildcard_policies(aws)) == {}


# --- IAM.3 stale access keys --------------------------------------------------


def _key_created(aws, user):
    return aws.iam.list_access_keys(UserName=user)["AccessKeyMetadata"][0]["CreateDate"]


def test_fresh_key_is_not_flagged(aws):
    make_user(aws, "new", access_key=True)
    assert dict(stale_access_keys(aws)) == {}


def test_key_older_than_90_days_is_flagged(aws, monkeypatch):
    key_id = make_user(aws, "old", access_key=True)
    monkeypatch.setattr(iam_checks, "_now", lambda: _key_created(aws, "old") + timedelta(days=91))
    assert dict(stale_access_keys(aws)) == {key_id: "old's key is 91 days old"}


def test_key_exactly_90_days_old_is_not_flagged(aws, monkeypatch):
    make_user(aws, "edge", access_key=True)
    monkeypatch.setattr(iam_checks, "_now", lambda: _key_created(aws, "edge") + timedelta(days=90))
    assert dict(stale_access_keys(aws)) == {}


def test_old_inactive_key_is_not_flagged(aws, monkeypatch):
    key_id = make_user(aws, "retired", access_key=True)
    aws.iam.update_access_key(UserName="retired", AccessKeyId=key_id, Status="Inactive")
    monkeypatch.setattr(iam_checks, "_now", lambda: _key_created(aws, "retired") + timedelta(days=200))
    assert dict(stale_access_keys(aws)) == {}


# --- IAM.4 recent root usage --------------------------------------------------


def _days_ago(days):
    return (iam_checks._now() - timedelta(days=days)).isoformat(timespec="seconds")


def test_root_console_sign_in_last_week_is_flagged(aws, monkeypatch):
    fake_root_row(aws, monkeypatch, password_last_used=_days_ago(3))
    result = dict(recent_root_usage(aws))
    assert set(result) == {"<root_account>"}
    assert "console sign-in 3d ago" in result["<root_account>"]


def test_root_access_key_use_is_flagged(aws, monkeypatch):
    fake_root_row(aws, monkeypatch, key_2=_days_ago(10))
    assert "access key 2 10d ago" in dict(recent_root_usage(aws))["<root_account>"]


def test_root_used_long_ago_is_not_flagged(aws, monkeypatch):
    fake_root_row(aws, monkeypatch, password_last_used=_days_ago(31), key_1=_days_ago(400))
    assert dict(recent_root_usage(aws)) == {}


def test_root_never_used_is_not_flagged(aws, monkeypatch):
    fake_root_row(aws, monkeypatch, password_last_used="no_information")
    assert dict(recent_root_usage(aws)) == {}


def test_recently_active_iam_user_is_not_mistaken_for_root(aws, monkeypatch):
    fake_root_row(aws, monkeypatch, password_last_used=_days_ago(1), user="daily-driver")
    assert dict(recent_root_usage(aws)) == {}
