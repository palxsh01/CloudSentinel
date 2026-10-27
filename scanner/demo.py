"""`cs scan --demo`: the real scan, run against a mocked account with one issue
planted for every check.

moto fakes AWS in memory, so a demo needs no login, costs nothing and never
touches a real account.
"""

import json
import os
from contextlib import contextmanager
from datetime import timedelta
from unittest import mock

from moto import mock_aws

from .aws_client import AWS
from .checks import cloudtrail as ct_checks, ec2 as ec2_checks, iam as iam_checks

REGION = "us-east-1"


@contextmanager
def account():
    """Yields an `AWS` for a mocked account that fails all 14 checks."""
    fake_login = {"AWS_ACCESS_KEY_ID": "demo", "AWS_SECRET_ACCESS_KEY": "demo", "AWS_DEFAULT_REGION": REGION}
    # patch.dict restores the whole environment on exit, popped keys included.
    with mock.patch.dict(os.environ, fake_login), mock_aws():
        for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
            os.environ.pop(var, None)
        aws = AWS(region=REGION)
        _plant(aws)
        # IAM.3 needs a 91-day-old key: move the checks' clock instead of the key.
        later = iam_checks._now() + timedelta(days=91)
        with (
            mock.patch.object(iam_checks, "_now", lambda: later),
            mock.patch.object(aws.iam, "get_credential_report", _with_root_row(aws.iam.get_credential_report, later)),
            # moto lists ~38 regions; the planted resources are all in one.
            mock.patch.object(ec2_checks, "_regions", lambda aws: [REGION]),
            mock.patch.object(ct_checks, "_regions", lambda aws: [REGION]),
        ):
            yield aws


def _plant(aws):
    bucket = "cloudsentinel-public-bucket"
    aws.s3.create_bucket(Bucket=bucket)
    aws.s3.put_bucket_acl(Bucket=bucket, ACL="public-read")  # S3.1; S3.2-S3.4 by default

    user = "cloudsentinel-no-mfa"
    aws.iam.create_user(UserName=user)
    aws.iam.create_login_profile(UserName=user, Password="Correct-Horse-9!")  # IAM.1
    aws.iam.create_access_key(UserName=user)  # IAM.3, once the clock moves
    admin = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    aws.iam.create_policy(PolicyName="cloudsentinel-admin", PolicyDocument=json.dumps(admin))  # IAM.2

    group = aws.ec2.create_security_group(GroupName="cloudsentinel-open", Description="demo")["GroupId"]
    aws.ec2.authorize_security_group_ingress(  # EC2.1 (SSH) + EC2.2 (MySQL)
        GroupId=group,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            for port in (22, 3306)
        ],
    )
    aws.ec2.create_volume(Size=1, AvailabilityZone=f"{REGION}a")  # EC2.3

    # CT.1-CT.3: never started, single-region, no log file validation.
    aws.cloudtrail.create_trail(Name="cloudsentinel-trail", S3BucketName=bucket)


def _with_root_row(real, now):
    """moto's credential report has no <root_account> row (real AWS always has
    one); add one with a console sign-in two days ago, for IAM.4."""

    def report():
        content = real()["Content"].decode()
        header = content.splitlines()[0].split(",")
        used = (now - timedelta(days=2)).isoformat()
        row = dict.fromkeys(header, "N/A") | {"user": "<root_account>", "password_last_used": used}
        return {"Content": (content.rstrip("\n") + "\n" + ",".join(row[h] for h in header) + "\n").encode()}

    return report
