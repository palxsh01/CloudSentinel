import json

import boto3
import pytest
from moto import mock_aws

from scanner.aws_client import AWS

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    """A mocked AWS account. No real credentials are ever used or needed."""
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(var, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield AWS(region=REGION)


def make_bucket(
    aws,
    name,
    public_acl=False,
    public_policy=False,
    block_public=False,
    encrypted=False,
    versioning=None,
    log_to=None,
):
    s3 = aws.s3
    s3.create_bucket(Bucket=name)
    if public_acl:
        s3.put_bucket_acl(Bucket=name, ACL="public-read")
    if public_policy:
        s3.put_bucket_policy(
            Bucket=name,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{name}/*",
                        }
                    ],
                }
            ),
        )
    if block_public:
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    if encrypted:
        s3.put_bucket_encryption(
            Bucket=name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
    if versioning:  # "Enabled" or "Suspended"
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": versioning})
    if log_to:
        # Real AWS rule, enforced by moto: the target must let LogDelivery write.
        s3.put_bucket_acl(Bucket=log_to, ACL="log-delivery-write")
        s3.put_bucket_logging(
            Bucket=name,
            BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": log_to, "TargetPrefix": f"{name}/"}},
        )
    return name
