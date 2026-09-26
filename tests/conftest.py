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


def make_user(aws, name, console=False, mfa=False, access_key=False):
    iam = aws.iam
    iam.create_user(UserName=name)
    if console:
        iam.create_login_profile(UserName=name, Password="Correct-Horse-9!")
    if mfa:
        serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"][
            "SerialNumber"
        ]
        iam.enable_mfa_device(
            UserName=name, SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321"
        )
    if access_key:
        return iam.create_access_key(UserName=name)["AccessKey"]["AccessKeyId"]
    return name


def make_policy(aws, name, *statements):
    return aws.iam.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": list(statements)}),
    )["Policy"]["Arn"]


def fake_root_row(aws, monkeypatch, password_last_used="N/A", key_1="N/A", key_2="N/A", user="<root_account>"):
    """moto's credential report has no <root_account> row; real AWS always does.

    Append one so IAM.4's parsing and date logic run against the real CSV shape.
    """
    real = aws.iam.get_credential_report

    def with_root():
        content = real()["Content"].decode()
        header = content.splitlines()[0].split(",")
        row = dict.fromkeys(header, "N/A")
        row.update(
            user=user,
            password_last_used=password_last_used,
            access_key_1_last_used_date=key_1,
            access_key_2_last_used_date=key_2,
        )
        content = content.rstrip("\n") + "\n" + ",".join(row[h] for h in header) + "\n"
        return {"Content": content.encode()}

    monkeypatch.setattr(aws.iam, "get_credential_report", with_root)


def make_security_group(aws, name, *rules):
    """Rules are (protocol, from_port, to_port, cidr). A cidr with ':' is IPv6."""
    group_id = aws.ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    if rules:
        aws.ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": protocol,
                    "FromPort": low,
                    "ToPort": high,
                    **(
                        {"Ipv6Ranges": [{"CidrIpv6": cidr}]}
                        if ":" in cidr
                        else {"IpRanges": [{"CidrIp": cidr}]}
                    ),
                }
                for protocol, low, high, cidr in rules
            ],
        )
    return group_id


def make_volume(aws, encrypted=False):
    return aws.ec2.create_volume(Size=1, AvailabilityZone=f"{REGION}a", Encrypted=encrypted)["VolumeId"]
