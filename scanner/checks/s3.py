"""S3 checks (S3.1–S3.4)."""

import json

from botocore.exceptions import ClientError

from ..models import Severity
from .base import check

# The two canonical "anyone" grantees. AuthenticatedUsers counts as public:
# it means any AWS account, not any principal in *your* account.
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

# Condition keys that pin a "*" principal to a known account, org or network,
# which AWS itself treats as "not public". Keys are case-insensitive in IAM.
RESTRICTING_KEYS = {
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourceaccount", "aws:sourcearn", "aws:sourceowner", "aws:userid",
    "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip",
}


def _buckets(aws):
    """(name, s3 client in the bucket's own region) for every bucket.

    Per-bucket calls against a bucket outside the session region can fail with
    PermanentRedirect, so each bucket is read through a client in its region.
    """
    for b in aws.s3.list_buckets()["Buckets"]:
        # us-east-1 reports None; the legacy "EU" constraint means eu-west-1.
        region = aws.s3.get_bucket_location(Bucket=b["Name"])["LocationConstraint"] or "us-east-1"
        yield b["Name"], aws.client("s3", "eu-west-1" if region == "EU" else region)


def _missing(exc, *codes):
    """True if this ClientError is just AWS saying 'that isn't configured'."""
    return exc.response["Error"]["Code"] in codes


def _public_access_block(s3, bucket):
    """The bucket's Block Public Access settings, or {} if none are set."""
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _missing(exc, "NoSuchPublicAccessBlockConfiguration"):
            return {}
        raise


def _public_acl_permissions(s3, bucket):
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return sorted({g["Permission"] for g in grants if g["Grantee"].get("URI") in PUBLIC_GRANTEES})


def _is_restricted(condition):
    """True if the Condition pins the caller to a known account, org or network.

    Negated operators (StringNotEquals, NotIpAddress, ...) allow everyone *but*
    the named value, so they don't restrict; nor do unrelated keys such as
    aws:SecureTransport.
    """
    # ponytail: a restricting key counts whatever its value, so an over-broad
    # aws:SourceIp like 0.0.0.0/0 is treated as restricted. Inspect values if needed.
    return any(
        "Not" not in operator and key.lower() in RESTRICTING_KEYS
        for operator, keys in condition.items()
        for key in keys
    )


def _policy_is_public(s3, bucket):
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _missing(exc, "NoSuchBucketPolicy"):
            return False
        raise

    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        # A Condition can scope "*" down to something safe (a source VPC, an
        # org ID); one that doesn't (e.g. only requiring HTTPS) is still public.
        if _is_restricted(stmt.get("Condition", {})):
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS", [])
            if aws_principal == "*" or "*" in aws_principal:
                return True
    return False


@check(
    "S3.1",
    "s3",
    Severity.HIGH,
    "Bucket allows public access",
    "Enable Block Public Access on the bucket, remove AllUsers/AuthenticatedUsers "
    "ACL grants, and scope the bucket policy to specific principals.",
)
def public_buckets(aws):
    for bucket, s3 in _buckets(aws):
        # Each Block Public Access switch neutralises exactly one mechanism:
        # IgnorePublicAcls makes public ACL grants inert, RestrictPublicBuckets
        # does the same for a public policy. Judge each on its own switch.
        block = _public_access_block(s3, bucket)
        reasons = []
        if not block.get("IgnorePublicAcls"):
            permissions = _public_acl_permissions(s3, bucket)
            if permissions:
                reasons.append(f"ACL grants {', '.join(permissions)} to everyone")
        if not block.get("RestrictPublicBuckets") and _policy_is_public(s3, bucket):
            reasons.append("bucket policy allows Principal '*'")
        if reasons:
            yield bucket, "; ".join(reasons)


@check(
    "S3.2",
    "s3",
    Severity.MEDIUM,
    "Default encryption not enabled",
    "Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
)
def unencrypted_buckets(aws):
    # Since Jan 2023 AWS applies SSE-S3 to every new bucket automatically, so
    # on a real account this mostly fires for buckets created before then.
    for bucket, s3 in _buckets(aws):
        try:
            s3.get_bucket_encryption(Bucket=bucket)
        except ClientError as exc:
            if not _missing(exc, "ServerSideEncryptionConfigurationNotFoundError"):
                raise
            yield bucket, "no default encryption configured"


@check(
    "S3.3",
    "s3",
    Severity.LOW,
    "Versioning disabled",
    "Enable versioning so overwritten or deleted objects can be recovered.",
)
def unversioned_buckets(aws):
    for bucket, s3 in _buckets(aws):
        # Absent means never enabled; "Suspended" means turned off after being on.
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status", "never enabled")
        if status != "Enabled":
            yield bucket, f"versioning is {status.lower()}"


@check(
    "S3.4",
    "s3",
    Severity.LOW,
    "Access logging disabled",
    "Enable server access logging to a separate, dedicated log bucket.",
)
def unlogged_buckets(aws):
    for bucket, s3 in _buckets(aws):
        if "LoggingEnabled" not in s3.get_bucket_logging(Bucket=bucket):
            yield bucket, "server access logging is off"
