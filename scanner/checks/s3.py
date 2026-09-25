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


def _bucket_names(aws):
    return [b["Name"] for b in aws.s3.list_buckets()["Buckets"]]


def _missing(exc, *codes):
    """True if this ClientError is just AWS saying 'that isn't configured'."""
    return exc.response["Error"]["Code"] in codes


def _public_access_block(aws, bucket):
    """The bucket's Block Public Access settings, or {} if none are set."""
    try:
        return aws.s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _missing(exc, "NoSuchPublicAccessBlockConfiguration"):
            return {}
        raise


def _public_acl_permissions(aws, bucket):
    grants = aws.s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return sorted({g["Permission"] for g in grants if g["Grantee"].get("URI") in PUBLIC_GRANTEES})


def _policy_is_public(aws, bucket):
    try:
        policy = json.loads(aws.s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _missing(exc, "NoSuchBucketPolicy"):
            return False
        raise

    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        # A Condition can scope "*" down to something safe (a source VPC, an
        # org ID). Treating conditional statements as public would be a false
        # positive; treating them as safe can be a false negative, so they are
        # flagged by S3.1 only when unconditional.
        # ponytail: no condition analysis. If conditional-but-still-public
        # policies matter, parse aws:PrincipalOrgID / aws:SourceVpce here.
        if "Condition" in stmt:
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
    # ponytail: get_bucket_acl on a bucket outside the session region raises
    # PermanentRedirect. The runner surfaces that as a visible check error
    # rather than a silent skip. Add per-bucket region lookup if it bites.
    for bucket in _bucket_names(aws):
        # Each Block Public Access switch neutralises exactly one mechanism:
        # IgnorePublicAcls makes public ACL grants inert, RestrictPublicBuckets
        # does the same for a public policy. Judge each on its own switch.
        block = _public_access_block(aws, bucket)
        reasons = []
        if not block.get("IgnorePublicAcls"):
            permissions = _public_acl_permissions(aws, bucket)
            if permissions:
                reasons.append(f"ACL grants {', '.join(permissions)} to everyone")
        if not block.get("RestrictPublicBuckets") and _policy_is_public(aws, bucket):
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
    for bucket in _bucket_names(aws):
        try:
            aws.s3.get_bucket_encryption(Bucket=bucket)
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
    for bucket in _bucket_names(aws):
        # Absent means never enabled; "Suspended" means turned off after being on.
        status = aws.s3.get_bucket_versioning(Bucket=bucket).get("Status", "never enabled")
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
    for bucket in _bucket_names(aws):
        if "LoggingEnabled" not in aws.s3.get_bucket_logging(Bucket=bucket):
            yield bucket, "server access logging is off"
