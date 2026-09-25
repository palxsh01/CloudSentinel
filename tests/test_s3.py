from scanner.checks.s3 import (
    public_buckets,
    unencrypted_buckets,
    unlogged_buckets,
    unversioned_buckets,
)
from tests.conftest import make_bucket


def findings(aws):
    return dict(public_buckets(aws))


def test_public_acl_is_flagged(aws):
    make_bucket(aws, "open-via-acl", public_acl=True)
    result = findings(aws)
    assert set(result) == {"open-via-acl"}
    assert "ACL grants READ to everyone" in result["open-via-acl"]


def test_public_policy_is_flagged(aws):
    make_bucket(aws, "open-via-policy", public_policy=True)
    result = findings(aws)
    assert set(result) == {"open-via-policy"}
    assert "Principal '*'" in result["open-via-policy"]


def test_private_bucket_is_not_flagged(aws):
    make_bucket(aws, "locked-down")
    assert findings(aws) == {}


def test_block_public_access_suppresses_a_public_acl(aws):
    """A public ACL behind Block Public Access cannot actually expose data."""
    make_bucket(aws, "acl-but-blocked", public_acl=True, block_public=True)
    assert findings(aws) == {}


def test_only_the_public_bucket_is_flagged(aws):
    make_bucket(aws, "private-one")
    make_bucket(aws, "public-one", public_acl=True)
    make_bucket(aws, "private-two")
    assert set(findings(aws)) == {"public-one"}


# --- S3.2 encryption ---------------------------------------------------------


def test_unencrypted_bucket_is_flagged(aws):
    make_bucket(aws, "plain")
    assert dict(unencrypted_buckets(aws)) == {"plain": "no default encryption configured"}


def test_encrypted_bucket_is_not_flagged(aws):
    make_bucket(aws, "sealed", encrypted=True)
    assert dict(unencrypted_buckets(aws)) == {}


# --- S3.3 versioning ---------------------------------------------------------


def test_never_versioned_bucket_is_flagged(aws):
    make_bucket(aws, "no-history")
    assert dict(unversioned_buckets(aws)) == {"no-history": "versioning is never enabled"}


def test_suspended_versioning_is_flagged(aws):
    """Suspended is not Enabled: new writes stop being versioned."""
    make_bucket(aws, "was-versioned", versioning="Suspended")
    assert dict(unversioned_buckets(aws)) == {"was-versioned": "versioning is suspended"}


def test_versioned_bucket_is_not_flagged(aws):
    make_bucket(aws, "has-history", versioning="Enabled")
    assert dict(unversioned_buckets(aws)) == {}


# --- S3.4 access logging -----------------------------------------------------


def test_unlogged_bucket_is_flagged(aws):
    make_bucket(aws, "silent")
    assert dict(unlogged_buckets(aws)) == {"silent": "server access logging is off"}


def test_logged_bucket_is_not_flagged(aws):
    make_bucket(aws, "log-sink")
    make_bucket(aws, "audited", log_to="log-sink")
    # The sink itself is unlogged — that's a real finding, and the only one.
    assert set(dict(unlogged_buckets(aws))) == {"log-sink"}


# --- S3.1 Block Public Access: each switch neutralises one mechanism ---------


def _partial_block(aws, bucket, **switches):
    aws.s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=switches)


def test_ignore_public_acls_alone_neutralises_a_public_acl(aws):
    make_bucket(aws, "acl-ignored", public_acl=True)
    _partial_block(aws, "acl-ignored", IgnorePublicAcls=True)
    assert findings(aws) == {}


def test_ignore_public_acls_does_not_neutralise_a_public_policy(aws):
    make_bucket(aws, "policy-still-open", public_policy=True)
    _partial_block(aws, "policy-still-open", IgnorePublicAcls=True)
    assert set(findings(aws)) == {"policy-still-open"}


def test_restrict_public_buckets_alone_neutralises_a_public_policy(aws):
    make_bucket(aws, "policy-restricted", public_policy=True)
    _partial_block(aws, "policy-restricted", RestrictPublicBuckets=True)
    assert findings(aws) == {}
