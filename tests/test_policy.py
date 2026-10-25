"""The shipped IAM policy grants exactly what a full scan calls — no more, no less.

Calls are recorded at runtime, so dynamically named operations
(`get_{kind}_policy`) are caught where a grep of the source would miss them.
"""

import json
from pathlib import Path

from botocore.client import BaseClient

from scanner import runner
from tests.test_end_to_end import planted  # noqa: F401 - fixture

POLICY = Path(__file__).resolve().parent.parent / "iam" / "scanner-readonly-policy.json"

# Where the IAM action name differs from the API operation name.
RENAMED = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
    "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
}
# Needs no permission: AWS answers it for any valid credentials.
UNGATED = {"sts:GetCallerIdentity"}


def test_policy_grants_exactly_the_actions_a_scan_uses(aws, planted, monkeypatch):  # noqa: F811
    # One inline policy each, so the user/group/role inline walks all reach Get*Policy.
    doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    aws.iam.create_group(GroupName="g")
    aws.iam.create_role(RoleName="r", AssumeRolePolicyDocument=doc)
    aws.iam.put_user_policy(UserName="cloudsentinel-mfa", PolicyName="p", PolicyDocument=doc)
    aws.iam.put_group_policy(GroupName="g", PolicyName="p", PolicyDocument=doc)
    aws.iam.put_role_policy(RoleName="r", PolicyName="p", PolicyDocument=doc)

    called = set()
    real = BaseClient._make_api_call

    def record(client, operation, params):
        action = f"{client.meta.service_model.signing_name}:{operation}"
        called.add(RENAMED.get(action, action))
        return real(client, operation, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", record)
    findings, errors = runner.run(aws)
    aws.account_id  # the CLI's report header

    assert errors == []
    granted = set(json.loads(POLICY.read_text())["Statement"][0]["Action"])
    assert called - UNGATED == granted
