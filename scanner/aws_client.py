"""The single place AWS authentication lives.

Nothing else in the codebase constructs a boto3 session or client.
"""

import boto3


class AWS:
    """Lazy, cached boto3 clients: ``aws.s3``, ``aws.iam``, ``aws.ec2``, ...

    Clients are built on first use, so a ``--service s3`` scan never
    authenticates against IAM, EC2 or CloudTrail at all.
    """

    def __init__(self, profile=None, region=None):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self._clients = {}

    def client(self, name):
        if name not in self._clients:
            self._clients[name] = self.session.client(name)
        return self._clients[name]

    def __getattr__(self, name):
        # Only reached for attributes not found on the instance, so `session`
        # and `_clients` never route through here.
        if name.startswith("_"):
            raise AttributeError(name)
        return self.client(name)

    @property
    def account_id(self):
        return self.sts.get_caller_identity()["Account"]
