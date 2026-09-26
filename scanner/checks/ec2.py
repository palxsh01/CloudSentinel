"""EC2 checks (EC2.1–EC2.3)."""

from ..models import Severity
from .base import check

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis"}

# IPv6 "anywhere" is the same exposure as IPv4 "anywhere".
WORLD = {"0.0.0.0/0", "::/0"}

# ICMP rules reuse FromPort/ToPort for type/code, so only these protocols have
# ports. "-1" means every protocol and every port.
PORTED = {"tcp", "6", "udp", "17"}


def _paginate(aws, operation, key, **kwargs):
    for page in aws.ec2.get_paginator(operation).paginate(**kwargs):
        yield from page[key]


def _world_open_ports(rule, ports):
    """Which of `ports` this ingress rule opens to the whole internet."""
    sources = {r["CidrIp"] for r in rule.get("IpRanges", [])}
    sources |= {r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])}
    if not sources & WORLD:
        return set()
    if rule["IpProtocol"] == "-1":
        return set(ports)
    if rule["IpProtocol"] not in PORTED:
        return set()
    return {p for p in ports if rule["FromPort"] <= p <= rule["ToPort"]}


def _exposed_groups(aws, ports):
    # ponytail: session region only. Security groups are regional, so groups in
    # other regions are not scanned. Loop over describe_regions() if needed.
    for group in _paginate(aws, "describe_security_groups", "SecurityGroups"):
        exposed = set()
        for rule in group["IpPermissions"]:
            exposed |= _world_open_ports(rule, ports)
        if exposed:
            names = ", ".join(f"{p} ({ports[p]})" for p in sorted(exposed))
            yield f"{group['GroupId']} ({group['GroupName']})", f"open to the internet on {names}"


@check(
    "EC2.1",
    "ec2",
    Severity.HIGH,
    "SSH/RDP open to the internet",
    "Restrict the rule to known IP ranges, or remove it and use SSM Session "
    "Manager or a bastion host instead.",
)
def open_admin_ports(aws):
    yield from _exposed_groups(aws, ADMIN_PORTS)


@check(
    "EC2.2",
    "ec2",
    Severity.HIGH,
    "Database port open to the internet",
    "Remove the internet-facing rule; allow the database port only from the "
    "application's security group.",
)
def open_db_ports(aws):
    yield from _exposed_groups(aws, DB_PORTS)


@check(
    "EC2.3",
    "ec2",
    Severity.MEDIUM,
    "EBS volume not encrypted",
    "Snapshot the volume, copy the snapshot with encryption on, and restore "
    "from it. Turn on EBS encryption by default for new volumes.",
)
def unencrypted_volumes(aws):
    # ponytail: session region only, same as the security group checks.
    for volume in _paginate(aws, "describe_volumes", "Volumes"):
        if not volume["Encrypted"]:
            yield volume["VolumeId"], f"{volume['Size']} GiB volume, {volume['State']}, unencrypted"
