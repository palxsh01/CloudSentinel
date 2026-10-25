"""CloudTrail checks (CT.1–CT.3)."""

from ..models import Severity
from .base import check
from .ec2 import _regions


def _trails(aws):
    """(trail, is_logging) for every trail in the account, each read in its home region.

    ListTrails also returns multi-region trails homed elsewhere, so the same
    trail can appear in several regions; it is kept once, by ARN.
    """
    seen = {}
    for region in _regions(aws):
        for page in aws.client("cloudtrail", region).get_paginator("list_trails").paginate():
            for t in page["Trails"]:
                seen.setdefault(t["TrailARN"], t["HomeRegion"])
    for arn, home in seen.items():
        ct = aws.client("cloudtrail", home)
        trail = {"HomeRegion": home, **ct.get_trail(Name=arn)["Trail"]}
        yield trail, ct.get_trail_status(Name=arn)["IsLogging"]


@check(
    "CT.1",
    "cloudtrail",
    Severity.HIGH,
    "No CloudTrail trail is logging",
    "Create a multi-region trail with log file validation, and make sure "
    "logging is started.",
)
def no_active_trail(aws):
    trails = list(_trails(aws))
    if not any(logging for _, logging in trails):
        # Account-level: one finding, not one per resource.
        detail = f"{len(trails)} trail(s) exist but none is logging" if trails else "no trail exists"
        yield "account", detail


@check(
    "CT.2",
    "cloudtrail",
    Severity.MEDIUM,
    "Trail is not multi-region",
    "Turn on IsMultiRegionTrail so activity in every region is recorded.",
)
def single_region_trails(aws):
    for trail, _ in _trails(aws):
        if not trail["IsMultiRegionTrail"]:
            yield trail["Name"], f"records only {trail['HomeRegion']}"


@check(
    "CT.3",
    "cloudtrail",
    Severity.LOW,
    "Log file validation disabled",
    "Enable log file validation so tampering with delivered logs can be detected.",
)
def unvalidated_trails(aws):
    for trail, _ in _trails(aws):
        if not trail["LogFileValidationEnabled"]:
            yield trail["Name"], "log file validation is off"
