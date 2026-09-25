"""The one data shape every check produces and every reporter consumes."""

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """IntEnum so findings sort by severity without a lookup table."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Finding:
    """One misconfigured resource.

    Checks never build these directly — they yield ``(resource, detail)`` and
    the runner stamps on the metadata declared by the ``@check`` decorator, so
    a check cannot contradict its own declared severity or ID.
    """

    check_id: str
    service: str
    severity: Severity
    title: str
    resource: str
    detail: str
    remediation: str
