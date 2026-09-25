"""Walks the check registry and collects findings.

Knows nothing about what any individual check does, and nothing about how
findings are formatted.
"""

from .models import Finding
# Importing the package runs every check module, which populates the registry.
from .checks import REGISTRY


def run(aws, service=None):
    """Run every registered check (or just one service's).

    Returns ``(findings, errors)``. A check that raises is recorded in
    ``errors`` and the scan continues — one broken check must never silence
    the other thirteen.
    """
    findings, errors = [], []
    for fn in REGISTRY:
        check_id, svc, severity, title, remediation = fn.meta
        if service and svc != service:
            continue
        try:
            for resource, detail in fn(aws):
                findings.append(
                    Finding(check_id, svc, severity, title, resource, detail, remediation)
                )
        except Exception as exc:
            errors.append((check_id, f"{type(exc).__name__}: {exc}"))
    findings.sort(key=lambda f: (-f.severity, f.check_id, f.resource))
    return findings, errors
