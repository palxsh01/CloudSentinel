"""Check registration.

A check is a generator function taking an ``AWS`` client and yielding one
``(resource, detail)`` pair per *failing* resource. A clean account yields
nothing. Everything else about a check — its ID, service, severity, title and
remediation — is declared once on the decorator and lives nowhere else.
"""

REGISTRY = []


def check(check_id, service, severity, title, remediation):
    def decorate(fn):
        fn.meta = (check_id, service, severity, title, remediation)
        REGISTRY.append(fn)
        return fn

    return decorate
