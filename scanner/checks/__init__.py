"""Importing this package registers every check.

Explicit imports rather than dynamic discovery: the list is known at import
time, and a missing check should be a visible one-line omission here.
"""

from .base import REGISTRY, check  # noqa: F401

from . import s3  # noqa: F401,E402
