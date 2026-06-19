"""JWT vulnerability checks.

Each check function receives the decoded token parts and returns a list of
finding dicts of the shape::

    {
        "type": "alg_none",
        "severity": "Critical",
        "title": "alg=none — token has no signature",
        "detail": "...",
    }
"""

from .algorithm import check_algorithm
from .signature import check_signature
from .claims import check_claims
from .payload import check_payload

# Severity ordering, highest first. Used for sorting and scoring.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "OK"]

__all__ = [
    "check_algorithm",
    "check_signature",
    "check_claims",
    "check_payload",
    "SEVERITY_ORDER",
]
