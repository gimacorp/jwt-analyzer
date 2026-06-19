"""Payload content analysis: sensitive data / PII leakage.

JWT payloads are only base64url-encoded, not encrypted. Anything placed in the
payload is readable by anyone who holds the token, so secrets and PII must not
live there.
"""

from __future__ import annotations

import re
from typing import Any

# Claim keys whose presence is suspicious on its own.
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "pin",
}

# Value patterns that look like PII regardless of the key name.
_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
}


def _walk(obj: Any, prefix: str = ""):
    """Yield (dotted_key, value) pairs over a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            yield from _walk(v, key)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{prefix}[{i}]")
    else:
        yield prefix, obj


def check_payload(header: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    flagged_keys: list[str] = []

    for key, value in _walk(payload):
        leaf = key.split(".")[-1].split("[")[0].lower()
        if leaf in SENSITIVE_KEYS:
            flagged_keys.append(key)
            continue
        if isinstance(value, str):
            for kind, pattern in _PATTERNS.items():
                # Skip email unless the value clearly is one to avoid noise.
                if pattern.search(value):
                    if kind == "email" and leaf in {"email", "mail", "sub", "username"}:
                        # An email in an expected place is normal-ish; still note PII.
                        flagged_keys.append(f"{key} (email)")
                    elif kind != "email":
                        flagged_keys.append(f"{key} (looks like {kind})")
                    elif kind == "email":
                        flagged_keys.append(f"{key} (email)")
                    break

    if flagged_keys:
        unique = sorted(set(flagged_keys))
        findings.append(
            {
                "type": "sensitive_data",
                "severity": "Medium",
                "title": "Sensitive data found in payload",
                "detail": "JWT payloads are not encrypted, only encoded. "
                "The following claims expose secrets or PII to anyone holding "
                "the token: " + ", ".join(unique) + ". Move them server-side "
                "and keep only opaque identifiers in the token.",
            }
        )

    return findings
