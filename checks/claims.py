"""Temporal claim checks: exp (expiry), nbf (not-before), iat (issued-at)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _humanise_delta(seconds: float) -> str:
    seconds = abs(int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days} day{'s' if days != 1 else ''}"
    if hours:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if minutes:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return "less than a minute"


def check_claims(header: dict[str, Any], payload: dict[str, Any], now: float | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    now = time.time() if now is None else now

    exp = payload.get("exp")
    if exp is None:
        findings.append(
            {
                "type": "missing_exp",
                "severity": "High",
                "title": "Token has no 'exp' claim",
                "detail": "Without an expiry the token is valid forever, so a "
                "single leaked token grants permanent access and cannot age out. "
                "Always set a short 'exp'.",
            }
        )
    else:
        try:
            exp = float(exp)
            if exp < now:
                findings.append(
                    {
                        "type": "expired",
                        "severity": "High",
                        "title": f"Token expired {_humanise_delta(now - exp)} ago",
                        "detail": f"'exp' is {_fmt(exp)}, which is in the past. "
                        "A correct verifier rejects this token.",
                    }
                )
        except (TypeError, ValueError):
            findings.append(
                {
                    "type": "malformed_exp",
                    "severity": "Medium",
                    "title": "Claim 'exp' is not a numeric timestamp",
                    "detail": "'exp' must be a NumericDate (seconds since epoch).",
                }
            )

    nbf_present = "nbf" in payload
    iat_present = "iat" in payload
    if not nbf_present and not iat_present:
        findings.append(
            {
                "type": "missing_temporal",
                "severity": "Low",
                "title": "Token has neither 'nbf' nor 'iat'",
                "detail": "Without issued-at / not-before timestamps it is harder "
                "to reason about token age and to build revocation windows.",
            }
        )

    # nbf in the future means the token is not yet valid.
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf = float(nbf)
            if nbf > now:
                findings.append(
                    {
                        "type": "not_yet_valid",
                        "severity": "Low",
                        "title": f"Token not valid for another {_humanise_delta(nbf - now)}",
                        "detail": f"'nbf' is {_fmt(nbf)}, in the future.",
                    }
                )
        except (TypeError, ValueError):
            pass

    return findings
