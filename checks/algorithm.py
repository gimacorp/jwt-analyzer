"""Algorithm-related checks: alg=none and weak algorithm selection.

The RS256->HS256 algorithm-confusion attack is exploited in signature.py
(it needs a public key), but the *detection* of a confusable setup lives
there too. Here we cover the purely header-driven issues.
"""

from __future__ import annotations

from typing import Any

# Algorithms considered weak for production use. Symmetric HMAC algorithms
# share a single secret between issuer and verifier, which is far easier to
# leak or brute-force than an asymmetric private key.
WEAK_ALGORITHMS = {"HS256", "HS384", "HS512"}

# "none" in any casing — servers have historically accepted "None", "nOnE".
NONE_VARIANTS = {"none"}


def check_algorithm(header: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    alg = header.get("alg")
    if alg is None:
        findings.append(
            {
                "type": "alg_missing",
                "severity": "High",
                "title": "Header has no 'alg' field",
                "detail": "The token header does not declare an algorithm, "
                "which is malformed and may be mishandled by lenient parsers.",
            }
        )
        return findings

    alg_normalised = str(alg).strip().lower()

    if alg_normalised in NONE_VARIANTS:
        findings.append(
            {
                "type": "alg_none",
                "severity": "Critical",
                "title": "alg=none — token has no signature",
                "detail": "The token declares the 'none' algorithm, meaning it "
                "carries no signature. A server that honours this accepts "
                "arbitrary attacker-forged tokens. Always pin the expected "
                "algorithm(s) on the verifier side and reject 'none'.",
            }
        )
        # No point reporting "weak algorithm" on top of none.
        return findings

    if str(alg).upper() in WEAK_ALGORITHMS:
        findings.append(
            {
                "type": "weak_algorithm",
                "severity": "Medium",
                "title": f"Weak algorithm in use: {alg}",
                "detail": "Symmetric HMAC algorithms (HS256/384/512) rely on a "
                "shared secret. In production, prefer asymmetric signatures "
                "(RS256/ES256) so the verifier never holds signing material, "
                "and so a leaked verification key cannot be used to forge tokens.",
            }
        )

    return findings
