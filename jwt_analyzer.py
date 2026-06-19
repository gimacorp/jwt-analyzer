#!/usr/bin/env python3
"""JWT Security Analyzer — CLI entrypoint.

Decodes a JWT without verifying its signature, runs a battery of security
checks, and reports findings to the console, as JSON, or as an HTML report.

For educational purposes only. Only use against systems you own or have
explicit permission to test.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import jwt
from jwt.utils import base64url_decode

from checks import (
    SEVERITY_ORDER,
    check_algorithm,
    check_claims,
    check_payload,
    check_signature,
)


def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode header and payload WITHOUT verifying the signature.

    Verification is intentionally skipped: the whole point is to inspect
    potentially malicious / malformed tokens.
    """
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    return header, payload


def _raw_decode_fallback(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Best-effort manual decode when PyJWT rejects the token."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Token does not have at least header.payload structure")

    def _seg(seg: str) -> dict[str, Any]:
        decoded = base64url_decode(seg.encode("ascii"))
        return json.loads(decoded)

    return _seg(parts[0]), _seg(parts[1])


def analyze(
    token: str,
    wordlist_path: str | None = None,
    public_key: str | None = None,
) -> dict[str, Any]:
    """Run all checks against a token and return a structured result."""
    token = token.strip()
    decoded = True
    try:
        header, payload = decode_token(token)
    except Exception:
        try:
            header, payload = _raw_decode_fallback(token)
        except Exception as exc:  # truly unparseable
            return {
                "decoded": False,
                "error": str(exc),
                "header": {},
                "payload": {},
                "vulnerabilities": [],
                "score": {},
            }

    findings: list[dict[str, str]] = []
    findings += check_algorithm(header, payload)
    findings += check_signature(token, header, payload, wordlist_path, public_key)
    findings += check_claims(header, payload)
    findings += check_payload(header, payload)

    # Sort by severity (Critical first).
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity", "Low")))

    score = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        score[f.get("severity", "Low")] = score.get(f.get("severity", "Low"), 0) + 1

    return {
        "decoded": decoded,
        "header": header,
        "payload": payload,
        "vulnerabilities": findings,
        "score": score,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwt_analyzer.py",
        description="Analyze a JWT for common security vulnerabilities. "
        "For educational use against systems you own or are authorised to test.",
    )
    parser.add_argument("--token", required=True, help="JWT token to analyze (required)")
    parser.add_argument("--wordlist", help="Path to a wordlist for HMAC secret brute-force")
    parser.add_argument("--public-key", help="Path to an RSA/EC public key (for RS256->HS256 detection)")
    parser.add_argument("--output", help="Path to save an HTML report")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--verbose", action="store_true", help="Show detailed explanation for each finding")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    public_key = None
    if args.public_key:
        try:
            with open(args.public_key, "r", encoding="utf-8") as fh:
                public_key = fh.read()
        except OSError as exc:
            print(f"Could not read public key: {exc}", file=sys.stderr)
            return 2

    result = analyze(args.token, wordlist_path=args.wordlist, public_key=public_key)

    if not result["decoded"]:
        print(f"Failed to decode token: {result.get('error')}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        from report import render_console

        render_console(result, verbose=args.verbose)

    if args.output:
        from report import render_html

        path = render_html(result, args.output)
        if not args.json:
            print(f"\n  HTML report written to {path}")

    # Exit non-zero if any Critical/High issue was found (useful in CI).
    critical_high = result["score"].get("Critical", 0) + result["score"].get("High", 0)
    return 1 if critical_high else 0


if __name__ == "__main__":
    raise SystemExit(main())
