"""Signature attacks: HMAC secret brute-force and RS256->HS256 confusion.

These checks actually attempt to *break* the signature, so they need the raw
token string (header.payload.signature) rather than only the decoded parts.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

import jwt

# Default wordlist shipped with the tool.
_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists",
    "common.txt",
)

_HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _load_words(wordlist_path: str | None) -> list[str]:
    path = wordlist_path or _DEFAULT_WORDLIST
    if not os.path.exists(path):
        return []
    words: list[str] = []
    # rockyou.txt and friends are latin-1 / contain undecodable bytes.
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.rstrip("\n").rstrip("\r")
            if word:
                words.append(word)
    return words


def _signing_input(token: str) -> bytes:
    """Return the bytes that were signed: header.payload (ASCII)."""
    header_b64, payload_b64, _ = token.split(".")
    return f"{header_b64}.{payload_b64}".encode("ascii")


def _provided_signature(token: str) -> bytes:
    from jwt.utils import base64url_decode

    _, _, sig_b64 = token.split(".")
    return base64url_decode(sig_b64.encode("ascii"))


def brute_force_hmac(token: str, header: dict[str, Any], wordlist_path: str | None) -> str | None:
    """Try every word as the HMAC secret. Returns the secret if found."""
    alg = str(header.get("alg", "")).upper()
    hash_alg = _HMAC_HASHES.get(alg)
    if hash_alg is None:
        return None

    try:
        signing_input = _signing_input(token)
        expected_sig = _provided_signature(token)
    except (ValueError, Exception):  # malformed token
        return None

    for word in _load_words(wordlist_path):
        candidate = hmac.new(word.encode("utf-8"), signing_input, hash_alg).digest()
        if hmac.compare_digest(candidate, expected_sig):
            return word
    return None


def try_algorithm_confusion(token: str, header: dict[str, Any], public_key: str | None) -> bool:
    """Detect RS256->HS256 confusion.

    If a token claims an HMAC algorithm but the verifier holds an RSA/EC
    *public* key, an attacker can sign with that public key as if it were the
    HMAC secret. We test whether the token's signature validates when the
    supplied public key is used as the HMAC secret.
    """
    alg = str(header.get("alg", "")).upper()
    if alg not in _HMAC_HASHES or not public_key:
        return False

    hash_alg = _HMAC_HASHES[alg]
    try:
        signing_input = _signing_input(token)
        expected_sig = _provided_signature(token)
    except Exception:
        return False

    candidate = hmac.new(public_key.encode("utf-8"), signing_input, hash_alg).digest()
    return hmac.compare_digest(candidate, expected_sig)


def check_signature(
    token: str,
    header: dict[str, Any],
    payload: dict[str, Any],
    wordlist_path: str | None = None,
    public_key: str | None = None,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    secret = brute_force_hmac(token, header, wordlist_path)
    if secret is not None:
        findings.append(
            {
                "type": "weak_secret",
                "severity": "Critical",
                "title": f"Secret found: '{secret}'",
                "detail": "The HMAC signing secret was recovered from a wordlist. "
                "Anyone with this secret can forge arbitrary valid tokens. "
                "Use a long, random, high-entropy secret (>= 256 bits) stored "
                "outside the codebase.",
                "secret": secret,
            }
        )

    if try_algorithm_confusion(token, header, public_key):
        findings.append(
            {
                "type": "algorithm_confusion",
                "severity": "Critical",
                "title": "RS256 -> HS256 algorithm confusion",
                "detail": "The token validates when the RSA/EC public key is used "
                "as an HMAC secret. Because the public key is not secret, an "
                "attacker can forge tokens. Pin the expected algorithm on the "
                "verifier and never let the token's header dictate it.",
            }
        )

    return findings
