"""Tests for signature attacks: brute-force and RS256->HS256 confusion."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_analyzer import analyze

WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "common.txt")


def test_weak_secret_bruteforced():
    # 'secret123' is in the shipped wordlist.
    token = jwt.encode({"user": "admin", "exp": 9999999999, "iat": 1}, "secret123", algorithm="HS256")
    result = analyze(token, wordlist_path=WORDLIST)
    weak = [v for v in result["vulnerabilities"] if v["type"] == "weak_secret"]
    assert weak, "weak secret should be detected"
    assert weak[0]["severity"] == "Critical"
    assert weak[0]["secret"] == "secret123"


def test_strong_secret_not_bruteforced():
    token = jwt.encode(
        {"user": "admin", "exp": 9999999999, "iat": 1},
        "Zx9!aQ7#kL2$pR8vWm4nT6yB0cF3hJ5d",
        algorithm="HS256",
    )
    result = analyze(token, wordlist_path=WORDLIST)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "weak_secret" not in types


def test_algorithm_confusion_detected():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Attacker signs an HS256 token using the PUBLIC key as the HMAC secret.
    # PyJWT deliberately refuses to do this, so we forge the token by hand —
    # exactly the manual step a real attacker performs.
    import base64
    import hashlib
    import hmac
    import json

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"user": "attacker", "exp": 9999999999, "iat": 1}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(pub_pem.encode(), signing_input, hashlib.sha256).digest()
    forged = f"{header}.{payload}.{b64(sig)}"
    result = analyze(forged, public_key=pub_pem)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "algorithm_confusion" in types
    conf = next(v for v in result["vulnerabilities"] if v["type"] == "algorithm_confusion")
    assert conf["severity"] == "Critical"
