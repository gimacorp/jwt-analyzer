"""Tests for algorithm checks."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt

from jwt_analyzer import analyze


def test_alg_none_detected():
    # Build an alg=none token manually (PyJWT >=2 blocks encoding 'none').
    import base64
    import json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({"user": "admin"})
    token = f"{header}.{payload}."

    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "alg_none" in types
    alg_none = next(v for v in result["vulnerabilities"] if v["type"] == "alg_none")
    assert alg_none["severity"] == "Critical"


def test_weak_algorithm_detected():
    token = jwt.encode({"user": "bob", "exp": 9999999999, "iat": 1}, "longsecret", algorithm="HS256")
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "weak_algorithm" in types
    weak = next(v for v in result["vulnerabilities"] if v["type"] == "weak_algorithm")
    assert weak["severity"] == "Medium"


def test_rs256_not_flagged_as_weak():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    token = jwt.encode({"user": "x", "exp": 9999999999, "iat": 1}, pem, algorithm="RS256")
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "weak_algorithm" not in types
