"""Tests for temporal claim checks and payload analysis."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt

from jwt_analyzer import analyze


def test_expired_token_detected():
    token = jwt.encode({"user": "x", "exp": int(time.time()) - 86400, "iat": 1}, "k", algorithm="HS256")
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "expired" in types
    expired = next(v for v in result["vulnerabilities"] if v["type"] == "expired")
    assert expired["severity"] == "High"


def test_missing_exp_detected():
    token = jwt.encode({"user": "x", "iat": 1}, "k", algorithm="HS256")
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "missing_exp" in types
    missing = next(v for v in result["vulnerabilities"] if v["type"] == "missing_exp")
    assert missing["severity"] == "High"


def test_missing_temporal_detected():
    token = jwt.encode({"user": "x", "exp": 9999999999}, "k", algorithm="HS256")
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "missing_temporal" in types


def test_sensitive_data_detected():
    token = jwt.encode(
        {"user": "x", "password": "hunter2", "exp": 9999999999, "iat": 1},
        "k",
        algorithm="HS256",
    )
    result = analyze(token)
    types = [v["type"] for v in result["vulnerabilities"]]
    assert "sensitive_data" in types
    sens = next(v for v in result["vulnerabilities"] if v["type"] == "sensitive_data")
    assert sens["severity"] == "Medium"


def test_clean_token_has_no_high_findings():
    token = jwt.encode(
        {"sub": "user-123", "exp": 9999999999, "iat": int(time.time()), "nbf": int(time.time())},
        "Zx9!aQ7#kL2$pR8vWm4nT6yB0cF3hJ5d",
        algorithm="HS256",
    )
    result = analyze(token)
    severities = {v["severity"] for v in result["vulnerabilities"]}
    assert "Critical" not in severities
    assert "High" not in severities
