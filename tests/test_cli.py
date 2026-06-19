"""Tests for the CLI entrypoint and report rendering."""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt

import jwt_analyzer
from report import render_html

WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "common.txt")


def _alg_none_token():
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'user': 'admin'})}."


def test_main_json_output(capsys):
    token = jwt.encode({"user": "x", "exp": 1, "iat": 1}, "secret123", algorithm="HS256")
    rc = jwt_analyzer.main(["--token", token, "--wordlist", WORDLIST, "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["decoded"] is True
    assert any(v["type"] == "weak_secret" for v in data["vulnerabilities"])
    # Critical/High present -> non-zero exit.
    assert rc == 1


def test_main_console_output(capsys):
    rc = jwt_analyzer.main(["--token", _alg_none_token(), "--verbose"])
    out = capsys.readouterr().out
    assert "JWT Security Analyzer" in out
    assert "CRITICAL" in out
    assert rc == 1


def test_main_bad_token_returns_2(capsys):
    rc = jwt_analyzer.main(["--token", "not-a-jwt"])
    assert rc == 2


def test_html_report_written(tmp_path):
    token = jwt.encode({"sub": "u", "exp": 9999999999, "iat": 1, "nbf": 1}, "k", algorithm="HS256")
    result = jwt_analyzer.analyze(token)
    out = tmp_path / "report.html"
    render_html(result, str(out))
    html = out.read_text()
    assert "JWT Security Analyzer" in html
    assert "Detected vulnerabilities" in html


def test_clean_strong_token_exit_zero(capsys):
    import time

    token = jwt.encode(
        {"sub": "u", "exp": 9999999999, "iat": int(time.time()), "nbf": int(time.time())},
        "Zx9!aQ7#kL2$pR8vWm4nT6yB0cF3hJ5d",
        algorithm="RS256-ish-strong",  # invalid alg falls back; keep simple
    ) if False else jwt.encode(
        {"sub": "u", "exp": 9999999999, "iat": int(time.time()), "nbf": int(time.time())},
        "Zx9!aQ7#kL2$pR8vWm4nT6yB0cF3hJ5d",
        algorithm="HS256",
    )
    # HS256 triggers a Medium 'weak algorithm' but no Critical/High -> exit 0.
    rc = jwt_analyzer.main(["--token", token, "--wordlist", WORDLIST])
    assert rc == 0
