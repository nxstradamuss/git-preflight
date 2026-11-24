"""Tests for preflight secret detection.

Run:  python -m pytest -q
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import preflight  # noqa: E402


def scan(tmp_path, text, name="f.txt", min_sev="low", entropy=False):
    p = tmp_path / name
    p.write_text(text)
    return preflight.scan_file(p, tmp_path, min_sev, entropy)


def rules_found(findings):
    return {f.rule for f in findings}


# ---------------------------------------------------------------- rules

@pytest.mark.parametrize(
    "content,expected",
    [
        ("-----BEGIN RSA PRIVATE KEY-----", "private-key-pem"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-pem"),
        ("token = 'ghp_" + "a" * 36 + "'", "github-pat"),
        ("pat = 'github_pat_" + "b" * 70 + "'", "github-fine-grained"),
        ("key = 'glpat-" + "c" * 24 + "'", "gitlab-pat"),
        ("AWS_KEY=AKIAIOSFODNN7EXAMPLE", "aws-access-key"),
        ("aws_secret_access_key = '" + "d" * 40 + "'", "aws-secret-key"),
        ('{"type": "service_account"}', "gcp-service-account"),
        ("openai = 'sk-proj-" + "e" * 40 + "'", "openai-key"),
        ("anthropic = 'sk-ant-api03-" + "f" * 40 + "'", "anthropic-key"),
        ("stripe = 'sk_live_" + "g" * 30 + "'", "stripe-secret"),
        ("slack = 'xoxb-" + "1" * 20 + "-" + "h" * 20 + "'", "slack-token"),
        ("bot = '123456789:" + "A" * 35 + "'", "telegram-bot-token"),
        ("key = 'npm_" + "i" * 36 + "'", "npm-token"),
        ("url = 'postgres://user:" + "j" * 12 + "@db.example.com/x'", "db-url-with-password"),
    ],
)
def test_rule_matches(tmp_path, content, expected):
    assert expected in rules_found(scan(tmp_path, content))


def test_evm_private_key(tmp_path):
    key = "0x" + "a1" * 32
    assert "evm-private-key" in rules_found(scan(tmp_path, f"PRIVATE_KEY={key}"))


def test_bip39_mnemonic(tmp_path):
    words = " ".join(["abandon"] * 11 + ["about"])
    found = scan(tmp_path, f"mnemonic = '{words}'")
    assert "bip39-mnemonic" in rules_found(found)


# ------------------------------------------------------------- redaction

def test_secret_is_redacted_in_output(tmp_path):
    secret = "ghp_" + "z" * 36
    found = scan(tmp_path, f"token = '{secret}'")
    assert found, "expected a finding"
    for f in found:
        assert secret not in f.preview, "raw secret leaked into preview"
        assert "*" in f.preview


def test_redact_short_value():
    assert preflight.redact("abc") == "***"


def test_redact_keeps_edges():
    out = preflight.redact("sk-abcdefghijklmnopqrstuvwxyz")
    assert out.startswith("sk-a")
    assert out.endswith("wxyz")
    assert "*" in out


# ---------------------------------------------------------- placeholders

@pytest.mark.parametrize(
    "value",
    ["your_api_key_here", "changeme", "<token>", "${API_KEY}", "xxxxxxxx", "placeholder", "REDACTED"],
)
def test_placeholders_are_ignored(tmp_path, value):
    found = scan(tmp_path, f'api_key = "{value}"')
    assert not [f for f in found if f.rule == "generic-secret-assignment"]


def test_real_value_not_treated_as_placeholder(tmp_path):
    found = scan(tmp_path, 'api_key = "8f2kL9mQ4nR7tV1xZ5bC3dW6"')
    assert any(f.rule == "generic-secret-assignment" for f in found)


# ------------------------------------------------------------- scanning

def test_clean_file_has_no_findings(tmp_path):
    assert scan(tmp_path, "print('hello world')\n") == []


def test_binary_extension_skipped(tmp_path):
    p = tmp_path / "img.png"
    p.write_bytes(b"ghp_" + b"a" * 36)
    assert preflight.scan_file(p, tmp_path, "low", False) == []


def test_skip_dirs(tmp_path):
    d = tmp_path / "node_modules" / "pkg"
    d.mkdir(parents=True)
    (d / "index.js").write_text("token = 'ghp_" + "a" * 36 + "'")
    found = list(preflight.iter_files([tmp_path], [], tmp_path))
    assert all("node_modules" not in str(f) for f in found)


def test_preflightignore_respected(tmp_path):
    (tmp_path / ".preflightignore").write_text("fixtures/\n*.lock\n")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "key.txt").write_text("token = 'ghp_" + "a" * 36 + "'")
    (tmp_path / "yarn.lock").write_text("token = 'ghp_" + "a" * 36 + "'")
    (tmp_path / "real.py").write_text("x = 1\n")

    pats = preflight.load_ignore_patterns(tmp_path)
    files = [f.name for f in preflight.iter_files([tmp_path], pats, tmp_path)]
    assert "key.txt" not in files
    assert "yarn.lock" not in files
    assert "real.py" in files


# -------------------------------------------------------------- entropy

def test_entropy_opt_in(tmp_path):
    blob = "Zx9" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"
    plain = scan(tmp_path, blob, entropy=False)
    assert not any(f.rule == "high-entropy-string" for f in plain)

    with_entropy = scan(tmp_path, blob, entropy=True)
    assert any(f.rule == "high-entropy-string" for f in with_entropy)


def test_entropy_ignores_repetitive(tmp_path):
    found = scan(tmp_path, "a" * 80, entropy=True)
    assert not any(f.rule == "high-entropy-string" for f in found)


# ------------------------------------------------------------ severity

def test_min_severity_filters(tmp_path):
    text = 'password = "hunter2hunter2"\n'   # medium (generic)
    assert any(f.severity == "medium" for f in scan(tmp_path, text, min_sev="low"))
    assert not scan(tmp_path, text, min_sev="critical")


# --------------------------------------------------------------- CLI

def run_cli(args, cwd):
    return subprocess.run(
        [sys.executable, str(Path(preflight.__file__)), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_cli_clean_exit_zero(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    r = run_cli(["scan", "."], tmp_path)
    assert r.returncode == 0
    assert "clean" in r.stdout


def test_cli_findings_exit_one(tmp_path):
    (tmp_path / "a.py").write_text("token = 'ghp_" + "a" * 36 + "'\n")
    r = run_cli(["scan", "."], tmp_path)
    assert r.returncode == 1
    assert "github-pat" in r.stdout


def test_cli_json_output(tmp_path):
    (tmp_path / "a.py").write_text("token = 'ghp_" + "a" * 36 + "'\n")
    r = run_cli(["scan", ".", "--json"], tmp_path)
    data = json.loads(r.stdout)
    assert data["ok"] is False
    assert data["findings"][0]["rule"] == "github-pat"
    assert data["scanned_files"] >= 1


def test_cli_rules_listing():
    r = subprocess.run(
        [sys.executable, str(Path(preflight.__file__)), "rules"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "github-pat" in r.stdout


def test_cli_staged(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "leak.py").write_text("token = 'ghp_" + "a" * 36 + "'\n")
    subprocess.run(["git", "add", "leak.py"], cwd=tmp_path, check=True)
    r = run_cli(["staged"], tmp_path)
    assert r.returncode == 1
    assert "github-pat" in r.stdout


def test_cli_staged_clean(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "ok.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "ok.py"], cwd=tmp_path, check=True)
    r = run_cli(["staged"], tmp_path)
    assert r.returncode == 0
