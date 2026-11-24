#!/usr/bin/env python3
"""
preflight — catch secrets before they leave your machine.

Scans a directory (or just your git staged files) for credentials that have no
business being committed: private keys, cloud tokens, exchange API keys, wallet
seeds, and generic `password = "..."` assignments.

Matched values are ALWAYS redacted in output. The tool never prints the secret
it found — only the file, line, rule and a masked preview.

Usage:
    preflight scan .                 # scan a directory
    preflight scan src/ config.yaml  # scan specific paths
    preflight staged                 # scan only git staged files
    preflight scan . --json          # machine-readable
    preflight scan . --min-severity high

Exit codes:
    0  clean
    1  findings
    2  usage / IO error
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__version__ = "1.0.0"

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
# Each rule: (id, severity, description, compiled regex)
# Regexes use named group `secret` where possible so we know what to redact.
# --------------------------------------------------------------------------

RAW_RULES: list[tuple[str, str, str, str]] = [
    # --- private keys -----------------------------------------------------
    (
        "private-key-pem",
        "critical",
        "PEM private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    ),
    (
        "evm-private-key",
        "critical",
        "EVM private key (64 hex chars, 0x-prefixed) assigned to a variable",
        r"(?i)\b(?:private_?key|priv_?key|secret_?key|signer_?key)\b\s*[:=]\s*['\"]?(?:0x)?(?P<secret>[0-9a-f]{64})['\"]?",
    ),
    (
        "bip39-mnemonic",
        "critical",
        "BIP-39 seed phrase (12/15/18/21/24 lowercase words)",
        r"(?i)\b(?:mnemonic|seed_?phrase|recovery_?phrase)\b\s*[:=]\s*['\"]?(?P<secret>(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})['\"]?",
    ),
    # --- source control / CI ---------------------------------------------
    (
        "github-pat",
        "critical",
        "GitHub personal access token",
        r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{36,255})\b",
    ),
    (
        "github-fine-grained",
        "critical",
        "GitHub fine-grained PAT",
        r"\b(?P<secret>github_pat_[A-Za-z0-9_]{60,255})\b",
    ),
    (
        "gitlab-pat",
        "high",
        "GitLab personal access token",
        r"\b(?P<secret>glpat-[A-Za-z0-9_\-]{20,64})\b",
    ),
    # --- cloud ------------------------------------------------------------
    (
        "aws-access-key",
        "critical",
        "AWS access key ID",
        r"\b(?P<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
    ),
    (
        "aws-secret-key",
        "critical",
        "AWS secret access key assigned to a variable",
        r"(?i)\baws_?secret_?access_?key\b\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?",
    ),
    (
        "gcp-service-account",
        "high",
        "GCP service-account private key marker",
        r'"type"\s*:\s*"service_account"',
    ),
    (
        "azure-storage-key",
        "high",
        "Azure storage account key",
        r"(?i)\bAccountKey\s*=\s*(?P<secret>[A-Za-z0-9+/=]{40,})",
    ),
    # --- AI / SaaS --------------------------------------------------------
    (
        "openai-key",
        "critical",
        "OpenAI / compatible API key (sk-...)",
        r"\b(?P<secret>sk-(?:proj-|ant-|live-)?[A-Za-z0-9_\-]{20,200})\b",
    ),
    (
        "anthropic-key",
        "critical",
        "Anthropic API key",
        r"\b(?P<secret>sk-ant-[A-Za-z0-9_\-]{20,200})\b",
    ),
    (
        "stripe-secret",
        "critical",
        "Stripe secret key",
        r"\b(?P<secret>[sr]k_(?:live|test)_[A-Za-z0-9]{16,99})\b",
    ),
    (
        "slack-token",
        "high",
        "Slack token",
        r"\b(?P<secret>xox[abposr]-[A-Za-z0-9\-]{10,250})\b",
    ),
    (
        "slack-webhook",
        "high",
        "Slack incoming webhook URL",
        r"(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)",
    ),
    (
        "telegram-bot-token",
        "high",
        "Telegram bot token",
        r"\b(?P<secret>\d{8,12}:[A-Za-z0-9_\-]{30,40})\b",
    ),
    (
        "discord-webhook",
        "medium",
        "Discord webhook URL",
        r"(?P<secret>https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)",
    ),
    (
        "sendgrid-key",
        "high",
        "SendGrid API key",
        r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{20,32}\.[A-Za-z0-9_\-]{30,64})\b",
    ),
    (
        "npm-token",
        "high",
        "npm access token",
        r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b",
    ),
    (
        "pypi-token",
        "high",
        "PyPI upload token",
        r"\b(?P<secret>pypi-[A-Za-z0-9_\-]{50,})",
    ),
    # --- crypto exchanges / wallets --------------------------------------
    (
        "binance-key",
        "high",
        "Binance API key assigned to a variable",
        r"(?i)\bbinance(?:_|_?api_?)?(?:key|secret)\b\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9]{40,64})['\"]?",
    ),
    (
        "alchemy-key",
        "medium",
        "Alchemy / Infura RPC key in a URL",
        r"(?P<secret>https://(?:eth|polygon|arb|opt|base)-(?:mainnet|goerli|sepolia)\.g\.alchemy\.com/v2/[A-Za-z0-9_\-]{20,})",
    ),
    (
        "infura-project-id",
        "medium",
        "Infura project ID in a URL",
        r"(?P<secret>https://[a-z\-]+\.infura\.io/v3/[0-9a-f]{32})",
    ),
    # --- generic assignments ---------------------------------------------
    (
        "generic-secret-assignment",
        "medium",
        "Hardcoded credential assignment",
        r"""(?ix)
        \b(?:api_?key|apikey|secret|token|passwd|password|passphrase|auth_?token|access_?token|client_?secret|webhook_?secret)\b
        \s*[:=]\s*
        ['"](?P<secret>[^'"\s]{12,200})['"]
        """,
    ),
    (
        "bearer-token",
        "medium",
        "Hardcoded bearer token",
        r"(?i)\bauthorization\b\s*[:=]\s*['\"]?Bearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{20,})",
    ),
    # --- connection strings ----------------------------------------------
    (
        "db-url-with-password",
        "high",
        "Database URL containing a password",
        r"\b(?P<secret>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{6,}@[^\s/]+)",
    ),
]

RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    (rid, sev, desc, re.compile(rx)) for rid, sev, desc, rx in RAW_RULES
]

# Generic assignment rule is noisy; drop matches that are obviously placeholders.
# A placeholder is anything a human typed as a stand-in: angle brackets, env
# references, repeated x's, or wording like "your_api_key_here".
PLACEHOLDER_RES: list[re.Pattern[str]] = [
    # <token>, ${ENV_VAR}, {{ var }}, xxxxxxxx, ****, ...
    re.compile(r"^(?:x{4,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|\*{3,}|-+)$", re.I),
    # your_api_key_here / my-token / insert_your_secret / example_key
    re.compile(
        r"(?i)\b(?:your|you|my|the|some|insert|enter|add|put|replace)"
        r"[_\- ]*(?:api[_\- ]?|access[_\- ]?|secret[_\- ]?|auth[_\- ]?)?"
        r"(?:key|token|secret|password|pass|value|string|id|here)\b"
    ),
    # bare placeholder nouns
    re.compile(
        r"(?i)^(?:changeme|change_me|placeholder|example|dummy|sample|fake|"
        r"redacted|none|null|nil|undefined|todo|tbd|secret|password|token|"
        r"apikey|api_key|pass|test)$"
    ),
    # trailing "_here" / "_goes_here"
    re.compile(r"(?i)(?:^|[_\-\s])here$"),
]


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return any(rx.search(v) for rx in PLACEHOLDER_RES)

# High-entropy detector (opt-in via --entropy). Finds long random-looking strings
# that no named rule caught.
ENTROPY_MIN_LEN = 32
ENTROPY_THRESHOLD = 4.3
ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % ENTROPY_MIN_LEN)

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".webm", ".mov", ".avi",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".pyo", ".o", ".a",
    ".db", ".sqlite", ".sqlite3", ".parquet", ".npy", ".npz", ".pkl",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".venv", "venv", "env",
    "site-packages", "dist-packages", "dist", "build", ".next", ".nuxt",
    "target", "vendor", ".idea", ".vscode", "coverage", "htmlcov",
}

MAX_FILE_BYTES = 2 * 1024 * 1024
IGNORE_FILE = ".preflightignore"


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Finding:
    path: str
    line: int
    column: int
    rule: str
    severity: str
    description: str
    preview: str

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """Mask a secret, keeping only a short prefix so it stays identifiable."""
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * max(4, len(value) - keep * 2)}{value[-keep:]}"


def load_ignore_patterns(root: Path) -> list[str]:
    """Read .preflightignore from root (and any parent up to filesystem root)."""
    patterns: list[str] = []
    for base in [root, *root.parents]:
        f = base / IGNORE_FILE
        if f.is_file():
            try:
                for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
            except OSError:
                pass
    return patterns


def is_ignored(rel_path: str, patterns: Sequence[str]) -> bool:
    rel = rel_path.replace(os.sep, "/")
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        p = pat.lstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p):
            return True
        # directory prefix match: "secrets/" ignores everything under it
        if p.endswith("/") and rel.startswith(p):
            return True
        if fnmatch.fnmatch(rel, p.rstrip("/") + "/*"):
            return True
    return False


def iter_files(paths: Iterable[Path], patterns: Sequence[str], root: Path) -> Iterator[Path]:
    for p in paths:
        if p.is_file():
            yield p
            continue
        if not p.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                f = Path(dirpath) / fn
                try:
                    rel = str(f.relative_to(root))
                except ValueError:
                    rel = str(f)
                if is_ignored(rel, patterns):
                    continue
                yield f


def scan_text(text: str, rel_path: str, min_sev: str, entropy: bool) -> list[Finding]:
    findings: list[Finding] = []
    threshold = SEVERITY_ORDER[min_sev]
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for rid, sev, desc, rx in RULES:
            if SEVERITY_ORDER[sev] < threshold:
                continue
            for m in rx.finditer(line):
                secret = ""
                if "secret" in (m.groupdict() or {}):
                    secret = m.group("secret") or ""
                if secret and is_placeholder(secret):
                    continue
                preview = redact(secret) if secret else redact(m.group(0), keep=6)
                findings.append(
                    Finding(
                        path=rel_path,
                        line=lineno,
                        column=m.start() + 1,
                        rule=rid,
                        severity=sev,
                        description=desc,
                        preview=preview,
                    )
                )

        if entropy and len(line) < 4096:
            for m in ENTROPY_CANDIDATE_RE.finditer(line):
                cand = m.group(0)
                if shannon_entropy(cand) < ENTROPY_THRESHOLD:
                    continue
                if any(f.line == lineno and f.path == rel_path for f in findings):
                    continue
                findings.append(
                    Finding(
                        path=rel_path,
                        line=lineno,
                        column=m.start() + 1,
                        rule="high-entropy-string",
                        severity="low",
                        description="Long high-entropy string (possible secret)",
                        preview=redact(cand, keep=4),
                    )
                )
    return findings


def scan_file(path: Path, root: Path, min_sev: str, entropy: bool) -> list[Finding]:
    if path.suffix.lower() in BINARY_EXT:
        return []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
    except OSError:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if "\x00" in text[:8192]:
        return []
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)
    return scan_text(text, rel, min_sev, entropy)


def git_staged_files() -> list[Path]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "git command failed")
    return [Path(p) for p in out.stdout.splitlines() if p.strip()]


def git_staged_blob(path: str) -> str | None:
    out = subprocess.run(["git", "show", f":{path}"], capture_output=True)
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def sev_key(name: str) -> int:
    return SEVERITY_ORDER[name]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="preflight",
        description="Catch secrets before they leave your machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  preflight scan .\n"
            "  preflight staged\n"
            "  preflight scan src/ --json --min-severity high\n"
            "  preflight rules\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"preflight {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan paths for secrets")
    s.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.add_argument("--min-severity", default="low", choices=sorted(SEVERITY_ORDER, key=sev_key))
    s.add_argument("--entropy", action="store_true", help="also flag long high-entropy strings")
    s.add_argument("--no-ignore", action="store_true", help=f"ignore {IGNORE_FILE}")

    t = sub.add_parser("staged", help="scan only git staged files")
    t.add_argument("--json", action="store_true")
    t.add_argument("--min-severity", default="low", choices=sorted(SEVERITY_ORDER, key=sev_key))
    t.add_argument("--entropy", action="store_true")

    sub.add_parser("rules", help="list detection rules")
    return p


def cmd_rules() -> int:
    print(f"{'RULE':32} {'SEVERITY':10} DESCRIPTION")
    print("-" * 88)
    for rid, sev, desc, _ in RULES:
        print(f"{rid:32} {sev:10} {desc}")
    return 0


def report(findings: list[Finding], as_json: bool, scanned: int) -> int:
    if as_json:
        print(json.dumps(
            {
                "version": __version__,
                "scanned_files": scanned,
                "findings": [f.to_dict() for f in findings],
                "ok": not findings,
            },
            indent=2,
        ))
        return 1 if findings else 0

    if not findings:
        print(f"✓ clean — {scanned} file(s) scanned, no secrets found")
        return 0

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))
    print(f"✗ {len(findings)} finding(s) across {scanned} file(s) scanned\n")
    for f in findings:
        print(f"  {f.severity.upper():9} {f.path}:{f.line}:{f.column}")
        print(f"            {f.description}")
        print(f"            rule={f.rule}  value={f.preview}")
        print()
    print("Fix these before pushing. Add false positives to", IGNORE_FILE + ".")
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "rules":
        return cmd_rules()

    entropy = bool(getattr(args, "entropy", False))
    min_sev = getattr(args, "min_severity", "low")

    if args.cmd == "staged":
        try:
            staged = git_staged_files()
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        findings: list[Finding] = []
        for p in staged:
            text = git_staged_blob(str(p))
            if text is None:
                continue
            findings.extend(scan_text(text, str(p), min_sev, entropy))
        return report(findings, args.json, len(staged))

    # scan
    root = Path.cwd()
    patterns: list[str] = [] if getattr(args, "no_ignore", False) else load_ignore_patterns(root)
    targets = [Path(x) for x in (args.paths or ["."])]

    findings = []
    scanned = 0
    for f in iter_files(targets, patterns, root):
        scanned += 1
        findings.extend(scan_file(f, root, min_sev, entropy))
    return report(findings, args.json, scanned)


if __name__ == "__main__":
    sys.exit(main())
