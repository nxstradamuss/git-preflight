# preflight

[![tests](https://github.com/nxstradamuss/git-preflight/actions/workflows/test.yml/badge.svg)](https://github.com/nxstradamuss/git-preflight/actions/workflows/test.yml)
![python](https://img.shields.io/badge/python-3.9%2B-3776ab?logo=python&logoColor=white)
![deps](https://img.shields.io/badge/dependencies-none-22c55e)
![license](https://img.shields.io/badge/license-MIT-blue)

**Catch secrets before they leave your machine.**

`preflight` is a single-file, zero-dependency secret scanner you run right before
`git push`. It reads your files, finds credentials that have no business being
committed, and tells you where they are — **without ever printing the secret
itself**.

```console
$ preflight scan .
✗ 3 finding(s) across 2 file(s) scanned

  CRITICAL  app.py:3:11
            GitHub personal access token
            rule=github-pat  value=ghp_********************************QrSt

  HIGH      app.py:4:7
            Database URL containing a password
            rule=db-url-with-password  value=post***********************************5432

  MEDIUM    app.py:2:1
            Hardcoded credential assignment
            rule=generic-secret-assignment  value=8f2k****************3dW6

Fix these before pushing. Add false positives to .preflightignore.
```

## Why another secret scanner

Because the moment you need it is the moment you're about to push, and installing
a 200 MB dependency tree at that moment is exactly when you won't. `preflight` is
one file, stdlib only, Python 3.9+. Copy it anywhere and run it.

Two design choices matter more than the rule list:

- **Secrets are redacted, always.** A scanner that echoes your live AWS key into
  scrollback and CI logs is a second leak. `preflight` prints a masked preview —
  enough to identify the value, not enough to use it.
- **Placeholders are not findings.** `API_KEY = "your_api_key_here"` and
  `token = "${GITHUB_TOKEN}"` are how good code looks. Flagging them trains you
  to ignore the tool, and an ignored tool catches nothing.

## Install

No package, no install step. Drop the file in and go:

```bash
curl -O https://raw.githubusercontent.com/nxstradamuss/git-preflight/main/preflight.py
chmod +x preflight.py
./preflight.py scan .
```

Or keep it on your `PATH`:

```bash
mkdir -p ~/.local/bin
cp preflight.py ~/.local/bin/preflight
chmod +x ~/.local/bin/preflight
preflight --version
```

## Usage

```bash
preflight scan .                       # scan the current directory
preflight scan src/ config.yaml        # scan specific paths
preflight staged                       # scan only what's git staged
preflight scan . --min-severity high   # ignore medium/low noise
preflight scan . --entropy             # also flag long random-looking strings
preflight scan . --json                # machine-readable output
preflight rules                        # list every detection rule
```

Exit codes are CI-friendly: `0` clean, `1` findings, `2` usage or IO error.

### As a pre-commit hook

`.git/hooks/pre-commit`:

```bash
#!/bin/sh
exec preflight staged
```

```bash
chmod +x .git/hooks/pre-commit
```

### In CI

```yaml
- name: preflight
  run: python preflight.py scan . --min-severity high
```

## What it detects

25 rules, grouped by blast radius.

| Group | Examples |
|---|---|
| **Private keys** | PEM blocks (RSA/EC/OpenSSH/PGP), EVM private keys, BIP-39 seed phrases |
| **Source control** | GitHub PATs (`ghp_`, `github_pat_`), GitLab PATs |
| **Cloud** | AWS access key IDs + secret keys, GCP service-account JSON, Azure storage keys |
| **AI / SaaS** | [OI]-compatible `sk-` keys, Anthropic, Stripe, Slack tokens + webhooks, Telegram bot tokens, Discord webhooks, SendGrid, npm, PyPI |
| **Crypto** | Exchange API keys, Alchemy/Infura RPC keys in URLs |
| **Generic** | `password = "..."` assignments, bearer tokens, DB URLs with inline passwords |

Run `preflight rules` for the full list with severities.

### Severity

| Level | Meaning | Typical action |
|---|---|---|
| `critical` | Usable credential, immediate loss | Rotate now |
| `high` | High-value token or connection string | Rotate before push |
| `medium` | Possibly a secret, context-dependent | Check by hand |
| `low` | Entropy heuristic only (`--entropy`) | Investigate if unexpected |

## Ignoring false positives

Create `.preflightignore` in your project root. Gitignore-style globs, one per line:

```gitignore
# test fixtures contain fake keys by design
tests/
fixtures/*.json

# lockfiles are noisy and not secrets
*.lock
package-lock.json
```

`preflight` walks up from the current directory looking for `.preflightignore`,
so a single file at your repo root covers subdirectories.

## How it works

1. Walk the target paths, skipping `.git`, `node_modules`, `__pycache__`, virtualenvs,
   build output, and anything matching `.preflightignore`.
2. Skip binary extensions and files over 2 MB; skip anything with NUL bytes in the
   first 8 KB.
3. Run each line against the rule set. Rules use a named `secret` group where
   possible, so redaction knows exactly which substring to mask.
4. Drop matches that are placeholders (`<token>`, `${VAR}`, `your_api_key_here`,
   `changeme`, `xxxxxxxx`).
5. Optionally flag long high-entropy strings that no named rule caught
   (Shannon entropy ≥ 4.3 bits/char, ≥ 32 chars) — off by default because
   minified JS and hashes trip it constantly.

## Limits — read this

`preflight` is a **fast first pass, not a guarantee**.

- It scans text it can read. Encrypted blobs, archives, and binaries are skipped.
- It knows ~25 credential shapes. A secret in a format nobody anticipated — or a
  bare random string with no `key =` next to it — will pass unless you use
  `--entropy`, which has its own false-positive rate.
- **History is not scanned.** A secret committed three years ago is still in your
  repo. `preflight` looks at working-tree files and the staged diff only. If a key
  ever reached a remote, rotate it — cleaning history does not un-leak it.

If a credential has already been pushed, the fix is rotation, not deletion.

## Development

```bash
python -m venv .venv
.venv/bin/pip install pytest
.venv/bin/python -m pytest -q
```

41 tests covering every rule, redaction, placeholder suppression, ignore handling,
entropy, severity filtering, and all CLI modes.

## License

MIT — see [LICENSE](LICENSE).
