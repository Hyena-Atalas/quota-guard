# Contributing

Thanks for taking a look. This project is a **read-only** local log scanner. Please keep that boundary intact.

## Ground rules

- Do not add code that reads `auth.json`, `.credentials.json`, Keychain, cookies, or OAuth tokens.
- Do not add network calls to provider usage APIs, unofficial or official.
- Do not add process killing, session interrupts, or file writes to the user's Claude/Codex config. `check-config` must stay read-only.
- Do not commit real user logs. JSONL often contains source code, prompts, and secrets. Tests and fixtures must stay **constructed samples**.
- Do not invent official default values or undocumented settings keys. If something is not confirmed, label it unconfirmed and skip it with a warning rather than crashing.
- Reports must not include prompt text. Session ids are hashed unless the caller passes `--no-hash`.

## Development

Python 3.11+ and the standard library only for the core CLI.

```bash
python3 -m unittest discover -s tests -v
python3 quota_guard.py scan \
  --claude-root ./fixtures/claude \
  --codex-root ./fixtures/codex \
  --json
```

If you add a log shape, add a constructed fixture and a test. Prefer skipping an unknown record with a warning over guessing.

Idle detection must stay anchored to the last real user input, ignore tool_result / sidechain / system injections, leave cache_read out of the idle increment, and classify long autonomous runs as `long_run` rather than `idle_drain`.

`.jsonl.zst` support is optional (`compression.zstd` or the `zstandard` package). Without a backend, those files must be skipped with `zst_unsupported`, not a crash. The `zstd` extra is `pip install zstandard`.

## Issues

Use the issue templates. Redact timelines. Do not upload raw session files.
