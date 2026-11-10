# How to run quota-guard on your own logs

This is a **read-only** local scan. It does not read credentials, does not call OpenAI or Anthropic, and does not upload anything. The constructed fixtures in this repository are not a substitute for a run on your machine.

You need **Python 3.11+**. If you use Codex and have `archived_sessions/**/*.jsonl.zst` files, also install a decompressor. Python 3.14+ has `compression.zstd` in the standard library; on 3.11–3.13 run `pip install zstandard` (or `pip install 'quota-guard[zstd]'` after a local install). If zstd support is missing, those files are counted as `skipped: zst_unsupported` and the rest of the scan still runs.

## One-shot commands

From a clone of this repository. `scan` is the default subcommand.

**macOS / Linux (bash or zsh):**

```bash
cd quota-guard
python3 quota_guard.py --version
python3 quota_guard.py scan
python3 quota_guard.py report --report ./evidence.md
python3 quota_guard.py check-config
```

To point at non-default roots (including `CLAUDE_CONFIG_DIR` / `CODEX_HOME`):

```bash
python3 quota_guard.py scan \
  --claude-root "${CLAUDE_CONFIG_DIR:-$HOME/.claude}" \
  --codex-root "${CODEX_HOME:-$HOME/.codex}"
```

**Windows (cmd.exe):**

```bat
cd quota-guard
python quota_guard.py --version
python quota_guard.py scan
python quota_guard.py report --report evidence.md
python quota_guard.py check-config
```

```bat
python quota_guard.py scan --claude-root %USERPROFILE%\.claude --codex-root %USERPROFILE%\.codex
```

**Windows (PowerShell):**

```powershell
cd quota-guard
python quota_guard.py scan --claude-root "$env:USERPROFILE\.claude" --codex-root "$env:USERPROFILE\.codex"
```

Useful flags:

- `--idle-seconds 180` — quiet gap after the last real user input (default 3 minutes)
- `--token-threshold 200` — minimum *new* tokens (not cache reads) in that gap
- `--percent-threshold 2.0` — minimum Codex `used_percent` step for Type B
- `--long-run-seconds 1800` — continuous work longer than this is `long_run`, not `idle_drain`
- `--min-severity low` — also print low-severity `long_run` alerts (hidden by default)
- `--explain sha256:________` — timeline for one session only (see below)
- `--json` — machine-readable stdout, including the same summary object

## Expected output shape

You should always see a **Summary** block first, even when there are no alerts. It is written to look like this (numbers are examples, not a prediction for your machine):

```text
Summary: files found 433, scanned 179, skipped 254 (zst_unsupported: 254).
Sessions: 120 (sidechain excluded from idle detection: 3; no real user input: 2).
Alerts: type A: 1, type B: 0, long_run: 2 (shown: 1; 2 hidden by --min-severity medium).
Thresholds: idle 180s, new-token 200, percent 2.0, long-run 1800s. zstd: unavailable.
```

If zstd works, `skipped` should be `0` (or only unrelated reasons) and `zstd` will show `zstandard` or `compression.zstd`. A prototype-style run that only saw ~108 files while you have hundreds of `archived_sessions` rollouts usually means `.jsonl.zst` were not opened — install a decompressor and run again.

An idle-drain alert looks like this (session id hashed unless you pass `--no-hash`):

```text
[ALERT] medium type A  claude sha256:ad8065fd9fb2: new tokens grew by 750 after a quiet gap of >= 180s from the last real user input (cache_read +50000 not counted)
        last real user input: 2026-11-10T01:00:00+00:00
        first post-gap usage: 2026-11-10T01:04:10+00:00
```

Type A on current Codex logs is **post-complete** usage after a quiet gap, not “the last user prompt was a long time ago.” An agent that keeps working in the same turn will not be Type A; it may be `long_run`. Sessions without `task_started`/`task_complete` (Claude or older Codex) still use the user-anchor rule, at low confidence and low severity (hidden by default).

Type B (quota percent moved, no local new tokens) is compared by `limit_id` across all local sessions, and only in intervals where no local turn is open. A `resets_at` window reset is not counted as growth, and activity in any other local session on the same pool suppresses the alert. The report still notes that other devices, Codex Cloud, or surfaces that do not write local logs are invisible. That is a limitation of local logs, not a proof of a billing error.

The summary classifies sessions with **no real user input** as `no user messages`, `all inherited`, or `sub-agent`. `--explain` prints the user-input **anchor type** (`client_authored=true`, `fallback_role_user`, or the older `event_msg/user_message`) without prompt text. Malformed or non-JSON lines in one file are reported as a single "N lines skipped" warning, not one line per record.


`long_run` means the agent kept working after you typed a prompt, with no quiet gap, for longer than `--long-run-seconds`. It is **not** classified as idle drain. Those lines are hidden unless you pass `--min-severity low`.

Exit status: `0` if no alerts are shown at the current `--min-severity`, `2` if one or more are shown, `1` on a hard error or a failed `--explain` lookup.

## Explain one session

Copy the hashed id from an alert, then:

```bash
python3 quota_guard.py scan --explain sha256:ad8065fd9fb2
```

The output is only that session’s timeline: timestamps, record types, new-token / cache_read counts, and the last real-user-input **ANCHOR**. It does not include prompt text or message bodies.

## What “new tokens” means

Idle increments use **input + output + cache_creation** (plus Codex `reasoning_output_tokens` when present). `cache_read_input_tokens` / `cached_input_tokens` are printed separately and are **not** added. A later assistant message that mostly rereads the cache can show a huge cache_read and still correctly stay under the new-token threshold.

The last **real** user prompt is the anchor (in timestamp order, even if the file is not sorted). Tool results, `isSidechain` / `subagents/` records, and meta or `<system-reminder>` injections are not anchors. Usage while a tool call is still open is treated as continuation of the same run, not as idle.

This is still a local reconstruction. It will not match the official `/usage` or `/status` bars exactly, and it cannot see other devices or cloud tasks.

## How to share a redacted result

The default CLI and `--explain` output are already meant to be shareable:

1. Do **not** attach original `.jsonl` or `.jsonl.zst` files. They often contain source code, prompts, and secrets.
2. Do **not** pass `--no-hash` or `--no-redact-home` on anything you will paste in public.
3. Copy the **Summary** block, any `[ALERT]` lines, and optionally one `--explain sha256:…` timeline.
4. You may say whether the timestamps were in the same ballpark as `/usage` or `/status`. You do not need to paste account identifiers.
5. If you file a GitHub issue, use the “I caught an idle-drain event” template and keep the same redaction rules.

quota-guard is not an official dashboard and cannot refund or reset quota. OpenAI Support will not reset ChatGPT/Codex usage limits.
