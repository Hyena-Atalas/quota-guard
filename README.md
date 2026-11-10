# quota-guard

**Waitlist:** [join here](<WAITLIST_FORM_URL>)

> Replace `<WAITLIST_FORM_URL>` with your Google Form or Tally link before you publish. A field list lives in [`docs/waitlist-form-spec.md`](docs/waitlist-form-spec.md). Replace `<REPO_URL>` and `<AUTHOR>` the same way.

Free, open-source, **read-only** CLI that inspects **local** Claude Code and Codex CLI session logs for a simple pattern: token counts or Codex quota percentages that keep moving after you have not entered a prompt for a while.

It is **not an official quota dashboard**. It does not contact OpenAI or Anthropic, does not read credentials, and does not upload your logs. It does **not** guarantee that anyone will refund or restore usage. [OpenAI Support will not reset](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan) ChatGPT/Codex usage limits. If you contact Support, treat the markdown timeline as extra local evidence for an investigation, not as a claim that quota will come back.

## What this is (and is not)

- **Free** MIT-licensed CLI. No account, no telemetry in this repository.
- **Read-only local files.** JSONL session logs, plus (for `check-config` only) `config.toml` / `settings.json`.
- **No credentials.** It will not open `auth.json`, `.credentials.json`, Keychain, or cookies, and it will not call unused or unofficial usage APIs.
- **No network.** A scan does not make HTTP requests. Doc links in the output are for you to open.
- **No process control.** It will not kill or interrupt `claude` or `codex`.
- **Constructed samples in this repo are not real user logs.** Run it on your own machine before you trust the numbers.

## Install and run

Requires **Python 3.11+** (the standard library only; `check-config` uses `tomllib`).

```bash
git clone <REPO_URL>
cd quota-guard

# No install required:
python3 quota_guard.py scan --help

# Or install the console script:
pip install .
quota-guard scan --help
```

Scan the default local roots (`$CLAUDE_CONFIG_DIR` or `~/.claude`, and `$CODEX_HOME` or `~/.codex`):

```bash
python3 quota_guard.py scan
python3 quota_guard.py report --report ./evidence.md
python3 quota_guard.py check-config
python3 quota_guard.py --version
```

`scan` is the default subcommand, so `python3 quota_guard.py --idle-seconds 180` is the same as `scan`.

Point the tool at the constructed samples in this repository (these are **not** real user sessions):

```bash
python3 quota_guard.py scan \
  --claude-root ./fixtures/claude \
  --codex-root ./fixtures/codex \
  --idle-seconds 180 \
  --json

python3 tests/test_quota_guard.py
# or: python3 -m unittest discover -s tests -v
```

A first run on your own machine, including how to read the summary line and how to share a redacted result, is in [`docs/real-run-howto.md`](docs/real-run-howto.md).

Useful flags (on `scan` and `report`):

| Flag | Meaning |
| --- | --- |
| `--claude-root`, `--codex-root` | Override log/config roots |
| `--idle-seconds` | Quiet gap after the last real user input, default 180 |
| `--token-threshold` | Minimum *new* tokens (not cache_read) in that gap, default 200 |
| `--percent-threshold` | Minimum Codex `used_percent` step to flag, default 2.0 |
| `--long-run-seconds` | Continuous work longer than this is `long_run`, not idle drain, default 1800 |
| `--min-severity` | `low` / `medium` / `high`; default `medium` hides `long_run` |
| `--explain SESSION_HASH` | Print only that session's timeline (no prompt text) |
| `--report PATH` | Write a markdown evidence report |
| `--json` | Machine-readable stdout, including the summary object |
| `--no-hash` | Show raw session ids (default: SHA-256 prefix) |
| `--no-redact-home` | Leave home-directory prefixes in paths (default: replace with `~`) |

Exit status: `0` if no alerts are *shown* at the current `--min-severity`, `2` if one or more are shown, `1` on a hard error or a failed `--explain`.

## Paths it reads

Only these, and only as files, never as a login:

| Tool | Default root | What is scanned |
| --- | --- | --- |
| Claude Code | `$CLAUDE_CONFIG_DIR` or `~/.claude` | `projects/**/*.jsonl`, recursively, including `subagents/` |
| Codex CLI | `$CODEX_HOME` or `~/.codex` (Windows: `%USERPROFILE%\.codex`) | `sessions/**/rollout-*.jsonl` and `archived_sessions/**/rollout-*.jsonl`, including `.jsonl.zst` |
| `check-config` only | same roots | `~/.codex/config.toml` and `~/.claude/settings.json` |

`CLAUDE_CONFIG_DIR` may be a comma-separated list. Some community tools report that behavior; whether it is official complete behavior is **unverified**. This tool does **not** automatically also scan `~/.config/claude`.

Custom roots work on Windows and POSIX because paths are handled with `pathlib`.

`.jsonl.zst` files are decompressed with Python 3.14's `compression.zstd` or, if you install it, the optional [`zstandard`](https://pypi.org/project/zstandard/) package (`pip install zstandard` or `pip install 'quota-guard[zstd]'`). If neither is available, those files are counted as `skipped: zst_unsupported` and the scan continues. The summary line always reports how many files were found, scanned, and skipped.

## Paths it does not read

- `~/.codex/auth.json`
- `~/.claude/.credentials.json` or `credentials.json`
- macOS Keychain, browser cookies, or OAuth tokens
- Official usage HTTP endpoints, including unofficial community usage APIs
- `logs_2.sqlite` (out of scope for this version)
- Source files in your project directories (it only opens the log/config paths above)

If a credentials-like filename appears next to logs, it is skipped on purpose.

## Detection types (and their limits)

The quiet gap defaults to **3 minutes** and is configurable. Detection walks events in **timestamp order** and uses the **last real user prompt** as the only anchor. Tool results, `isSidechain` / `subagents/` records, and meta or `<system-reminder>` injections are not anchors. Usage while a tool call is still open is treated as part of the same run.

On current Codex rollouts, a real user prompt is a `response_item` message with `payload.role=user` where `metadata.client_authored` is true and `metadata.inherited_user_message` is not true. If `client_authored` is absent, the tool falls back to `role=user` (and not `developer`). Older `event_msg/user_message` records are still accepted. `task_started` is shown on the `--explain` timeline with its raw `turn_trigger` but is not a user anchor. Sub-agent turns (a nested `initiating_agent_path`, or `inter_agent_communication_metadata`) are excluded from idle detection. Prefer `token_usage_record` over `event_msg/token_count` when both exist (deduped by `response_id`).

**New tokens vs cache reads.** Idle increments use `input_tokens + output_tokens + cache_creation_input_tokens` (plus Codex `reasoning_output_tokens` when present). `cache_read_input_tokens` / `cached_input_tokens` are recorded on the timeline and **not** added. A later turn that mostly rereads a large cache can show tens of millions of cache_read tokens and still correctly stay under the new-token threshold (default 200).

**Type A — new tokens grew after a quiet gap.** After the last real user input, there was a gap of at least `--idle-seconds` with no activity (and no open tool call), and then new tokens increased by at least `--token-threshold`. That can be background work the official apps document (memories, recap, idle compaction, prompt suggestions, scheduled tasks, and similar), or a session that did not actually stop. This is **not** proof of a vendor bug.

**Long runs are not idle drain.** If you gave the agent a task and it kept working without a quiet gap, that is expected. If that continuous run lasts at least `--long-run-seconds` (default 30 minutes), quota-guard emits a low-severity `long_run` alert instead of `idle_drain`. Those alerts are hidden unless you pass `--min-severity low`.

**Type B — Codex `used_percent` rose, but local new tokens did not.** The official client writes rate-limit snapshots into local Codex logs. Those snapshots are **not a live API** and may lag. Comparisons are grouped by `limit_id` across all local sessions (the same pool can appear in concurrent sessions). A change in `resets_at` is treated as a window reset, not as growth. If **any** local session recorded new tokens in that interval, it is not Type B. A Type B alert means: *no local log on this machine showed a matching new-token delta for that `limit_id` in the interval*. It does **not** mean the usage is fake. Still out of view:

- **Other devices** signed into the same account.
- **Cloud / scheduled tasks** and other surfaces that do not write local logs (some plans share usage across Codex, ChatGPT, and other products).
- **Accounting delay** between local activity and the snapshot written to the log.

Claude JSONL generally has **tokens, not official 5-hour or weekly percent bars**. Local totals can disagree with `/usage`, `/status`, and the website. Use those official views as the authority; use this report as a timeline of what this machine wrote down.

Type C (a session that “ran away” after a recent prompt, or after you tried to interrupt it) is **not implemented**.

## Privacy

JSONL files often contain source code, prompts, and secrets. By default the report and `--json` output contain only:

- timestamps
- token counts and quota-percent steps
- **hashed** session ids (`sha256:` plus 12 hex characters; pass `--no-hash` to turn this off). If a file path contains the same id, that substring is replaced too
- redacted file paths (your home directory becomes `~`; pass `--no-redact-home` to turn this off)
- configuration **key names** and the values of a short documented list, for `check-config`

The tool never writes prompt text or message bodies into the report. Please do not upload raw JSONL when you file an issue.

## Config check

`quota-guard check-config` is read-only. It prints suggestions and official documentation links. It will not edit `config.toml` or `settings.json`.

- Codex: `[features].memories`, `[memories].generate_memories`, `[memories].use_memories`, `[memories].min_rate_limit_remaining_percent`. Docs: [Config basics](https://learn.chatgpt.com/docs/config-file/config-basic), [Memories](https://learn.chatgpt.com/docs/customization/memories).
- Claude: documented settings such as `promptSuggestionEnabled` and `idleCompaction`. Docs: [Manage costs](https://code.claude.com/docs/en/costs), [Interactive mode](https://code.claude.com/docs/en/interactive-mode), [Prompt caching](https://code.claude.com/docs/en/prompt-caching). Features whose exact `settings.json` key is not confirmed here (session recap, scheduled tasks, goal check-ins, and similar) are labeled **unconfirmed**. Missing keys are reported as not set; this tool does not invent default values for unconfirmed keys.

Turning a documented idle feature off may reduce *that* path of background usage. It does not guarantee that quota will stop moving.

## How this compares (honestly)

These are tools you may already use. quota-guard is not a replacement for an official usage page, and it is not the first log parser.

| Tool | What it is already good at | How quota-guard relates |
| --- | --- | --- |
| [quotatrace](https://github.com/lowkey-studio/quotatrace) | Free, local, read-only Codex/Claude log analysis, including “percent moved with no local calls,” plus a markdown report | Closest existing tool. quota-guard is also a local post-hoc scan. The extra work here is a packaged CLI with `scan` / `report` / `check-config`, hashed ids by default, and documented config hints. It is **not** a unique invention of Type B detection. |
| [ccusage](https://github.com/ccusage/ccusage/) | Strong local token/cost accounting and Claude 5-hour *blocks* views | Better than this tool if you want a cost breakdown. ccusage does not advertise idle-drain detection. Local totals from either tool can still disagree with the official plan bars. |
| [CodexBar](https://github.com/steipete/CodexBar) | Free menu bar / desktop usage meter across vendors, with reset countdowns and notifications | Better than this tool if you want a live usage glance. CodexBar is not documented as an idle-drain detector or a config linter. quota-guard does not try to be a multi-vendor meter. |

quota-guard does **not** read Keychain or call unofficial usage APIs the way some other meters do. That is a deliberate limit: you will not get a live official percentage from this CLI.

## Feedback

- Waitlist (paid tray / later work, if it happens): `<WAITLIST_FORM_URL>`
- Issues: `<REPO_URL>/issues`
  - “I caught an idle-drain event” — please send a **redacted** timeline only
  - “I ran it successfully” — install/run feedback, including whether timestamps roughly line up with `/usage` or `/status`

Please do not attach original session files that contain source code, prompts, or secrets.

If you are the person publishing this repository, say so in community posts. Draft wording (still drafts, not published from this repo) is in [`docs/post-drafts.md`](docs/post-drafts.md).

## License

MIT. Copyright (c) 2026 `<AUTHOR>`.
