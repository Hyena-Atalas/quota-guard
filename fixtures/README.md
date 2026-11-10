# Fixtures

Every file under this directory is a **constructed sample**. None of it is a real user session, and none of it should be treated as production log format confirmation.

- `claude/` and `codex/` — updated 8.1-style cases. Idle increments are *new* tokens (input+output+cache_creation). cache_read is present in the idle turn but must not be counted.
- `extra/` — truncated last lines, missing/unknown fields, a subagent file, `archived_sessions/`, and cache field-name aliases
- `regression/` — false-positive shapes from the first real-run summary: tool_result mistaken for a user, an in-progress tool call, `isSidechain` / `subagents/`, a huge cache_read with tiny new tokens, out-of-order timestamps, a long autonomous run, and a meta/system injection. Also a constructed `archived_sessions/*.jsonl.zst`.
- `regression/codex-modern/` — constructed current Codex rollout shape (`response_item` user messages, `client_authored` / `inherited_user_message`, `task_started`, `token_usage_record`, `limit_id` / `resets_at`, sub-agent turns, and mid-file non-JSON lines). No real transcripts.
- `regression/codex-turns/` — turn-state detection: a 2-hour in-turn run (not Type A, only long_run), post-complete `token_usage_record` (Type A), older logs with no `task_*` (low-confidence Type A), and Type B with an open vs completed turn.
- `config/` — read-only `check-config` samples
- `secrets/` — constructed agent-config samples for the unreleased `secrets` / `doctor` subcommands: `leaky/`, `clean/`, `false-positives/`, and `ssh/`. Values are fake placeholders only (`NOTREAL` / example prefixes), never production credentials.

Do not add real transcripts here.
