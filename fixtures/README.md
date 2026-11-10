# Fixtures

Every file under this directory is a **constructed sample**. None of it is a real user session, and none of it should be treated as production log format confirmation.

- `claude/` and `codex/` — updated 8.1-style cases. Idle increments are *new* tokens (input+output+cache_creation). cache_read is present in the idle turn but must not be counted.
- `extra/` — truncated last lines, missing/unknown fields, a subagent file, `archived_sessions/`, and cache field-name aliases
- `regression/` — false-positive shapes from the first real-run summary: tool_result mistaken for a user, an in-progress tool call, `isSidechain` / `subagents/`, a huge cache_read with tiny new tokens, out-of-order timestamps, a long autonomous run, and a meta/system injection. Also a constructed `archived_sessions/*.jsonl.zst`.
- `config/` — read-only `check-config` samples

Do not add real transcripts here.
