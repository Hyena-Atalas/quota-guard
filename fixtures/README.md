# Fixtures

Every file under this directory is a **constructed sample**. None of it is a real user session, and none of it should be treated as production log format confirmation.

- `claude/` and `codex/` — the four cases in the MVP plan, section 8.1
- `extra/` — truncated last lines, missing/unknown fields, a subagent file, `archived_sessions/`, and the `cache_read_input_tokens` / `cached_input_tokens` alias
- `config/` — read-only `check-config` samples, including a partial Codex config and an empty Claude `settings.json`

Do not add real transcripts here.
