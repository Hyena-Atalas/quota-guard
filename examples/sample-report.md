# Quota drain evidence report

Generated locally by quota-guard. This is **not** an official quota dashboard.
Token totals are reconstructed from local logs and may differ from the official usage page.
Codex `used_percent` values come from snapshots the official client wrote into local logs; they may lag.
No account credentials were read. No provider API was called.

OpenAI Support will not reset ChatGPT/Codex usage limits. If you contact Support, treat this
timeline as extra local evidence for an investigation, not as a promise that quota will be restored.
See: https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan

Please also screenshot the official usage pages when you file a report:
- ChatGPT / Codex: https://chatgpt.com/settings/usage
- Claude: https://claude.ai/settings/usage
- Or compare with `/status` (Codex) or `/usage` (Claude) in the official CLI.

Sessions scanned: 4
Alerts: 3

## Sessions scanned

- claude / `sha256:ad8065fd9fb2` — local tokens counted: 6450; last user input (UTC): 2026-11-10T01:00:00+00:00
  - File: `fixtures/claude/projects/demo-idle/sha256:ad8065fd9fb2.jsonl`
- claude / `sha256:fc77a58a0e5f` — local tokens counted: 70; last user input (UTC): 2026-11-10T02:00:40+00:00
  - File: `fixtures/claude/projects/demo-ok/sha256:fc77a58a0e5f.jsonl`
- codex / `sha256:fb5f932bb0d7` — local tokens counted: 1460; last user input (UTC): 2026-11-10T03:00:01+00:00
  - File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:fb5f932bb0d7.jsonl`
- codex / `sha256:b3714f181a1a` — local tokens counted: 60; last user input (UTC): 2026-11-10T04:00:02+00:00
  - File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:b3714f181a1a.jsonl`

## claude / `sha256:ad8065fd9fb2`

- Detection: Type A — local tokens grew after the idle window (possible background work or a session that did not stop).
- Reason: local tokens grew by 5100 after no user input for >= 180s
- File: `fixtures/claude/projects/demo-idle/sha256:ad8065fd9fb2.jsonl`
- Last user input (UTC): 2026-11-10T01:00:00+00:00
- First idle usage (UTC): 2026-11-10T01:04:10+00:00
- Last idle usage (UTC): 2026-11-10T01:04:10+00:00
- Idle local tokens: 5100
- Quota percent step: n/a

- Timeline (timestamps and counts only; no prompt text):
  - 2026-11-10T01:00:00+00:00  user input
  - 2026-11-10T01:00:05+00:00  local tokens +1350
  - 2026-11-10T01:04:10+00:00  local tokens +5100

## codex / `sha256:fb5f932bb0d7`

- Detection: Type A — local tokens grew after the idle window (possible background work or a session that did not stop).
- Reason: local tokens grew by 420 after no user input for >= 180s; Codex primary used_percent rose by 8.0 during idle
- File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:fb5f932bb0d7.jsonl`
- Last user input (UTC): 2026-11-10T03:00:01+00:00
- First idle usage (UTC): 2026-11-10T03:05:30+00:00
- Last idle usage (UTC): 2026-11-10T03:05:30+00:00
- Idle local tokens: 420
- Quota percent step: 8.0

- Timeline (timestamps and counts only; no prompt text):
  - 2026-11-10T03:00:01+00:00  user input
  - 2026-11-10T03:00:20+00:00  primary used_percent=10.0
  - 2026-11-10T03:00:20+00:00  secondary used_percent=20.0
  - 2026-11-10T03:00:20+00:00  local tokens +1040
  - 2026-11-10T03:05:30+00:00  primary used_percent=18.0
  - 2026-11-10T03:05:30+00:00  secondary used_percent=22.0
  - 2026-11-10T03:05:30+00:00  local tokens +420

## codex / `sha256:b3714f181a1a`

- Detection: Type B — quota percent rose with no matching local token delta. Local logs cannot see other devices, Codex Cloud / scheduled tasks, or a shared quota pool (some plans share usage across Codex, ChatGPT, and other surfaces). Accounting may also lag.
- Reason: Codex secondary used_percent rose by 28.0 during idle; no matching local token_count delta (possible other device, cloud task, shared quota pool, or accounting lag)
- File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:b3714f181a1a.jsonl`
- Last user input (UTC): 2026-11-10T04:00:02+00:00
- First idle usage (UTC): n/a
- Last idle usage (UTC): 2026-11-10T04:00:10+00:00
- Idle local tokens: 0
- Quota percent step: 28.0

- Timeline (timestamps and counts only; no prompt text):
  - 2026-11-10T04:00:02+00:00  user input
  - 2026-11-10T04:00:10+00:00  primary used_percent=40.0
  - 2026-11-10T04:00:10+00:00  secondary used_percent=5.0
  - 2026-11-10T04:00:10+00:00  local tokens +60
  - 2026-11-10T04:06:10+00:00  primary used_percent=40.0
  - 2026-11-10T04:06:10+00:00  secondary used_percent=33.0
