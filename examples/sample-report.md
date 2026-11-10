# Quota drain evidence report

Generated locally by quota-guard. This is **not** an official quota dashboard.
New-token totals use input + output + cache_creation (plus Codex reasoning when present).
cache_read / cached_input_tokens are listed separately and are not added to idle increments.
Idle detection is anchored to the last real user input in timestamp order.
Codex `used_percent` values come from snapshots the official client wrote into local logs; they may lag.
No account credentials were read. No provider API was called.

OpenAI Support will not reset ChatGPT/Codex usage limits. If you contact Support, treat this
timeline as extra local evidence for an investigation, not as a promise that quota will be restored.
See: https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan

Please also screenshot the official usage pages when you file a report:
- ChatGPT / Codex: https://chatgpt.com/settings/usage
- Claude: https://claude.ai/settings/usage
- Or compare with `/status` (Codex) or `/usage` (Claude) in the official CLI.

Summary: files found 4, scanned 4, skipped 0.
Sessions: 4 (sidechain excluded from idle detection: 0; no real user input: 0).
Alerts: type A: 2, type B: 1 (shown: 3).
Thresholds: idle 180s, new-token 200, percent 2.0, long-run 1800s. zstd: unavailable.

## Sessions scanned

- claude / `sha256:ad8065fd9fb2` — new tokens: 1100; cache_read: 51000; last real user input (UTC): 2026-11-10T01:00:00+00:00
  - File: `fixtures/claude/projects/demo-idle/sha256:ad8065fd9fb2.jsonl`
- claude / `sha256:fc77a58a0e5f` — new tokens: 70; cache_read: 0; last real user input (UTC): 2026-11-10T02:00:40+00:00
  - File: `fixtures/claude/projects/demo-ok/sha256:fc77a58a0e5f.jsonl`
- codex / `sha256:fb5f932bb0d7` — new tokens: 1350; cache_read: 1100; last real user input (UTC): 2026-11-10T03:00:01+00:00
  - File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:fb5f932bb0d7.jsonl`
- codex / `sha256:b3714f181a1a` — new tokens: 60; cache_read: 0; last real user input (UTC): 2026-11-10T04:00:02+00:00
  - File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:b3714f181a1a.jsonl`

## claude / `sha256:ad8065fd9fb2`  [medium / A]

- Detection: Type A — new tokens grew after a quiet gap following the last real user input.
- Reason: new tokens grew by 750 after a quiet gap of >= 180s from the last real user input (cache_read +50000 not counted)
- File: `fixtures/claude/projects/demo-idle/sha256:ad8065fd9fb2.jsonl`
- Last real user input (UTC): 2026-11-10T01:00:00+00:00
- First post-gap usage (UTC): 2026-11-10T01:04:10+00:00
- Last post-gap usage (UTC): 2026-11-10T01:04:10+00:00
- Idle new tokens: 750
- Idle cache_read (not counted): 50000
- Quota percent step: n/a

- Timeline (timestamps, types, and counts only; no prompt text):
  - 2026-11-10T01:00:00+00:00  user  ANCHOR (last real user input)
  - 2026-11-10T01:00:05+00:00  usage  new_tokens=+350  cache_read=+1000
  - 2026-11-10T01:04:10+00:00  usage  new_tokens=+750  cache_read=+50000

## codex / `sha256:fb5f932bb0d7`  [medium / A]

- Detection: Type A — new tokens grew after a quiet gap following the last real user input.
- Reason: new tokens grew by 1100 after a quiet gap of >= 180s from the last real user input (cache_read +300 not counted); Codex primary used_percent rose by 8.0 during the quiet gap
- File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:fb5f932bb0d7.jsonl`
- Last real user input (UTC): 2026-11-10T03:00:01+00:00
- First post-gap usage (UTC): 2026-11-10T03:05:30+00:00
- Last post-gap usage (UTC): 2026-11-10T03:05:30+00:00
- Idle new tokens: 1100
- Idle cache_read (not counted): 300
- Quota percent step: 8.0

- Timeline (timestamps, types, and counts only; no prompt text):
  - 2026-11-10T03:00:01+00:00  user  ANCHOR (last real user input)
  - 2026-11-10T03:00:20+00:00  quota  primary used_percent=10.0
  - 2026-11-10T03:00:20+00:00  quota  secondary used_percent=20.0
  - 2026-11-10T03:00:20+00:00  usage  new_tokens=+250  cache_read=+800
  - 2026-11-10T03:05:30+00:00  quota  primary used_percent=18.0
  - 2026-11-10T03:05:30+00:00  quota  secondary used_percent=22.0
  - 2026-11-10T03:05:30+00:00  usage  new_tokens=+1100  cache_read=+300

## codex / `sha256:b3714f181a1a`  [medium / B]

- Detection: Type B — quota percent rose with no matching local new-token delta. Local logs cannot see other devices, Codex Cloud / scheduled tasks, or a shared quota pool (some plans share usage across Codex, ChatGPT, and other surfaces). Accounting may also lag.
- Reason: Codex secondary used_percent rose by 28.0 during the quiet gap; no matching local new-token delta (possible other device, cloud task, shared quota pool, or accounting lag)
- File: `fixtures/codex/sessions/2026/11/10/rollout-sha256:b3714f181a1a.jsonl`
- Last real user input (UTC): 2026-11-10T04:00:02+00:00
- First post-gap usage (UTC): n/a
- Last post-gap usage (UTC): 2026-11-10T04:00:10+00:00
- Idle new tokens: 0
- Idle cache_read (not counted): 0
- Quota percent step: 28.0

- Timeline (timestamps, types, and counts only; no prompt text):
  - 2026-11-10T04:00:02+00:00  user  ANCHOR (last real user input)
  - 2026-11-10T04:00:10+00:00  quota  primary used_percent=40.0
  - 2026-11-10T04:00:10+00:00  quota  secondary used_percent=5.0
  - 2026-11-10T04:00:10+00:00  usage  new_tokens=+60  cache_read=+0
  - 2026-11-10T04:06:10+00:00  quota  primary used_percent=40.0
  - 2026-11-10T04:06:10+00:00  quota  secondary used_percent=33.0
