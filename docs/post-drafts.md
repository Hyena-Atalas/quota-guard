# Community post drafts (not published)

These are still drafts. Nothing in this repository sends them, and they must not be posted automatically. Before you publish, re-read the current rules of the target issue or subreddit, replace `<REPO_URL>` and `<WAITLIST_FORM_URL>`, and speak in your own name as the author.

Goals for any revision:

- Disclose that you are the author.
- Do not claim an official bug has been proven.
- Do not promise a refund, a credit, or a quota reset. OpenAI Support [will not reset](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan) ChatGPT/Codex usage limits.
- Do not overstate what local logs can see (shared pools, other devices, cloud tasks, accounting lag).
- Do not ask people to upload raw logs.
- Do not bash official products or competing tools.

The originals below are from the MVP plan, section 7.4.

---

## Draft A — GitHub issue comment

Use only on issues that are already about auditable local timelines (for example an idle-quota thread you are actually helping with). Do not mass-comment.

### Original

```text
I work from local Codex/Claude session logs only (no credentials, no API calls) and have been trying to tell apart:

1. token usage that continues after the last user message (possible background work or a session that did not actually stop), and
2. used_percent going up with no matching local token_count delta (other device, cloud/shared pool, or delayed accounting).

I put a small read-only CLI here: <REPO_URL>

It writes a markdown timeline (counts and timestamps only; it does not include prompt text). I would treat this as extra local evidence to attach when contacting Support, not as a substitute for the official usage page.

If anyone tries it, I would value a note on whether the timestamps line up with /status or /usage on your machine. I am the author; the detector is free. I am not asking anyone to share logs that contain source code or secrets.
```

### What already works

- Author identity is disclosed.
- Scope is limited to local logs, no credentials, no API calls.
- The two detection cases are described without calling them a confirmed vendor bug.
- The official usage page stays the authority.
- People are asked not to share secret-bearing logs.

### Suggested revisions

1. Say clearly that this is **not an official dashboard** and that local `used_percent` values are snapshots from the log, which may lag.
2. On OpenAI/Codex issues, mention the documented Support policy: Support will not reset usage limits. The timeline is for an investigation, not a path to getting quota back.
3. Mention Type B limits in one clause: shared quota pools and other surfaces are invisible to a single machine's logs.
4. Keep the waitlist form out of issue comments. In a thread about a live problem, a signup link reads like promotion. Point at the repo; let the README carry the form.
5. A single sentence about `check-config` is optional and should stay modest (documented idle features, read-only, no file changes). Do not imply that turning a setting off will stop all quota movement.
6. Do not add language about “fixing the drain” or “recovering tokens.”

### Suggested rewrite

```text
I work from local Codex/Claude session logs only (no credentials, no API calls) and have been trying to tell apart:

1. token usage that continues after the last user message (possible background work the official docs already describe, or a session that did not actually stop), and
2. used_percent going up with no matching local token_count delta (other device, cloud/scheduled tasks, a shared quota pool, or delayed accounting). Local logs on one machine cannot see the other surfaces.

I put a small free, read-only CLI here: <REPO_URL>

I am the author. It can write a markdown timeline of counts and timestamps only (no prompt text). Codex used_percent values come from snapshots the official client already wrote to disk; they may lag and this is not an official usage dashboard or a substitute for the usage page or /status.

If you contact Support, I would treat the timeline as extra local evidence for an investigation. OpenAI's help center states that Support will not reset ChatGPT/Codex usage limits, so I am not claiming this will get quota restored.

If anyone tries it, I would value a note on whether the timestamps line up with /status or /usage on your machine. Please do not share logs that contain source code or secrets.
```

---

## Draft B — Reddit r/ClaudeCode

Recheck the subreddit rules first. If project posts belong in a weekly showcase, use that instead of a standalone thread. Disclose authorship. Do not use referral links.

### Original

```text
Title: Has anyone tried to audit Claude Code usage that continues after you step away?

I have been trying to understand cases where usage keeps moving after I have not entered a prompt for several minutes. Anthropic's own cost docs mention that some features can use tokens while a session is idle (session recap, idle compaction, prompt suggestions, scheduled tasks, and similar). I wanted a local way to see the timing, without pasting transcripts anywhere.

I wrote a small read-only script that parses the local JSONL under ~/.claude/projects (and Codex rollouts, if you also use Codex). It flags token growth after a configurable idle window and can print a markdown timeline of counts and timestamps only. It does not read credentials or call the usage API.

Repo: <REPO_URL>
I am the author. The script is free. If this kind of post belongs in the weekly showcase instead of a standalone thread, I will move it — please let me know.

If you try it, I would be interested in whether it matches what you see in /usage, and whether the idle-window default (3 minutes) is too noisy. Please do not upload session files that contain source code or secrets.
```

### What already works

- The title is a genuine question, not a launch announcement.
- Official Anthropic cost docs are cited as the reason idle usage can happen, instead of alleging a secret bug.
- Author identity is disclosed, the tool is described as free, and the showcase rule is respected.
- People are asked about false positives and told not to upload session files.

### Suggested revisions

1. Add one plain sentence: this is not an official dashboard, and it will not recover quota.
2. Note that Claude logs usually have tokens, not official plan-percentage bars, so a mismatch with `/usage` can be normal.
3. A short mention of `check-config` is fine if you say it only prints documented keys and official links and does not edit files.
4. If you include a waitlist link, put it after the repo and make it clearly optional. Do not lead with it.
5. Keep the tone as “I wrote a script and would like feedback,” not “this will catch every silent drain.”
6. Do not imply you have confirmed a Claude bug; the official docs already describe several idle features.

### Suggested rewrite

```text
Title: Has anyone tried to audit Claude Code usage that continues after you step away?

I have been trying to understand cases where usage keeps moving after I have not entered a prompt for several minutes. Anthropic's own cost docs mention that some features can use tokens while a session is idle (session recap, idle compaction, prompt suggestions, scheduled tasks, and similar). I wanted a local way to see the timing, without pasting transcripts anywhere.

I wrote a small free, read-only script (I am the author) that parses the local JSONL under ~/.claude/projects, and Codex rollouts if you also use Codex. It flags token growth after a configurable idle window and can print a markdown timeline of counts and timestamps only. It does not read credentials or call the usage API. It is not an official usage dashboard, and it cannot refund or reset quota.

Local Claude logs usually record tokens, not the official plan-percentage bars, so I would not expect a perfect match with /usage. There is also a read-only config check that prints documented settings and doc links; it does not change any files.

Repo: <REPO_URL>
Optional waitlist for later work: <WAITLIST_FORM_URL>

If this kind of post belongs in the weekly showcase instead of a standalone thread, I will move it — please let me know.

If you try it, I would be interested in whether the timeline is in the same ballpark as /usage, and whether the idle-window default (3 minutes) is too noisy. Please do not upload session files that contain source code or secrets.
```
