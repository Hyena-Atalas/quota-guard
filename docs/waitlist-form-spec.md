# Waitlist form spec

Use this as a checklist when you create a **Google Form** or a **Tally** form. This repository does not host a backend and does not send email. Replace `<WAITLIST_FORM_URL>` in the README and in `.github/ISSUE_TEMPLATE/config.yml` once the form exists.

Do **not** ask people to upload session logs. JSONL files often contain source code, prompts, and secrets.

Suggested title: `quota-guard waitlist`

Suggested intro (edit freely):

> quota-guard is a free, read-only CLI that inspects local Claude Code and Codex logs for usage that continues after you step away. If you want to hear about later work (for example a tray app), leave a contact address. This is not an official OpenAI or Anthropic product. Joining does not guarantee a refund or a quota reset; OpenAI Support does not reset ChatGPT/Codex usage limits.

## Fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| Email | Short answer / email | Yes | Enable the form's email validation if available. State that you will only use it for product updates, and that you will not ask them to mail you raw logs. |
| Operating system | Multiple choice | Yes | Options: `macOS`, `Windows`, `Linux`, `Other` (with optional short text). |
| Which do you mainly use? | Multiple choice | Yes | Options: `Claude Code`, `Codex CLI`, `Both`, `Neither yet`. |
| Have you seen usage continue after you stopped typing? | Multiple choice | Yes | Options: `Yes`, `No`, `Not sure`. This is self-reported; it is not a verified capture. |
| Optional notes | Long answer | No | Ask them **not** to paste prompts, source code, secrets, or raw JSONL. A short description of the situation is enough. |

## Optional extras (keep them optional)

These are useful but not required for a first form:

- How you install tools (`pip`, `pipx`, `uv`, `git clone`, other)
- Whether you already use ccusage, CodexBar, quotatrace, or something else (multiple choice, “none” allowed)
- Permission to email when a new release is tagged (checkbox, default unchecked if the platform allows)

Do **not** add a file-upload field.

## After you create it

1. Put the public link in the README waitlist line and in the GitHub issue `contact_links` entry.
2. Check the sharing settings: anyone with the link can respond; you do not need to require a Google sign-in unless you want that.
3. Keep responses private. Export them yourself; do not commit a results sheet to this repo.
