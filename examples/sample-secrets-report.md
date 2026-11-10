# Agent config secret audit

Generated locally. Secret values are redacted (first two characters + *** and length only; never the raw secret).
No account credentials were read. Nothing was uploaded. This is not a proof that a repository is clean.

Files scanned: 6
Findings: 11

## HIGH (10)

### anthropic-key

- File: `fixtures/secrets/leaky/.claude/settings.json`
- Line: 3
- Location: line 3, col 27 (/env/ANTHROPIC_API_KEY)
- Rule: anthropic-key
- Category: known-token-format
- Evidence (redacted): `sk*** (len=92)`
- What to do: Rotate this credential, then replace the literal with an environment-variable reference and delete the old rule or value.

### authorization-bearer

- File: `fixtures/secrets/leaky/.claude/settings.local.json`
- Line: 7
- Location: line 7, col 22 (/permissions/allow/3)
- Rule: authorization-bearer
- Category: command-embedded-password
- Evidence (redacted): `gh*** (len=40)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

### gitignore-missing-settings-local

- File: `fixtures/secrets/leaky/.claude/settings.local.json`
- Line: n/a
- Location: .gitignore
- Rule: gitignore-missing-settings-local
- Category: git-hygiene
- Evidence (redacted): `.claude/settings.local.json is not listed in the project .gitignore`
- What to do: Add `**/.claude/settings.local.json` to the repository .gitignore (Claude's global exclude does not travel with the repo). Then `git rm --cached` if it was already tracked, and rotate any secret the file ever held.

### mysql-p

- File: `fixtures/secrets/leaky/.claude/settings.local.json`
- Line: 6
- Location: line 6, col 13 (/permissions/allow/2)
- Rule: mysql-p
- Category: command-embedded-password
- Evidence (redacted): `De*** (len=11)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

### pgpassword

- File: `fixtures/secrets/leaky/.claude/settings.local.json`
- Line: 4
- Location: line 4, col 13 (/permissions/allow/0)
- Rule: pgpassword
- Category: command-embedded-password
- Evidence (redacted): `fa*** (len=20)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

### sshpass-p

- File: `fixtures/secrets/leaky/.claude/settings.local.json`
- Line: 5
- Location: line 5, col 13 (/permissions/allow/1)
- Rule: sshpass-p
- Category: command-embedded-password
- Evidence (redacted): `de*** (len=22)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

### linear-key

- File: `fixtures/secrets/leaky/.cursor/mcp.json`
- Line: 7
- Location: line 7, col 28 (/mcpServers/linear/env/LINEAR_API_KEY)
- Rule: linear-key
- Category: known-token-format
- Evidence (redacted): `li*** (len=48)`
- What to do: Rotate this credential, then replace the literal with an environment-variable reference and delete the old rule or value.

### github-fine-grained-pat

- File: `fixtures/secrets/leaky/.mcp.json`
- Line: 7
- Location: line 7, col 42 (/mcpServers/github/env/GITHUB_PERSONAL_ACCESS_TOKEN)
- Rule: github-fine-grained-pat
- Category: known-token-format
- Evidence (redacted): `gi*** (len=88)`
- What to do: Rotate this credential, then replace the literal with an environment-variable reference and delete the old rule or value.

### openai-project-key

- File: `fixtures/secrets/leaky/.mcp.json`
- Line: 13
- Location: line 13, col 34 (/mcpServers/remote/headers/Authorization)
- Rule: openai-project-key
- Category: known-token-format
- Evidence (redacted): `sk*** (len=52)`
- What to do: Rotate this credential, then replace the literal with an environment-variable reference and delete the old rule or value.

### aws-secret-assign

- File: `fixtures/secrets/leaky/CLAUDE.md`
- Line: 2
- Location: line 2, col 13
- Rule: aws-secret-assign
- Category: command-embedded-password
- Evidence (redacted): `wJ*** (len=39)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

## MEDIUM (1)

### generic-env-assign

- File: `fixtures/secrets/leaky/.codex/config.toml`
- Line: 6
- Location: line 6, col 1
- Rule: generic-env-assign
- Category: command-embedded-password
- Evidence (redacted): `sk*** (len=51)`
- What to do: Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.

## Suggested .gitignore lines

```gitignore
# Agent local settings — may contain allow-rule commands with passwords
**/.claude/settings.local.json
.claude/settings.local.json
```
