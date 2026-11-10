# Comparison against current gitleaks and TruffleHog (local, 2026-11-10)

This note records a read-only comparison run on the constructed `fixtures/secrets/` samples. It was not published. No raw secret values are included.

Versions installed on the box (checksum-verified GitHub release assets):

- gitleaks **8.30.1** (latest GitHub release as of 2026-11-10; published 2026-03-21). Command used: `gitleaks dir` (the current directory scanner). `gitleaks detect --no-git` produced the same empty result on these fixtures.
- TruffleHog **3.99.8** (latest GitHub release as of 2026-11-10; published 2026-11-02). Command used: `trufflehog filesystem --no-verification --no-update`. Verification was disabled so the tools did not contact vendor APIs.

## Results on the committed leaky / clean / false-positives fixtures

| Target | quota-guard `secrets` | gitleaks 8.30.1 | TruffleHog 3.99.8 |
| --- | --- | --- | --- |
| `fixtures/secrets/leaky` | 11 findings (10 high + 1 medium), including `pgpassword`, `sshpass-p`, `mysql-p`, Bearer token, known key formats, and a missing `.gitignore` entry | **0** | **0** |
| `fixtures/secrets/clean` | 0 | 0 | 0 |
| `fixtures/secrets/false-positives` | 0 | 0 | 0 |

On `leaky/.claude/settings.local.json` (the allow-rule commands), quota-guard flagged `PGPASSWORD=…`, `sshpass -p …`, `mysql -pSECRET`, and `Authorization: Bearer …`. Neither gitleaks nor TruffleHog flagged any of those lines in this fixture.

**Do not over-read the zero counts on known token formats.** The committed leaky tokens are deliberately fake placeholders (long runs of `0` / `A`, or `EXAMPLEKEY`). gitleaks default rules for `github-pat` use a minimum entropy (the embedded rule text is `entropy = 3`). Those placeholder values are therefore a poor test of whether gitleaks or TruffleHog can detect a *real-looking* `ghp_` / `sk-ant-` token. The zeros above are still the literal result of running the tools on the fixtures as they stand.

## Supplementary high-entropy control (not committed)

A temporary control file used a high-entropy ordinary password (no vendor prefix) in the same four allow-rule shapes, plus a correctly shaped high-entropy `ghp_` token. Results:

| Pattern | gitleaks 8.30.1 | TruffleHog 3.99.8 | quota-guard `secrets` |
| --- | --- | --- | --- |
| `PGPASSWORD=` + ordinary high-entropy password | **Caught** as `generic-api-key` | Missed | Caught as `pgpassword` |
| `sshpass -p` + the same password | Missed | Missed | Caught as `sshpass-p` |
| `mysql -pSECRET` + the same password | Missed | Missed | Caught as `mysql-p` |
| `Authorization: Bearer` + high-entropy `ghp_` | Caught as `github-pat` (token format, not the Bearer header itself) | Caught as `Github` (token format) | Caught as `authorization-bearer` and/or `github-pat` |
| A plain high-entropy `ghp_` in a text file | Caught as `github-pat` | Caught as `Github` | Caught as `github-pat` if that file were in the scan set |

Default gitleaks rule text in this 8.30.1 binary contains **no** `sshpass` or `PGPASSWORD` rule names. `PGPASSWORD=` was only caught when the value itself looked like a generic API key (high entropy). That is why the same rule missed the low-entropy placeholder in the committed leaky fixture.

## Takeaway for product wording

It is still fair to say that **command-embedded passwords without a vendor prefix**, especially `sshpass -p` and `mysql -pSECRET` in Claude allow rules, are missed by current default gitleaks 8.30.1 and TruffleHog 3.99.8. It is **not** fair to say those tools missed every secret in the leaky fixture because they cannot detect GitHub or Anthropic keys at all. A later fixture revision should include high-entropy, still-fake command passwords so the committed samples demonstrate the same miss without a side control.
