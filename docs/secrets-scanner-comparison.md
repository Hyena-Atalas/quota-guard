# Comparison against current gitleaks and TruffleHog (local, 2026-11-10)

This note records a read-only comparison run on the constructed `fixtures/secrets/` samples. It was not published. No raw secret values are included.

Versions installed on the box (checksum-verified GitHub release assets):

- gitleaks **8.30.1** (latest GitHub release as of 2026-11-10; published 2026-03-21). Command used: `gitleaks dir` (the current directory scanner). `gitleaks detect --no-git` produced the same empty result on the low-entropy `leaky/` fixture.
- TruffleHog **3.99.8** (latest GitHub release as of 2026-11-10; published 2026-11-02). Command used: `trufflehog filesystem --no-verification --no-update`. Verification was disabled so the tools did not contact vendor APIs.

## Results on the committed leaky / clean / false-positives fixtures

| Target | quota-guard `secrets` | gitleaks 8.30.1 | TruffleHog 3.99.8 |
| --- | --- | --- | --- |
| `fixtures/secrets/leaky` | 11 findings (10 high + 1 medium), including `pgpassword`, `sshpass-p`, `mysql-p`, Bearer token, known key formats, and a missing `.gitignore` entry | **0** | **0** |
| `fixtures/secrets/clean` | 0 | 0 | 0 |
| `fixtures/secrets/false-positives` | 0 | 0 | 0 |

On `leaky/.claude/settings.local.json` (the allow-rule commands), quota-guard flagged `PGPASSWORD=…`, `sshpass -p …`, `mysql -pSECRET`, and `Authorization: Bearer …`. Neither gitleaks nor TruffleHog flagged any of those lines in this fixture.

**Do not over-read the zero counts on known token formats.** The committed `leaky/` tokens are deliberately fake placeholders (long runs of `0` / `A`, or `EXAMPLEKEY`). gitleaks default rules for `github-pat` use a minimum entropy (the embedded rule text is `entropy = 3`). Those placeholder values are therefore a poor test of whether gitleaks or TruffleHog can detect a *real-looking* `ghp_` / `sk-ant-` token. The zeros above are still the literal result of running the tools on `leaky/` as it stands.

## High-entropy fixture (`fixtures/secrets/leaky-highentropy/`)

This fixture uses the same four allow-rule shapes, but with high-entropy constructed values. Filenames, the fixture README, and the JSON `_comment` field are marked `FAKE`. Values are not real credentials. The GitHub classic PAT is format-correct (`ghp_` plus 36 alphanumeric characters) and contains `FAKE` immediately after the prefix. The three ordinary command passwords are distinct high-entropy strings; they do **not** contain the substring `FAKE`, because gitleaks 8.30.1's default `generic-api-key` rule lists `fake` as a stopword and would otherwise drop `PGPASSWORD=`.

Reproduce (from the repository root; `--redact` keeps gitleaks from printing values; TruffleHog's JSON may still contain raw values, so do not paste that output):

```bash
# quota-guard (this branch)
python3 quota_guard.py secrets --root ./fixtures/secrets/leaky-highentropy --skip-git

# gitleaks 8.30.1
gitleaks dir ./fixtures/secrets/leaky-highentropy --no-banner --redact \
  --report-format json --report-path /tmp/gitleaks-highentropy.json

# TruffleHog 3.99.8
trufflehog filesystem ./fixtures/secrets/leaky-highentropy \
  --json --no-verification --no-update --results=unverified,unknown
```

Results from a local run on 2026-11-10 (Asia/Shanghai):

| Pattern | gitleaks 8.30.1 | TruffleHog 3.99.8 | quota-guard `secrets` |
| --- | --- | --- | --- |
| `PGPASSWORD=` + high-entropy ordinary password | **Caught** as `generic-api-key` on `settings.local.json` line 5 | Missed | Caught as `pgpassword` |
| `sshpass -p` + a distinct high-entropy ordinary password | Missed | Missed | Caught as `sshpass-p` |
| `mysql -pSECRET` + a distinct high-entropy ordinary password | Missed | Missed | Caught as `mysql-p` |
| `Authorization: Bearer` + format-correct `ghp_FAKE…` | Caught as `github-pat` on `settings.local.json` line 8 (token format, not a Bearer-header rule) | Caught as `Github` on `settings.local.json` (token format) | Caught as `authorization-bearer` |
| The same `ghp_FAKE…` in `FAKE-github-pat.txt` | Caught as `github-pat` on line 3 | Caught as `Github` | Not scanned: `.txt` files are outside the default agent-config path set |

Totals on this fixture: gitleaks reported **3** findings, TruffleHog reported **2** unverified findings, quota-guard reported the four allow-rule cases above (plus git-hygiene if you leave `--skip-git` off inside this repository).

Default gitleaks rule text in this 8.30.1 binary contains **no** `sshpass` or `PGPASSWORD` rule names. `PGPASSWORD=` was only caught when the value itself looked like a generic API key (high entropy, and not matching the `fake` stopword). That is why the same rule missed the low-entropy placeholder in `leaky/`.

## Takeaway for product wording

It is fair to say that **command-embedded passwords without a vendor prefix**, especially `sshpass -p` and `mysql -pSECRET` in Claude allow rules, are missed by current default gitleaks 8.30.1 and TruffleHog 3.99.8. That result is reproducible on the committed `leaky-highentropy/` fixture. It is **not** fair to say those tools missed every secret in `leaky/` because they cannot detect GitHub or Anthropic keys at all: on `leaky-highentropy/` both tools flag the format-correct `ghp_` token, and gitleaks also flags a high-entropy `PGPASSWORD=` assignment as `generic-api-key`.
