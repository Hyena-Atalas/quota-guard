# Secret-scan fixtures

All values in this directory are **constructed placeholders**. They are not real
credentials, and they must never be treated as production secrets.

- `leaky/` — allow-rule command passwords, known token formats, a literal MCP token, and a `.gitignore` that does not mention `settings.local.json` (low-entropy placeholders; general-purpose scanners may filter them)
- `leaky-highentropy/` — the same four allow-rule shapes with high-entropy constructed values, plus `FAKE-github-pat.txt`. Filenames and comments are marked `FAKE`. Not real credentials.
- `clean/` — environment-variable references and a correct `.gitignore` (should be silent)
- `false-positives/` — placeholders such as `${PGPASSWORD}`, `changeme`, `<PASSWORD>`, `your-password-here`, a bare `mysql -p` prompt, and the official AWS example key (should be silent)
- `ssh/config` — `ForwardAgent yes` on a named lab host, plus a commented line that must not be flagged

Do not add real project configs or live credentials here.
