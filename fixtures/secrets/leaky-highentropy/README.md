# FAKE high-entropy leaky fixture

All values in this directory are **constructed and fake**. They are not real
credentials. Filenames, this README, and the settings `_comment` field are
marked `FAKE`.

This fixture exists so gitleaks / TruffleHog can be compared against
command-embedded passwords that are high-entropy (unlike the low-entropy
placeholders in `../leaky/`). Each allow-rule password is a distinct
high-entropy string. The GitHub classic PAT is `ghp_` plus 36 alphanumeric
characters, with `FAKE` immediately after the prefix, so the format is valid
but the value is obviously not a live token.

The ordinary command passwords do **not** contain the substring `FAKE`.
gitleaks 8.30.1's default `generic-api-key` rule lists `fake` as a stopword,
so putting `FAKE` inside those values would change the comparison. Their
fakeness is documented here and in the JSON comment instead.

Do not copy these values into documentation or reports unredacted.
