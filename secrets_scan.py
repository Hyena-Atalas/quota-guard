#!/usr/bin/env python3
"""Read-only scanner for secrets in AI coding-agent config files.

Looks at project and (optionally) user agent configs: Claude Code
settings and allow rules, Cursor/Codex/MCP configs, instruction files,
gitignore / git history, and SSH ForwardAgent.

This prototype does NOT read credentials (auth.json, Keychain), upload
data, or print raw secret values. Reports are redacted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# Known provider prefixes. These are the cases gitleaks/TruffleHog already
# catch reasonably well; we still flag them when they sit in agent configs.
PREFIX_RULES: list[tuple[str, str, str]] = [
    ("github-pat", "high", r"ghp_[A-Za-z0-9_]{20,}"),
    ("github-fine-grained-pat", "high", r"github_pat_[A-Za-z0-9]{11,}_[A-Za-z0-9]{20,}"),
    ("github-oauth", "high", r"gho_[A-Za-z0-9_]{20,}"),
    ("anthropic-key", "high", r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{20,}"),
    ("openai-project-key", "high", r"sk-proj-[A-Za-z0-9\-_]{20,}"),
    ("openai-svcacct-key", "high", r"sk-svcacct-[A-Za-z0-9\-_]{20,}"),
    ("openai-key", "high", r"(?<![A-Za-z0-9_-])sk-(?!ant-|proj-|svcacct-)[A-Za-z0-9]{20,}"),
    ("aws-access-key", "high", r"AKIA[0-9A-Z]{16}"),
    ("slack-bot", "high", r"xoxb-[0-9]{8,}-[0-9]{8,}-[A-Za-z0-9]{16,}"),
    ("gitlab-pat", "high", r"glpat-[A-Za-z0-9\-_]{16,}"),
    ("npm-token", "high", r"npm_[A-Za-z0-9]{20,}"),
    ("hf-token", "high", r"hf_[A-Za-z0-9]{20,}"),
    ("linear-key", "high", r"lin_api_[A-Za-z0-9]{20,}"),
]

# Command-embedded passwords: the class Apiiro measured as the main miss
# for gitleaks / TruffleHog (Tim Schipper reproduced sshpass/mysql/Bearer
# misses on gitleaks 8.30.1 and TruffleHog 3.99.8 around 2026-11-07).
COMMAND_RULES: list[tuple[str, str, str]] = [
    ("pgpassword", "high", r"""PGPASSWORD\s*=\s*(['\"]?)([^\s'\"]+)\1"""),
    ("mysql-pwd-env", "high", r"""MYSQL_PWD\s*=\s*(['\"]?)([^\s'\"]+)\1"""),
    ("sshpass-p", "high", r"""sshpass\s+-p\s+(?:(['\"])([^'\"]+)\1|(\S+))"""),
    # mysql -pSECRET (no space). Plain `mysql -p` only prompts — not a leak.
    ("mysql-p", "high", r"""mysql(?:\s+\S+)*\s+-p(?![\s\-\"')\]]|$)([^\s\"')\]]{4,})"""),
    ("authorization-bearer", "high", r"""(?i)Authorization:\s*Bearer\s+([^\s\"')\]]+)"""),
    ("api-key-header", "high", r"""(?i)(?:X-Api-Key|X-API-KEY|Api-Key):\s*([^\s\"')\]]+)"""),
    ("curl-basic-auth", "high", r"""(?:curl\s+[^\n]*?-u\s+|--user\s+)(['\"]?)([^:'\"\s]+):([^\s'\"]+)\1"""),
    ("url-password", "high", r"""(?i)(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|https?)://[^/\s:]+:([^@\s]+)@"""),
    ("aws-secret-assign", "high", r"""AWS_SECRET_ACCESS_KEY\s*=\s*(['\"]?)([^\s'\"]+)\1"""),
    ("generic-env-assign", "medium", r"""(?i)(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|GH_TOKEN|API_KEY|API_TOKEN)\s*=\s*(['\"]?)([^\s'\"]+)\1"""),
]

# JSON/TOML/MCP keys whose values should be treated as secrets if literal.
SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|bearer|private[_-]?key)$"
)

PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    ^(
        \$\{[^}]+\}$
      | \$[A-Za-z_][A-Za-z0-9_]*$
      | \%[A-Za-z_][A-Za-z0-9_]*\%$
      | \{\{[^}]+\}\}$
      | <[^>]+>$
      | (your|my|the)[-_].+
      | .*[-_](here|placeholder|example|sample|dummy|changeme)$
      | changeme
      | replace-with-.*
      | insert-.*
      | todo
      | redacted
      | sanitized
      | placeholder
      | example
      | dummy
      | secret
      | password
      | passwd
      | x+
      | \*+
      | •+
      | \.+
    )$
    """
)

LOW_ENTROPY_RE = re.compile(r"^(.)\1{5,}$")  # aaaaaa, 000000
DOC_EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

PROJECT_RELATIVE_PATHS = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".cursor/permissions.json",
    ".cursor/sandbox.json",
    ".gemini/settings.json",
    ".vscode/mcp.json",
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
]

HOME_RELATIVE_PATHS = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".cursor/permissions.json",
    ".cursor/sandbox.json",
    ".ssh/config",
]


@dataclass
class Finding:
    rule_id: str
    severity: str
    path: str
    location: str
    evidence: str  # already redacted; never the raw secret
    remediation: str
    category: str
    line: int | None = None

    def as_public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    files_scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Redaction / placeholder filters
# ---------------------------------------------------------------------------

def normalize_secret(value: str) -> str:
    text = value.strip().strip(chr(39) + chr(34))
    trailing = set('.,;:) ' + chr(39) + chr(34) + chr(92))
    while text and text[-1] in trailing:
        text = text[:-1]
    return text.strip()


def redact(secret: str) -> str:
    """Return a short, non-reversible snippet. Never include a suffix.

    Format: first two characters + '***' and the length. Values of length
    2 or less are only '*** (len=N)', so the whole secret is never shown.
    """
    text = normalize_secret(secret)
    n = len(text)
    if n == 0:
        return "(empty)"
    if n <= 2:
        return f"*** (len={n})"
    return f"{text[:2]}*** (len={n})"


def is_placeholder(value: str) -> bool:
    text = normalize_secret(value)
    if not text:
        return True
    if text in DOC_EXAMPLE_KEYS:
        return True
    if "EXAMPLE" in text.upper() and ("AKIA" in text or "KEY" in text or "SECRET" in text):
        # Official AWS docs use EXAMPLE in sample keys; still flag sk-ant etc.
        if text.startswith("AKIA") or "/" in text:
            return True
    if "REDACTED" in text.upper() or "SANITIZED" in text.upper():
        return True
    if PLACEHOLDER_RE.match(text):
        return True
    if LOW_ENTROPY_RE.match(text):
        return True
    if set(text) <= set("xX*•.0-"):
        return True
    return False


def looks_like_var_ref(value: str) -> bool:
    text = value.strip()
    return bool(
        re.match(r"^\$\{[^}]+\}$", text)
        or re.match(r"^\$[A-Za-z_][A-Za-z0-9_]*$", text)
        or re.match(r"^\%[A-Za-z_][A-Za-z0-9_]*\%$", text)
        or re.match(r"^\$\{env:[^}]+\}$", text)
    )


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    if offset < 0 or not text:
        return 0, 0
    offset = min(offset, len(text))
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return line, col


def find_value_offset(file_text: str, value: str, start: int = 0) -> int:
    if not value:
        return -1
    idx = file_text.find(value, start)
    if idx >= 0:
        return idx
    escaped = json.dumps(value)[1:-1]
    if escaped and escaped != value:
        return file_text.find(escaped, start)
    return -1


def format_location(line: int, col: int, prefix: str = "") -> str:
    if line <= 0:
        base = prefix or "unknown location"
        return base
    loc = f"line {line}, col {col}" if col > 0 else f"line {line}"
    if prefix and prefix not in {"text", "file"}:
        return f"{loc} ({prefix})"
    return loc


def _group_secret(match: re.Match[str], rule_id: str) -> str | None:
    if rule_id == "sshpass-p":
        return match.group(2) or match.group(3)
    if rule_id == "curl-basic-auth":
        return match.group(3)
    # Most command rules: last non-empty capturing group is the secret.
    # pgpassword / mysql-pwd-env / generic-env-assign / aws-secret-assign
    # have (quote)(value); mysql-p, bearer, api-key-header, url-password
    # have a single value group.
    for g in reversed(match.groups() or ()):
        if g is not None and not re.fullmatch(r"[\"']?", g):
            return g
    return match.group(0)


def find_in_text(
    text: str,
    source_path: Path,
    location_prefix: str = "file",
    *,
    file_text: str | None = None,
    base_offset: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    source = file_text if file_text is not None else text

    def add(rule_id: str, severity: str, secret: str, start: int, category: str, remediation: str) -> None:
        secret = normalize_secret(secret or "")
        if not secret or is_placeholder(secret) or looks_like_var_ref(secret):
            return
        key = (rule_id, str(source_path), redact(secret))
        if key in seen:
            return
        seen.add(key)
        line, col = offset_to_line_col(source, base_offset + start)
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                path=str(source_path),
                location=format_location(line, col, location_prefix),
                evidence=redact(secret),
                remediation=remediation,
                category=category,
                line=line or None,
            )
        )

    for rule_id, severity, pattern in PREFIX_RULES:
        for m in re.finditer(pattern, text):
            add(
                rule_id,
                severity,
                m.group(0),
                m.start(),
                "known-token-format",
                "Rotate this credential, then replace the literal with an environment-variable reference and delete the old rule or value.",
            )

    for rule_id, severity, pattern in COMMAND_RULES:
        for m in re.finditer(pattern, text):
            secret = _group_secret(m, rule_id)
            if secret is None:
                continue
            add(
                rule_id,
                severity,
                secret,
                m.start(),
                "command-embedded-password",
                "Rotate the password. Rewrite the allow rule / command so it references $VAR (or ${VAR}), not the literal secret, then remove the old rule from settings and from git history.",
            )
    return findings


def walk_json_strings(obj: Any, pointer: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{pointer}/{k}" if pointer else f"/{k}"
            yield from walk_json_strings(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_json_strings(v, f"{pointer}/{i}")
    elif isinstance(obj, str):
        yield pointer or "/", obj


def scan_json_file(path: Path) -> tuple[list[Finding], list[str]]:
    notes: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"Could not parse {path} as JSON: {exc}"]

    findings: list[Finding] = []
    cursors: dict[str, int] = {}
    for pointer, value in walk_json_strings(data):
        start = cursors.get(value, 0)
        off = find_value_offset(raw, value, start)
        if off >= 0:
            cursors[value] = off + max(len(value), 1)
        findings.extend(
            find_in_text(
                value,
                path,
                location_prefix=pointer,
                file_text=raw,
                base_offset=max(off, 0),
            )
        )
        key_name = pointer.rsplit("/", 1)[-1]
        if SECRET_KEY_RE.search(key_name) and not looks_like_var_ref(value) and not is_placeholder(value):
            if len(value.strip()) >= 8:
                already = any(f.path == str(path) and pointer in f.location for f in findings)
                if not already:
                    if off >= 0:
                        line, col = offset_to_line_col(raw, off)
                    else:
                        line, col = 0, 0
                    findings.append(
                        Finding(
                            rule_id="secret-key-literal",
                            severity="high",
                            path=str(path),
                            location=format_location(line, col, pointer),
                            evidence=redact(value),
                            remediation="Move the value to an environment variable and store only a reference (${VAR} or ${env:VAR}) in the agent config.",
                            category="config-literal-secret",
                            line=line or None,
                        )
                    )
    return findings, notes


def scan_toml_or_text(path: Path) -> tuple[list[Finding], list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"Could not read {path}: {exc}"]
    return find_in_text(text, path, location_prefix="file", file_text=text, base_offset=0), []


def scan_ssh_config(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return findings
    current_host = "*"
    for i, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "host":
            current_host = " ".join(parts[1:])
            continue
        if len(parts) >= 2 and parts[0].lower() == "forwardagent" and parts[1].lower() in {"yes", "true"}:
            findings.append(
                Finding(
                    rule_id="ssh-forward-agent",
                    severity="medium",
                    path=str(path),
                    location=f"line {i} (Host {current_host})",
                    evidence="ForwardAgent yes",
                    remediation="Set ForwardAgent no unless a specific hop requires it. ChatGPT Desktop has been reported to forward the local SSH agent (HN 50422628); keep agent forwarding off by default and use a locked-down forward only for named hosts.",
                    category="ssh-forward-agent",
                    line=i,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Git / gitignore hygiene
# ---------------------------------------------------------------------------

SENSITIVE_PROJECT_FILES = [
    ".claude/settings.local.json",
    ".claude/settings.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".codex/config.toml",
]


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    # Local git only. Never prompt or reach a remote.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def git_repo_root(start: Path) -> Path | None:
    proc = _run_git(start, ["rev-parse", "--show-toplevel"])
    if proc is None or proc.returncode != 0:
        return None
    top = proc.stdout.strip()
    return Path(top) if top else None


def is_ignored(repo: Path, rel: str) -> bool:
    proc = _run_git(repo, ["check-ignore", "-q", rel])
    return proc is not None and proc.returncode == 0


def is_tracked(repo: Path, rel: str) -> bool:
    proc = _run_git(repo, ["ls-files", "--error-unmatch", rel])
    return proc is not None and proc.returncode == 0


def history_hits(repo: Path, rel: str) -> int:
    proc = _run_git(repo, ["log", "--all", "--pretty=%H", "--", rel])
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return 0
    return len([ln for ln in proc.stdout.splitlines() if ln.strip()])


def gitignore_mentions_local_settings(root: Path) -> bool:
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    text = gi.read_text(encoding="utf-8", errors="replace")
    patterns = (
        "settings.local.json",
        ".claude/settings.local.json",
        "**/.claude/settings.local.json",
        ".claude/",
        "**/.claude/",
    )
    return any(p in text for p in patterns)


def scan_git_hygiene(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    settings_local = root / ".claude" / "settings.local.json"
    if settings_local.is_file() and not gitignore_mentions_local_settings(root):
        findings.append(
            Finding(
                rule_id="gitignore-missing-settings-local",
                severity="high",
                path=str(settings_local),
                location=".gitignore",
                evidence=".claude/settings.local.json is not listed in the project .gitignore",
                remediation="Add `**/.claude/settings.local.json` to the repository .gitignore (Claude's global exclude does not travel with the repo). Then `git rm --cached` if it was already tracked, and rotate any secret the file ever held.",
                category="git-hygiene",
            )
        )

    repo = git_repo_root(root)
    if repo is None:
        return findings

    for rel in SENSITIVE_PROJECT_FILES:
        path = root / rel
        # Paths in a nested root: use path relative to the repo.
        try:
            repo_rel = str(path.relative_to(repo))
        except ValueError:
            repo_rel = rel
        if path.is_file() and is_tracked(repo, repo_rel):
            findings.append(
                Finding(
                    rule_id="agent-config-tracked",
                    severity="high",
                    path=str(path),
                    location="git index",
                    evidence=f"{repo_rel} is tracked by git",
                    remediation=f"Rotate any secret this file ever held. Then `git rm --cached {repo_rel}` and add it to .gitignore. History still contains old copies until rewritten, and forks keep them, so rotation comes first.",
                    category="git-hygiene",
                )
            )
        hits = history_hits(repo, repo_rel)
        if hits and not (path.is_file() and is_tracked(repo, repo_rel)):
            # Present in history even if not in the current tree, or currently
            # untracked but previously committed.
            if hits:
                findings.append(
                    Finding(
                        rule_id="agent-config-in-git-history",
                        severity="high",
                        path=str(path if path.exists() else repo / repo_rel),
                        location=f"git history ({hits} commit(s))",
                        evidence=f"{repo_rel} appears in git history",
                        remediation="Rotate every secret this path ever held. Removing the file from the latest commit is not enough; history, forks, and images keep copies.",
                        category="git-hygiene",
                    )
                )
        elif hits and path.is_file() and is_tracked(repo, repo_rel):
            # Already flagged as tracked; add a history note only if >1 commit.
            if hits > 1:
                findings.append(
                    Finding(
                        rule_id="agent-config-in-git-history",
                        severity="medium",
                        path=str(path),
                        location=f"git history ({hits} commit(s))",
                        evidence=f"{repo_rel} appears in {hits} commits",
                        remediation="After untracking, rotate secrets. History rewrite does not reach forks or anyone who already cloned.",
                        category="git-hygiene",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_project_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in PROJECT_RELATIVE_PATHS:
        path = root / rel
        if path.is_file():
            files.append(path)
    # Monorepos: any nested settings.local.json / .mcp.json
    for pattern in (".claude/settings.local.json", ".claude/settings.json", ".mcp.json", ".cursor/mcp.json"):
        files.extend(p for p in root.glob(f"**/{pattern}") if p.is_file())
    # Unique, keep stable order
    seen: set[Path] = set()
    out: list[Path] = []
    for p in files:
        rp = p.resolve() if p.exists() else p
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def discover_home_files(home: Path) -> list[Path]:
    files: list[Path] = []
    for rel in HOME_RELATIVE_PATHS:
        path = home / rel
        if path.is_file():
            files.append(path)
    desktop = home / "Library/Application Support/Claude/claude_desktop_config.json"
    if desktop.is_file():
        files.append(desktop)
    return files


def skip_credential_file(path: Path) -> bool:
    name = path.name.lower()
    if name in {"auth.json", ".credentials.json", "credentials.json"}:
        return True
    if name.endswith(".pem") or name.endswith(".key"):
        return True
    if name.startswith("id_") and path.parent.name.lower() in {".ssh", "ssh"}:
        return True
    return False


def scan_path(path: Path) -> tuple[list[Finding], list[str]]:
    if skip_credential_file(path):
        return [], [f"Skipped credential file {path}"]
    suffix = path.suffix.lower()
    name = path.name.lower()
    if path.name == "config" and path.parent.name in {".ssh", "ssh"}:
        return scan_ssh_config(path), []
    if suffix == ".json":
        return scan_json_file(path)
    return scan_toml_or_text(path)


def suggest_gitignore() -> str:
    return "\n".join(
        [
            "# Agent local settings — may contain allow-rule commands with passwords",
            "**/.claude/settings.local.json",
            ".claude/settings.local.json",
            # MCP project files sometimes hold tokens; keep if the team shares
            # a redacted, env-ref-only copy, otherwise ignore:
            # ".mcp.json",
            # ".cursor/mcp.json",
        ]
    ) + "\n"


def suggest_pre_commit_hook() -> str:
    return """#!/usr/bin/env bash
# pre-commit hook: block committing AI agent local settings / obvious secret files
# Printed by `quota-guard secrets --print-hook`. This hook is not installed by default.
set -euo pipefail
blocked='\\.claude/settings\\.local\\.json$|\\.credentials\\.json$|auth\\.json$'
if git diff --cached --name-only | grep -E "$blocked" >/dev/null; then
  echo "Refusing to commit agent local settings or credential files."
  echo "Use environment-variable references in allow rules, not literal secrets."
  exit 1
fi
ROOT="$(git rev-parse --show-toplevel)"
if command -v quota-guard >/dev/null 2>&1; then
  quota-guard secrets --root "$ROOT" --fail-on high >/dev/null
elif [[ -f "$ROOT/quota_guard.py" ]]; then
  python3 "$ROOT/quota_guard.py" secrets --root "$ROOT" --fail-on high >/dev/null
fi
"""


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def render_report_text(result: ScanResult) -> str:
    lines = [
        "# Agent config secret audit",
        "",
        "Generated locally. Secret values are redacted (first two characters + *** and length only; never the raw secret).",
        "No account credentials were read. Nothing was uploaded. This is not a proof that a repository is clean.",
        "",
        f"Files scanned: {len(result.files_scanned)}",
        f"Findings: {len(result.findings)}",
        "",
    ]
    if result.notes:
        lines.append("## Notes")
        lines.append("")
        for n in result.notes:
            lines.append(f"- {n}")
        lines.append("")
    if not result.findings:
        lines.append("No secret or git-hygiene issue detected with the current rules.")
    else:
        by_sev = {"high": [], "medium": [], "low": []}
        for f in result.findings:
            by_sev.setdefault(f.severity, []).append(f)
        for sev in ("high", "medium", "low"):
            items = by_sev.get(sev) or []
            if not items:
                continue
            lines += [f"## {sev.upper()} ({len(items)})", ""]
            for f in items:
                lines += [
                    f"### {f.rule_id}",
                    "",
                    f"- File: `{f.path}`",
                    f"- Line: {f.line if f.line else 'n/a'}",
                    f"- Location: {f.location}",
                    f"- Rule: {f.rule_id}",
                    f"- Category: {f.category}",
                    f"- Evidence (redacted): `{f.evidence}`",
                    f"- What to do: {f.remediation}",
                    "",
                ]
        lines += [
            "## Suggested .gitignore lines",
            "",
            "```gitignore",
            suggest_gitignore().rstrip(),
            "```",
            "",
        ]
    return "\n".join(lines)


def write_report(path: Path, result: ScanResult) -> None:
    path.write_text(render_report_text(result), encoding="utf-8")


def result_to_json(result: ScanResult) -> dict[str, Any]:
    return {
        "files_scanned": result.files_scanned,
        "findings": [f.as_public_dict() for f in result.findings],
        "notes": result.notes,
    }


def assert_no_raw_leak(public_text: str, raw_secrets: Iterable[str]) -> None:
    for secret in raw_secrets:
        if secret and len(secret) >= 6 and secret in public_text:
            raise AssertionError(f"raw secret leaked into output: {redact(secret)}")


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (path, line, redacted evidence).

    Line is part of the key so two different secrets that happen to redact
    to the same snippet (for example two FAKE*** passwords of equal length)
    stay distinct. The same value on the same line, caught by both a
    command-password rule and a known-prefix rule, still collapses to one
    finding, preferring command-password rules, then known prefixes.
    """
    priority = {
        "command-embedded-password": 0,
        "known-token-format": 1,
        "config-literal-secret": 2,
        "git-hygiene": 3,
        "ssh-forward-agent": 4,
    }
    best: dict[tuple[str, int | None, str], Finding] = {}
    for f in findings:
        key = (f.path, f.line, f.evidence)
        prev = best.get(key)
        if prev is None or priority.get(f.category, 9) < priority.get(prev.category, 9):
            best[key] = f
        elif prev is not None and f.rule_id != prev.rule_id and priority.get(f.category, 9) == priority.get(prev.category, 9):
            if f.rule_id not in prev.rule_id:
                prev.rule_id = f"{prev.rule_id}+{f.rule_id}"
    return list(best.values())


def run_scan(
    root: Path,
    home: Path | None = None,
    ssh_config: Path | None = None,
    skip_git: bool = False,
) -> ScanResult:
    result = ScanResult()
    files = discover_project_files(root)
    if home is not None:
        files.extend(discover_home_files(home))
    if ssh_config is not None and ssh_config.is_file():
        files.append(ssh_config)

    seen: set[Path] = set()
    for path in files:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            continue
        seen.add(resolved)
        result.files_scanned.append(str(path))
        findings, notes = scan_path(path)
        result.findings.extend(findings)
        result.notes.extend(notes)

    if ssh_config is not None and ssh_config.is_file():
        # If parent is not ssh/.ssh, scan_path may have treated it as text.
        already = any(f.rule_id == "ssh-forward-agent" and f.path == str(ssh_config) for f in result.findings)
        if not already:
            result.findings.extend(scan_ssh_config(ssh_config))

    if not skip_git:
        result.findings.extend(scan_git_hygiene(root))

    result.findings = dedupe_findings(result.findings)
    # Stable order: severity, path, rule
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    result.findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.path, f.rule_id, f.location))
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Scan AI coding-agent configs for leaked secrets (local, redacted, no uploads)."
    )
    p.add_argument("--root", default=".", help="Project directory to scan (default: current directory)")
    p.add_argument("--home", action="store_true", help="Also scan user-level agent configs under $HOME")
    p.add_argument("--home-root", default="", help="Override home directory (for tests)")
    p.add_argument("--ssh-config", default="", help="Extra SSH config file to check for ForwardAgent")
    p.add_argument("--skip-git", action="store_true", help="Skip gitignore / git history checks")
    p.add_argument("--report", default="", help="Write a redacted markdown report to this path")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "none"])
    p.add_argument("--print-gitignore", action="store_true", help="Print suggested .gitignore lines and exit")
    p.add_argument("--print-hook", action="store_true", help="Print a suggested pre-commit hook and exit")
    args = p.parse_args(argv)

    if args.print_gitignore:
        sys.stdout.write(suggest_gitignore())
        return 0
    if args.print_hook:
        sys.stdout.write(suggest_pre_commit_hook())
        return 0

    root = Path(args.root).expanduser().resolve()
    home = None
    if args.home or args.home_root:
        home = Path(args.home_root or Path.home()).expanduser()
    ssh_config = Path(args.ssh_config).expanduser() if args.ssh_config else None

    result = run_scan(root, home=home, ssh_config=ssh_config, skip_git=args.skip_git)

    payload = result_to_json(result)
    public = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.json:
        print(public)
    else:
        print(f"Scanned {len(result.files_scanned)} file(s). Findings: {len(result.findings)}")
        if not result.findings:
            print("No secret or git-hygiene issue detected.")
        for f in result.findings:
            print(f"[{f.severity.upper()}] {f.rule_id}: {f.path} ({f.location})")
            print(f"         evidence: {f.evidence}")  # already redacted
        for n in result.notes:
            print(f"[note] {n}")

    if args.report:
        write_report(Path(args.report), result)
        print(f"Wrote report: {args.report}", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    rank = {"high": 0, "medium": 1, "low": 2}
    threshold = rank[args.fail_on]
    if any(rank.get(f.severity, 9) <= threshold for f in result.findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
