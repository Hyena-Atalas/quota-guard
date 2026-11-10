#!/usr/bin/env python3
"""quota-guard: read-only local detector for idle Claude/Codex usage.

Reads Claude Code JSONL transcripts and Codex CLI rollout JSONL files.
Detects token or quota-percent growth after a configurable idle window.

This tool does NOT read credentials, call provider APIs, or kill processes.
Unknown or incomplete log records are skipped with a warning; they do not
crash the scan.

Field names that vary by client version are handled conservatively. Anything
not confirmed against public docs is treated as unverified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO

__version__ = "0.1.0"

# Default idle window: usage after this many seconds with no user event is "idle".
DEFAULT_IDLE_SECONDS = 180
# Minimum token delta in the idle window before we alert (local tokens only).
DEFAULT_TOKEN_THRESHOLD = 1
# Minimum Codex used_percent step to flag even if local tokens are 0
# (possible other-device / cloud / accounting movement).
DEFAULT_PERCENT_THRESHOLD = 1.0

# Official documentation linked by check-config (do not invent extras).
CODEX_CONFIG_DOCS = "https://learn.chatgpt.com/docs/config-file/config-basic"
CODEX_MEMORIES_DOCS = "https://learn.chatgpt.com/docs/customization/memories"
CLAUDE_COSTS_DOCS = "https://code.claude.com/docs/en/costs"
CLAUDE_INTERACTIVE_DOCS = "https://code.claude.com/docs/en/interactive-mode"
CLAUDE_CACHING_DOCS = "https://code.claude.com/docs/en/prompt-caching"
CHATGPT_USAGE_URL = "https://chatgpt.com/settings/usage"
CLAUDE_USAGE_URL = "https://claude.ai/settings/usage"
CODEX_PLAN_HELP = (
    "https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan"
)

# Usage keys we know how to read. If a usage object has none of these, skip it.
KNOWN_TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cached_input_tokens",
    "cache_creation_input_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)

# Filenames this tool will never open, even if they sit next to logs or config.
FORBIDDEN_NAME_FRAGMENTS = (
    "auth.json",
    ".credentials.json",
    "credentials.json",
    "keychain",
    "cookie",
)

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------


@dataclass
class ParseWarning:
    path: str
    line: int | None
    message: str

    def __str__(self) -> str:
        loc = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{loc}: {self.message}"


# ---------------------------------------------------------------------------
# Time and privacy helpers
# ---------------------------------------------------------------------------


def parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Codex rate_limits.resets_at is unix seconds; timestamps in jsonl are ISO.
        if value > 10_000_000_000:  # ms
            value = value / 1000.0
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat()


def hash_session_id(session_id: str) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:12]}"


def display_session_id(session_id: str, no_hash: bool) -> str:
    return session_id if no_hash else hash_session_id(session_id)


def display_path(
    path: str | Path,
    *,
    no_redact: bool = False,
    home: Path | None = None,
    session_ids: Iterable[str] = (),
    no_hash: bool = False,
) -> str:
    """Redact $HOME and, unless --no-hash, replace raw session ids in the path."""
    shown = str(path) if no_redact else redact_path(path, home)
    if not no_hash:
        for sid in sorted({s for s in session_ids if s}, key=len, reverse=True):
            if sid in shown:
                shown = shown.replace(sid, hash_session_id(sid))
    return shown


def _as_path(value: str | Path) -> Path:
    # pathlib handles Windows and POSIX separators on the running platform.
    return Path(value)


def redact_path(path: str | Path, home: str | Path | None = None) -> str:
    """Replace the home directory prefix with ~. Works with POSIX and Windows paths."""
    raw = str(path)
    home_path = _as_path(home) if home is not None else Path.home()
    candidates = [str(home_path)]
    try:
        candidates.append(str(home_path.expanduser()))
    except (RuntimeError, OSError):
        pass
    # Also try the POSIX and Windows-style spellings of the same home.
    extras: list[str] = []
    for c in candidates:
        extras.append(c.replace("\\", "/"))
        extras.append(c.replace("/", "\\"))
    candidates.extend(extras)

    best: str | None = None
    for home_s in candidates:
        if not home_s:
            continue
        if raw == home_s or raw.startswith(home_s + "/") or raw.startswith(home_s + "\\"):
            if best is None or len(home_s) > len(best):
                best = home_s
        # Case-insensitive match for Windows drive letters / user folders.
        raw_l = raw.lower()
        home_l = home_s.lower()
        if raw_l == home_l or raw_l.startswith(home_l + "/") or raw_l.startswith(home_l + "\\"):
            if best is None or len(home_s) > len(best):
                best = home_s
    if best is None:
        return raw
    suffix = raw[len(best) :]
    if suffix and suffix[0] not in "\\/":
        return raw
    return "~" + suffix.replace("\\", "/") if "\\" in raw and "/" not in raw else "~" + suffix.replace("\\", "/")


def is_forbidden_path(path: Path) -> bool:
    name = path.name.lower()
    return any(frag in name for frag in FORBIDDEN_NAME_FRAGMENTS)


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


@dataclass
class Event:
    source: str  # claude | codex
    session_id: str
    path: str
    ts: datetime | None
    kind: str  # user | usage | quota | other
    tokens: int = 0
    used_percent: float | None = None
    window_label: str | None = None  # e.g. primary/secondary
    note: str = ""


@dataclass
class SessionState:
    source: str
    session_id: str
    path: str
    events: list[Event] = field(default_factory=list)
    last_user_ts: datetime | None = None
    last_usage_ts: datetime | None = None
    total_tokens: int = 0
    last_used_percent: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# JSONL reader
# ---------------------------------------------------------------------------


def iter_jsonl(
    path: Path, warnings: list[ParseWarning] | None = None
) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield (line_number, object) for complete JSON objects.

    A truncated or half-written last line (common while a session is still
    being written) is skipped with a warning instead of raising.
    Missing/invalid records elsewhere are also skipped with a warning.
    """
    if warnings is None:
        warnings = []
    if is_forbidden_path(path):
        warnings.append(ParseWarning(str(path), None, "refusing to read a credentials-like filename"))
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not read file: {exc}"))
        return
    raw_lines = text.splitlines()
    # Preserve a trailing incomplete line even if it has no newline yet.
    if text.endswith("\n"):
        lines = raw_lines
    else:
        lines = raw_lines  # last element is the unterminated line, if any

    last_nonempty = 0
    for i, line in enumerate(lines, start=1):
        if line.strip():
            last_nonempty = i

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if i == last_nonempty:
                warnings.append(
                    ParseWarning(
                        str(path),
                        i,
                        "skipped truncated or partial last line (session may still be writing)",
                    )
                )
            else:
                warnings.append(
                    ParseWarning(
                        str(path),
                        i,
                        f"skipped malformed JSON ({exc.msg})",
                    )
                )
            continue
        if not isinstance(obj, dict):
            warnings.append(
                ParseWarning(str(path), i, "skipped non-object JSONL record")
            )
            continue
        yield i, obj


def _first_int(record: dict[str, Any], *keys: str) -> int | None:
    """Return the first key that is a number. Does not sum aliases."""
    for key in keys:
        val = record.get(key)
        if isinstance(val, (int, float)):
            return int(val)
    return None


def claude_usage_tokens(usage: dict[str, Any]) -> int | None:
    """Sum documented Claude usage fields.

    Confirmed fields in public writeups: input_tokens, output_tokens,
    cache_read_input_tokens, cache_creation_input_tokens.
    Some versions may spell the cache-read field cached_input_tokens.
    Do not also add cache_creation.ephemeral_* or you will double-count.
    Do not add both cache_read_input_tokens and cached_input_tokens.
    """
    if not any(k in usage for k in KNOWN_TOKEN_KEYS):
        return None
    total = 0
    for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens"):
        val = usage.get(key)
        if isinstance(val, (int, float)):
            total += int(val)
    cache_read = _first_int(usage, "cache_read_input_tokens", "cached_input_tokens")
    if cache_read is not None:
        total += cache_read
    return total


def parse_claude_file(
    path: Path, warnings: list[ParseWarning] | None = None
) -> list[Event]:
    if warnings is None:
        warnings = []
    events: list[Event] = []
    seen_usage: set[str] = set()
    session_from_name = path.stem
    for line_no, rec in iter_jsonl(path, warnings):
        session_id = str(rec.get("sessionId") or session_from_name)
        ts = parse_ts(rec.get("timestamp"))
        typ = rec.get("type")
        if typ == "user":
            # Tool results are also type=user in some transcripts. If the
            # record looks like a tool result, do not treat it as user input.
            # Field shape can vary; this heuristic is unverified on live data.
            msg = rec.get("message") or {}
            content = msg.get("content") if isinstance(msg, dict) else None
            is_tool_result = False
            if isinstance(content, list):
                is_tool_result = any(
                    isinstance(part, dict)
                    and part.get("type") in {"tool_result", "tool_use"}
                    for part in content
                )
            elif isinstance(content, str) and "tool_result" in content[:80]:
                is_tool_result = True
            if not is_tool_result:
                events.append(
                    Event("claude", session_id, str(path), ts, "user", note="user_message")
                )
            continue
        if typ != "assistant":
            # Other record types (system, file-history, progress, etc.) are
            # expected and skipped quietly. We only warn when a record looks
            # like usage we failed to parse.
            continue
        msg = rec.get("message")
        if msg is None:
            continue
        if not isinstance(msg, dict):
            warnings.append(
                ParseWarning(str(path), line_no, "skipped assistant record with non-object message")
            )
            continue
        usage = msg.get("usage")
        if usage is None:
            continue
        if not isinstance(usage, dict):
            warnings.append(
                ParseWarning(str(path), line_no, "skipped assistant record with non-object usage")
            )
            continue
        tokens = claude_usage_tokens(usage)
        if tokens is None:
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "skipped usage record: no known token fields "
                    "(unknown version or missing fields)",
                )
            )
            continue
        # Dedup key confirmed by ccusage / public format docs:
        # message.id + requestId. Group and take the max token total.
        key = f"{rec.get('requestId', '')}:{msg.get('id', '')}"
        if key != ":" and key in seen_usage:
            for ev in reversed(events):
                if ev.note == key:
                    if tokens > ev.tokens:
                        ev.tokens = tokens
                        ev.ts = ts or ev.ts
                    break
            continue
        if key != ":":
            seen_usage.add(key)
        else:
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "usage record missing message.id and requestId; counted without dedup key",
                )
            )
        events.append(
            Event(
                "claude",
                session_id,
                str(path),
                ts,
                "usage",
                tokens=tokens,
                note=key,
            )
        )
    return events


def codex_usage_tokens(info: dict[str, Any]) -> tuple[int, str] | None:
    """Return (tokens, source) from a Codex token_count info object.

    Prefer cumulative total_token_usage; caller should delta it.
    Confirmed fields: input_tokens, cached_input_tokens (some versions
    write cache_read_input_tokens), output_tokens, reasoning_output_tokens,
    total_tokens. Cached tokens are usually already inside input_tokens;
    do not add them again when summing parts.
    """
    usage = info.get("total_token_usage") or info.get("last_token_usage")
    if usage is None:
        return None
    if not isinstance(usage, dict):
        return None
    source = "total_token_usage" if info.get("total_token_usage") else "last_token_usage"
    if "total_tokens" in usage and isinstance(usage["total_tokens"], (int, float)):
        return int(usage["total_tokens"]), source
    if not any(k in usage for k in KNOWN_TOKEN_KEYS):
        return None
    inp = int(usage.get("input_tokens") or 0)
    out = int(usage.get("output_tokens") or 0)
    reason = int(usage.get("reasoning_output_tokens") or 0)
    # cached / cache_read is usually already inside input_tokens; do not add it.
    return inp + out + reason, "sum_parts"


def parse_codex_file(
    path: Path, warnings: list[ParseWarning] | None = None
) -> list[Event]:
    if warnings is None:
        warnings = []
    events: list[Event] = []
    session_id = path.stem
    last_cumulative = 0
    have_cumulative = False
    for line_no, rec in iter_jsonl(path, warnings):
        typ = rec.get("type")
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
        ts = parse_ts(rec.get("timestamp"))
        if typ == "session_meta":
            session_id = str(payload.get("id") or session_id)
            continue
        if typ == "event_msg" and payload.get("type") == "user_message":
            events.append(
                Event("codex", session_id, str(path), ts, "user", note="user_message")
            )
            continue
        if typ != "event_msg" or payload.get("type") != "token_count":
            continue
        info = payload.get("info")
        if info is None and "rate_limits" not in payload:
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "skipped token_count record: missing info and rate_limits",
                )
            )
            continue
        if info is not None and not isinstance(info, dict):
            warnings.append(
                ParseWarning(str(path), line_no, "skipped token_count record: info is not an object")
            )
            info = {}
        if not isinstance(info, dict):
            info = {}

        tokens_src = codex_usage_tokens(info) if info else None
        if info and tokens_src is None and not payload.get("rate_limits"):
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "skipped token_count record: no known token fields "
                    "(unknown version or missing fields)",
                )
            )
        if tokens_src is not None:
            tokens, src = tokens_src
            delta = 0
            if src == "total_token_usage" or (have_cumulative and src != "none"):
                if have_cumulative:
                    delta = max(0, tokens - last_cumulative)
                else:
                    # First cumulative snapshot is the session total so far,
                    # not necessarily an idle increment by itself.
                    delta = tokens
                last_cumulative = tokens
                have_cumulative = True
            elif tokens:
                delta = tokens  # last_token_usage fallback; may overcount if repeated
            if delta:
                events.append(
                    Event("codex", session_id, str(path), ts, "usage", tokens=delta, note=src)
                )
        rate = payload.get("rate_limits")
        if isinstance(rate, dict):
            for label in ("primary", "secondary"):
                bucket = rate.get(label)
                if not isinstance(bucket, dict):
                    continue
                pct = bucket.get("used_percent")
                if isinstance(pct, (int, float)):
                    events.append(
                        Event(
                            "codex",
                            session_id,
                            str(path),
                            ts,
                            "quota",
                            used_percent=float(pct),
                            window_label=label,
                            note=f"window_minutes={bucket.get('window_minutes')}",
                        )
                    )
    return events


def discover(root: Path, kind: str) -> list[Path]:
    """Find log files under a Claude or Codex root. Uses pathlib throughout."""
    root = Path(root)
    if not root.exists():
        return []
    if root.is_file():
        if is_forbidden_path(root):
            return []
        if root.suffix == ".jsonl":
            return [root]
        return []
    if kind == "claude":
        base = root / "projects" if (root / "projects").is_dir() else root
        files = sorted(p for p in base.rglob("*.jsonl") if p.is_file() and not is_forbidden_path(p))
        return files
    # Codex: $CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl
    # and $CODEX_HOME/archived_sessions/rollout-*.jsonl
    files: list[Path] = []
    sessions = root / "sessions" if (root / "sessions").is_dir() else root
    files.extend(
        p
        for p in sessions.rglob("*")
        if p.is_file()
        and p.name.startswith("rollout-")
        and p.suffix == ".jsonl"
        and not is_forbidden_path(p)
    )
    archived = root / "archived_sessions"
    if archived.is_dir():
        files.extend(
            p
            for p in archived.rglob("*")
            if p.is_file()
            and p.name.startswith("rollout-")
            and p.suffix == ".jsonl"
            and not is_forbidden_path(p)
        )
    # De-duplicate while keeping a stable order.
    unique: list[Path] = []
    seen: set[Path] = set()
    for p in files:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return sorted(unique, key=lambda p: str(p))


def claude_roots_from_env_or_arg(override: str) -> list[Path]:
    """Resolve Claude config roots.

    CLAUDE_CONFIG_DIR may be comma-separated (reported by some community
    tools; whether that is official complete behavior is unverified).
    This tool does not automatically also scan ~/.config/claude.
    """
    raw = override or os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return [Path(part.strip()) for part in str(raw).split(",") if part.strip()]


def codex_root_from_env_or_arg(override: str) -> Path:
    raw = override or os.environ.get("CODEX_HOME") or str(Path.home() / ".codex")
    return Path(raw)


def build_sessions(events: list[Event]) -> dict[str, SessionState]:
    sessions: dict[str, SessionState] = {}
    for ev in events:
        key = f"{ev.source}:{ev.session_id}"
        st = sessions.get(key)
        if st is None:
            st = SessionState(ev.source, ev.session_id, ev.path)
            sessions[key] = st
        st.events.append(ev)
        if ev.kind == "user" and ev.ts:
            if st.last_user_ts is None or ev.ts > st.last_user_ts:
                st.last_user_ts = ev.ts
        if ev.kind == "usage":
            st.total_tokens += ev.tokens
            if ev.ts and (st.last_usage_ts is None or ev.ts > st.last_usage_ts):
                st.last_usage_ts = ev.ts
        if ev.kind == "quota" and ev.window_label and ev.used_percent is not None:
            st.last_used_percent[ev.window_label] = ev.used_percent
    return sessions


@dataclass
class Alert:
    severity: str
    alert_type: str  # A, B, or A+B
    session_id: str
    source: str
    path: str
    reason: str
    idle_tokens: int
    percent_step: float | None
    last_user_ts: str
    first_idle_usage_ts: str
    last_usage_ts: str

    def public_dict(
        self,
        no_hash: bool,
        no_redact: bool,
        home: Path | None = None,
        session_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        data = asdict(self)
        data["session_id"] = display_session_id(self.session_id, no_hash)
        ids = tuple(session_ids) or (self.session_id,)
        data["path"] = display_path(
            self.path, no_redact=no_redact, home=home, session_ids=ids, no_hash=no_hash
        )
        return data


def _min_utc() -> datetime:
    return datetime.min.replace(tzinfo=timezone.utc)


def detect(
    sessions: dict[str, SessionState],
    idle_seconds: int,
    token_threshold: int,
    percent_threshold: float,
) -> list[Alert]:
    alerts: list[Alert] = []
    for st in sessions.values():
        # Idle usage: usage events whose ts is more than idle_seconds after last
        # preceding user event (not necessarily the session's final user event,
        # so a later user message doesn't hide earlier drain).
        last_user: datetime | None = None
        idle_tokens = 0
        first_idle_ts: datetime | None = None
        last_idle_ts: datetime | None = None
        percent_by_window: dict[str, list[tuple[datetime | None, float]]] = defaultdict(list)

        for ev in sorted(st.events, key=lambda e: (e.ts or _min_utc(), e.kind)):
            if ev.kind == "user":
                last_user = ev.ts or last_user
                continue
            is_idle = False
            if ev.ts and last_user:
                is_idle = (ev.ts - last_user).total_seconds() >= idle_seconds
            elif ev.ts and last_user is None:
                # Usage with no user message in this file. Could be background
                # memory work or a truncated log. Flag conservatively.
                is_idle = True
            if ev.kind == "usage" and is_idle:
                idle_tokens += ev.tokens
                if first_idle_ts is None:
                    first_idle_ts = ev.ts
                last_idle_ts = ev.ts
            if ev.kind == "quota" and ev.window_label and ev.used_percent is not None:
                percent_by_window[ev.window_label].append((ev.ts, ev.used_percent))

        # Quota percent can rise with zero local tokens (other device / cloud /
        # delayed accounting). Baseline = last snapshot at or before the idle
        # threshold; compare with the last snapshot after the threshold.
        percent_step = None
        percent_note = ""
        for label, series in percent_by_window.items():
            if not series:
                continue
            if last_user is None:
                if len(series) >= 2:
                    step = series[-1][1] - series[0][1]
                else:
                    continue
            else:
                baseline = None
                latest_idle = None
                for ts, pct in series:
                    if ts is None:
                        continue
                    if (ts - last_user).total_seconds() < idle_seconds:
                        baseline = pct
                    else:
                        if baseline is None:
                            baseline = pct
                        latest_idle = pct
                if baseline is None or latest_idle is None:
                    continue
                step = latest_idle - baseline
            if step >= percent_threshold and (percent_step is None or step > percent_step):
                percent_step = step
                percent_note = label

        has_a = idle_tokens >= token_threshold
        has_b = percent_step is not None and percent_step >= percent_threshold and idle_tokens == 0
        has_percent_with_tokens = (
            percent_step is not None and percent_step >= percent_threshold and idle_tokens > 0
        )
        if not (has_a or has_b or has_percent_with_tokens):
            continue
        if has_a and (has_b or has_percent_with_tokens):
            alert_type = "A+B" if has_b else "A"
            # If local tokens also grew, the percent step is accompanying type A,
            # not a standalone type B (type B is "percent up, local tokens did not").
            if has_percent_with_tokens and not has_b:
                alert_type = "A"
        elif has_a:
            alert_type = "A"
        else:
            alert_type = "B"

        parts = []
        if has_a:
            parts.append(
                f"local tokens grew by {idle_tokens} after no user input for >= {idle_seconds}s"
            )
        if percent_step is not None and percent_step >= percent_threshold:
            parts.append(
                f"Codex {percent_note or 'quota'} used_percent rose by {percent_step:.1f} during idle"
            )
            if idle_tokens == 0:
                parts.append(
                    "no matching local token_count delta (possible other device, "
                    "cloud task, shared quota pool, or accounting lag)"
                )
        alerts.append(
            Alert(
                severity="idle_drain",
                alert_type=alert_type,
                session_id=st.session_id,
                source=st.source,
                path=st.path,
                reason="; ".join(parts),
                idle_tokens=idle_tokens,
                percent_step=percent_step,
                last_user_ts=iso(st.last_user_ts),
                first_idle_usage_ts=iso(first_idle_ts),
                last_usage_ts=iso(last_idle_ts or st.last_usage_ts),
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    events: list[Event]
    sessions: dict[str, SessionState]
    alerts: list[Alert]
    scanned: list[str]
    warnings: list[ParseWarning]


def scan_roots(
    claude_roots: list[Path],
    codex_root: Path,
    idle_seconds: int,
    token_threshold: int,
    percent_threshold: float,
) -> ScanResult:
    events: list[Event] = []
    scanned: list[str] = []
    warnings: list[ParseWarning] = []
    for root in claude_roots:
        if not root.exists():
            continue
        for path in discover(root, "claude"):
            scanned.append(str(path))
            events.extend(parse_claude_file(path, warnings))
    if codex_root.exists():
        for path in discover(codex_root, "codex"):
            scanned.append(str(path))
            events.extend(parse_codex_file(path, warnings))
    sessions = build_sessions(events)
    alerts = detect(sessions, idle_seconds, token_threshold, percent_threshold)
    return ScanResult(events, sessions, alerts, scanned, warnings)


def emit_warnings(warnings: list[ParseWarning], stream: TextIO = sys.stderr) -> None:
    for w in warnings:
        print(f"warning: {w}", file=stream)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _timeline_lines(st: SessionState) -> list[str]:
    """Timestamps and counts only. Never includes prompt text or message bodies."""
    lines = ["- Timeline (timestamps and counts only; no prompt text):"]
    ordered = sorted(st.events, key=lambda e: (e.ts or _min_utc(), e.kind))
    if not ordered:
        lines.append("  - (no events)")
        return lines
    for ev in ordered:
        ts = iso(ev.ts) or "unknown time"
        if ev.kind == "user":
            lines.append(f"  - {ts}  user input")
        elif ev.kind == "usage":
            lines.append(f"  - {ts}  local tokens +{ev.tokens}")
        elif ev.kind == "quota":
            label = ev.window_label or "quota"
            pct = ev.used_percent
            pct_s = f"{pct:.1f}" if pct is not None else "n/a"
            lines.append(f"  - {ts}  {label} used_percent={pct_s}")
        else:
            lines.append(f"  - {ts}  {ev.kind}")
    return lines


def render_report(
    alerts: list[Alert],
    sessions: dict[str, SessionState],
    *,
    no_hash: bool = False,
    no_redact: bool = False,
    home: Path | None = None,
    warnings: list[ParseWarning] | None = None,
) -> str:
    lines = [
        "# Quota drain evidence report",
        "",
        "Generated locally by quota-guard. This is **not** an official quota dashboard.",
        "Token totals are reconstructed from local logs and may differ from the official usage page.",
        "Codex `used_percent` values come from snapshots the official client wrote into local logs; they may lag.",
        "No account credentials were read. No provider API was called.",
        "",
        "OpenAI Support will not reset ChatGPT/Codex usage limits. If you contact Support, treat this",
        "timeline as extra local evidence for an investigation, not as a promise that quota will be restored.",
        f"See: {CODEX_PLAN_HELP}",
        "",
        "Please also screenshot the official usage pages when you file a report:",
        f"- ChatGPT / Codex: {CHATGPT_USAGE_URL}",
        f"- Claude: {CLAUDE_USAGE_URL}",
        "- Or compare with `/status` (Codex) or `/usage` (Claude) in the official CLI.",
        "",
        f"Sessions scanned: {len(sessions)}",
        f"Alerts: {len(alerts)}",
        "",
    ]
    if warnings:
        lines.append(f"Parse warnings: {len(warnings)} (see below). Incomplete or unknown records were skipped.")
        lines.append("")

    all_ids = tuple(st.session_id for st in sessions.values())
    if sessions:
        lines += ["## Sessions scanned", ""]
        for st in sessions.values():
            sid = display_session_id(st.session_id, no_hash)
            path = display_path(
                st.path, no_redact=no_redact, home=home, session_ids=all_ids, no_hash=no_hash
            )
            lines.append(
                f"- {st.source} / `{sid}` — local tokens counted: {st.total_tokens}"
                f"{'; last user input (UTC): ' + iso(st.last_user_ts) if st.last_user_ts else '; no user input in this file'}"
            )
            lines.append(f"  - File: `{path}`")
        lines.append("")

    if not alerts:
        lines.append("No idle-drain pattern detected with the current thresholds.")
        lines.append("")
    for a in alerts:
        sid = display_session_id(a.session_id, no_hash)
        path = display_path(
            a.path, no_redact=no_redact, home=home, session_ids=all_ids or (a.session_id,), no_hash=no_hash
        )
        type_note = {
            "A": "Type A — local tokens grew after the idle window (possible background work or a session that did not stop).",
            "B": (
                "Type B — quota percent rose with no matching local token delta. "
                "Local logs cannot see other devices, Codex Cloud / scheduled tasks, or a shared quota pool "
                "(some plans share usage across Codex, ChatGPT, and other surfaces). Accounting may also lag."
            ),
            "A+B": "Type A+B — local token growth and a quota-percent step during idle.",
        }.get(a.alert_type, a.alert_type)
        key = f"{a.source}:{a.session_id}"
        st = sessions.get(key)
        lines += [
            f"## {a.source} / `{sid}`",
            "",
            f"- Detection: {type_note}",
            f"- Reason: {a.reason}",
            f"- File: `{path}`",
            f"- Last user input (UTC): {a.last_user_ts or 'none in this file'}",
            f"- First idle usage (UTC): {a.first_idle_usage_ts or 'n/a'}",
            f"- Last idle usage (UTC): {a.last_usage_ts or 'n/a'}",
            f"- Idle local tokens: {a.idle_tokens}",
            f"- Quota percent step: {a.percent_step if a.percent_step is not None else 'n/a'}",
            "",
        ]
        if st is not None:
            lines += _timeline_lines(st)
            lines.append("")

    if warnings:
        lines += ["## Parse warnings", ""]
        lines.append("These records were skipped. They did not crash the scan.")
        for w in warnings:
            shown_path = display_path(
                w.path, no_redact=no_redact, home=home, session_ids=all_ids, no_hash=no_hash
            )
            shown = str(ParseWarning(shown_path, w.line, w.message))
            lines.append(f"- {shown}")
        lines.append("")
    return "\n".join(lines)


def write_report(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# check-config (read-only)
# ---------------------------------------------------------------------------


@dataclass
class ConfigItem:
    source: str
    key: str
    value: Any
    present: bool
    status: str  # ok | review | unconfirmed | missing_file
    advice: str
    docs: str


def _format_value(value: Any) -> str:
    if value is None:
        return "(not set)"
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, ensure_ascii=False)


def _lookup_toml(data: dict[str, Any], *parts: str) -> tuple[bool, Any]:
    cur: Any = data
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def load_codex_config(root: Path, warnings: list[ParseWarning]) -> tuple[Path, dict[str, Any] | None]:
    path = Path(root) / "config.toml"
    if not path.is_file():
        return path, None
    if is_forbidden_path(path):
        warnings.append(ParseWarning(str(path), None, "refusing to read a credentials-like filename"))
        return path, None
    try:
        import tomllib
    except ImportError:  # pragma: no cover - requires Python 3.11+
        warnings.append(
            ParseWarning(str(path), None, "tomllib is unavailable; Python 3.11+ is required to parse config.toml")
        )
        return path, None
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not read config.toml: {exc}"))
        return path, None
    except tomllib.TOMLDecodeError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not parse config.toml: {exc}"))
        return path, None
    if not isinstance(data, dict):
        warnings.append(ParseWarning(str(path), None, "config.toml did not contain a table"))
        return path, None
    return path, data


def load_claude_settings(root: Path, warnings: list[ParseWarning]) -> tuple[Path, dict[str, Any] | None]:
    path = Path(root) / "settings.json"
    if not path.is_file():
        return path, None
    if is_forbidden_path(path):
        warnings.append(ParseWarning(str(path), None, "refusing to read a credentials-like filename"))
        return path, None
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except OSError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not read settings.json: {exc}"))
        return path, None
    except json.JSONDecodeError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not parse settings.json: {exc}"))
        return path, None
    if not isinstance(data, dict):
        warnings.append(ParseWarning(str(path), None, "settings.json is not an object"))
        return path, None
    return path, data


def check_codex_config(root: Path, warnings: list[ParseWarning]) -> tuple[Path, list[ConfigItem]]:
    path, data = load_codex_config(root, warnings)
    items: list[ConfigItem] = []

    def add(
        key: str,
        present: bool,
        value: Any,
        *,
        status: str,
        advice: str,
        docs: str = CODEX_MEMORIES_DOCS,
    ) -> None:
        items.append(
            ConfigItem("codex", key, value if present else None, present, status, advice, docs)
        )

    if data is None:
        add(
            "(file)",
            False,
            None,
            status="missing_file",
            advice=(
                f"No config.toml was found at this Codex home. That is not treated as an error. "
                f"Review official Memories and config docs if you use Codex memories or scheduled/cloud tasks. "
                f"This tool does not invent a default for keys that are not in a file."
            ),
            docs=CODEX_CONFIG_DOCS,
        )
        return path, items

    present, value = _lookup_toml(data, "features", "memories")
    if present:
        if value is True:
            status, advice = (
                "review",
                "Official docs say [features].memories defaults to false. When enabled, memory generation "
                "can use tokens. Turning this off is a documented way to limit that path; it does not "
                "guarantee that quota will stop moving (cloud/scheduled tasks and other clients can still run).",
            )
        elif value is False:
            status, advice = (
                "ok",
                "Memories feature flag is false, which matches the documented default. "
                "Background memory generation should be off, but other idle paths can still exist.",
            )
        else:
            status, advice = (
                "review",
                "Unexpected value type for [features].memories. See the official config docs. "
                "This tool will not change the file.",
            )
        add("[features].memories", True, value, status=status, advice=advice, docs=CODEX_MEMORIES_DOCS)
    else:
        add(
            "[features].memories",
            False,
            None,
            status="ok",
            advice=(
                "Not set in config.toml. Official docs state that the default is false. "
                "This tool is not changing any files."
            ),
            docs=CODEX_MEMORIES_DOCS,
        )

    memories_keys = (
        (
            "generate_memories",
            "Controls whether new conversations are used as input for memory generation. "
            "Official Memories docs describe this as a way to limit background memory work. "
            "No default is assumed here because it was not restated as a confirmed default in the project notes.",
        ),
        (
            "use_memories",
            "Controls whether existing memories are injected into later sessions. "
            "See official Memories docs. No default is assumed here.",
        ),
        (
            "min_rate_limit_remaining_percent",
            "Skip memory generation when remaining quota is below this percent. "
            "See official Memories docs. No default is assumed here.",
        ),
    )
    for leaf, advice in memories_keys:
        present, value = _lookup_toml(data, "memories", leaf)
        if present:
            add(
                f"[memories].{leaf}",
                True,
                value,
                status="review",
                advice=advice + " This tool only reports the value; it will not edit config.toml.",
            )
        else:
            add(
                f"[memories].{leaf}",
                False,
                None,
                status="review",
                advice="Not set in config.toml. " + advice,
            )

    items.append(
        ConfigItem(
            "codex",
            "Scheduled Tasks / Codex Cloud (not read from this file)",
            None,
            False,
            "unconfirmed",
            "Official help mentions scheduled tasks and cloud tasks that can continue while the computer sleeps. "
            "This tool does not claim to see those jobs in config.toml, and local session logs will not show "
            "usage that happened only in the cloud or on another device.",
            CODEX_CONFIG_DOCS,
        )
    )
    return path, items


def check_claude_settings(root: Path, warnings: list[ParseWarning]) -> tuple[Path, list[ConfigItem]]:
    path, data = load_claude_settings(root, warnings)
    items: list[ConfigItem] = []

    def add(key: str, present: bool, value: Any, status: str, advice: str, docs: str) -> None:
        items.append(ConfigItem("claude", key, value if present else None, present, status, advice, docs))

    if data is None:
        add(
            "(file)",
            False,
            None,
            "missing_file",
            "No settings.json was found at this Claude config dir. That is not treated as an error. "
            "Several idle features are documented in the official cost docs and can be reviewed in `/config`. "
            "This tool does not invent default values for missing files.",
            CLAUDE_COSTS_DOCS,
        )
        # Still list documented features so the user has the links.
    settings = data or {}

    # Documented settings.json keys (names taken from public cost / caching docs).
    if "promptSuggestionEnabled" in settings:
        val = settings["promptSuggestionEnabled"]
        if val is True:
            status, advice = (
                "review",
                "Official cost docs say prompt suggestions are short background requests that count toward usage. "
                "You can disable them with promptSuggestionEnabled=false or via `/config`. This tool will not edit the file.",
            )
        elif val is False:
            status, advice = (
                "ok",
                "Prompt suggestions are disabled in settings.json, which matches the documented way to turn them off.",
            )
        else:
            status, advice = (
                "review",
                "promptSuggestionEnabled is present but is not a boolean in this file. See the official cost docs.",
            )
        add("promptSuggestionEnabled", True, val, status, advice, CLAUDE_COSTS_DOCS)
    else:
        add(
            "promptSuggestionEnabled",
            False,
            None,
            "review",
            "Not set in settings.json. Official cost docs describe prompt suggestions as background requests "
            "that count toward usage, and document disabling them with promptSuggestionEnabled=false or `/config`. "
            "This tool does not invent the current default from a missing key.",
            CLAUDE_COSTS_DOCS,
        )

    if "idleCompaction" in settings:
        val = settings["idleCompaction"]
        if val is True:
            status, advice = (
                "review",
                "Official prompt-caching docs describe idle compaction of long conversations (requires Claude Code "
                "v2.1.290+ to set idleCompaction: false). Compaction itself is a request and can use tokens. "
                "This tool will not edit the file.",
            )
        elif val is False:
            status, advice = (
                "ok",
                "idleCompaction is false in settings.json, which is the documented way to disable idle compaction "
                "(Claude Code v2.1.290+).",
            )
        else:
            status, advice = (
                "review",
                "idleCompaction is present but is not a boolean in this file. See the official prompt-caching docs.",
            )
        add("idleCompaction", True, val, status, advice, CLAUDE_CACHING_DOCS)
    else:
        add(
            "idleCompaction",
            False,
            None,
            "review",
            "Not set in settings.json. Official prompt-caching docs mention idle compaction and the key "
            "idleCompaction: false (v2.1.290+). This tool does not invent the current default from a missing key.",
            CLAUDE_CACHING_DOCS,
        )

    # Features that official docs describe, but whose exact settings.json key is unconfirmed here.
    add(
        "session recap",
        False,
        None,
        "unconfirmed",
        "Official interactive-mode / cost docs say session recap is on by default and can run in the background "
        "after the terminal loses focus and a few minutes have passed since the last turn. Docs say it can be "
        "turned off in `/config`. The exact settings.json key name is unconfirmed here, so this tool will not "
        "guess a key or a file default.",
        CLAUDE_INTERACTIVE_DOCS,
    )
    add(
        "scheduled tasks / goal check-ins / crossSessionInbound",
        False,
        None,
        "unconfirmed",
        "Official cost docs say session-level scheduled tasks, goal check-ins, and cross-session inbound delivery "
        "can send context again while you are idle. Exact settings.json key names for these are unconfirmed here. "
        "Review them in `/config` and the official cost docs. This tool will not invent keys or defaults.",
        CLAUDE_COSTS_DOCS,
    )
    add(
        "side agents such as “You should know”",
        False,
        None,
        "unconfirmed",
        "Official cost docs mention that some side agents, if enabled, are also background requests. "
        "The exact settings.json key is unconfirmed here.",
        CLAUDE_COSTS_DOCS,
    )
    return path, items


def render_config_report(
    codex_path: Path,
    codex_items: list[ConfigItem],
    claude_paths: list[tuple[Path, list[ConfigItem]]],
    *,
    no_redact: bool = False,
    home: Path | None = None,
) -> str:
    def show(p: Path) -> str:
        return str(p) if no_redact else redact_path(p, home)

    lines = [
        "# quota-guard config check (read-only)",
        "",
        "This command only reads documented keys from local config files and prints suggestions plus official doc links.",
        "It does not modify any file, and it does not read credentials.",
        "Values that are not in the file are reported as not set. Defaults are quoted only when official docs state them.",
        "Keys or defaults that this project has not confirmed are marked unconfirmed.",
        "",
        f"## Codex  ({show(codex_path)})",
        "",
    ]
    for item in codex_items:
        lines.append(f"- `{item.key}` = {_format_value(item.value)}  [{item.status}]")
        lines.append(f"  {item.advice}")
        lines.append(f"  Docs: {item.docs}")
        lines.append("")

    for cpath, citems in claude_paths:
        lines += [f"## Claude  ({show(cpath)})", ""]
        for item in citems:
            lines.append(f"- `{item.key}` = {_format_value(item.value)}  [{item.status}]")
            lines.append(f"  {item.advice}")
            lines.append(f"  Docs: {item.docs}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _add_root_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--claude-root",
        default="",
        help="Override Claude config dir (default: $CLAUDE_CONFIG_DIR or ~/.claude). "
        "Comma-separated paths are accepted (community-reported; official behavior unverified).",
    )
    p.add_argument(
        "--codex-root",
        default="",
        help="Override Codex home (default: $CODEX_HOME or ~/.codex).",
    )


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    _add_root_args(p)
    p.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE_SECONDS)
    p.add_argument("--token-threshold", type=int, default=DEFAULT_TOKEN_THRESHOLD)
    p.add_argument("--percent-threshold", type=float, default=DEFAULT_PERCENT_THRESHOLD)
    p.add_argument("--report", default="", help="Write a markdown evidence report to this path")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON to stdout")
    p.add_argument(
        "--no-hash",
        action="store_true",
        help="Show raw session ids instead of sha256 prefixes (default is to hash)",
    )
    p.add_argument(
        "--no-redact-home",
        action="store_true",
        help="Do not replace the home directory with ~ in paths",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quota-guard",
        description=(
            "Detect idle token/quota drain from local Claude Code and Codex CLI logs. "
            "Read-only: no credentials, no network, no process killing. "
            "If no subcommand is given, 'scan' is used."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"quota-guard {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser(
        "scan",
        help="Scan local logs and print alerts (default subcommand)",
    )
    _add_scan_args(scan_p)

    report_p = sub.add_parser(
        "report",
        help="Scan local logs and write (or print) a markdown evidence report",
    )
    _add_scan_args(report_p)

    cfg_p = sub.add_parser(
        "check-config",
        help="Read-only review of Codex and Claude settings that can use tokens while idle",
    )
    _add_root_args(cfg_p)
    cfg_p.add_argument("--json", action="store_true", help="Print machine-readable JSON to stdout")
    cfg_p.add_argument(
        "--no-redact-home",
        action="store_true",
        help="Do not replace the home directory with ~ in paths",
    )
    return parser


def normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["scan"]
    if argv[0] in {"scan", "check-config", "report", "-h", "--help", "--version", "-V"}:
        return argv
    # Unknown first token that looks like a flag: default to scan.
    if argv[0].startswith("-"):
        return ["scan", *argv]
    return argv


def _print_scan_human(
    result: ScanResult,
    *,
    no_hash: bool,
    no_redact: bool,
    home: Path | None,
) -> None:
    print(f"Scanned {len(result.scanned)} file(s), {len(result.sessions)} session(s).")
    if not result.alerts:
        print("No idle-drain pattern detected.")
    for a in result.alerts:
        sid = display_session_id(a.session_id, no_hash)
        print(f"[ALERT] type {a.alert_type}  {a.source} {sid}: {a.reason}")
        if a.last_user_ts:
            print(f"        last user input: {a.last_user_ts}")


def cmd_scan_or_report(args: argparse.Namespace, as_report: bool) -> int:
    claude_roots = claude_roots_from_env_or_arg(args.claude_root)
    codex_root = codex_root_from_env_or_arg(args.codex_root)
    result = scan_roots(
        claude_roots,
        codex_root,
        args.idle_seconds,
        args.token_threshold,
        args.percent_threshold,
    )
    emit_warnings(result.warnings)
    home = Path.home()
    body = render_report(
        result.alerts,
        result.sessions,
        no_hash=args.no_hash,
        no_redact=args.no_redact_home,
        home=home,
        warnings=result.warnings,
    )

    if args.json:
        all_ids = tuple(st.session_id for st in result.sessions.values())
        payload = {
            "files_scanned": [
                display_path(
                    p,
                    no_redact=args.no_redact_home,
                    home=home,
                    session_ids=all_ids,
                    no_hash=args.no_hash,
                )
                for p in result.scanned
            ],
            "sessions": len(result.sessions),
            "alerts": [
                a.public_dict(args.no_hash, args.no_redact_home, home, all_ids)
                for a in result.alerts
            ],
            "warnings": [
                {
                    "path": display_path(
                        w.path,
                        no_redact=args.no_redact_home,
                        home=home,
                        session_ids=all_ids,
                        no_hash=args.no_hash,
                    ),
                    "line": w.line,
                    "message": w.message,
                }
                for w in result.warnings
            ],
        }
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
        print()
    elif not as_report:
        _print_scan_human(result, no_hash=args.no_hash, no_redact=args.no_redact_home, home=home)
    else:
        # report subcommand with no --report and no --json: markdown on stdout.
        if not args.report:
            sys.stdout.write(body)
            if not body.endswith("\n"):
                sys.stdout.write("\n")

    if args.report:
        write_report(Path(args.report), body)
        print(f"Wrote report: {args.report}", file=sys.stderr)
    return 2 if result.alerts else 0


def cmd_check_config(args: argparse.Namespace) -> int:
    claude_roots = claude_roots_from_env_or_arg(args.claude_root)
    codex_root = codex_root_from_env_or_arg(args.codex_root)
    warnings: list[ParseWarning] = []
    cpath, citems = check_codex_config(codex_root, warnings)
    claude_blocks: list[tuple[Path, list[ConfigItem]]] = []
    for root in claude_roots:
        claude_blocks.append(check_claude_settings(root, warnings))
    emit_warnings(warnings)
    home = Path.home()
    if args.json:
        def item_dict(item: ConfigItem) -> dict[str, Any]:
            return {
                "source": item.source,
                "key": item.key,
                "value": item.value,
                "present": item.present,
                "status": item.status,
                "advice": item.advice,
                "docs": item.docs,
            }

        payload = {
            "codex": {
                "path": str(cpath) if args.no_redact_home else redact_path(cpath, home),
                "items": [item_dict(i) for i in citems],
            },
            "claude": [
                {
                    "path": str(p) if args.no_redact_home else redact_path(p, home),
                    "items": [item_dict(i) for i in items],
                }
                for p, items in claude_blocks
            ],
            "warnings": [
                {
                    "path": w.path if args.no_redact_home else redact_path(w.path, home),
                    "line": w.line,
                    "message": w.message,
                }
                for w in warnings
            ],
        }
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        body = render_config_report(
            cpath,
            citems,
            claude_blocks,
            no_redact=args.no_redact_home,
            home=home,
        )
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    raw = normalize_argv(raw)
    parser = _build_parser()
    args = parser.parse_args(raw)
    command = args.command or "scan"
    try:
        if command == "check-config":
            return cmd_check_config(args)
        if command == "report":
            return cmd_scan_or_report(args, as_report=True)
        return cmd_scan_or_report(args, as_report=False)
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
