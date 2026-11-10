#!/usr/bin/env python3
"""quota-guard: read-only local detector for idle Claude/Codex usage.

Reads Claude Code JSONL transcripts and Codex CLI rollout JSONL files
(including .jsonl.zst when a decompressor is available). Detects new-token
or quota-percent growth after a quiet gap following the last real user input.

This tool does NOT read credentials, call provider APIs, or kill processes.
Unknown or incomplete log records are skipped with a warning; they do not
crash the scan.

Field names that vary by client version are handled conservatively. Anything
not confirmed against public docs is treated as unverified.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO

__version__ = "0.3.0"

# Default idle window: usage after this many seconds of quiet following the
# last real user input (and after any in-progress tool call) is "idle".
DEFAULT_IDLE_SECONDS = 180
# Minimum *new* token delta (input+output+cache_creation; not cache_read)
# in the post-gap window before we emit an idle_drain alert.
DEFAULT_TOKEN_THRESHOLD = 200
# Minimum Codex used_percent step to flag when local new tokens are 0.
DEFAULT_PERCENT_THRESHOLD = 2.0
# Continuous work after a real user prompt is not idle_drain. If it lasts
# at least this long, emit a low-severity long_run alert instead.
DEFAULT_LONG_RUN_SECONDS = 1800
DEFAULT_MIN_SEVERITY = "medium"

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

KNOWN_TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cached_input_tokens",
    "cache_creation_input_tokens",
    "cache_write_input_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)

FORBIDDEN_NAME_FRAGMENTS = (
    "auth.json",
    ".credentials.json",
    "credentials.json",
    "keychain",
    "cookie",
)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
META_RECORD_TYPES = {
    "system",
    "progress",
    "attachment",
    "file-history-snapshot",
    "file_history_snapshot",
}

# ---------------------------------------------------------------------------
# Warnings / skips
# ---------------------------------------------------------------------------


@dataclass
class ParseWarning:
    path: str
    line: int | None
    message: str

    def __str__(self) -> str:
        loc = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{loc}: {self.message}"


@dataclass
class SkipRecord:
    path: str
    reason: str


# ---------------------------------------------------------------------------
# Time and privacy helpers
# ---------------------------------------------------------------------------


def parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
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
    return "~" + suffix.replace("\\", "/")


def is_forbidden_path(path: Path) -> bool:
    name = path.name.lower()
    return any(frag in name for frag in FORBIDDEN_NAME_FRAGMENTS)


def is_jsonl_log(path: Path) -> bool:
    name = path.name
    return name.endswith(".jsonl") or name.endswith(".jsonl.zst")


def is_jsonl_zst(path: Path) -> bool:
    return path.name.endswith(".jsonl.zst")


def is_codex_rollout(path: Path) -> bool:
    return path.name.startswith("rollout-") and is_jsonl_log(path)


def path_looks_like_subagent(path: Path) -> bool:
    return "subagents" in path.parts


# ---------------------------------------------------------------------------
# zstd (optional) and line-oriented log reading
# ---------------------------------------------------------------------------


class ZstdUnsupported(RuntimeError):
    pass


def zstd_backend() -> str | None:
    """Return a backend name, or None if .jsonl.zst cannot be decompressed.

    Preference: Python 3.14+ compression.zstd, then the optional `zstandard` package.
    """
    try:
        import compression.zstd  # type: ignore[import-not-found]  # noqa: F401

        return "compression.zstd"
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]  # noqa: F401

        return "zstandard"
    except ImportError:
        return None


def _zstd_stream_reader(binary_fh):
    """Return a binary stream that concatenates all zstd frames.

    A one-shot decompressor may stop after the first frame. Archived rollouts
    can be multi-frame; TextIOWrapper on a stream reader also keeps line
    boundaries intact across read buffers.
    """
    backend = zstd_backend()
    if backend == "compression.zstd":
        from compression import zstd  # type: ignore[import-not-found]

        decompressor = zstd.ZstdDecompressor()
        if hasattr(decompressor, "stream_reader"):
            return decompressor.stream_reader(binary_fh)
        if hasattr(zstd, "open"):
            # zstd.open may re-open by path; fall back to reading all frames.
            return io.BytesIO(_decompress_all_frames_stdlib(binary_fh.read()))
        return io.BytesIO(zstd.decompress(binary_fh.read()))
    if backend == "zstandard":
        import zstandard  # type: ignore[import-not-found]

        return zstandard.ZstdDecompressor().stream_reader(binary_fh)
    raise ZstdUnsupported("zst unsupported")


def _decompress_all_frames_stdlib(data: bytes) -> bytes:
    from compression import zstd  # type: ignore[import-not-found]

    out = io.BytesIO()
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            chunk = zstd.decompress(view[offset:])
        except Exception:
            break
        out.write(chunk)
        # stdlib may not expose the consumed length; stop after one frame
        # if we cannot advance. stream_reader is preferred above.
        break
    return out.getvalue()


def decompress_zstd_bytes(data: bytes) -> bytes:
    """Decompress one or more zstd frames into bytes (used by tests and fallbacks)."""
    backend = zstd_backend()
    if backend == "compression.zstd":
        from compression import zstd  # type: ignore[import-not-found]

        if hasattr(zstd, "ZstdDecompressor") and hasattr(zstd.ZstdDecompressor(), "stream_reader"):
            reader = zstd.ZstdDecompressor().stream_reader(io.BytesIO(data))
            try:
                return reader.read()
            finally:
                reader.close()
        return zstd.decompress(data)
    if backend == "zstandard":
        import zstandard  # type: ignore[import-not-found]

        reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))
        try:
            return reader.read()
        finally:
            reader.close()
    raise RuntimeError("zst unsupported")


@contextmanager
def open_log_text(path: Path):
    """Yield a text stream for a .jsonl or .jsonl.zst file, line-buffered correctly."""
    if is_jsonl_zst(path):
        if zstd_backend() is None:
            raise ZstdUnsupported(
                "skipped: zst unsupported (need Python 3.14+ compression.zstd or pip install zstandard)"
            )
        fh = path.open("rb")
        reader = None
        wrapper = None
        try:
            reader = _zstd_stream_reader(fh)
            wrapper = io.TextIOWrapper(reader, encoding="utf-8", errors="strict", newline="")
            yield wrapper
        finally:
            if wrapper is not None:
                try:
                    wrapper.close()
                except Exception:
                    pass
            if reader is not None and reader is not fh:
                try:
                    reader.close()
                except Exception:
                    pass
            fh.close()
        return
    fh = path.open("r", encoding="utf-8", newline="")
    try:
        yield fh
    finally:
        fh.close()


def read_log_text(path: Path, warnings: list[ParseWarning]) -> tuple[str | None, str | None]:
    """Return (text, skip_reason). skip_reason is set when the file cannot be read."""
    if is_forbidden_path(path):
        warnings.append(ParseWarning(str(path), None, "refusing to read a credentials-like filename"))
        return None, "forbidden"
    try:
        with open_log_text(path) as fh:
            return fh.read(), None
    except ZstdUnsupported as exc:
        warnings.append(ParseWarning(str(path), None, str(exc)))
        return None, "zst_unsupported"
    except OSError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not read file: {exc}"))
        return None, "unreadable"
    except UnicodeDecodeError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not decode as utf-8: {exc}"))
        return None, "unreadable"
    except Exception as exc:  # noqa: BLE001 - remain up on corrupt zstd archives
        if is_jsonl_zst(path):
            warnings.append(ParseWarning(str(path), None, f"could not decompress .jsonl.zst: {exc}"))
            return None, "zst_error"
        warnings.append(ParseWarning(str(path), None, f"could not read file: {exc}"))
        return None, "unreadable"


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


@dataclass
class Event:
    source: str  # claude | codex
    session_id: str
    path: str
    ts: datetime | None
    kind: str  # user | inherited_user | tool_result | tool_use | usage | quota | meta | sidechain | turn_start
    tokens: int = 0  # new tokens: input+output+cache_creation/cache_write (+ reasoning)
    cache_read: int = 0
    used_percent: float | None = None
    window_label: str | None = None
    note: str = ""
    is_sidechain: bool = False
    tool_delta: int = 0
    record_type: str = ""
    anchor_type: str = ""
    limit_id: str = ""
    limit_name: str = ""
    resets_at: datetime | None = None
    response_id: str = ""
    turn_id: str = ""
    turn_trigger: str = ""  # raw value; not interpreted
    initiating_agent_path: str = ""


@dataclass
class SessionState:
    source: str
    session_id: str
    path: str
    events: list[Event] = field(default_factory=list)
    last_user_ts: datetime | None = None
    last_usage_ts: datetime | None = None
    total_tokens: int = 0  # sum of new tokens (not cache_read)
    total_cache_read: int = 0
    last_used_percent: dict[str, float] = field(default_factory=dict)
    is_sidechain: bool = False
    last_anchor_type: str = ""
    no_anchor_reason: str | None = None  # no_user_messages | all_inherited | sub_agent


# ---------------------------------------------------------------------------
# JSONL reader
# ---------------------------------------------------------------------------


def _format_line_span(lines: list[int]) -> str:
    if not lines:
        return ""
    lines = sorted(lines)
    # Collapse consecutive runs: 726-730, 740
    parts: list[str] = []
    start = prev = lines[0]
    for n in lines[1:]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = n
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ", ".join(parts)


def iter_jsonl(
    path: Path,
    warnings: list[ParseWarning] | None = None,
) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield (line_number, object) for complete JSON objects.

    Lines are assembled via a text stream (TextIOWrapper over a zstd stream
    reader when needed) so a decompressor buffer boundary cannot split a line.
    Malformed or non-JSON lines in one file are aggregated into a single warning.
    """
    if warnings is None:
        warnings = []
    if is_forbidden_path(path):
        warnings.append(ParseWarning(str(path), None, "refusing to read a credentials-like filename"))
        return
    malformed: list[int] = []
    truncated_last: int | None = None
    line_no = 0
    last_had_newline = True
    last_nonempty: int | None = None
    try:
        with open_log_text(path) as fh:
            while True:
                line = fh.readline()
                if line == "":
                    break
                line_no += 1
                last_had_newline = line.endswith("\n") or line.endswith("\r")
                stripped = line.strip()
                if not stripped:
                    continue
                last_nonempty = line_no
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    # A last line with no terminating newline is the usual
                    # half-written record; other failures are malformed/non-JSON.
                    if not last_had_newline:
                        truncated_last = line_no
                    else:
                        malformed.append(line_no)
                    continue
                if not isinstance(obj, dict):
                    malformed.append(line_no)
                    continue
                yield line_no, obj
    except ZstdUnsupported as exc:
        warnings.append(ParseWarning(str(path), None, str(exc)))
        return
    except OSError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not read file: {exc}"))
        return
    except UnicodeDecodeError as exc:
        warnings.append(ParseWarning(str(path), None, f"could not decode as utf-8: {exc}"))
        return
    except Exception as exc:  # noqa: BLE001
        if is_jsonl_zst(path):
            warnings.append(ParseWarning(str(path), None, f"could not decompress .jsonl.zst: {exc}"))
        else:
            warnings.append(ParseWarning(str(path), None, f"could not read file: {exc}"))
        return

    if truncated_last is None and malformed and last_nonempty == malformed[-1]:
        truncated_last = malformed.pop()
    bits: list[str] = []
    if malformed:
        bits.append(
            f"{len(malformed)} malformed or non-JSON line(s) skipped ({_format_line_span(malformed)})"
        )
    if truncated_last is not None:
        bits.append(
            f"truncated or partial last line skipped (line {truncated_last}; session may still be writing)"
        )
    if bits:
        warnings.append(ParseWarning(str(path), None, "; ".join(bits)))


def iter_jsonl_text(
    path_label: str, text: str, warnings: list[ParseWarning]
) -> Iterable[tuple[int, dict[str, Any]]]:
    """Parse a complete text buffer. Used by tests that feed constructed strings."""
    # Reuse the same aggregation rules as the file reader.
    class _Buf:
        def __init__(self, s: str) -> None:
            self._io = io.StringIO(s)

        def readline(self) -> str:
            return self._io.readline()

        def close(self) -> None:
            self._io.close()

    # Temporary path-like label only; walk the string with the same line rules.
    malformed: list[int] = []
    truncated_last: int | None = None
    line_no = 0
    last_had_newline = True
    last_nonempty: int | None = None
    buf = io.StringIO(text)
    while True:
        line = buf.readline()
        if line == "":
            break
        line_no += 1
        last_had_newline = line.endswith("\n") or line.endswith("\r")
        stripped = line.strip()
        if not stripped:
            continue
        last_nonempty = line_no
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            if not last_had_newline:
                truncated_last = line_no
            else:
                malformed.append(line_no)
            continue
        if not isinstance(obj, dict):
            malformed.append(line_no)
            continue
        yield line_no, obj
    if truncated_last is None and malformed and last_nonempty == malformed[-1]:
        truncated_last = malformed.pop()
    bits: list[str] = []
    if malformed:
        bits.append(
            f"{len(malformed)} malformed or non-JSON line(s) skipped ({_format_line_span(malformed)})"
        )
    if truncated_last is not None:
        bits.append(
            f"truncated or partial last line skipped (line {truncated_last}; session may still be writing)"
        )
    if bits:
        warnings.append(ParseWarning(path_label, None, "; ".join(bits)))


def _first_int(record: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        val = record.get(key)
        if isinstance(val, (int, float)):
            return int(val)
    return None


def _int_or_zero(record: dict[str, Any], key: str) -> int:
    val = record.get(key)
    if isinstance(val, (int, float)):
        return int(val)
    return 0


@dataclass
class TokenSplit:
    new_tokens: int
    cache_read: int
    source: str = ""


def split_claude_usage(usage: dict[str, Any]) -> TokenSplit | None:
    """Split Claude usage into new tokens vs cache reads.

    New tokens = input_tokens + output_tokens + cache_creation_input_tokens.
    cache_read (cache_read_input_tokens or cached_input_tokens) is recorded
    separately and is not an idle increment. Do not also add
    cache_creation.ephemeral_* (that would double-count).
    """
    if not any(k in usage for k in KNOWN_TOKEN_KEYS):
        return None
    new = 0
    for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens"):
        new += _int_or_zero(usage, key)
    cache_read = _first_int(usage, "cache_read_input_tokens", "cached_input_tokens") or 0
    return TokenSplit(new, cache_read, "claude_parts")


def split_codex_usage(usage: dict[str, Any], label: str) -> TokenSplit | None:
    """Split a Codex token_usage object into new tokens vs cache reads.

    cached_input_tokens (or cache_read_input_tokens) is usually already
    included in input_tokens; subtract it so cache hits are not treated as
    new work. Fallback to total_tokens only when no parts are present
    (that fallback may still include cache; it is marked as such).
    """
    if not isinstance(usage, dict):
        return None
    cache_read = _first_int(usage, "cached_input_tokens", "cache_read_input_tokens") or 0
    has_parts = any(
        k in usage
        for k in (
            "input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
            "cache_creation_input_tokens",
            "cache_write_input_tokens",
            "cached_input_tokens",
            "cache_read_input_tokens",
        )
    )
    if has_parts:
        inp = _int_or_zero(usage, "input_tokens")
        out = _int_or_zero(usage, "output_tokens")
        reason = _int_or_zero(usage, "reasoning_output_tokens")
        # cache_write_input_tokens is the current Codex name for cache creation.
        created = _first_int(usage, "cache_write_input_tokens", "cache_creation_input_tokens") or 0
        non_cached_input = max(0, inp - cache_read) if inp else 0
        return TokenSplit(non_cached_input + out + reason + created, cache_read, label)
    if "total_tokens" in usage and isinstance(usage["total_tokens"], (int, float)):
        return TokenSplit(int(usage["total_tokens"]), 0, f"{label}_total_tokens_only")
    if not any(k in usage for k in KNOWN_TOKEN_KEYS):
        return None
    return TokenSplit(0, 0, label)


def _iter_content_parts(content: Any) -> Iterable[Any]:
    if content is None:
        return
    if isinstance(content, list):
        yield from content
        return
    yield content


def _part_type(part: Any) -> str | None:
    if isinstance(part, dict):
        typ = part.get("type")
        return typ if isinstance(typ, str) else None
    return None


def _part_text(part: Any) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        for key in ("text", "content", "body"):
            val = part.get(key)
            if isinstance(val, str):
                return val
    return ""


def _looks_like_system_injection(content: Any) -> bool:
    """True when a user record is only a meta/system injection, not typed input.

    Known shapes (still unverified against every client version): a lone
    <system-reminder> block, or parts typed as system / system_reminder.
    A record that also contains ordinary user text is treated as a real prompt.
    """
    parts = list(_iter_content_parts(content))
    if not parts:
        return False
    saw_meta = False
    saw_user_text = False
    for part in parts:
        typ = _part_type(part)
        text = _part_text(part).lstrip()
        if typ in {"system", "system_reminder", "system-reminder"}:
            saw_meta = True
            continue
        if typ in {"tool_result", "tool_use"}:
            continue
        if text.startswith("<system-reminder>") or text.startswith("<system_reminder>"):
            saw_meta = True
            continue
        if typ == "text" or typ is None:
            if text:
                saw_user_text = True
    if saw_user_text:
        return False
    return saw_meta


def _count_part_types(content: Any, *types: str) -> int:
    n = 0
    for part in _iter_content_parts(content):
        typ = _part_type(part)
        if typ in types:
            n += 1
        elif isinstance(part, str) and any(t in part[:80] for t in types):
            n += 1
    return n


def _claude_message_content(rec: dict[str, Any]) -> Any:
    msg = rec.get("message") or {}
    if isinstance(msg, dict):
        return msg.get("content")
    return None


def parse_claude_file(
    path: Path, warnings: list[ParseWarning] | None = None
) -> list[Event]:
    if warnings is None:
        warnings = []
    events: list[Event] = []
    seen_usage: set[str] = set()
    if path.name.endswith(".jsonl.zst"):
        session_from_name = path.name[: -len(".jsonl.zst")]
    elif path.name.endswith(".jsonl"):
        session_from_name = path.name[: -len(".jsonl")]
    else:
        session_from_name = path.stem
    file_is_subagent = path_looks_like_subagent(path)

    for line_no, rec in iter_jsonl(path, warnings):
        session_id = str(rec.get("sessionId") or session_from_name)
        ts = parse_ts(rec.get("timestamp"))
        typ = rec.get("type")
        record_type = typ if isinstance(typ, str) else ""
        is_sidechain = file_is_subagent or rec.get("isSidechain") is True
        content = _claude_message_content(rec)

        if rec.get("isMeta") is True or (isinstance(typ, str) and typ in META_RECORD_TYPES):
            events.append(
                Event(
                    "claude",
                    session_id,
                    str(path),
                    ts,
                    "meta",
                    note="meta_or_system",
                    is_sidechain=is_sidechain,
                    record_type=record_type or "meta",
                )
            )
            continue

        if typ == "user":
            n_results = _count_part_types(content, "tool_result")
            n_tool_use = _count_part_types(content, "tool_use")
            if n_results or n_tool_use:
                events.append(
                    Event(
                        "claude",
                        session_id,
                        str(path),
                        ts,
                        "tool_result",
                        note="tool_result",
                        is_sidechain=is_sidechain,
                        tool_delta=-n_results,
                        record_type="user/tool_result",
                    )
                )
                continue
            if _looks_like_system_injection(content):
                events.append(
                    Event(
                        "claude",
                        session_id,
                        str(path),
                        ts,
                        "meta",
                        note="system_injection",
                        is_sidechain=is_sidechain,
                        record_type="user/system_injection",
                    )
                )
                continue
            if is_sidechain:
                events.append(
                    Event(
                        "claude",
                        session_id,
                        str(path),
                        ts,
                        "sidechain",
                        note="sidechain_user",
                        is_sidechain=True,
                        record_type="user/sidechain",
                    )
                )
                continue
            events.append(
                Event(
                    "claude",
                    session_id,
                    str(path),
                    ts,
                    "user",
                    note="user_message",
                    is_sidechain=False,
                    record_type="user",
                    anchor_type="type=user",
                )
            )
            continue

        if typ != "assistant":
            continue

        msg = rec.get("message")
        if msg is None:
            # tool_use can also appear at the top level in some versions (unverified).
            continue
        if not isinstance(msg, dict):
            warnings.append(
                ParseWarning(str(path), line_no, "skipped assistant record with non-object message")
            )
            continue

        n_tools = _count_part_types(msg.get("content"), "tool_use")
        if n_tools:
            events.append(
                Event(
                    "claude",
                    session_id,
                    str(path),
                    ts,
                    "tool_use",
                    note="tool_use",
                    is_sidechain=is_sidechain,
                    tool_delta=n_tools,
                    record_type="assistant/tool_use",
                )
            )

        usage = msg.get("usage")
        if usage is None:
            continue
        if not isinstance(usage, dict):
            warnings.append(
                ParseWarning(str(path), line_no, "skipped assistant record with non-object usage")
            )
            continue
        split = split_claude_usage(usage)
        if split is None:
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "skipped usage record: no known token fields "
                    "(unknown version or missing fields)",
                )
            )
            continue
        key = f"{rec.get('requestId', '')}:{msg.get('id', '')}"
        if key != ":" and key in seen_usage:
            for ev in reversed(events):
                if ev.kind == "usage" and ev.note == key:
                    if split.new_tokens > ev.tokens or split.cache_read > ev.cache_read:
                        ev.tokens = max(ev.tokens, split.new_tokens)
                        ev.cache_read = max(ev.cache_read, split.cache_read)
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
                tokens=split.new_tokens,
                cache_read=split.cache_read,
                note=key,
                is_sidechain=is_sidechain,
                record_type="assistant/usage",
            )
        )
    return events


def _codex_session_name_from_path(path: Path) -> str:
    name = path.name
    if name.endswith(".jsonl.zst"):
        name = name[: -len(".jsonl.zst")]
    elif name.endswith(".jsonl"):
        name = name[: -len(".jsonl")]
    return name


def _as_meta_dict(*candidates: Any) -> dict[str, Any]:
    """Merge metadata dicts. Earlier candidates win on key conflicts.

    Real Codex rollouts put client_authored / inherited_user_message on the
    record's top-level metadata. payload.metadata is also consulted if present.
    """
    out: dict[str, Any] = {}
    for cand in reversed([c for c in candidates if isinstance(c, dict)]):
        out.update(cand)
    return out


def _stringify_path(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        parts = [str(x) for x in value if x is not None and str(x) != ""]
        return "/".join(parts)
    return str(value)


def initiating_path_looks_nested(value: Any) -> bool:
    """Unverified heuristic for a sub-agent initiating path.

    The live vocabulary of initiating_agent_path has not been confirmed. This
    only treats a value as nested when it has more than one path segment
    (a '/' or '\\' in a string, or a list/tuple longer than 1). Other values
    are recorded for --explain and are not used to decide.
    """
    if value is None or value is False:
        return False
    if isinstance(value, (list, tuple)):
        return len([x for x in value if x is not None and str(x) != ""]) > 1
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return False
        return ("/" in s) or ("\\" in s)
    return False


def classify_codex_user_message(role: Any, meta: dict[str, Any]) -> str:
    """Classify a response_item message. Does not invent field meanings.

    Preferred anchor: client_authored is True and inherited_user_message is not True.
    If client_authored is absent, fall back to role=user and not developer.
    inherited_user_message is True → not an anchor, even if client_authored is True.
    client_authored is False → not an anchor.
    """
    if role == "developer":
        return "developer"
    if role != "user":
        return "other"
    if meta.get("inherited_user_message") is True:
        return "inherited"
    if meta.get("client_authored") is True:
        return "anchor"
    if meta.get("client_authored") is False:
        return "non_client"
    return "fallback_anchor"


def _collect_turn_ids(obj: Any, into: set[str]) -> None:
    if not isinstance(obj, dict):
        return
    for key in ("turn_id", "root_turn_id", "parent_turn_id"):
        val = obj.get(key)
        if val is not None and val != "":
            into.add(str(val))


def _extract_quota_events(
    *,
    source: str,
    session_id: str,
    path: Path,
    ts: datetime | None,
    rate: dict[str, Any],
    record_type: str,
) -> list[Event]:
    """Split a rate_limits object into per-limit snapshots.

    limit_id / limit_name may sit on rate_limits itself and/or on each
    primary/secondary bucket. Grouping key is the most specific limit_id
    available, falling back to the bucket label.
    """
    events: list[Event] = []
    top_id = rate.get("limit_id")
    top_name = rate.get("limit_name")
    for label in ("primary", "secondary"):
        bucket = rate.get(label)
        if not isinstance(bucket, dict):
            continue
        pct = bucket.get("used_percent")
        if not isinstance(pct, (int, float)):
            continue
        limit_id = bucket.get("limit_id", top_id)
        limit_name = bucket.get("limit_name", top_name)
        if limit_id is None or limit_id == "":
            window = str(label)
        else:
            window = str(limit_id)
        resets = parse_ts(bucket.get("resets_at"))
        name = "" if limit_name is None else str(limit_name)
        events.append(
            Event(
                source,
                session_id,
                str(path),
                ts,
                "quota",
                used_percent=float(pct),
                window_label=window,
                note=f"window={label} window_minutes={bucket.get('window_minutes')} limit_name={name or 'n/a'}",
                record_type=record_type,
                limit_id=str(limit_id) if limit_id not in (None, "") else "",
                limit_name=name,
                resets_at=resets,
            )
        )
    return events


def _token_usage_from_record(payload: dict[str, Any]) -> tuple[TokenSplit | None, str, bool]:
    """Return (split, source, is_cumulative) for a token_usage_record payload.

    Preference: thread_token_usage as a cumulative total, else usage as a
    single increment, else turn_token_usage as a fallback increment.
    """
    thread = payload.get("thread_token_usage")
    if isinstance(thread, dict):
        split = split_codex_usage(thread, "thread_token_usage")
        if split is not None:
            return split, "thread_token_usage", True
    usage = payload.get("usage")
    if isinstance(usage, dict):
        split = split_codex_usage(usage, "token_usage_record.usage")
        if split is not None:
            return split, split.source, False
    turn = payload.get("turn_token_usage")
    if isinstance(turn, dict):
        split = split_codex_usage(turn, "turn_token_usage")
        if split is not None:
            return split, "turn_token_usage", False
    return None, "", False


def parse_codex_file(
    path: Path, warnings: list[ParseWarning] | None = None
) -> list[Event]:
    if warnings is None:
        warnings = []
    events: list[Event] = []
    token_count_usage: list[Event] = []
    usage_record_events: list[Event] = []
    session_id = _codex_session_name_from_path(path)
    last_new = 0
    last_cache = 0
    have_cumulative = False
    rec_last_new = 0
    rec_last_cache = 0
    rec_have_cumulative = False
    seen_response_ids: set[str] = set()
    subagent_turns: set[str] = set()

    for line_no, rec in iter_jsonl(path, warnings):
        typ = rec.get("type")
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
        ts = parse_ts(rec.get("timestamp"))
        if typ == "session_meta":
            session_id = str(payload.get("id") or rec.get("id") or session_id)
            continue

        # Sub-agent communication: collect any turn ids, do not guess more.
        if typ == "inter_agent_communication_metadata":
            _collect_turn_ids(payload, subagent_turns)
            _collect_turn_ids(rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}, subagent_turns)
            events.append(
                Event(
                    "codex",
                    session_id,
                    str(path),
                    ts,
                    "meta",
                    note="inter_agent_communication_metadata",
                    record_type="inter_agent_communication_metadata",
                    turn_id=str(payload.get("turn_id") or ""),
                    is_sidechain=True,
                )
            )
            continue

        # ---- user / assistant messages (current Codex shape) ----
        if typ == "response_item" and payload.get("type") == "message":
            role = payload.get("role")
            meta = _as_meta_dict(rec.get("metadata"), payload.get("metadata"))
            kind = classify_codex_user_message(role, meta)
            turn_id = str(payload.get("turn_id") or rec.get("turn_id") or meta.get("turn_id") or "")
            ev_kwargs = dict(
                source="codex",
                session_id=session_id,
                path=str(path),
                ts=ts,
                turn_id=turn_id,
                record_type=f"response_item/message role={role}",
            )
            if kind == "anchor":
                ev = Event(kind="user", note="client_authored=true", anchor_type="client_authored=true", **ev_kwargs)
            elif kind == "fallback_anchor":
                ev = Event(
                    kind="user",
                    note="fallback: role=user, client_authored absent, not developer",
                    anchor_type="fallback_role_user",
                    **ev_kwargs,
                )
            elif kind == "inherited":
                ev = Event(
                    kind="inherited_user",
                    note="inherited_user_message=true (not an anchor)",
                    anchor_type="",
                    **ev_kwargs,
                )
            elif kind == "developer":
                ev = Event(kind="meta", note="role=developer (not an anchor)", **ev_kwargs)
            elif kind == "non_client":
                ev = Event(kind="meta", note="client_authored=false (not an anchor)", **ev_kwargs)
            else:
                # assistant or other roles: keep a quiet meta mark only for assistant traces
                if role == "assistant":
                    ev = Event(
                        kind="meta",
                        note="assistant_message",
                        record_type="response_item/message role=assistant",
                        session_id=session_id,
                        source="codex",
                        path=str(path),
                        ts=ts,
                        turn_id=turn_id,
                    )
                    events.append(ev)
                continue
            events.append(ev)
            continue

        # Legacy shape still accepted (older fixtures / older clients).
        if typ == "event_msg" and payload.get("type") == "user_message":
            events.append(
                Event(
                    "codex",
                    session_id,
                    str(path),
                    ts,
                    "user",
                    note="user_message",
                    record_type="event_msg/user_message",
                    anchor_type="event_msg/user_message",
                )
            )
            continue

        if typ == "event_msg" and payload.get("type") == "task_started":
            if ts is None:
                ts = parse_ts(payload.get("started_at"))
            attrib = payload.get("turn_attribution") if isinstance(payload.get("turn_attribution"), dict) else {}
            trigger = attrib.get("turn_trigger")
            # Also accept a top-level payload.turn_trigger if present.
            if trigger is None:
                trigger = payload.get("turn_trigger")
            agent_path = attrib.get("initiating_agent_path")
            trigger_s = "" if trigger is None else str(trigger)
            path_s = _stringify_path(agent_path)
            turn_id = str(attrib.get("turn_id") or payload.get("turn_id") or "")
            root_turn = str(attrib.get("root_turn_id") or payload.get("root_turn_id") or "")
            is_sub = initiating_path_looks_nested(agent_path)
            if is_sub:
                if turn_id:
                    subagent_turns.add(turn_id)
                if root_turn:
                    subagent_turns.add(root_turn)
            ev = Event(
                "codex",
                session_id,
                str(path),
                ts,
                "turn_start",
                note=f"task_started turn_trigger={trigger_s!s} initiating_agent_path={path_s!s}",
                record_type="event_msg/task_started",
                is_sidechain=is_sub,
                turn_id=turn_id,
                turn_trigger=trigger_s,
                initiating_agent_path=path_s,
            )
            events.append(ev)
            continue

        # New token_usage_record (preferred over event_msg/token_count).
        if typ == "token_usage_record":
            sid = payload.get("session_id")
            if sid:
                session_id = str(sid)
            if ts is None:
                ts = parse_ts(payload.get("timestamp"))
            split, src, is_cum = _token_usage_from_record(payload)
            response_id = str(payload.get("response_id") or "")
            turn_id = str(payload.get("turn_id") or "")
            if split is None:
                continue
            if response_id and response_id in seen_response_ids:
                continue
            if response_id:
                seen_response_ids.add(response_id)
            if is_cum:
                if rec_have_cumulative:
                    delta_new = max(0, split.new_tokens - rec_last_new)
                    delta_cache = max(0, split.cache_read - rec_last_cache)
                else:
                    delta_new = split.new_tokens
                    delta_cache = split.cache_read
                rec_last_new = split.new_tokens
                rec_last_cache = split.cache_read
                rec_have_cumulative = True
            else:
                delta_new = split.new_tokens
                delta_cache = split.cache_read
            if delta_new or delta_cache:
                ev = Event(
                    "codex",
                    session_id,
                    str(path),
                    ts,
                    "usage",
                    tokens=delta_new,
                    cache_read=delta_cache,
                    note=src,
                    record_type="token_usage_record",
                    response_id=response_id,
                    turn_id=turn_id,
                )
                usage_record_events.append(ev)
                events.append(ev)
            continue

        if typ != "event_msg" or payload.get("type") != "token_count":
            # turn_context, world_state, compacted, item_completed, etc. are expected.
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

        usage_obj = None
        label = "none"
        if isinstance(info.get("total_token_usage"), dict):
            usage_obj = info["total_token_usage"]
            label = "total_token_usage"
        elif isinstance(info.get("last_token_usage"), dict):
            usage_obj = info["last_token_usage"]
            label = "last_token_usage"

        split = split_codex_usage(usage_obj, label) if usage_obj is not None else None
        if info and split is None and not payload.get("rate_limits"):
            warnings.append(
                ParseWarning(
                    str(path),
                    line_no,
                    "skipped token_count record: no known token fields "
                    "(unknown version or missing fields)",
                )
            )
        if split is not None:
            if label == "total_token_usage" or have_cumulative:
                if have_cumulative:
                    delta_new = max(0, split.new_tokens - last_new)
                    delta_cache = max(0, split.cache_read - last_cache)
                else:
                    delta_new = split.new_tokens
                    delta_cache = split.cache_read
                last_new = split.new_tokens
                last_cache = split.cache_read
                have_cumulative = True
            else:
                delta_new = split.new_tokens
                delta_cache = split.cache_read
            if delta_new or delta_cache:
                ev = Event(
                    "codex",
                    session_id,
                    str(path),
                    ts,
                    "usage",
                    tokens=delta_new,
                    cache_read=delta_cache,
                    note=split.source,
                    record_type="event_msg/token_count",
                )
                token_count_usage.append(ev)
                events.append(ev)
        rate = payload.get("rate_limits")
        if isinstance(rate, dict):
            events.extend(
                _extract_quota_events(
                    source="codex",
                    session_id=session_id,
                    path=path,
                    ts=ts,
                    rate=rate,
                    record_type="event_msg/rate_limits",
                )
            )

    # Prefer token_usage_record over event_msg/token_count usage in the same
    # session so cumulative totals are not applied twice. Rate-limit snapshots
    # from token_count are kept.
    if usage_record_events:
        drop = set(id(ev) for ev in token_count_usage)
        events = [ev for ev in events if id(ev) not in drop]

    if subagent_turns:
        for ev in events:
            if ev.turn_id and ev.turn_id in subagent_turns:
                ev.is_sidechain = True

    return events



def discover(root: Path, kind: str) -> list[Path]:
    """Find log files under a Claude or Codex root, including .jsonl.zst."""
    root = Path(root)
    if not root.exists():
        return []
    if root.is_file():
        if is_forbidden_path(root):
            return []
        if is_jsonl_log(root):
            return [root]
        return []
    files: list[Path] = []
    if kind == "claude":
        base = root / "projects" if (root / "projects").is_dir() else root
        files.extend(p for p in base.rglob("*") if p.is_file() and is_jsonl_log(p) and not is_forbidden_path(p))
    else:
        sessions = root / "sessions" if (root / "sessions").is_dir() else root
        files.extend(
            p
            for p in sessions.rglob("*")
            if p.is_file() and is_codex_rollout(p) and not is_forbidden_path(p)
        )
        archived = root / "archived_sessions"
        if archived.is_dir():
            files.extend(
                p
                for p in archived.rglob("*")
                if p.is_file() and is_codex_rollout(p) and not is_forbidden_path(p)
            )
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
        if ev.kind == "user" and ev.ts and not ev.is_sidechain:
            if st.last_user_ts is None or ev.ts > st.last_user_ts:
                st.last_user_ts = ev.ts
                st.last_anchor_type = ev.anchor_type
        if ev.kind == "usage" and not ev.is_sidechain:
            st.total_tokens += ev.tokens
            st.total_cache_read += ev.cache_read
            if ev.ts and (st.last_usage_ts is None or ev.ts > st.last_usage_ts):
                st.last_usage_ts = ev.ts
        if ev.kind == "quota" and ev.window_label and ev.used_percent is not None:
            st.last_used_percent[ev.window_label] = ev.used_percent
    for st in sessions.values():
        _finalize_session(st)
    return sessions


def _finalize_session(st: SessionState) -> None:
    """Set no_anchor_reason and whether the *whole* session is a sub-agent."""
    main_users = [e for e in st.events if e.kind == "user" and not e.is_sidechain]
    inherited = [e for e in st.events if e.kind == "inherited_user"]
    side_users = [e for e in st.events if e.kind == "user" and e.is_sidechain]
    main_usage = [e for e in st.events if e.kind == "usage" and not e.is_sidechain]
    sub_activity = [
        e
        for e in st.events
        if e.is_sidechain and e.kind in {"user", "usage", "turn_start", "inherited_user"}
    ]
    if main_users:
        last = max(main_users, key=lambda e: e.ts or _min_utc())
        st.last_user_ts = last.ts
        st.last_anchor_type = last.anchor_type
        st.no_anchor_reason = None
        st.is_sidechain = False
        return
    st.last_user_ts = None
    st.last_anchor_type = ""
    if sub_activity and not main_usage and not main_users:
        st.is_sidechain = True
        st.no_anchor_reason = "sub_agent"
        return
    if side_users and not main_users:
        st.is_sidechain = True
        st.no_anchor_reason = "sub_agent"
        return
    if inherited:
        st.no_anchor_reason = "all_inherited"
        return
    st.no_anchor_reason = "no_user_messages"


@dataclass
class Alert:
    severity: str  # low | medium | high
    alert_type: str  # A, B, A+B, long_run
    session_id: str
    source: str
    path: str
    reason: str
    idle_tokens: int
    idle_cache_read: int
    percent_step: float | None
    last_user_ts: str
    first_idle_usage_ts: str
    last_usage_ts: str
    run_seconds: float | None = None
    limit_id: str = ""
    limit_name: str = ""

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


def _event_sort_key(ev: Event) -> tuple[datetime, int, str]:
    kind_rank = {
        "user": 0,
        "turn_start": 1,
        "tool_result": 2,
        "tool_use": 3,
        "inherited_user": 4,
        "meta": 5,
        "sidechain": 6,
        "quota": 7,
        "usage": 8,
    }
    return (ev.ts or _min_utc(), kind_rank.get(ev.kind, 9), ev.kind)


def _session_percent_step_after_gap(
    dated: list[Event],
    last_anchor: datetime | None,
    gap_start: datetime | None,
    idle_seconds: int,
    percent_threshold: float,
) -> tuple[float | None, str]:
    """Per-session percent step in the quiet gap, grouped by limit_id, ignoring window resets."""
    if last_anchor is None or gap_start is None:
        return None, ""
    by_limit: dict[str, list[Event]] = defaultdict(list)
    for ev in dated:
        if ev.kind != "quota" or ev.used_percent is None or ev.ts is None:
            continue
        key = ev.limit_id or ev.window_label or "unknown"
        by_limit[key].append(ev)
    best_step = None
    best_note = ""
    for key, series in by_limit.items():
        series = sorted(series, key=lambda e: e.ts or _min_utc())
        # Split when resets_at changes so a new window is not a "rise".
        segments: list[list[Event]] = []
        cur: list[Event] = []
        for ev in series:
            if cur and ev.resets_at != cur[-1].resets_at:
                segments.append(cur)
                cur = [ev]
            else:
                cur.append(ev)
        if cur:
            segments.append(cur)
        for seg in segments:
            baseline = None
            latest = None
            name = ""
            for ev in seg:
                if ev.ts is None:
                    continue
                if ev.ts < last_anchor:
                    continue
                if (ev.ts - gap_start).total_seconds() < idle_seconds:
                    baseline = ev.used_percent
                    name = ev.limit_id or ev.window_label or key
                else:
                    if baseline is None:
                        baseline = ev.used_percent
                        name = ev.limit_id or ev.window_label or key
                    latest = ev.used_percent
                    name = ev.limit_id or ev.window_label or name or key
            if baseline is None or latest is None:
                continue
            step = latest - baseline
            if step >= percent_threshold and (best_step is None or step > best_step):
                best_step = step
                best_note = name
    return best_step, best_note


def detect_type_b_global(
    sessions: dict[str, SessionState],
    idle_seconds: int,
    percent_threshold: float,
) -> list[Alert]:
    """Type B: used_percent rose for a limit_id with no local new tokens in that interval.

    Snapshots are grouped by limit_id across all sessions (shared quota pools).
    A change in resets_at starts a new window and is not treated as growth.
    If any local, non-sub-agent session has new tokens in the open interval
    (baseline_ts, later_ts], the rise is not reported as Type B.
    """
    usage_points: list[tuple[datetime, int]] = []
    for st in sessions.values():
        for ev in st.events:
            # Sub-agent tokens still count as local-machine activity, so they
            # suppress Type B even though those turns are excluded from Type A.
            if ev.kind == "usage" and ev.ts and ev.tokens > 0:
                usage_points.append((ev.ts, ev.tokens))

    by_limit: dict[str, list[Event]] = defaultdict(list)
    for st in sessions.values():
        for ev in st.events:
            if ev.kind == "quota" and ev.ts and ev.used_percent is not None:
                key = ev.limit_id or ev.window_label or "unknown"
                by_limit[key].append(ev)

    alerts: list[Alert] = []
    for key, series in by_limit.items():
        series = sorted(series, key=lambda e: e.ts or _min_utc())
        segments: list[list[Event]] = []
        cur: list[Event] = []
        for ev in series:
            if cur and ev.resets_at != cur[-1].resets_at:
                segments.append(cur)
                cur = [ev]
            else:
                cur.append(ev)
        if cur:
            segments.append(cur)

        best: tuple[float, Event, Event] | None = None
        for seg in segments:
            for earlier, later in zip(seg, seg[1:]):
                if earlier.ts is None or later.ts is None:
                    continue
                span = (later.ts - earlier.ts).total_seconds()
                if span < idle_seconds:
                    continue
                step = (later.used_percent or 0) - (earlier.used_percent or 0)
                if step < percent_threshold:
                    continue
                local = sum(tok for ts, tok in usage_points if earlier.ts < ts <= later.ts)
                if local > 0:
                    continue
                if best is None or step > best[0]:
                    best = (step, earlier, later)
        if best is None:
            continue
        step, earlier, later = best
        lid = later.limit_id or earlier.limit_id or key
        lname = later.limit_name or earlier.limit_name or ""
        name_bit = f" ({lname})" if lname else ""
        reason = (
            f"Codex used_percent for limit_id={lid}{name_bit} rose by {step:.1f} "
            f"between {iso(earlier.ts)} and {iso(later.ts)} with no matching new tokens "
            "on any local session in that interval. Compared globally by limit_id; "
            "a used_percent change across a resets_at window reset is not counted as growth. "
            "This still cannot see other devices, Codex Cloud, or surfaces that do not write local logs."
        )
        alerts.append(
            Alert(
                severity="medium",
                alert_type="B",
                session_id=later.session_id,
                source=later.source,
                path=later.path,
                reason=reason,
                idle_tokens=0,
                idle_cache_read=0,
                percent_step=step,
                last_user_ts="",
                first_idle_usage_ts=iso(earlier.ts),
                last_usage_ts=iso(later.ts),
                limit_id=str(lid),
                limit_name=lname,
            )
        )
    return alerts


def detect(
    sessions: dict[str, SessionState],
    idle_seconds: int,
    token_threshold: int,
    percent_threshold: float,
    long_run_seconds: int = DEFAULT_LONG_RUN_SECONDS,
) -> list[Alert]:
    """Anchor Type A to the last real user input, in time order.

    Type B is computed globally by limit_id (see detect_type_b_global).
    A long stretch of work that follows a user prompt without a quiet gap is
    not idle_drain. If it lasts at least long_run_seconds, a low-severity
    long_run alert is emitted instead.
    """
    alerts: list[Alert] = []
    for st in sessions.values():
        if st.is_sidechain:
            continue

        ordered = sorted(st.events, key=_event_sort_key)
        dated = [ev for ev in ordered if ev.ts is not None and not ev.is_sidechain]

        last_anchor: datetime | None = None
        last_anchor_type = ""
        for ev in dated:
            if ev.kind == "user":
                last_anchor = ev.ts
                last_anchor_type = ev.anchor_type

        idle_tokens = 0
        idle_cache = 0
        first_idle_ts: datetime | None = None
        last_idle_ts: datetime | None = None
        run_tokens = 0
        run_end: datetime | None = last_anchor
        outstanding = 0

        for ev in dated:
            if last_anchor is not None and ev.ts is not None and ev.ts < last_anchor:
                continue
            if ev.kind == "user":
                outstanding = 0
                run_end = ev.ts
                continue
            if ev.kind == "turn_start":
                # Recorded for explain. The trigger value is not interpreted,
                # so this does not move the user anchor or the idle clock.
                continue
            if ev.kind in {"tool_use", "tool_result"}:
                outstanding = max(0, outstanding + ev.tool_delta)
                if ev.ts:
                    run_end = ev.ts if run_end is None else max(run_end, ev.ts)
                continue
            if ev.kind in {"meta", "inherited_user"}:
                continue
            if ev.kind == "quota":
                continue
            if ev.kind != "usage" or ev.ts is None:
                continue

            active_until = run_end or last_anchor
            tool_busy = outstanding > 0
            quiet = False
            if not tool_busy and last_anchor is not None and active_until is not None:
                quiet = (ev.ts - active_until).total_seconds() >= idle_seconds
            elif last_anchor is None:
                quiet = False

            if quiet:
                idle_tokens += ev.tokens
                idle_cache += ev.cache_read
                if first_idle_ts is None:
                    first_idle_ts = ev.ts
                last_idle_ts = ev.ts
            else:
                run_tokens += ev.tokens
                run_end = ev.ts if run_end is None else max(run_end, ev.ts)

        percent_step, percent_note = _session_percent_step_after_gap(
            dated, last_anchor, run_end or last_anchor, idle_seconds, percent_threshold
        )

        has_a = idle_tokens >= token_threshold
        run_seconds = None
        if last_anchor is not None and run_end is not None:
            run_seconds = (run_end - last_anchor).total_seconds()
        has_long = (
            run_seconds is not None
            and run_seconds >= long_run_seconds
            and run_tokens >= token_threshold
        )

        if has_a:
            parts = [
                f"new tokens grew by {idle_tokens} after a quiet gap of >= {idle_seconds}s "
                f"from the last real user input (cache_read +{idle_cache} not counted)"
            ]
            if last_anchor_type:
                parts.append(f"anchor type: {last_anchor_type}")
            if percent_step is not None and percent_step >= percent_threshold:
                parts.append(
                    f"Codex {percent_note or 'quota'} used_percent also rose by {percent_step:.1f} during the quiet gap"
                )
            if first_idle_ts and last_anchor and first_idle_ts < last_anchor:
                parts.append("internal warning: first idle timestamp precedes the user anchor")
            alerts.append(
                Alert(
                    severity="medium",
                    alert_type="A",
                    session_id=st.session_id,
                    source=st.source,
                    path=st.path,
                    reason="; ".join(parts),
                    idle_tokens=idle_tokens,
                    idle_cache_read=idle_cache,
                    percent_step=percent_step,
                    last_user_ts=iso(last_anchor),
                    first_idle_usage_ts=iso(first_idle_ts),
                    last_usage_ts=iso(last_idle_ts or st.last_usage_ts),
                    run_seconds=run_seconds,
                    limit_id=percent_note if percent_note else "",
                )
            )

        if has_long:
            alerts.append(
                Alert(
                    severity="low",
                    alert_type="long_run",
                    session_id=st.session_id,
                    source=st.source,
                    path=st.path,
                    reason=(
                        f"agent kept working for {int(run_seconds)}s after the last real user input "
                        f"with no quiet gap of {idle_seconds}s ({run_tokens} new tokens). "
                        "This is not classified as idle_drain."
                    ),
                    idle_tokens=0,
                    idle_cache_read=0,
                    percent_step=None,
                    last_user_ts=iso(last_anchor),
                    first_idle_usage_ts="",
                    last_usage_ts=iso(run_end),
                    run_seconds=run_seconds,
                )
            )

    alerts.extend(detect_type_b_global(sessions, idle_seconds, percent_threshold))
    return alerts



def visible_alerts(alerts: list[Alert], min_severity: str) -> list[Alert]:
    floor = SEVERITY_RANK.get(min_severity, SEVERITY_RANK[DEFAULT_MIN_SEVERITY])
    return [a for a in alerts if SEVERITY_RANK.get(a.severity, 0) >= floor]


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


@dataclass
class ScanSummary:
    files_found: int
    files_scanned: int
    files_skipped: dict[str, int]
    sessions: int
    sessions_sidechain_excluded: int
    sessions_no_user_anchor: int
    sessions_no_user_anchor_by_reason: dict[str, int]
    alerts_by_type: dict[str, int]
    alerts_shown: int
    alerts_hidden: int
    min_severity: str
    thresholds: dict[str, int | float]
    zstd_backend: str | None


@dataclass
class ScanResult:
    events: list[Event]
    sessions: dict[str, SessionState]
    alerts: list[Alert]
    scanned: list[str]
    skipped: list[SkipRecord]
    warnings: list[ParseWarning]
    summary: ScanSummary


def _build_summary(
    *,
    found: int,
    scanned: list[str],
    skipped: list[SkipRecord],
    sessions: dict[str, SessionState],
    alerts: list[Alert],
    shown: list[Alert],
    min_severity: str,
    idle_seconds: int,
    token_threshold: int,
    percent_threshold: float,
    long_run_seconds: int,
) -> ScanSummary:
    skip_counts: dict[str, int] = dict(Counter(s.reason for s in skipped))
    type_counts: dict[str, int] = dict(Counter(a.alert_type for a in alerts))
    return ScanSummary(
        files_found=found,
        files_scanned=len(scanned),
        files_skipped=skip_counts,
        sessions=len(sessions),
        sessions_sidechain_excluded=sum(1 for st in sessions.values() if st.is_sidechain),
        sessions_no_user_anchor=sum(
            1 for st in sessions.values() if st.last_user_ts is None
        ),
        sessions_no_user_anchor_by_reason=dict(
            Counter(st.no_anchor_reason for st in sessions.values() if st.last_user_ts is None and st.no_anchor_reason)
        ),
        alerts_by_type=type_counts,
        alerts_shown=len(shown),
        alerts_hidden=max(0, len(alerts) - len(shown)),
        min_severity=min_severity,
        thresholds={
            "idle_seconds": idle_seconds,
            "token_threshold": token_threshold,
            "percent_threshold": percent_threshold,
            "long_run_seconds": long_run_seconds,
        },
        zstd_backend=zstd_backend(),
    )


def scan_roots(
    claude_roots: list[Path],
    codex_root: Path,
    idle_seconds: int,
    token_threshold: int,
    percent_threshold: float,
    long_run_seconds: int = DEFAULT_LONG_RUN_SECONDS,
    min_severity: str = DEFAULT_MIN_SEVERITY,
) -> ScanResult:
    events: list[Event] = []
    scanned: list[str] = []
    skipped: list[SkipRecord] = []
    warnings: list[ParseWarning] = []
    found_paths: list[Path] = []
    for root in claude_roots:
        if not root.exists():
            continue
        found_paths.extend(discover(root, "claude"))
    if codex_root.exists():
        found_paths.extend(discover(codex_root, "codex"))

    # De-dup across overlapping roots.
    unique_found: list[Path] = []
    seen: set[Path] = set()
    for p in found_paths:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        unique_found.append(p)

    for path in unique_found:
        text, reason = read_log_text(path, warnings)
        if text is None:
            skipped.append(SkipRecord(str(path), reason or "unreadable"))
            continue
        scanned.append(str(path))
        kind = "codex" if is_codex_rollout(path) else "claude"
        # Re-parse via the file path so line warnings keep the real path.
        # text was already decoded; parse_* will read the file again. For
        # zst that is fine (decompress twice). Avoid a second read failure
        # by calling parse functions normally.
        if kind == "claude":
            events.extend(parse_claude_file(path, warnings))
        else:
            events.extend(parse_codex_file(path, warnings))

    sessions = build_sessions(events)
    alerts = detect(
        sessions, idle_seconds, token_threshold, percent_threshold, long_run_seconds
    )
    shown = visible_alerts(alerts, min_severity)
    summary = _build_summary(
        found=len(unique_found),
        scanned=scanned,
        skipped=skipped,
        sessions=sessions,
        alerts=alerts,
        shown=shown,
        min_severity=min_severity,
        idle_seconds=idle_seconds,
        token_threshold=token_threshold,
        percent_threshold=percent_threshold,
        long_run_seconds=long_run_seconds,
    )
    return ScanResult(events, sessions, alerts, scanned, skipped, warnings, summary)


def emit_warnings(warnings: list[ParseWarning], stream: TextIO = sys.stderr) -> None:
    for w in warnings:
        print(f"warning: {w}", file=stream)


def format_summary_lines(summary: ScanSummary) -> list[str]:
    skip_total = sum(summary.files_skipped.values())
    if summary.files_skipped:
        skip_bits = ", ".join(f"{k}: {v}" for k, v in sorted(summary.files_skipped.items()))
        skip_txt = f"{skip_total} ({skip_bits})"
    else:
        skip_txt = "0"
    type_names = {"A": "type A", "B": "type B", "A+B": "type A+B", "long_run": "long_run"}
    if summary.alerts_by_type:
        alert_bits = ", ".join(
            f"{type_names.get(k, k)}: {v}" for k, v in sorted(summary.alerts_by_type.items())
        )
    else:
        alert_bits = "none"
    hidden = ""
    if summary.alerts_hidden:
        hidden = f"; {summary.alerts_hidden} hidden by --min-severity {summary.min_severity}"
    zstd = summary.zstd_backend or "unavailable"
    return [
        (
            f"Summary: files found {summary.files_found}, scanned {summary.files_scanned}, "
            f"skipped {skip_txt}."
        ),
        (
            f"Sessions: {summary.sessions} "
            f"(sidechain/sub-agent excluded from idle detection: {summary.sessions_sidechain_excluded}; "
            f"no real user input: {summary.sessions_no_user_anchor}"
            + (
                " — "
                + ", ".join(
                    f"{ {'no_user_messages': 'no user messages', 'all_inherited': 'all inherited', 'sub_agent': 'sub-agent'}.get(k, k)}: {v}"
                    for k, v in sorted(summary.sessions_no_user_anchor_by_reason.items())
                )
                if summary.sessions_no_user_anchor_by_reason
                else ""
            )
            + ")."
        ),
        f"Alerts: {alert_bits} (shown: {summary.alerts_shown}{hidden}).",
        (
            f"Thresholds: idle {summary.thresholds['idle_seconds']}s, "
            f"new-token {summary.thresholds['token_threshold']}, "
            f"percent {summary.thresholds['percent_threshold']}, "
            f"long-run {summary.thresholds['long_run_seconds']}s. zstd: {zstd}."
        ),
    ]


# ---------------------------------------------------------------------------
# Markdown report and --explain
# ---------------------------------------------------------------------------


def _timeline_lines(st: SessionState, *, anchor: datetime | None = None) -> list[str]:
    """Timestamps, types, counts, and anchors. Never includes prompt text."""
    lines = ["- Timeline (timestamps, types, and counts only; no prompt text):"]
    ordered = sorted(st.events, key=_event_sort_key)
    if not ordered:
        lines.append("  - (no events)")
        return lines
    for ev in ordered:
        ts = iso(ev.ts) or "unknown time"
        marks: list[str] = []
        if ev.kind == "user":
            atype = ev.anchor_type or "real user input"
            if ev.ts and anchor and ev.ts == anchor:
                marks = [f"ANCHOR (last real user input; {atype})"]
            else:
                marks = [f"real user input ({atype})"]
            lines.append(f"  - {ts}  user  {' '.join(marks)}")
        elif ev.kind == "inherited_user":
            lines.append(f"  - {ts}  inherited_user  (not an anchor; inherited_user_message=true)")
        elif ev.kind == "turn_start":
            extra = []
            if ev.turn_trigger:
                extra.append(f"turn_trigger={ev.turn_trigger}")
            if ev.initiating_agent_path:
                extra.append(f"initiating_agent_path={ev.initiating_agent_path}")
            if ev.is_sidechain:
                extra.append("sub-agent turn; excluded from idle detection")
            suffix = ("  " + " ".join(extra)) if extra else ""
            lines.append(f"  - {ts}  task_started{suffix}")
        elif ev.kind == "tool_result":
            lines.append(f"  - {ts}  tool_result  (not a user anchor; tool_delta={ev.tool_delta})")
        elif ev.kind == "tool_use":
            lines.append(f"  - {ts}  tool_use  (tool_delta=+{ev.tool_delta})")
        elif ev.kind == "usage":
            lines.append(
                f"  - {ts}  usage  new_tokens=+{ev.tokens}  cache_read=+{ev.cache_read}"
            )
        elif ev.kind == "quota":
            label = ev.window_label or "quota"
            pct = ev.used_percent
            pct_s = f"{pct:.1f}" if pct is not None else "n/a"
            bits = [f"{label} used_percent={pct_s}"]
            if ev.limit_id:
                bits.append(f"limit_id={ev.limit_id}")
            if ev.limit_name:
                bits.append(f"limit_name={ev.limit_name}")
            if ev.resets_at:
                bits.append(f"resets_at={iso(ev.resets_at)}")
            lines.append(f"  - {ts}  quota  {' '.join(bits)}")
        elif ev.kind == "meta":
            lines.append(f"  - {ts}  meta  {ev.note or ev.record_type}  (not a user anchor)")
        elif ev.kind == "sidechain":
            lines.append(f"  - {ts}  sidechain  (excluded from idle detection)")
        else:
            lines.append(f"  - {ts}  {ev.kind}")
    return lines


def render_explain(
    st: SessionState,
    *,
    no_hash: bool = False,
    no_redact: bool = False,
    home: Path | None = None,
) -> str:
    sid = display_session_id(st.session_id, no_hash)
    path = display_path(
        st.path,
        no_redact=no_redact,
        home=home,
        session_ids=(st.session_id,),
        no_hash=no_hash,
    )
    lines = [
        f"# explain {sid}  ({st.source})",
        "",
        "Timestamps, types, counts, and the last real-user-input anchor only. No prompt text.",
        f"- File: `{path}`",
        f"- Sidechain / sub-agent session: {'yes' if st.is_sidechain else 'no'}",
        f"- Last real user input (UTC): {iso(st.last_user_ts) or 'none in this file'}",
        f"- Anchor type: {st.last_anchor_type or ('real user input' if st.last_user_ts else 'none — ' + (st.no_anchor_reason or 'unknown'))}",
        f"- New tokens (input+output+cache_creation): {st.total_tokens}",
        f"- cache_read (not counted in idle increment): {st.total_cache_read}",
        "",
    ]
    lines += _timeline_lines(st, anchor=st.last_user_ts)
    lines.append("")
    return "\n".join(lines)


def match_sessions(sessions: dict[str, SessionState], query: str) -> list[SessionState]:
    q = query.strip().lower()
    if q.startswith("sha256:"):
        q = q[len("sha256:") :]
    hits: list[SessionState] = []
    for st in sessions.values():
        hid = hash_session_id(st.session_id).lower()
        hid_bare = hid[len("sha256:") :] if hid.startswith("sha256:") else hid
        raw = st.session_id.lower()
        if q in {hid, hid_bare, raw} or hid_bare.startswith(q) or raw.startswith(q):
            hits.append(st)
    return hits


def render_report(
    alerts: list[Alert],
    sessions: dict[str, SessionState],
    *,
    no_hash: bool = False,
    no_redact: bool = False,
    home: Path | None = None,
    warnings: list[ParseWarning] | None = None,
    summary: ScanSummary | None = None,
    skipped: list[SkipRecord] | None = None,
) -> str:
    lines = [
        "# Quota drain evidence report",
        "",
        "Generated locally by quota-guard. This is **not** an official quota dashboard.",
        "New-token totals use input + output + cache_creation (plus Codex reasoning when present).",
        "cache_read / cached_input_tokens are listed separately and are not added to idle increments.",
        "Idle detection is anchored to the last real user input in timestamp order.",
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
    ]
    if summary is not None:
        lines += format_summary_lines(summary)
        lines.append("")

    if warnings:
        lines.append(
            f"Parse warnings: {len(warnings)} (see below). Incomplete or unknown records were skipped."
        )
        lines.append("")

    all_ids = tuple(st.session_id for st in sessions.values())
    if skipped:
        lines += ["## Skipped files", ""]
        for rec in skipped:
            path = display_path(
                rec.path, no_redact=no_redact, home=home, session_ids=all_ids, no_hash=no_hash
            )
            lines.append(f"- `{path}` — {rec.reason}")
        lines.append("")

    if sessions:
        lines += ["## Sessions scanned", ""]
        for st in sessions.values():
            sid = display_session_id(st.session_id, no_hash)
            path = display_path(
                st.path, no_redact=no_redact, home=home, session_ids=all_ids, no_hash=no_hash
            )
            extra = ""
            if st.is_sidechain:
                extra = "; sidechain/sub-agent (excluded from idle detection)"
                if not st.last_user_ts:
                    extra += "; no real user input (sub-agent)"
            elif st.last_user_ts:
                extra = f"; last real user input (UTC): {iso(st.last_user_ts)}; anchor type: {st.last_anchor_type or 'n/a'}"
            else:
                reason = st.no_anchor_reason or "unknown"
                label = {
                    "no_user_messages": "no user messages",
                    "all_inherited": "all inherited",
                    "sub_agent": "sub-agent",
                }.get(reason, reason)
                extra = f"; no real user input ({label})"
            lines.append(
                f"- {st.source} / `{sid}` — new tokens: {st.total_tokens}; "
                f"cache_read: {st.total_cache_read}{extra}"
            )
            lines.append(f"  - File: `{path}`")
        lines.append("")

    shown_idle = [a for a in alerts if a.alert_type != "long_run"]
    shown_long = [a for a in alerts if a.alert_type == "long_run"]
    if not shown_idle and not shown_long:
        lines.append("No idle-drain or long-run pattern detected with the current thresholds.")
        lines.append("")

    type_note = {
        "A": "Type A — new tokens grew after a quiet gap following the last real user input.",
        "B": (
            "Type B — quota percent rose for a limit_id, compared across all local sessions, "
            "with no matching new-token delta on any of them in that interval. "
            "Window resets (a change in resets_at) are not counted as growth. "
            "This still cannot see other devices, Codex Cloud, or surfaces that do not write local logs."
        ),
        "A+B": "Type A+B — new-token growth and a quota-percent step after a quiet gap.",
        "long_run": (
            "long_run — the agent kept working after a real user prompt with no quiet gap, "
            "longer than the configured cap. This is not idle_drain."
        ),
    }
    for a in alerts:
        sid = display_session_id(a.session_id, no_hash)
        path = display_path(
            a.path, no_redact=no_redact, home=home, session_ids=all_ids or (a.session_id,), no_hash=no_hash
        )
        key = f"{a.source}:{a.session_id}"
        st = sessions.get(key)
        lines += [
            f"## {a.source} / `{sid}`  [{a.severity} / {a.alert_type}]",
            "",
            f"- Detection: {type_note.get(a.alert_type, a.alert_type)}",
            f"- Reason: {a.reason}",
            f"- File: `{path}`",
            f"- Last real user input (UTC): {a.last_user_ts or 'none in this file'}",
            f"- First post-gap usage (UTC): {a.first_idle_usage_ts or 'n/a'}",
            f"- Last post-gap usage (UTC): {a.last_usage_ts or 'n/a'}",
            f"- Idle new tokens: {a.idle_tokens}",
            f"- Idle cache_read (not counted): {a.idle_cache_read}",
            f"- Quota percent step: {a.percent_step if a.percent_step is not None else 'n/a'}",
            "",
        ]
        if st is not None:
            lines += _timeline_lines(st, anchor=st.last_user_ts)
            lines.append("")

    if warnings:
        lines += ["## Parse warnings", ""]
        lines.append("These records were skipped. They did not crash the scan.")
        for w in warnings:
            shown_path = display_path(
                w.path, no_redact=no_redact, home=home, session_ids=all_ids, no_hash=no_hash
            )
            lines.append(f"- {ParseWarning(shown_path, w.line, w.message)}")
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
    p.add_argument(
        "--token-threshold",
        type=int,
        default=DEFAULT_TOKEN_THRESHOLD,
        help="Minimum new tokens (not cache_read) in a quiet gap to emit idle_drain (default: 200).",
    )
    p.add_argument(
        "--percent-threshold",
        type=float,
        default=DEFAULT_PERCENT_THRESHOLD,
        help="Minimum Codex used_percent step during a quiet gap (default: 2.0).",
    )
    p.add_argument(
        "--long-run-seconds",
        type=int,
        default=DEFAULT_LONG_RUN_SECONDS,
        help="Continuous work after a user prompt longer than this is long_run, not idle_drain (default: 1800).",
    )
    p.add_argument(
        "--min-severity",
        choices=("low", "medium", "high"),
        default=DEFAULT_MIN_SEVERITY,
        help="Hide alerts below this severity. long_run is low; idle_drain is medium (default: medium).",
    )
    p.add_argument("--report", default="", help="Write a markdown evidence report to this path")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON to stdout")
    p.add_argument(
        "--explain",
        default="",
        metavar="SESSION_HASH",
        help="Print only the timeline for this session (sha256 prefix or raw id). No prompt text.",
    )
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
        help="Scan local logs and print a summary plus alerts (default subcommand)",
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
    if argv[0].startswith("-"):
        return ["scan", *argv]
    return argv


def _print_scan_human(
    result: ScanResult,
    *,
    no_hash: bool,
    no_redact: bool,
    home: Path | None,
    min_severity: str,
) -> None:
    for line in format_summary_lines(result.summary):
        print(line)
    shown = visible_alerts(result.alerts, min_severity)
    if not shown:
        if result.alerts:
            print("No alerts at or above the current --min-severity.")
        else:
            print("No idle-drain pattern detected.")
        return
    for a in shown:
        sid = display_session_id(a.session_id, no_hash)
        print(f"[ALERT] {a.severity} type {a.alert_type}  {a.source} {sid}: {a.reason}")
        if a.last_user_ts:
            print(f"        last real user input: {a.last_user_ts}")
        if a.first_idle_usage_ts:
            print(f"        first post-gap usage: {a.first_idle_usage_ts}")


def _summary_dict(summary: ScanSummary) -> dict[str, Any]:
    return {
        "files_found": summary.files_found,
        "files_scanned": summary.files_scanned,
        "files_skipped": summary.files_skipped,
        "sessions": summary.sessions,
        "sessions_sidechain_excluded": summary.sessions_sidechain_excluded,
        "sessions_no_user_anchor": summary.sessions_no_user_anchor,
        "sessions_no_user_anchor_by_reason": summary.sessions_no_user_anchor_by_reason,
        "alerts_by_type": summary.alerts_by_type,
        "alerts_shown": summary.alerts_shown,
        "alerts_hidden": summary.alerts_hidden,
        "min_severity": summary.min_severity,
        "thresholds": summary.thresholds,
        "zstd_backend": summary.zstd_backend,
    }


def cmd_scan_or_report(args: argparse.Namespace, as_report: bool) -> int:
    claude_roots = claude_roots_from_env_or_arg(args.claude_root)
    codex_root = codex_root_from_env_or_arg(args.codex_root)
    result = scan_roots(
        claude_roots,
        codex_root,
        args.idle_seconds,
        args.token_threshold,
        args.percent_threshold,
        long_run_seconds=args.long_run_seconds,
        min_severity=args.min_severity,
    )
    emit_warnings(result.warnings)
    home = Path.home()
    shown = visible_alerts(result.alerts, args.min_severity)

    if args.explain:
        hits = match_sessions(result.sessions, args.explain)
        if not hits:
            print(
                f"No session matched {args.explain!r}. "
                f"Scanned {result.summary.sessions} session(s).",
                file=sys.stderr,
            )
            return 1
        for st in hits:
            sys.stdout.write(
                render_explain(
                    st,
                    no_hash=args.no_hash,
                    no_redact=args.no_redact_home,
                    home=home,
                )
            )
        return 0

    body = render_report(
        shown,
        result.sessions,
        no_hash=args.no_hash,
        no_redact=args.no_redact_home,
        home=home,
        warnings=result.warnings,
        summary=result.summary,
        skipped=result.skipped,
    )

    if args.json:
        all_ids = tuple(st.session_id for st in result.sessions.values())
        payload = {
            "summary": _summary_dict(result.summary),
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
            "files_skipped": [
                {
                    "path": display_path(
                        s.path,
                        no_redact=args.no_redact_home,
                        home=home,
                        session_ids=all_ids,
                        no_hash=args.no_hash,
                    ),
                    "reason": s.reason,
                }
                for s in result.skipped
            ],
            "sessions": len(result.sessions),
            "alerts": [
                a.public_dict(args.no_hash, args.no_redact_home, home, all_ids) for a in shown
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
        _print_scan_human(
            result,
            no_hash=args.no_hash,
            no_redact=args.no_redact_home,
            home=home,
            min_severity=args.min_severity,
        )
    else:
        if not args.report:
            sys.stdout.write(body)
            if not body.endswith("\n"):
                sys.stdout.write("\n")

    if args.report:
        write_report(Path(args.report), body)
        print(f"Wrote report: {args.report}", file=sys.stderr)
    return 2 if shown else 0


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
