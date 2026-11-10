#!/usr/bin/env python3
"""Regression tests for idle-anchor rules, zstd, --explain, and summaries.

All logs here are constructed samples, not real user sessions.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import quota_guard as qg  # noqa: E402

REG_CLAUDE = ROOT / "fixtures" / "regression" / "claude"
REG_CODEX = ROOT / "fixtures" / "regression" / "codex"
PY = sys.executable


def run_cli(args: list[str], env: dict[str, str] | None = None) -> object:
    import subprocess

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env.setdefault("CLAUDE_CONFIG_DIR", str(ROOT / "fixtures" / "missing-claude"))
    full_env.setdefault("CODEX_HOME", str(ROOT / "fixtures" / "missing-codex"))
    return subprocess.run(
        [PY, str(ROOT / "quota_guard.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=full_env,
    )


def parse_one(path: Path) -> qg.SessionState:
    warnings: list[qg.ParseWarning] = []
    events = qg.parse_claude_file(path, warnings)
    sessions = qg.build_sessions(events)
    if len(sessions) != 1:
        raise AssertionError(f"expected 1 session in {path}, got {list(sessions)}")
    return next(iter(sessions.values()))


def detect_one(path: Path, **kwargs) -> list[qg.Alert]:
    st = parse_one(path)
    sessions = {f"{st.source}:{st.session_id}": st}
    return qg.detect(
        sessions,
        kwargs.get("idle_seconds", 180),
        kwargs.get("token_threshold", 200),
        kwargs.get("percent_threshold", 2.0),
        kwargs.get("long_run_seconds", 1800),
    )


class TestToolResultAndBusyTools(unittest.TestCase):
    def test_tool_result_is_not_a_user_anchor(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-tool-result.jsonl"
        st = parse_one(path)
        kinds = [e.kind for e in st.events]
        self.assertIn("tool_result", kinds)
        self.assertEqual(st.last_user_ts.isoformat(), "2026-11-10T01:00:00+00:00")
        alerts = detect_one(path)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].idle_tokens, 800)
        self.assertEqual(idle[0].idle_cache_read, 8000)
        # The real-run bug: last_user_ts was later than first_idle_usage_ts
        # when tool_result was treated as a user and the report used the
        # session-final stamp.
        self.assertLess(idle[0].last_user_ts, idle[0].first_idle_usage_ts)
        self.assertEqual(idle[0].last_user_ts, "2026-11-10T01:00:00+00:00")
        self.assertEqual(idle[0].first_idle_usage_ts, "2026-11-10T01:04:10+00:00")

    def test_usage_during_open_tool_call_is_not_idle(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-tool-busy.jsonl"
        st = parse_one(path)
        self.assertTrue(any(e.kind == "tool_use" for e in st.events))
        alerts = detect_one(path)
        self.assertEqual([a.alert_type for a in alerts], [])


class TestSidechainAndMeta(unittest.TestCase):
    def test_is_sidechain_session_is_excluded(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-side.jsonl"
        st = parse_one(path)
        self.assertTrue(st.is_sidechain)
        alerts = detect_one(path)
        self.assertEqual(alerts, [])

    def test_subagent_directory_is_excluded(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "subagents" / "sess-subagent.jsonl"
        st = parse_one(path)
        self.assertTrue(st.is_sidechain)
        alerts = detect_one(path)
        self.assertEqual(alerts, [])

    def test_system_injection_is_not_an_anchor(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-meta.jsonl"
        st = parse_one(path)
        self.assertTrue(any(e.kind == "meta" for e in st.events))
        self.assertEqual(st.last_user_ts.isoformat(), "2026-11-10T07:00:00+00:00")
        alerts = detect_one(path)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].idle_tokens, 600)
        self.assertLess(idle[0].last_user_ts, idle[0].first_idle_usage_ts)


class TestCacheReadAndOrder(unittest.TestCase):
    def test_huge_cache_read_is_not_idle_increment(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-huge-cache.jsonl"
        st = parse_one(path)
        usage = [e for e in st.events if e.kind == "usage"]
        self.assertEqual(usage[0].tokens, 15)
        self.assertEqual(usage[0].cache_read, 99364222)
        alerts = detect_one(path)
        self.assertEqual(alerts, [])

    def test_out_of_order_lines_use_last_real_user_as_anchor(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-ooo.jsonl"
        st = parse_one(path)
        # File order is messy; the last real user in time is 05:10.
        self.assertEqual(st.last_user_ts.isoformat(), "2026-11-10T05:10:00+00:00")
        alerts = detect_one(path)
        self.assertEqual(alerts, [])


class TestLongRun(unittest.TestCase):
    def test_continuous_work_is_long_run_not_idle_drain(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-long-run.jsonl"
        alerts = detect_one(path, long_run_seconds=1800)
        types = [a.alert_type for a in alerts]
        self.assertEqual(types, ["long_run"])
        self.assertEqual(alerts[0].severity, "low")
        self.assertGreaterEqual(alerts[0].run_seconds or 0, 1800)
        self.assertIn("not classified as idle_drain", alerts[0].reason)

    def test_default_min_severity_hides_long_run(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-long-run.jsonl"
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(path),
                "--codex-root",
                str(ROOT / "fixtures" / "missing-codex"),
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("long_run: 1", proc.stdout)
        self.assertIn("hidden by --min-severity medium", proc.stdout)
        self.assertNotIn("[ALERT]", proc.stdout)

    def test_min_severity_low_shows_long_run(self) -> None:
        path = REG_CLAUDE / "projects" / "demo-fp" / "sess-long-run.jsonl"
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(path),
                "--codex-root",
                str(ROOT / "fixtures" / "missing-codex"),
                "--min-severity",
                "low",
            ]
        )
        self.assertEqual(proc.returncode, 2, msg=proc.stderr + proc.stdout)
        self.assertIn("[ALERT] low type long_run", proc.stdout)


class TestZstd(unittest.TestCase):
    def test_discover_lists_archived_zst(self) -> None:
        files = qg.discover(REG_CODEX, "codex")
        names = {p.name for p in files}
        self.assertIn("rollout-sess-archived-zst.jsonl.zst", names)

    def test_zst_is_skipped_when_unsupported(self) -> None:
        path = REG_CODEX / "archived_sessions" / "rollout-sess-archived-zst.jsonl.zst"
        with mock.patch.object(qg, "zstd_backend", return_value=None):
            warnings: list[qg.ParseWarning] = []
            text, reason = qg.read_log_text(path, warnings)
            self.assertIsNone(text)
            self.assertEqual(reason, "zst_unsupported")
            self.assertTrue(any("zst unsupported" in w.message for w in warnings))

        with mock.patch.object(qg, "zstd_backend", return_value=None):
            result = qg.scan_roots(
                [ROOT / "fixtures" / "missing-claude"],
                REG_CODEX,
                180,
                200,
                2.0,
            )
        self.assertEqual(result.summary.files_found, 1)
        self.assertEqual(result.summary.files_scanned, 0)
        self.assertEqual(result.summary.files_skipped, {"zst_unsupported": 1})
        self.assertEqual(result.scanned, [])

    def test_zst_unsupported_warnings_are_summarized_unless_verbose(self) -> None:
        warnings = [
            qg.ParseWarning("/tmp/a.jsonl.zst", None, "skipped: zst unsupported (need Python 3.14+ compression.zstd or pip install zstandard)"),
            qg.ParseWarning("/tmp/b.jsonl.zst", None, "skipped: zst unsupported (need Python 3.14+ compression.zstd or pip install zstandard)"),
            qg.ParseWarning("/tmp/c.jsonl.zst", None, "skipped: zst unsupported (need Python 3.14+ compression.zstd or pip install zstandard)"),
            qg.ParseWarning("/tmp/ok.jsonl", 3, "truncated or partial last line"),
        ]
        lines = qg.format_emitted_warnings(warnings, verbose=False)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("warning: skipped 3 .jsonl.zst files"))
        self.assertIn("pip install zstandard", lines[0])
        self.assertIn("--verbose", lines[0])
        self.assertNotIn("/tmp/a.jsonl.zst", "\n".join(lines))
        self.assertIn("truncated or partial last line", lines[1])

        verbose_lines = qg.format_emitted_warnings(warnings, verbose=True)
        self.assertEqual(len(verbose_lines), 4)
        self.assertTrue(any("/tmp/a.jsonl.zst" in ln for ln in verbose_lines))
        self.assertTrue(any("/tmp/c.jsonl.zst" in ln for ln in verbose_lines))
        self.assertTrue(all(ln.startswith("warning: ") for ln in verbose_lines))

    def test_cli_summarizes_multiple_zst_skips_and_lists_them_with_verbose(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions = Path(td) / "sessions" / "2026" / "11" / "10"
            sessions.mkdir(parents=True)
            names = []
            for i in range(3):
                path = sessions / f"rollout-sess-zst-{i}.jsonl.zst"
                path.write_bytes(b"not-a-zstd-frame")
                names.append(path.name)
            common = [
                "scan",
                "--claude-root",
                str(ROOT / "fixtures" / "missing-claude"),
                "--codex-root",
                str(td),
                "--json",
            ]
            # These dummy files are skipped only when no zstd backend is present.
            # If a backend is installed, they become zst_error instead; still assert
            # we do not print one identical-style flood without --verbose for unsupported.
            proc = run_cli(common)
            self.assertIn(proc.returncode, (0, 2), proc.stderr + proc.stdout)
            if qg.zstd_backend() is None:
                summary = [ln for ln in proc.stderr.splitlines() if "skipped 3 .jsonl.zst" in ln]
                self.assertEqual(len(summary), 1, proc.stderr)
                self.assertIn("pip install zstandard", summary[0])
                for name in names:
                    self.assertNotIn(name, proc.stderr)
                verbose = run_cli([*common, "--verbose"])
                self.assertIn(verbose.returncode, (0, 2), verbose.stderr + verbose.stdout)
                for name in names:
                    self.assertIn(name, verbose.stderr)
                listed = [ln for ln in verbose.stderr.splitlines() if "zst unsupported" in ln]
                self.assertEqual(len(listed), 3, verbose.stderr)
            else:
                # Backend present: dummy bytes are errors, not "unsupported". Still
                # confirm --verbose exists and the command runs.
                self.assertNotIn("skipped 3 .jsonl.zst", proc.stderr)

    def test_report_summarizes_zst_skips_without_verbose(self) -> None:
        warnings = [
            qg.ParseWarning("/tmp/a.jsonl.zst", None, "skipped: zst unsupported (need pip install zstandard)"),
            qg.ParseWarning("/tmp/b.jsonl.zst", None, "skipped: zst unsupported (need pip install zstandard)"),
        ]
        # Minimal empty sessions/alerts
        body = qg.render_report([], {}, warnings=warnings, verbose=False)
        self.assertIn("Skipped 2 .jsonl.zst files", body)
        self.assertIn("pip install zstandard", body)
        self.assertNotIn("/tmp/a.jsonl.zst", body)
        verbose_body = qg.render_report([], {}, warnings=warnings, verbose=True)
        self.assertIn("/tmp/a.jsonl.zst", verbose_body)
        self.assertIn("/tmp/b.jsonl.zst", verbose_body)

    @unittest.skipUnless(qg.zstd_backend() is not None, "no zstd backend installed")
    def test_archived_zst_is_parsed_when_supported(self) -> None:
        path = REG_CODEX / "archived_sessions" / "rollout-sess-archived-zst.jsonl.zst"
        warnings: list[qg.ParseWarning] = []
        events = qg.parse_codex_file(path, warnings)
        self.assertFalse(warnings)
        users = [e for e in events if e.kind == "user"]
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(users), 1)
        # new = (40-10)+6 = 36
        self.assertEqual(usage[0].tokens, 36)
        self.assertEqual(usage[0].cache_read, 10)
        sessions = qg.build_sessions(events)
        self.assertIn("codex:sess-archived-zst", sessions)


class TestExplainAndSummary(unittest.TestCase):
    def test_explain_prints_timeline_without_prompt_text(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(ROOT / "fixtures" / "claude"),
                "--codex-root",
                str(ROOT / "fixtures" / "codex"),
                "--explain",
                "sess-idle",
                "--no-hash",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("# explain sess-idle", proc.stdout)
        self.assertIn("ANCHOR (last real user input;", proc.stdout)
        self.assertIn("Anchor type: type=user", proc.stdout)
        self.assertIn("new_tokens=+750", proc.stdout)
        self.assertIn("cache_read=+50000", proc.stdout)
        self.assertNotIn("please review this file", proc.stdout)
        self.assertNotIn("[ALERT]", proc.stdout)

    def test_explain_accepts_sha256_prefix(self) -> None:
        hashed = qg.hash_session_id("sess-idle")
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(ROOT / "fixtures" / "claude"),
                "--codex-root",
                str(ROOT / "fixtures" / "codex"),
                "--explain",
                hashed,
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn(hashed, proc.stdout)
        self.assertNotIn("sess-idle", proc.stdout)

    def test_explain_unknown_session_exits_1(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(ROOT / "fixtures" / "claude"),
                "--codex-root",
                str(ROOT / "fixtures" / "codex"),
                "--explain",
                "does-not-exist",
            ]
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("No session matched", proc.stderr)

    def test_scan_json_includes_summary(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(ROOT / "fixtures" / "claude"),
                "--codex-root",
                str(ROOT / "fixtures" / "codex"),
                "--json",
                "--no-hash",
                "--no-redact-home",
            ]
        )
        self.assertEqual(proc.returncode, 2, msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["files_scanned"], 4)
        self.assertEqual(payload["summary"]["sessions"], 4)
        self.assertEqual(payload["summary"]["alerts_by_type"].get("A"), 2)
        self.assertEqual(payload["summary"]["alerts_by_type"].get("B"), 1)
        self.assertIsInstance(payload["summary"]["files_skipped"], dict)


class TestVersion(unittest.TestCase):
    def test_version_is_0_4_0(self) -> None:
        proc = run_cli(["--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0.4.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
