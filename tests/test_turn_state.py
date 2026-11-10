#!/usr/bin/env python3
"""Turn-state Type A / Type B / long_run regression tests.

All logs here are constructed samples, not real user sessions.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import quota_guard as qg  # noqa: E402

TURNS = ROOT / "fixtures" / "regression" / "codex-turns"
MISSING_CLAUDE = ROOT / "fixtures" / "missing-claude"
PY = sys.executable
PROMPT = "constructed ping"


def run_cli(args: list[str], env: dict[str, str] | None = None) -> object:
    import subprocess

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env.setdefault("CLAUDE_CONFIG_DIR", str(MISSING_CLAUDE))
    full_env.setdefault("CODEX_HOME", str(ROOT / "fixtures" / "missing-codex"))
    return subprocess.run(
        [PY, str(ROOT / "quota_guard.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=full_env,
    )


def parse_named(folder: Path, name: str) -> qg.SessionState:
    path = next(folder.rglob(name))
    events = qg.parse_codex_file(path, [])
    sessions = qg.build_sessions(events)
    if len(sessions) != 1:
        raise AssertionError(f"expected 1 session in {path}, got {list(sessions)}")
    return next(iter(sessions.values()))


def detect_st(st: qg.SessionState, **kwargs) -> list[qg.Alert]:
    return qg.detect(
        {f"{st.source}:{st.session_id}": st},
        kwargs.get("idle_seconds", 180),
        kwargs.get("token_threshold", 200),
        kwargs.get("percent_threshold", 2.0),
        kwargs.get("long_run_seconds", 1800),
    )


class TestLongAutonomousTurn(unittest.TestCase):
    def test_in_turn_usage_is_long_run_not_type_a(self) -> None:
        st = parse_named(TURNS, "rollout-sess-long-turn.jsonl")
        self.assertTrue(st.has_turn_events)
        self.assertEqual(len(st.turns), 1)
        self.assertTrue(st.turns[0].completed)
        self.assertEqual(st.post_complete_usage_events, 0)
        alerts = detect_st(st)
        types = [a.alert_type for a in alerts]
        self.assertEqual(types, ["long_run"])
        self.assertEqual(alerts[0].severity, "low")
        self.assertGreaterEqual(alerts[0].run_seconds or 0, 7200)
        self.assertIn("not classified as idle_drain", alerts[0].reason)
        self.assertIn("turn_id=turn-long", alerts[0].reason)


class TestPostCompleteTypeA(unittest.TestCase):
    def test_usage_after_task_complete_is_type_a(self) -> None:
        st = parse_named(TURNS, "rollout-sess-post-complete.jsonl")
        self.assertEqual(st.post_complete_usage_events, 1)
        alerts = detect_st(st)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].severity, "medium")
        self.assertEqual(idle[0].confidence, "high")
        self.assertEqual(idle[0].idle_tokens, 250)
        self.assertIn("after a task_complete", idle[0].reason)
        self.assertIn("turn_id", idle[0].reason)
        self.assertEqual(idle[0].first_idle_usage_ts, "2026-11-10T11:10:11+00:00")
        self.assertEqual([a.alert_type for a in alerts if a.alert_type == "long_run"], [])

    def test_explain_shows_task_complete_and_turn_id(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(TURNS),
                "--explain",
                "sess-post-complete",
                "--no-hash",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("task_complete", proc.stdout)
        self.assertIn("turn_id=turn-pc", proc.stdout)
        self.assertIn("post-complete", proc.stdout)
        self.assertIn("Turns: 1 total, 1 with task_complete", proc.stdout)
        self.assertIn("Post-complete usage events: 1", proc.stdout)
        self.assertNotIn(PROMPT, proc.stdout)


class TestLegacyLowConfidence(unittest.TestCase):
    def test_old_format_without_task_events_is_low_confidence(self) -> None:
        st = parse_named(TURNS, "rollout-sess-legacy-gap.jsonl")
        self.assertFalse(st.has_turn_events)
        alerts = detect_st(st)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].severity, "low")
        self.assertEqual(idle[0].confidence, "low")
        self.assertEqual(idle[0].idle_tokens, 300)
        self.assertIn("low confidence", idle[0].reason)
        self.assertIn("no task_started/task_complete", idle[0].reason)

    def test_default_scan_hides_low_confidence_type_a(self) -> None:
        only_legacy = TURNS  # folder also has Type B after-complete, so exit may be 2
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(TURNS),
            ]
        )
        # High-confidence Type A (post-complete) and Type B are shown; legacy Type A is hidden.
        self.assertIn("hidden by --min-severity medium", proc.stdout)
        # The [ALERT] lines must not be low type A (legacy fallback is hidden).
        for line in proc.stdout.splitlines():
            if line.startswith("[ALERT]") and "type A" in line:
                self.assertNotIn("low type A", line)
                self.assertIn("medium type A", line)


class TestTypeBOpenTurn(unittest.TestCase):
    def test_percent_rise_during_open_turn_is_not_type_b(self) -> None:
        st = parse_named(TURNS, "rollout-sess-typeb-open-turn.jsonl")
        alerts = detect_st(st)
        self.assertEqual([a.alert_type for a in alerts if a.alert_type == "B"], [])

    def test_percent_rise_after_complete_with_no_tokens_is_type_b(self) -> None:
        st = parse_named(TURNS, "rollout-sess-typeb-after-complete.jsonl")
        alerts = detect_st(st)
        typb = [a for a in alerts if a.alert_type == "B"]
        self.assertEqual(len(typb), 1)
        self.assertAlmostEqual(typb[0].percent_step or 0, 30.0)
        self.assertIn("no local turn was open", typb[0].reason)


class TestSummaryTurnCounts(unittest.TestCase):
    def test_scan_json_includes_turn_totals(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(TURNS),
                "--json",
                "--no-hash",
            ]
        )
        self.assertIn(proc.returncode, (0, 2), msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        summary = payload["summary"]
        self.assertGreaterEqual(summary["turns_total"], 4)
        self.assertGreaterEqual(summary["turns_completed"], 3)
        self.assertGreaterEqual(summary["post_complete_usage_events"], 1)
        human = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(TURNS),
                "--no-hash",
            ]
        )
        self.assertIn("Turns:", human.stdout)
        self.assertIn("with task_complete", human.stdout)
        self.assertIn("post-complete usage events:", human.stdout)


if __name__ == "__main__":
    unittest.main()
