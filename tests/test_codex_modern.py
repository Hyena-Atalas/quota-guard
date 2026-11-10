#!/usr/bin/env python3
"""Regression tests for the current Codex rollout shape.

All logs here are constructed samples, not real user sessions. Prompt bodies
are dummy placeholders and must not appear in --explain or report output.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import quota_guard as qg  # noqa: E402

MODERN = ROOT / "fixtures" / "regression" / "codex-modern"
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


def scan_modern(**kwargs) -> qg.ScanResult:
    return qg.scan_roots(
        [MISSING_CLAUDE],
        MODERN,
        kwargs.get("idle_seconds", 180),
        kwargs.get("token_threshold", 200),
        kwargs.get("percent_threshold", 2.0),
    )


def parse_named(name: str) -> tuple[qg.SessionState, list[qg.ParseWarning]]:
    path = next(MODERN.rglob(name))
    warnings: list[qg.ParseWarning] = []
    events = qg.parse_codex_file(path, warnings)
    sessions = qg.build_sessions(events)
    if len(sessions) != 1:
        raise AssertionError(f"expected 1 session in {path}, got {list(sessions)}")
    return next(iter(sessions.values())), warnings


class TestClassifyCodexUserMessage(unittest.TestCase):
    def test_client_authored_true_is_anchor(self) -> None:
        self.assertEqual(qg.classify_codex_user_message("user", {"client_authored": True}), "anchor")

    def test_inherited_is_not_an_anchor_even_if_client_authored(self) -> None:
        self.assertEqual(
            qg.classify_codex_user_message(
                "user", {"client_authored": True, "inherited_user_message": True}
            ),
            "inherited",
        )

    def test_missing_client_authored_falls_back_to_role_user(self) -> None:
        self.assertEqual(qg.classify_codex_user_message("user", {}), "fallback_anchor")

    def test_client_authored_false_is_not_an_anchor(self) -> None:
        self.assertEqual(qg.classify_codex_user_message("user", {"client_authored": False}), "non_client")

    def test_developer_is_not_an_anchor(self) -> None:
        self.assertEqual(qg.classify_codex_user_message("developer", {"client_authored": True}), "developer")


class TestModernAnchors(unittest.TestCase):
    def test_client_authored_anchor_and_no_double_count(self) -> None:
        st, warnings = parse_named("rollout-sess-modern-idle.jsonl")
        self.assertFalse(warnings)
        self.assertEqual(st.last_anchor_type, "client_authored=true")
        self.assertIsNotNone(st.last_user_ts)
        usage = [e for e in st.events if e.kind == "usage"]
        self.assertEqual(len(usage), 2)
        self.assertTrue(all(e.record_type == "token_usage_record" for e in usage))
        # First thread total 100, second 580, delta 480. token_count must not add again.
        self.assertEqual(usage[0].tokens, 100)
        self.assertEqual(usage[1].tokens, 480)
        self.assertEqual(st.total_tokens, 580)
        self.assertTrue(any(e.kind == "turn_start" and e.turn_trigger == "constructed_trigger" for e in st.events))

        sessions = {f"{st.source}:{st.session_id}": st}
        alerts = qg.detect(sessions, 180, 200, 2.0)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].idle_tokens, 480)
        self.assertEqual(idle[0].severity, "medium")
        self.assertEqual(idle[0].confidence, "high")
        self.assertIn("after a task_complete", idle[0].reason)
        self.assertIn("anchor type: client_authored=true", idle[0].reason)

    def test_inherited_only_is_not_an_anchor(self) -> None:
        st, _ = parse_named("rollout-sess-inherited.jsonl")
        self.assertIsNone(st.last_user_ts)
        self.assertEqual(st.no_anchor_reason, "all_inherited")
        self.assertFalse(st.is_sidechain)
        alerts = qg.detect({f"{st.source}:{st.session_id}": st}, 180, 200, 2.0)
        self.assertEqual([a.alert_type for a in alerts if a.alert_type == "A"], [])

    def test_fallback_role_user_is_an_anchor(self) -> None:
        st, _ = parse_named("rollout-sess-fallback.jsonl")
        self.assertEqual(st.last_anchor_type, "fallback_role_user")
        self.assertIsNotNone(st.last_user_ts)
        alerts = qg.detect({f"{st.source}:{st.session_id}": st}, 180, 200, 2.0)
        idle = [a for a in alerts if a.alert_type == "A"]
        self.assertEqual(len(idle), 1)
        self.assertEqual(idle[0].idle_tokens, 300)
        self.assertEqual(idle[0].severity, "low")
        self.assertEqual(idle[0].confidence, "low")
        self.assertIn("anchor type: fallback_role_user", idle[0].reason)
        self.assertIn("low confidence", idle[0].reason)

    def test_no_user_messages_reason(self) -> None:
        st, _ = parse_named("rollout-sess-no-user.jsonl")
        self.assertIsNone(st.last_user_ts)
        self.assertEqual(st.no_anchor_reason, "no_user_messages")

    def test_subagent_turns_are_excluded_from_idle(self) -> None:
        st, _ = parse_named("rollout-sess-subagent.jsonl")
        self.assertTrue(st.is_sidechain)
        self.assertEqual(st.no_anchor_reason, "sub_agent")
        self.assertIsNone(st.last_user_ts)
        alerts = qg.detect({f"{st.source}:{st.session_id}": st}, 180, 200, 2.0)
        self.assertEqual([a for a in alerts if a.alert_type == "A"], [])
        start = next(e for e in st.events if e.kind == "turn_start")
        self.assertEqual(start.turn_trigger, "constructed_auto")
        self.assertEqual(start.initiating_agent_path, "parent/child")
        self.assertTrue(start.is_sidechain)


class TestTypeBLimitId(unittest.TestCase):
    def test_global_limit_id_and_resets_at(self) -> None:
        result = scan_modern()
        type_b = [a for a in result.alerts if a.alert_type == "B"]
        # Only pool-other should fire. pool-shared is explained by sess-pool-active
        # tokens. A resets_at change is not growth.
        self.assertEqual({a.limit_id for a in type_b}, {"pool-other"})
        self.assertEqual(len(type_b), 1)
        self.assertAlmostEqual(type_b[0].percent_step or 0, 30.0)
        self.assertIn("limit_id=pool-other", type_b[0].reason)
        self.assertIn("resets_at", type_b[0].reason)
        self.assertNotIn("pool-shared", "".join(a.limit_id for a in type_b))
        self.assertNotIn("pool-reset", "".join(a.limit_id for a in type_b))

    def test_same_response_id_is_deduped(self) -> None:
        # Two token_usage_record rows with the same response_id should count once.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sessions" / "rollout-dup.jsonl"
            path.parent.mkdir(parents=True)
            rows = [
                {"timestamp": "2026-11-10T16:00:00.000Z", "type": "session_meta", "payload": {"id": "sess-dup"}},
                {
                    "timestamp": "2026-11-10T16:00:01.000Z",
                    "type": "response_item",
                    "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "x"}]},
                    "metadata": {"client_authored": True},
                },
                {
                    "timestamp": "2026-11-10T16:00:02.000Z",
                    "type": "token_usage_record",
                    "payload": {
                        "response_id": "resp-same",
                        "session_id": "sess-dup",
                        "turn_id": "t",
                        "usage": {
                            "input_tokens": 50,
                            "cached_input_tokens": 0,
                            "cache_write_input_tokens": 0,
                            "output_tokens": 10,
                            "reasoning_output_tokens": 0,
                            "total_tokens": 60,
                        },
                    },
                },
                {
                    "timestamp": "2026-11-10T16:00:03.000Z",
                    "type": "token_usage_record",
                    "payload": {
                        "response_id": "resp-same",
                        "session_id": "sess-dup",
                        "turn_id": "t",
                        "usage": {
                            "input_tokens": 50,
                            "cached_input_tokens": 0,
                            "cache_write_input_tokens": 0,
                            "output_tokens": 10,
                            "reasoning_output_tokens": 0,
                            "total_tokens": 60,
                        },
                    },
                },
            ]
            path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            events = qg.parse_codex_file(path, [])
            usage = [e for e in events if e.kind == "usage"]
            self.assertEqual(len(usage), 1)
            self.assertEqual(usage[0].tokens, 60)


class TestExplainAndSummaryReasons(unittest.TestCase):
    def test_explain_shows_anchor_type_and_omits_prompt(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
                "--explain",
                "sess-modern-idle",
                "--no-hash",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("Anchor type: client_authored=true", proc.stdout)
        self.assertIn("ANCHOR (last real user input; client_authored=true)", proc.stdout)
        self.assertIn("task_started", proc.stdout)
        self.assertIn("task_complete", proc.stdout)
        self.assertIn("turn_id=turn-main", proc.stdout)
        self.assertIn("turn_trigger=constructed_trigger", proc.stdout)
        self.assertNotIn(PROMPT, proc.stdout)

    def test_explain_fallback_anchor_type(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
                "--explain",
                "sess-fallback",
                "--no-hash",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("Anchor type: fallback_role_user", proc.stdout)
        self.assertNotIn(PROMPT, proc.stdout)

    def test_summary_classifies_no_user_input_reasons(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
                "--json",
                "--no-hash",
            ]
        )
        self.assertIn(proc.returncode, (0, 2), msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        reasons = payload["summary"]["sessions_no_user_anchor_by_reason"]
        self.assertEqual(reasons.get("all_inherited"), 1)
        self.assertEqual(reasons.get("no_user_messages"), 1)
        self.assertEqual(reasons.get("sub_agent"), 1)
        # Also run without --json to check the printed classification.
        human = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
                "--no-hash",
            ]
        )
        self.assertIn("no user messages: 1", human.stdout)
        self.assertIn("all inherited: 1", human.stdout)
        self.assertIn("sub-agent: 1", human.stdout)
        report = run_cli(
            [
                "report",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
                "--no-hash",
            ]
        )
        self.assertIn("no real user input (all inherited)", report.stdout)
        self.assertIn("no real user input (no user messages)", report.stdout)
        self.assertIn("no real user input (sub-agent)", report.stdout)


class TestMalformedAggregationAndZstdLines(unittest.TestCase):
    def test_malformed_lines_are_aggregated_per_file(self) -> None:
        st, warnings = parse_named("rollout-sess-malformed.jsonl")
        self.assertEqual(len(warnings), 1)
        self.assertIsNone(warnings[0].line)
        self.assertIn("malformed or non-JSON line(s) skipped", warnings[0].message)
        self.assertIn("3-4", warnings[0].message)
        self.assertNotIn("Expecting value", warnings[0].message)
        usage = [e for e in st.events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0].tokens, 15)

    def test_scan_does_not_print_one_warning_per_line(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(MISSING_CLAUDE),
                "--codex-root",
                str(MODERN),
            ]
        )
        self.assertIn(proc.returncode, (0, 2), msg=proc.stderr + proc.stdout)
        # One aggregated warning for the malformed file, not four "skipped malformed" lines.
        skipped = [ln for ln in proc.stderr.splitlines() if "malformed or non-JSON" in ln]
        self.assertEqual(len(skipped), 1)
        self.assertNotIn("skipped malformed JSON", proc.stderr)

    @unittest.skipUnless(qg.zstd_backend() is not None, "no zstd backend installed")
    def test_zstd_stream_keeps_lines_intact_and_aggregates(self) -> None:
        src = next(MODERN.rglob("rollout-sess-malformed.jsonl"))
        raw = src.read_bytes()
        # Repeat a valid long line so a small decompressor chunk cannot be a full line.
        long_obj = json.dumps(
            {
                "timestamp": "2026-11-10T15:00:11.000Z",
                "type": "token_usage_record",
                "payload": {
                    "response_id": "resp-long",
                    "session_id": "sess-malformed",
                    "turn_id": "turn-mf",
                    "usage": {
                        "input_tokens": 8,
                        "cached_input_tokens": 0,
                        "cache_write_input_tokens": 0,
                        "output_tokens": 2,
                        "reasoning_output_tokens": 0,
                        "total_tokens": 10,
                        "pad": "x" * 8000,
                    },
                },
            }
        )
        payload = raw + long_obj.encode() + b"\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rollout-sess-malformed.jsonl.zst"
            data, fmt = _compress(payload)
            self.assertIsNotNone(data)
            path.write_bytes(data)
            warnings: list[qg.ParseWarning] = []
            events = qg.parse_codex_file(path, warnings)
            self.assertEqual(len(warnings), 1)
            self.assertIn("malformed or non-JSON line(s) skipped", warnings[0].message)
            usage = [e for e in events if e.kind == "usage"]
            self.assertEqual(len(usage), 2)
            self.assertEqual(usage[1].tokens, 10)
            self.assertEqual(usage[1].response_id, "resp-long")


def _compress(data: bytes) -> tuple[bytes | None, str | None]:
    backend = qg.zstd_backend()
    if backend == "zstandard":
        import zstandard

        return zstandard.ZstdCompressor().compress(data), backend
    if backend == "compression.zstd":
        from compression import zstd

        return zstd.compress(data), backend
    return None, None


if __name__ == "__main__":
    unittest.main()
