#!/usr/bin/env python3
"""Tests for quota-guard. All logs here are constructed samples, not real user sessions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import quota_guard as qg  # noqa: E402

FIXTURES = ROOT / "fixtures"
CLAUDE = FIXTURES / "claude"
CODEX = FIXTURES / "codex"
EXTRA_CLAUDE = FIXTURES / "extra" / "claude"
EXTRA_CODEX = FIXTURES / "extra" / "codex"
CONFIG_CODEX = FIXTURES / "config" / "codex"
CONFIG_CLAUDE = FIXTURES / "config" / "claude"
CONFIG_CLAUDE_EMPTY = FIXTURES / "config" / "claude-empty"
CONFIG_PARTIAL = FIXTURES / "config" / "partial-codex"

PY = sys.executable


def run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    # Point defaults at empty dirs so a missing flag cannot touch a real home tree.
    full_env.setdefault("CLAUDE_CONFIG_DIR", str(FIXTURES / "missing-claude"))
    full_env.setdefault("CODEX_HOME", str(FIXTURES / "missing-codex"))
    return subprocess.run(
        [PY, str(ROOT / "quota_guard.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=full_env,
    )


def scan_fixtures(**kwargs) -> qg.ScanResult:
    idle = kwargs.get("idle_seconds", 180)
    token = kwargs.get("token_threshold", 1)
    percent = kwargs.get("percent_threshold", 1.0)
    claude_root = kwargs.get("claude_root", CLAUDE)
    codex_root = kwargs.get("codex_root", CODEX)
    return qg.scan_roots([Path(claude_root)], Path(codex_root), idle, token, percent)


class TestEightOneSamples(unittest.TestCase):
    """Section 8.1 constructed-sample cases from the MVP plan."""

    def setUp(self) -> None:
        self.result = scan_fixtures()
        self.by_id = {a.session_id: a for a in self.result.alerts}

    def test_four_sessions_scanned(self) -> None:
        self.assertEqual(len(self.result.sessions), 4)
        self.assertEqual(len(self.result.alerts), 3)
        self.assertNotIn("sess-ok", self.by_id)

    def test_claude_idle_dedup_5100(self) -> None:
        # User input at 01:00, usage at 01:04:10. Duplicate message.id+requestId
        # must not be double-counted. Idle increment is 20+80+5000 = 5100.
        alert = self.by_id["sess-idle"]
        self.assertEqual(alert.source, "claude")
        self.assertEqual(alert.alert_type, "A")
        # New tokens only: 400+300+50 = 750. cache_read 50000 is not counted.
        self.assertEqual(alert.idle_tokens, 750)
        self.assertEqual(alert.idle_cache_read, 50000)
        sess = self.result.sessions["claude:sess-idle"]
        # Immediate reply (100+50+200=350) + idle (750); the duplicate line is not added.
        self.assertEqual(sess.total_tokens, 350 + 750)
        self.assertEqual(sess.total_cache_read, 1000 + 50000)
        # Anchor is the last real user, and it precedes first idle usage.
        self.assertLess(alert.last_user_ts, alert.first_idle_usage_ts)

    def test_claude_active_session_not_flagged(self) -> None:
        self.assertIn("claude:sess-ok", self.result.sessions)
        self.assertEqual(self.result.sessions["claude:sess-ok"].total_tokens, 70)
        self.assertNotIn("sess-ok", self.by_id)

    def test_codex_idle_delta_and_percent(self) -> None:
        # new-token cumulative 1350-250=1100; primary used_percent 10 -> 18.
        # cache is subtracted from input so it is not part of the idle increment.
        alert = self.by_id["sess-codex-idle"]
        self.assertEqual(alert.source, "codex")
        self.assertEqual(alert.alert_type, "A")
        self.assertEqual(alert.idle_tokens, 1100)
        self.assertIsNotNone(alert.percent_step)
        self.assertAlmostEqual(alert.percent_step or 0, 8.0)
        self.assertIn("primary", alert.reason)
        self.assertIn("8.0", alert.reason)
        self.assertLess(alert.last_user_ts, alert.first_idle_usage_ts)

    def test_codex_ghost_quota_type_b(self) -> None:
        # Tokens stay at 60; secondary used_percent 5 -> 33.
        alert = self.by_id["sess-ghost"]
        self.assertEqual(alert.source, "codex")
        self.assertEqual(alert.alert_type, "B")
        self.assertEqual(alert.idle_tokens, 0)
        self.assertAlmostEqual(alert.percent_step or 0, 28.0)
        self.assertIn("no matching new tokens on any local session", alert.reason)
        self.assertIn("limit_id", alert.reason)
        self.assertIn("resets_at", alert.reason)


class TestDedup(unittest.TestCase):
    def test_duplicate_message_id_takes_max_not_sum(self) -> None:
        # Isolated unit of the 8.1 Claude idle fixture.
        path = CLAUDE / "projects" / "demo-idle" / "sess-idle.jsonl"
        warnings: list[qg.ParseWarning] = []
        events = qg.parse_claude_file(path, warnings)
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 2)
        self.assertEqual(usage[0].tokens, 350)
        self.assertEqual(usage[0].cache_read, 1000)
        self.assertEqual(usage[1].tokens, 750)
        self.assertEqual(usage[1].cache_read, 50000)
        self.assertEqual(sum(e.tokens for e in usage), 1100)


class TestTruncatedAndOddRecords(unittest.TestCase):
    def test_truncated_last_line_does_not_crash_and_warns(self) -> None:
        path = EXTRA_CLAUDE / "projects" / "demo-sub" / "sess-trunc.jsonl"
        warnings: list[qg.ParseWarning] = []
        events = qg.parse_claude_file(path, warnings)
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0].tokens, 18)
        self.assertTrue(any("truncated or partial last line" in w.message for w in warnings))
        # The tool must still have counted the complete earlier line.
        # Malformed-line warnings are aggregated per file (line is in the message).
        self.assertTrue(any("line 3" in w.message for w in warnings))

    def test_missing_and_unknown_usage_fields_warn_and_skip(self) -> None:
        path = EXTRA_CLAUDE / "projects" / "demo-sub" / "sess-odd.jsonl"
        warnings: list[qg.ParseWarning] = []
        events = qg.parse_claude_file(path, warnings)
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0].tokens, 10)
        messages = [w.message for w in warnings]
        self.assertTrue(any("no known token fields" in m for m in messages))
        self.assertGreaterEqual(len(warnings), 2)

    def test_scan_extra_fixtures_via_cli_prints_warning(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(EXTRA_CLAUDE),
                "--codex-root",
                str(EXTRA_CODEX),
                "--json",
            ]
        )
        # Extra fixtures include no type-A/B idle drain, so exit 0 is fine;
        # truncated + odd records must not crash.
        self.assertIn(proc.returncode, (0, 2), msg=proc.stderr)
        self.assertIn("truncated or partial last line", proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("warnings", payload)
        self.assertGreaterEqual(len(payload["warnings"]), 1)


class TestDiscoveryAndAliases(unittest.TestCase):
    def test_claude_recursive_includes_subagents(self) -> None:
        files = qg.discover(EXTRA_CLAUDE, "claude")
        names = {p.name for p in files}
        self.assertIn("sess-sub.jsonl", names)
        self.assertIn("sess-trunc.jsonl", names)
        self.assertTrue(any("subagents" in p.parts for p in files))

    def test_codex_scans_archived_sessions(self) -> None:
        files = qg.discover(EXTRA_CODEX, "codex")
        names = {p.name for p in files}
        self.assertIn("rollout-sess-archived.jsonl", names)
        self.assertIn("rollout-sess-parts.jsonl", names)

    def test_claude_accepts_cached_input_tokens_alias(self) -> None:
        path = EXTRA_CLAUDE / "projects" / "demo-sub" / "subagents" / "sess-sub.jsonl"
        events = qg.parse_claude_file(path, [])
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        # new = 4+6+0 = 10; cached_input_tokens 2 is recorded separately.
        self.assertEqual(usage[0].tokens, 10)
        self.assertEqual(usage[0].cache_read, 2)

    def test_codex_accepts_cache_read_input_tokens_alias(self) -> None:
        path = EXTRA_CODEX / "archived_sessions" / "rollout-sess-archived.jsonl"
        events = qg.parse_codex_file(path, [])
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        # new = (30-10)+5+0 = 25; cache_read 10 is not added.
        self.assertEqual(usage[0].tokens, 25)
        self.assertEqual(usage[0].cache_read, 10)
        self.assertEqual(usage[0].note, "total_token_usage")

    def test_codex_sum_parts_does_not_add_cache_again(self) -> None:
        path = EXTRA_CODEX / "sessions" / "2026/11/10/rollout-sess-parts.jsonl"
        events = qg.parse_codex_file(path, [])
        usage = [e for e in events if e.kind == "usage"]
        self.assertEqual(len(usage), 1)
        # (12-4)+3+1 = 12; cache_read 4 is not added to new tokens.
        self.assertEqual(usage[0].tokens, 12)
        self.assertEqual(usage[0].cache_read, 4)
        self.assertIn("last_token_usage", usage[0].note)

    def test_env_var_roots(self) -> None:
        env = {
            "CLAUDE_CONFIG_DIR": str(CLAUDE),
            "CODEX_HOME": str(CODEX),
        }
        proc = run_cli(["scan", "--json"], env=env)
        self.assertEqual(proc.returncode, 2, msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["sessions"], 4)
        # Default --min-severity medium hides low-confidence Type A (no task_* events).
        self.assertEqual({a["alert_type"] for a in payload["alerts"]}, {"B"})
        self.assertEqual(payload["summary"]["alerts_by_type"].get("A"), 2)
        self.assertEqual(payload["summary"]["alerts_by_type"].get("B"), 1)

    def test_comma_separated_claude_config_dir(self) -> None:
        env = {
            "CLAUDE_CONFIG_DIR": f"{CLAUDE},{EXTRA_CLAUDE}",
            "CODEX_HOME": str(FIXTURES / "missing-codex"),
        }
        proc = run_cli(["scan", "--json", "--no-hash", "--no-redact-home"], env=env)
        payload = json.loads(proc.stdout)
        self.assertGreaterEqual(payload["sessions"], 4)
        paths = " ".join(payload["files_scanned"])
        self.assertIn("sess-sub.jsonl", paths)
        self.assertTrue(any("subagents" in p for p in payload["files_scanned"]))

    def test_never_opens_credential_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auth.json").write_text('{"access_token":"SECRET"}', encoding="utf-8")
            (root / ".credentials.json").write_text('{"access_token":"SECRET"}', encoding="utf-8")
            (root / "projects").mkdir()
            sample = root / "projects" / "ok.jsonl"
            sample.write_text(
                '{"type":"assistant","timestamp":"2026-11-10T00:00:00Z",'
                '"sessionId":"s","requestId":"r","message":{"id":"m",'
                '"usage":{"input_tokens":1,"output_tokens":1}}}\n',
                encoding="utf-8",
            )

            opened: list[str] = []
            real_read_text = Path.read_text
            real_open = Path.open

            def tracking_read_text(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                opened.append(self.name)
                return real_read_text(self, *args, **kwargs)

            def tracking_open(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                opened.append(self.name)
                return real_open(self, *args, **kwargs)

            orig_read, orig_open = Path.read_text, Path.open
            Path.read_text = tracking_read_text  # type: ignore[method-assign]
            Path.open = tracking_open  # type: ignore[method-assign]
            try:
                files = qg.discover(root, "claude")
                self.assertEqual([p.name for p in files], ["ok.jsonl"])
                qg.parse_claude_file(files[0], [])
                warnings: list[qg.ParseWarning] = []
                qg.load_claude_settings(root, warnings)
                # settings.json is absent; auth/credentials must never be opened.
            finally:
                Path.read_text = orig_read  # type: ignore[method-assign]
                Path.open = orig_open  # type: ignore[method-assign]
            self.assertNotIn("auth.json", opened)
            self.assertNotIn(".credentials.json", opened)


class TestPrivacy(unittest.TestCase):
    def test_hash_is_stable_sha256_prefix(self) -> None:
        self.assertEqual(qg.hash_session_id("sess-idle"), qg.hash_session_id("sess-idle"))
        self.assertTrue(qg.hash_session_id("sess-idle").startswith("sha256:"))
        self.assertNotEqual(qg.hash_session_id("sess-idle"), "sess-idle")

    def test_report_hashes_ids_and_omits_prompts_by_default(self) -> None:
        result = scan_fixtures()
        body = qg.render_report(result.alerts, result.sessions, no_hash=False, no_redact=False)
        self.assertNotIn("sess-idle", body)
        self.assertNotIn("please review this file", body)
        self.assertNotIn("fix the tests", body)
        self.assertNotIn("status?", body)
        self.assertIn("sha256:", body)
        self.assertIn("user input", body)
        self.assertIn("Type B", body)

    def test_no_hash_shows_raw_id(self) -> None:
        result = scan_fixtures()
        body = qg.render_report(result.alerts, result.sessions, no_hash=True, no_redact=True)
        self.assertIn("sess-idle", body)

    def test_home_redaction_posix_and_windows(self) -> None:
        self.assertEqual(qg.redact_path("/home/demo/proj/a.jsonl", "/home/demo"), "~/proj/a.jsonl")
        self.assertEqual(
            qg.redact_path(r"C:\Users\demo\proj\a.jsonl", r"C:\Users\demo"),
            "~/proj/a.jsonl",
        )
        self.assertEqual(
            qg.redact_path(r"C:\Users\Demo\proj\a.jsonl", r"C:\Users\demo"),
            "~/proj/a.jsonl",
        )
        # Unrelated path is left alone.
        self.assertEqual(qg.redact_path("/tmp/demo/a.jsonl", "/home/demo"), "/tmp/demo/a.jsonl")


class TestCheckConfig(unittest.TestCase):
    def test_reads_documented_codex_and_claude_keys(self) -> None:
        warnings: list[qg.ParseWarning] = []
        cpath, citems = qg.check_codex_config(CONFIG_CODEX, warnings)
        self.assertEqual(cpath, CONFIG_CODEX / "config.toml")
        by_key = {i.key: i for i in citems}
        self.assertTrue(by_key["[features].memories"].present)
        self.assertEqual(by_key["[features].memories"].value, True)
        self.assertEqual(by_key["[features].memories"].status, "review")
        self.assertEqual(by_key["[memories].generate_memories"].value, True)
        self.assertEqual(by_key["[memories].use_memories"].value, True)
        self.assertEqual(by_key["[memories].min_rate_limit_remaining_percent"].value, 15)
        self.assertEqual(by_key["Scheduled Tasks / Codex Cloud (not read from this file)"].status, "unconfirmed")
        self.assertFalse(warnings)

        npath, nitems = qg.check_claude_settings(CONFIG_CLAUDE, warnings)
        nkey = {i.key: i for i in nitems}
        self.assertEqual(nkey["promptSuggestionEnabled"].value, True)
        self.assertEqual(nkey["idleCompaction"].value, True)
        self.assertEqual(nkey["session recap"].status, "unconfirmed")
        self.assertIn(qg.CLAUDE_COSTS_DOCS, nkey["promptSuggestionEnabled"].docs)
        self.assertIn(qg.CLAUDE_CACHING_DOCS, nkey["idleCompaction"].docs)
        self.assertIn(qg.CODEX_MEMORIES_DOCS, by_key["[features].memories"].docs)

    def test_missing_keys_are_not_invented(self) -> None:
        warnings: list[qg.ParseWarning] = []
        _, citems = qg.check_codex_config(CONFIG_PARTIAL, warnings)
        by_key = {i.key: i for i in citems}
        self.assertEqual(by_key["[features].memories"].value, False)
        self.assertFalse(by_key["[memories].generate_memories"].present)
        self.assertIsNone(by_key["[memories].generate_memories"].value)

        _, nitems = qg.check_claude_settings(CONFIG_CLAUDE_EMPTY, warnings)
        nkey = {i.key: i for i in nitems}
        self.assertFalse(nkey["promptSuggestionEnabled"].present)
        self.assertIsNone(nkey["promptSuggestionEnabled"].value)
        self.assertIn("does not invent", nkey["promptSuggestionEnabled"].advice)

    def test_missing_files_do_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            warnings: list[qg.ParseWarning] = []
            path, items = qg.check_codex_config(Path(tmp), warnings)
            self.assertEqual(items[0].status, "missing_file")
            path2, items2 = qg.check_claude_settings(Path(tmp), warnings)
            self.assertEqual(items2[0].status, "missing_file")
            self.assertTrue(str(path).endswith("config.toml"))
            self.assertTrue(str(path2).endswith("settings.json"))

    def test_cli_check_config_json(self) -> None:
        proc = run_cli(
            [
                "check-config",
                "--claude-root",
                str(CONFIG_CLAUDE),
                "--codex-root",
                str(CONFIG_CODEX),
                "--json",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        memories = next(
            i for i in payload["codex"]["items"] if i["key"] == "[features].memories"
        )
        self.assertIs(memories["value"], True)
        claude_items = payload["claude"][0]["items"]
        prompt = next(i for i in claude_items if i["key"] == "promptSuggestionEnabled")
        self.assertIs(prompt["value"], True)
        self.assertIn("learn.chatgpt.com/docs/customization/memories", memories["docs"])

    def test_check_config_does_not_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "config.toml"
            cfg.write_text("[features]\nmemories = true\n", encoding="utf-8")
            before = cfg.read_bytes()
            mtime = cfg.stat().st_mtime_ns
            run_cli(["check-config", "--codex-root", str(root), "--claude-root", str(root)])
            self.assertEqual(cfg.read_bytes(), before)
            self.assertEqual(cfg.stat().st_mtime_ns, mtime)


class TestCLI(unittest.TestCase):
    def test_version(self) -> None:
        proc = run_cli(["--version"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("0.4.0", proc.stdout)

    def test_default_subcommand_is_scan(self) -> None:
        with_scan = run_cli(
            ["scan", "--claude-root", str(CLAUDE), "--codex-root", str(CODEX), "--json"]
        )
        without = run_cli(
            ["--claude-root", str(CLAUDE), "--codex-root", str(CODEX), "--json"]
        )
        self.assertEqual(with_scan.returncode, 2)
        self.assertEqual(without.returncode, 2)
        self.assertEqual(json.loads(with_scan.stdout)["alerts"], json.loads(without.stdout)["alerts"])

    def test_scan_json_matches_section_81(self) -> None:
        proc = run_cli(
            [
                "scan",
                "--claude-root",
                str(CLAUDE),
                "--codex-root",
                str(CODEX),
                "--idle-seconds",
                "180",
                "--min-severity",
                "low",
                "--json",
                "--no-hash",
                "--no-redact-home",
            ]
        )
        self.assertEqual(proc.returncode, 2, msg=proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        by_id = {a["session_id"]: a for a in payload["alerts"]}
        self.assertEqual(by_id["sess-idle"]["confidence"], "low")
        self.assertEqual(by_id["sess-idle"]["severity"], "low")
        self.assertEqual(by_id["sess-idle"]["idle_tokens"], 750)
        self.assertEqual(by_id["sess-idle"]["idle_cache_read"], 50000)
        self.assertEqual(by_id["sess-codex-idle"]["idle_tokens"], 1100)
        self.assertAlmostEqual(by_id["sess-codex-idle"]["percent_step"], 8.0)
        self.assertEqual(by_id["sess-ghost"]["idle_tokens"], 0)
        self.assertAlmostEqual(by_id["sess-ghost"]["percent_step"], 28.0)
        self.assertEqual({a["session_id"] for a in payload["alerts"]}, {"sess-idle", "sess-codex-idle", "sess-ghost"})

    def test_report_subcommand_writes_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.md"
            proc = run_cli(
                [
                    "report",
                    "--claude-root",
                    str(CLAUDE),
                    "--codex-root",
                    str(CODEX),
                    "--report",
                    str(out),
                ]
            )
            self.assertEqual(proc.returncode, 2, msg=proc.stderr + proc.stdout)
            text = out.read_text(encoding="utf-8")
            self.assertIn("Quota drain evidence report", text)
            self.assertIn("sha256:", text)
            self.assertNotIn("please review this file", text)
            self.assertIn("will not reset", text)
            self.assertIn("Wrote report:", proc.stderr)

    def test_help_lists_subcommands(self) -> None:
        proc = run_cli(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("scan", proc.stdout)
        self.assertIn("check-config", proc.stdout)
        self.assertIn("report", proc.stdout)


if __name__ == "__main__":
    unittest.main()
