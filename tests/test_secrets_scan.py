#!/usr/bin/env python3
"""Tests for the unreleased secrets / doctor subcommands. Constructed fixtures only."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "secrets"
PY = sys.executable

sys.path.insert(0, str(ROOT))
import secrets_scan  # noqa: E402
import quota_guard as qg  # noqa: E402


LEAKY_RAW_SECRETS = [
    "fake-db-pass-NOTREAL",
    "demo-root-pass-NOTREAL",
    "DemoPass123",
    "ghp_000000000000000000000000000000000000",
    "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "github_pat_11AAAAAAA0000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "sk-proj-EXAMPLEKEY0000000000000000000000000000000000",
    "EXAMPLE_FAKE_LINEAR_API_KEY_NOT_VALID",
    "sk-svcacct-EXAMPLEKEY000000000000000000000000000000",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNOTREAL99",
]

REDACTED_EVIDENCE_RE = re.compile(r"^(?:\*\*\*|\S{2}\*\*\*) \(len=\d+\)$")



def highentropy_raw_secrets() -> list[str]:
    """Read constructed FAKE values from the high-entropy fixture (not hard-coded twice)."""
    settings = json.loads(
        (FIXTURES / "leaky-highentropy" / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )
    blob = "\n".join(settings["permissions"]["allow"])
    values: list[str] = []
    for pat in (
        r"PGPASSWORD=(\S+)",
        r"sshpass\s+-p\s+(\S+)",
        r"mysql(?:\s+\S+)*\s+-p(?![\s\-\"')\]]|$)([^\s\"')\]]{4,})",
        r"Bearer\s+(\S+?)" + r'(?=["\s)])',
    ):
        for m in re.finditer(pat, blob):
            values.append(m.group(1).rstrip('"'))
    plain = (FIXTURES / "leaky-highentropy" / "FAKE-github-pat.txt").read_text(encoding="utf-8")
    for line in plain.splitlines():
        if line.startswith("token="):
            values.append(line.split("=", 1)[1].strip())
    # Unique, drop empties. All values in this fixture are marked FAKE.
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    if len(out) < 2:
        raise RuntimeError("failed to extract FAKE high-entropy fixture values")
    return out


def isolate_fixture(name: str, dest: Path) -> Path:
    """Copy a fixture tree out of this repo so parent-repo git hygiene does not leak into tests."""
    src = FIXTURES / name
    dst = dest / name
    shutil.copytree(src, dst)
    return dst


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PY, str(ROOT / "quota_guard.py"), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def assert_no_raw_secrets(test: unittest.TestCase, text: str, where: str) -> None:
    for secret in LEAKY_RAW_SECRETS:
        test.assertNotIn(secret, text, f"raw secret appeared in {where}")


def assert_evidence_is_tight(test: unittest.TestCase, evidence: str, secret: str) -> None:
    test.assertNotEqual(evidence, secret)
    test.assertNotIn(secret, evidence)
    test.assertRegex(evidence, REDACTED_EVIDENCE_RE)
    if len(secret) > 2:
        test.assertTrue(evidence.startswith(secret[:2] + "***"), evidence)
        test.assertNotIn(secret[2:], evidence)
        test.assertNotIn(secret[-4:] if len(secret) >= 8 else secret[-1], evidence)
    else:
        test.assertTrue(evidence.startswith("***"), evidence)


class SecretsScanTests(unittest.TestCase):
    def test_leaky_project_catches_command_passwords_and_key_formats(self) -> None:
        result = secrets_scan.run_scan(FIXTURES / "leaky")
        rules = {f.rule_id for f in result.findings}
        self.assertIn("pgpassword", rules)
        self.assertIn("sshpass-p", rules)
        self.assertIn("mysql-p", rules)
        self.assertTrue(
            "github-pat" in rules
            or "authorization-bearer" in rules
            or "github-pat+authorization-bearer" in rules
            or "authorization-bearer+github-pat" in rules,
            f"Bearer/GitHub token not flagged: {rules}",
        )
        self.assertTrue(
            any(r in rules or any(r in f.rule_id for f in result.findings) for r in ("anthropic-key", "secret-key-literal")),
            f"Anthropic key not flagged: {rules}",
        )
        self.assertTrue(
            any("github-fine-grained-pat" in f.rule_id or f.rule_id == "secret-key-literal" for f in result.findings),
            f"Fine-grained PAT not flagged: {rules}",
        )
        self.assertTrue(any("linear-key" in f.rule_id or f.rule_id == "secret-key-literal" for f in result.findings))
        self.assertTrue(any(f.rule_id == "aws-secret-assign" for f in result.findings))
        self.assertTrue(any(f.rule_id == "gitignore-missing-settings-local" for f in result.findings))
        secret_findings = [f for f in result.findings if f.category != "git-hygiene"]
        self.assertTrue(secret_findings)
        for f in secret_findings:
            self.assertIsNotNone(f.line)
            self.assertIn("line ", f.location)
            self.assertRegex(f.evidence, REDACTED_EVIDENCE_RE)
            for secret in LEAKY_RAW_SECRETS:
                if secret.startswith(f.evidence[:2]) and "***" in f.evidence:
                    assert_evidence_is_tight(self, f.evidence, secret)
                    break

    def test_clean_project_is_silent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = secrets_scan.run_scan(isolate_fixture("clean", Path(td)))
            self.assertEqual(
                result.findings,
                [],
                f"unexpected findings: {[f.rule_id + ':' + f.evidence for f in result.findings]}",
            )

    def test_false_positives_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = secrets_scan.run_scan(isolate_fixture("false-positives", Path(td)))
            self.assertEqual(
                result.findings,
                [],
                f"false positives: {[f.rule_id + ':' + f.evidence for f in result.findings]}",
            )

    def test_ssh_forward_agent(self) -> None:
        result = secrets_scan.run_scan(
            FIXTURES / "clean",
            ssh_config=FIXTURES / "ssh" / "config",
            skip_git=True,
        )
        fwd = [f for f in result.findings if f.rule_id == "ssh-forward-agent"]
        self.assertEqual(len(fwd), 1)
        self.assertIn("jump.example.internal", fwd[0].location)
        self.assertEqual(fwd[0].evidence, "ForwardAgent yes")
        self.assertEqual(fwd[0].line, 5)

    def test_output_redacts_secrets(self) -> None:
        result = secrets_scan.run_scan(FIXTURES / "leaky")
        payload = json.dumps(secrets_scan.result_to_json(result), ensure_ascii=False)
        md = secrets_scan.render_report_text(result)
        combined = payload + "\n" + md
        assert_no_raw_secrets(self, combined, "json+markdown report")
        self.assertIn("len=", md)
        self.assertIn("redacted", md.lower())
        self.assertIn("line ", md.lower())


    def test_highentropy_fixture_catches_command_passwords_and_redacts(self) -> None:
        raw = highentropy_raw_secrets()
        self.assertTrue(any(v.startswith("ghp_FAKE") and len(v) == 40 for v in raw))
        self.assertTrue(all("FAKE" not in v or v.startswith("ghp_FAKE") for v in raw))
        with tempfile.TemporaryDirectory() as td:
            root = isolate_fixture("leaky-highentropy", Path(td))
            result = secrets_scan.run_scan(root, skip_git=True)
            rules = {f.rule_id for f in result.findings}
            self.assertIn("pgpassword", rules)
            self.assertIn("sshpass-p", rules)
            self.assertIn("mysql-p", rules)
            self.assertTrue(
                any(
                    r == "authorization-bearer"
                    or "authorization-bearer" in r
                    or r == "github-pat"
                    or "github-pat" in r
                    for r in rules
                ),
                f"Bearer/GitHub token not flagged: {rules}",
            )
            payload = json.dumps(secrets_scan.result_to_json(result), ensure_ascii=False)
            md = secrets_scan.render_report_text(result)
            combined = payload + "\n" + md
            for secret in raw:
                self.assertNotIn(secret, combined, "raw high-entropy fixture value appeared in output")
                assert_evidence_is_tight(
                    self,
                    next(
                        f.evidence
                        for f in result.findings
                        if f.evidence.startswith(secret[:2] + "***") or (len(secret) <= 2 and f.evidence.startswith("***"))
                    ),
                    secret,
                )

    def test_redact_never_includes_suffix_or_short_values(self) -> None:
        self.assertEqual(secrets_scan.redact("ab"), "*** (len=2)")
        self.assertEqual(secrets_scan.redact("abc"), "ab*** (len=3)")
        self.assertTrue("xyz" not in secrets_scan.redact("abxyzCD"))
        self.assertNotIn("CD", secrets_scan.redact("abxyzCD"))

    def test_git_tracked_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            claude = repo / ".claude"
            claude.mkdir()
            target = claude / "settings.local.json"
            target.write_text(
                '{"permissions":{"allow":["Bash(PGPASSWORD=temp-git-pass-NOTREAL psql)"]}}\n',
                encoding="utf-8",
            )
            (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.com",
            }
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "add settings"], cwd=repo, check=True, capture_output=True, env=env)
            result = secrets_scan.run_scan(repo)
            rules = {f.rule_id for f in result.findings}
            self.assertIn("pgpassword", rules)
            self.assertIn("agent-config-tracked", rules)
            self.assertIn("gitignore-missing-settings-local", rules)
            public = json.dumps(secrets_scan.result_to_json(result), ensure_ascii=False)
            public += secrets_scan.render_report_text(result)
            self.assertNotIn("temp-git-pass-NOTREAL", public)

            subprocess.run(["git", "rm", "-f", ".claude/settings.local.json"], cwd=repo, check=True, capture_output=True)
            (repo / ".gitignore").write_text("**/.claude/settings.local.json\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitignore"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "remove settings"], cwd=repo, check=True, capture_output=True, env=env)
            result2 = secrets_scan.run_scan(repo)
            rules2 = {f.rule_id for f in result2.findings}
            self.assertIn("agent-config-in-git-history", rules2)
            self.assertNotIn("agent-config-tracked", rules2)

    def test_cli_prints_gitignore_and_hook(self) -> None:
        gi = run_cli(["secrets", "--print-gitignore"])
        self.assertEqual(gi.returncode, 0)
        self.assertIn("settings.local.json", gi.stdout)
        hook = run_cli(["secrets", "--print-hook"])
        self.assertEqual(hook.returncode, 0)
        self.assertIn("pre-commit", hook.stdout)
        self.assertIn("quota-guard secrets", hook.stdout)
        self.assertNotIn("demo-root-pass-NOTREAL", hook.stdout)
        for secret in LEAKY_RAW_SECRETS:
            self.assertNotIn(secret, gi.stdout + hook.stdout)


class SecretsCliTests(unittest.TestCase):
    def test_secrets_cli_redacts_and_flags_leaky_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "secrets.md"
            proc = run_cli(
                [
                    "secrets",
                    "--root",
                    str(FIXTURES / "leaky"),
                    "--report",
                    str(report),
                    "--json",
                ]
            )
            self.assertEqual(proc.returncode, 2)
            payload = json.loads(proc.stdout)
            rules = {f["rule_id"] for f in payload["findings"]}
            self.assertIn("pgpassword", rules)
            self.assertIn("sshpass-p", rules)
            self.assertIn("mysql-p", rules)
            md = report.read_text(encoding="utf-8")
            assert_no_raw_secrets(self, proc.stdout + proc.stderr + md, "secrets CLI output")
            self.assertIn("line ", md)


    def test_secrets_cli_highentropy_redacts(self) -> None:
        raw = highentropy_raw_secrets()
        proc = run_cli(
            [
                "secrets",
                "--root",
                str(FIXTURES / "leaky-highentropy"),
                "--skip-git",
                "--json",
            ]
        )
        self.assertEqual(proc.returncode, 2)
        payload = json.loads(proc.stdout)
        rules = {f["rule_id"] for f in payload["findings"]}
        self.assertIn("pgpassword", rules)
        self.assertIn("sshpass-p", rules)
        self.assertIn("mysql-p", rules)
        self.assertTrue(
            any("authorization-bearer" in r or "github-pat" in r for r in rules),
            f"Bearer/GitHub token not flagged: {rules}",
        )
        combined = proc.stdout + proc.stderr
        for secret in raw:
            self.assertNotIn(secret, combined, "raw high-entropy fixture value appeared in CLI output")

    def test_usage_is_alias_of_scan(self) -> None:
        common = [
            "--claude-root",
            str(ROOT / "fixtures" / "claude"),
            "--codex-root",
            str(ROOT / "fixtures" / "codex"),
            "--idle-seconds",
            "180",
            "--json",
        ]
        scan = run_cli(["scan", *common])
        usage = run_cli(["usage", *common])
        self.assertEqual(scan.returncode, usage.returncode)
        self.assertEqual(json.loads(scan.stdout)["summary"], json.loads(usage.stdout)["summary"])
        self.assertEqual(json.loads(scan.stdout)["alerts"], json.loads(usage.stdout)["alerts"])

    def test_doctor_combines_usage_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "doctor.md"
            proc = run_cli(
                [
                    "doctor",
                    "--claude-root",
                    str(ROOT / "fixtures" / "claude"),
                    "--codex-root",
                    str(ROOT / "fixtures" / "codex"),
                    "--idle-seconds",
                    "180",
                    "--root",
                    str(FIXTURES / "leaky"),
                    "--ssh-config",
                    str(FIXTURES / "ssh" / "config"),
                    "--report",
                    str(report),
                    "--json",
                ]
            )
            self.assertEqual(proc.returncode, 2)
            payload = json.loads(proc.stdout)
            self.assertIn("usage", payload)
            self.assertIn("secrets", payload)
            self.assertGreaterEqual(len(payload["usage"]["alerts"]), 1)
            rules = {f["rule_id"] for f in payload["secrets"]["findings"]}
            self.assertIn("pgpassword", rules)
            self.assertIn("ssh-forward-agent", rules)
            md = report.read_text(encoding="utf-8")
            self.assertIn("doctor report", md.lower())
            self.assertIn("idle", md.lower())
            self.assertIn("ssh-forward-agent", md)
            assert_no_raw_secrets(self, proc.stdout + proc.stderr + md, "doctor output")

    def test_existing_scan_subcommand_still_default(self) -> None:
        proc = run_cli(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("scan", proc.stdout)
        self.assertIn("secrets", proc.stdout)
        self.assertIn("doctor", proc.stdout)


class NormalizeArgvTests(unittest.TestCase):
    def test_known_commands_are_preserved(self) -> None:
        for cmd in ("scan", "usage", "report", "check-config", "secrets", "doctor"):
            self.assertEqual(qg.normalize_argv([cmd, "--json"]), [cmd, "--json"])

    def test_bare_flag_still_defaults_to_scan(self) -> None:
        self.assertEqual(qg.normalize_argv(["--json"]), ["scan", "--json"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
