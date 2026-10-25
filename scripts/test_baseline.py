#!/usr/bin/env python3
"""Run bounded local collector and synthetic Master Triage regression tests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest

from validate_vql import ROOT, prepare_config


class BaselineTests(unittest.TestCase):
    binary: str
    config: Path
    directory: Path

    def query(self, query: str) -> list[dict]:
        result = subprocess.run([
            self.binary, "--config", str(self.config),
            "--definitions", str(ROOT / "artifacts"),
            "query", "--format", "jsonl", query,
        ], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex(result.stderr, r"(?i)\[ERROR\]|symbol .+ not found|while parsing|unexpected token")
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    def cron(self, name: str, source: str | None = "CronTabs", **params) -> list[dict]:
        params = {
            "cronTabGlob": str(self.directory / "cron" / "*"),
            "cronTabScripts": str(self.directory / "scripts" / "*"),
            "SystemCronPathRegex": r"/system-crontab$",
            **params,
        }
        if source:
            params["source"] = source
        arguments = ", ".join(k + "=" + json.dumps(v) for k, v in params.items())
        return self.query(f"SELECT * FROM Artifact.{name}({arguments})")

    def test_system_and_user_cron_keep_commands_and_evidence(self):
        for name in ("LTH.SystemBaseline.Crontab", "LTH.Persistence.Crontab"):
            with self.subTest(artifact=name):
                rows = self.cron(name)
                parsed = [r for r in rows if r["ParseStatus"] == "Parsed"]
                self.assertEqual(len(parsed), 4)
                self.assertEqual(
                    {(r["User"], r["Command"]) for r in parsed},
                    {("root", "/usr/bin/true"),
                     ("daemon", "/usr/bin/printf system-start"),
                     ("analyst", "/usr/bin/printf user-scheduled"),
                     ("analyst", "/usr/bin/printf user-start")},
                )
                self.assertTrue(all(r["RawLine"] and r["ParserVersion"] == 2 for r in rows))
                self.assertEqual(sum(r["ParseStatus"] == "Unparsed" for r in rows), 1)

    def test_upload_is_disabled_when_collecting_all_cron_sources(self):
        for name in ("LTH.SystemBaseline.Crontab", "LTH.Persistence.Crontab"):
            with self.subTest(artifact=name):
                rows = self.cron(name, source=None)
                self.assertTrue(rows)
                self.assertFalse(any("Upload" in r for r in rows))
                self.assertEqual(self.cron(name, source="Uploaded"), [])

    def test_script_truncation_is_reported(self):
        rows = self.cron("LTH.SystemBaseline.Crontab", source="CronScripts", Length=8)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["Content"]), 8)
        self.assertTrue(rows[0]["PotentiallyTruncated"])
        self.assertEqual(rows[0]["ParserVersion"], 2)
        self.assertTrue(rows[0]["Path"])

    def test_baseline_retains_tcp_and_udp_sockets_without_tracker(self):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            udp.bind(("127.0.0.1", 0))
            ports = {tcp.getsockname()[1], udp.getsockname()[1]}
            rows = self.query("SELECT * FROM Artifact.LTH.SystemBaseline.NetstatEnriched()")
            self.assertTrue(ports.issubset({r.get("Lport") for r in rows}), rows)
            excluded = self.query(
                'SELECT * FROM Artifact.LTH.SystemBaseline.NetstatEnriched('
                'ProcessNameRegex="^lth-no-such-process-name$")'
            )
            self.assertFalse(excluded)

    def test_master_triage_keeps_zero_and_critical_scores_distinct(self):
        data = json.loads((ROOT / "notebooks/sources/00-master-triage.json").read_text())
        query = next(c["input"] for c in data["cells"] if c["order"] == 27)
        rows = []

        def row(client, source, **fields):
            rows.append(dict(ClientId=client, Fqdn=client + ".invalid",
                             ArtifactSource="LTH.SystemBaseline/" + source, **fields))

        for client in ("fixture-clean", "fixture-critical", "fixture-missing"):
            row(client, "Client_BasicInformation", Platform="ubuntu", Hostname=client)
        for client in ("fixture-clean", "fixture-critical"):
            row(client, "Users", User="root", Uid="0", Gid="0", Homedir="/root", Shell="/bin/bash")
        # Duplicate evidence must not multiply the per-area risk contribution.
        for _ in range(3):
            row("fixture-critical", "Users", User="extra-admin", Uid="0", Gid="0",
                Homedir="/home/extra-admin", Shell="/bin/bash")
        prefix = (
            "LET FixtureRows <= SELECT * FROM parse_json_array(data="
            + json.dumps(json.dumps(rows)) + ")\n"
            "LET fixture_results(hunt_id, artifact) = "
            "SELECT * FROM FixtureRows WHERE ArtifactSource=artifact\n"
        )
        replaced, count = re.subn(r"\bhunt_results\s*\(", "fixture_results(", query)
        self.assertGreater(count, 0)
        results = {r["ClientId"]: r for r in self.query(prefix + replaced)}
        self.assertEqual(set(results), {"fixture-clean", "fixture-critical", "fixture-missing"})
        self.assertEqual(results["fixture-clean"]["RiskScore"], 0)
        self.assertEqual(results["fixture-critical"]["RiskScore"], 5)
        self.assertEqual(results["fixture-critical"]["RiskLevel"], "High")
        self.assertEqual(results["fixture-missing"]["RiskLevel"], "Collection Review")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lth-test-") as temporary:
        directory = Path(temporary)
        BaselineTests.binary = str(Path(args.binary).resolve())
        BaselineTests.directory = directory
        BaselineTests.config = prepare_config(BaselineTests.binary, directory)
        (directory / "cron").mkdir()
        (directory / "scripts").mkdir()
        (directory / "cron" / "system-crontab").write_text(
            "# comment\nSHELL=/bin/sh\n"
            "* * * * * root /usr/bin/true\n"
            "@reboot daemon /usr/bin/printf system-start\n"
        )
        (directory / "cron" / "analyst").write_text(
            "  # comment\nMAILTO=analyst\n"
            "*/5 * * * * /usr/bin/printf user-scheduled\n"
            "@reboot /usr/bin/printf user-start\n"
            "not a schedule\n"
        )
        (directory / "scripts" / "maintenance").write_text("#!/bin/sh\n/usr/bin/true\n")
        unittest.main(argv=[__file__], verbosity=2)


if __name__ == "__main__":
    main()
