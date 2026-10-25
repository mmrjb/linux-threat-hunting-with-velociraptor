#!/usr/bin/env python3
"""Statically verify all collectors and public VQL inputs with Velociraptor.

Notebook and hunt queries are wrapped in temporary SERVER artifacts and verified,
never executed. Report queries are also extracted so template quoting is checked.
No connection to a deployed Velociraptor server or endpoint is required.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]


def prepare_config(binary: str, directory: Path) -> Path:
    generated = subprocess.run(
        [binary, "config", "generate"], check=True, capture_output=True, text=True
    )
    data = yaml.safe_load(generated.stdout)
    data.setdefault("Datastore", {}).update(
        location=str(directory / "datastore"),
        filestore_directory=str(directory / "filestore"),
    )
    data.setdefault("Logging", {})["output_directory"] = str(directory / "logs")
    config = directory / "server.config.yaml"
    config.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return config


def verify_command(binary: str) -> list[str]:
    # Older 0.76 builds expose the same verifier as the top-level "verify".
    for command in (["artifacts", "verify"], ["verify"]):
        result = subprocess.run(
            [binary, *command, "--help"], capture_output=True, text=True
        )
        if result.returncode == 0:
            return command
    raise RuntimeError("Velociraptor does not expose an artifact verifier")


def report_queries(data: dict):
    for report in data.get("reports", []):
        template = report.get("template", "")
        for match in re.finditer(
            r'{{\s*define\s+"[^"]+"\s*}}(.*?){{\s*end\s*}}',
            template, re.DOTALL,
        ):
            query = match.group(1).strip()
            if re.match(r"(?:SELECT|LET)\b", query, re.I):
                yield query
        for literal in re.findall(r'\bQuery\s+("(?:[^"\\]|\\.)*")', template):
            query = json.loads(literal)
            if re.match(r"(?:SELECT|LET)\b", query, re.I):
                yield query


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="lth-vql-") as temporary:
        directory = Path(temporary)
        config = prepare_config(binary, directory)
        paths = sorted((ROOT / "artifacts").rglob("*.yaml"))
        counts = {"collectors": len(paths), "notebook_cells": 0, "hunts": 0, "report_queries": 0}

        def add(name: str, query: str, kind: str) -> None:
            path = directory / (name + ".yaml")
            path.write_text(yaml.safe_dump({
                "name": "LTH.Validation." + name,
                "type": "SERVER",
                "sources": [{"query": query}],
            }, sort_keys=False), encoding="utf-8")
            paths.append(path)
            counts[kind] += 1

        for path in sorted((ROOT / "notebooks" / "sources").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for cell in data["cells"]:
                if cell["type"] == "vql":
                    add(f"N{data['module']:02d}.Cell{cell['order']:03d}", cell["input"], "notebook_cells")
        for number, path in enumerate(sorted((ROOT / "hunts" / "templates").glob("*.vql")), 1):
            add(f"Hunt{number:02d}", path.read_text(encoding="utf-8"), "hunts")
        for path in sorted((ROOT / "artifacts").rglob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for number, query in enumerate(report_queries(data), 1):
                add(data["name"] + f".Report{number}", query, "report_queries")
        print("VQL validation scope:", json.dumps(counts, sort_keys=True), flush=True)
        result = subprocess.run(
            [binary, "--config", str(config), *verify_command(binary), *map(str, paths)],
            cwd=ROOT, text=True, capture_output=True,
        )
        # Keep diagnostics available, including warnings from successful checks.
        print(result.stdout, end="")
        print(result.stderr, end="")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
