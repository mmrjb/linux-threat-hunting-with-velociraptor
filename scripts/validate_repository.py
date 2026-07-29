#!/usr/bin/env python3
"""Validate the public Linux Threat Hunting artifact repository."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sys

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = REPO_ROOT / "artifacts"

DEPENDENCY_RE = re.compile(r"Artifact\.(LTH\.[A-Za-z0-9_.-]+)")
NAMED_SOURCE_RE = re.compile(
    r"""Artifact\.(LTH\.[A-Za-z0-9_.-]+)\s*\(\s*source\s*=\s*["']([^"']+)["']"""
)
IDENTIFIER_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:H|C)\.[A-Z0-9]{8,}(?![A-Za-z0-9])"
)
PRIVATE_KEY_RE = re.compile(
    r"(?m)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*$"
)
CONFIG_SECRET_RE = re.compile(
    r"(?im)^\s*(?:client_private_key|api[_-]?key|token|password|nonce)"
    r"\s*:\s*\S+"
)


def query_is_present(source: object) -> bool:
    if not isinstance(source, dict):
        return False

    query = source.get("query")
    if isinstance(query, str) and query.strip():
        return True

    queries = source.get("queries")
    return (
        isinstance(queries, list)
        and bool(queries)
        and all(isinstance(item, str) and item.strip() for item in queries)
    )


def main() -> int:
    artifact_paths = sorted(ARTIFACT_ROOT.rglob("*.yaml"))
    errors: list[str] = []
    warnings: list[str] = []
    definitions: dict[str, tuple[Path, dict]] = {}
    dependency_count = 0
    dependency_targets: set[str] = set()
    execve_count = 0
    upload_count = 0
    implicit_type_count = 0

    if not artifact_paths:
        print("ERROR: no YAML artifacts found")
        return 1

    for path in artifact_paths:
        relative = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"{relative}: YAML parse error: {exc}")
            continue

        if not isinstance(data, dict):
            errors.append(f"{relative}: top level must be a YAML mapping")
            continue

        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{relative}: missing artifact name")
            continue

        if name in definitions:
            previous = definitions[name][0].relative_to(REPO_ROOT)
            errors.append(f"{relative}: duplicate name {name!r}; first seen in {previous}")
        else:
            definitions[name] = (path, data)

        if path.stem != name:
            errors.append(f"{relative}: filename does not match artifact name {name!r}")

        if not str(data.get("description", "")).strip():
            errors.append(f"{relative}: missing description")

        if not str(data.get("author", "")).strip():
            warnings.append(f"{relative}: author metadata is not set")

        if not str(data.get("type", "")).strip():
            implicit_type_count += 1

        sources = data.get("sources")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{relative}: sources must be a non-empty list")
            sources = []

        source_names = [
            source.get("name")
            for source in sources
            if isinstance(source, dict) and source.get("name")
        ]
        duplicate_sources = [
            source_name
            for source_name, count in Counter(source_names).items()
            if count > 1
        ]
        for source_name in duplicate_sources:
            errors.append(f"{relative}: duplicate source name {source_name!r}")

        if len(sources) > 1 and len(source_names) != len(sources):
            errors.append(f"{relative}: all sources must be named when multiple sources exist")

        for index, source in enumerate(sources, start=1):
            if not query_is_present(source):
                errors.append(f"{relative}: source {index} has no query or legacy queries list")

        if IDENTIFIER_RE.search(text):
            errors.append(f"{relative}: contains a hard-coded Hunt or Client identifier")

        if PRIVATE_KEY_RE.search(text):
            errors.append(f"{relative}: appears to contain private-key material")

        if CONFIG_SECRET_RE.search(text):
            errors.append(f"{relative}: appears to contain a populated secret field")

        if "execve(" in text:
            execve_count += 1

        if "upload(" in text:
            upload_count += 1

    names = set(definitions)

    for name, (path, data) in sorted(definitions.items()):
        relative = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")

        for target in DEPENDENCY_RE.findall(text):
            dependency_count += 1
            dependency_targets.add(target)
            if target not in names:
                errors.append(f"{relative}: unresolved internal dependency {target!r}")

        for target, source_name in NAMED_SOURCE_RE.findall(text):
            if target not in definitions:
                continue

            target_sources = definitions[target][1].get("sources") or []
            target_source_names = {
                source.get("name")
                for source in target_sources
                if isinstance(source, dict) and source.get("name")
            }
            if source_name not in target_source_names:
                errors.append(
                    f"{relative}: {target!r} has no source named {source_name!r}"
                )

    print(f"Artifacts: {len(artifact_paths)}")
    print(f"Unique names: {len(definitions)}")
    print(f"Internal dependency references: {dependency_count}")
    print(f"Distinct internal dependency targets: {len(dependency_targets)}")
    print(f"Implicit artifact types: {implicit_type_count}")
    print(f"Definitions using execve(): {execve_count}")
    print(f"Definitions containing upload(): {upload_count}")
    print(f"Warnings: {len(warnings)}")
    print(f"Errors: {len(errors)}")

    for warning in warnings:
        print(f"WARNING: {warning}")

    for error in errors:
        print(f"ERROR: {error}")

    if errors:
        return 1

    print("Validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
