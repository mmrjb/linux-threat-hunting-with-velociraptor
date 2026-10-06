#!/usr/bin/env python3
"""Validate the public Linux Threat Hunting artifact repository."""

from __future__ import annotations

from collections import Counter
import json
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
    r"(?<![A-Za-z0-9])(?:H|C|N|NC)\.[A-Za-z0-9]{8,}(?![A-Za-z0-9])"
)
PRIVATE_KEY_RE = re.compile(
    r"(?m)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*$"
)
CONFIG_SECRET_RE = re.compile(
    r"(?im)^\s*(?:client_private_key|api[_-]?key|token|password|nonce)"
    r"\s*:\s*\S+"
)
NOTEBOOK_REF_RE = re.compile(r'''["'](LTH\.[A-Za-z0-9_.]+)(?:/([A-Za-z0-9_]+))?["']''')


def public_source_checks(relative: Path, text: str, errors: list[str]) -> None:
    if IDENTIFIER_RE.search(text):
        errors.append(f"{relative}: contains a hard-coded Hunt, Client or Notebook identifier")
    if PRIVATE_KEY_RE.search(text):
        errors.append(f"{relative}: appears to contain private-key material")


def render_notebook(data: dict) -> str:
    lines = ["# " + data["name"], "",
             "Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.", ""]
    for cell in data["cells"]:
        lines += [f"## Cell {cell['order']} ({cell['type']})", ""]
        if cell["type"] == "vql":
            fence = "`" * max(3, max((len(m) + 1 for m in re.findall(r"`+", cell["input"])), default=3))
            lines += [fence + "vql", cell["input"], fence, ""]
        else:
            lines += [cell["input"], ""]
    return "\n".join(lines)


def validate_notebooks(definitions: dict, errors: list[str]) -> tuple[int, int]:
    root = REPO_ROOT / "notebooks"
    paths = sorted((root / "sources").glob("*.json"))
    modules = []
    cell_count = 0
    for path in paths:
        relative = path.relative_to(REPO_ROOT)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cells = data["cells"]
            module = data["module"]
            if not isinstance(module, int) or isinstance(module, bool):
                raise ValueError("module must be an integer")
            modules.append(module)
            if not isinstance(cells, list) or not cells:
                raise ValueError("cells must be a non-empty list")
            if [c.get("order") for c in cells] != list(range(1, len(cells) + 1)):
                raise ValueError("cell order must be contiguous starting at 1")
            if not isinstance(data.get("name"), str) or not data["name"]:
                raise ValueError("name must be a non-empty string")
            for cell in cells:
                if set(cell) != {"order", "type", "input"}:
                    raise ValueError("source cells may contain only order/type/input")
                if cell["type"] not in ("vql", "markdown") or not isinstance(cell["input"], str):
                    raise ValueError("invalid cell type or input")
                public_source_checks(relative, cell["input"], errors)
                if cell["type"] == "vql":
                    for artifact, source in NOTEBOOK_REF_RE.findall(cell["input"]):
                        if artifact not in definitions:
                            errors.append(f"{relative} cell {cell['order']}: unresolved artifact {artifact!r}")
                        elif source and source not in {s.get("name") for s in definitions[artifact][1].get("sources", [])}:
                            errors.append(f"{relative} cell {cell['order']}: unresolved source {artifact + '/' + source!r}")
            markdown = root / path.with_suffix(".md").name
            if not markdown.is_file() or markdown.read_text(encoding="utf-8") != render_notebook(data):
                errors.append(f"{relative}: companion Markdown does not match ordered source cells")
            cell_count += len(cells)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{relative}: invalid notebook source: {exc}")
    if sorted(modules) != list(range(15)):
        errors.append("notebooks/sources: expected exactly one notebook for each module 00 through 14")
    return len(paths), cell_count


def validate_hunts(definitions: dict, errors: list[str]) -> int:
    root = REPO_ROOT / "hunts"
    templates = sorted((root / "templates").glob("*.vql"))
    for path in templates:
        relative = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        public_source_checks(relative, text, errors)
        code = re.sub(r"--[^\n]*", "", text)
        if re.findall(r"\bpause\s*=\s*(TRUE|FALSE)", code) != ["TRUE"]:
            errors.append(f"{relative}: must create a paused hunt explicitly")
        if 'TargetLabel != "SET_TARGET_LABEL"' not in code or 'TargetLabel != ""' not in code:
            errors.append(f"{relative}: missing target-label placeholder/empty guard")
        if 'include_labels=[TargetLabel]' not in code or not re.search(r"FROM\s+if\s*\(", code):
            errors.append(f"{relative}: target label must gate hunt creation")
        artifacts = re.findall(r'''artifacts=\["(LTH\.[A-Za-z0-9_.]+)"\]''', code)
        if len(artifacts) != 1 or artifacts[0] not in definitions:
            errors.append(f"{relative}: missing or unresolved collection wrapper")
    try:
        catalog = json.loads((root / "profiles.json").read_text(encoding="utf-8"))
        profiles = catalog["profiles"]
        if sorted(p["module"] for p in profiles) != list(range(1, 15)):
            errors.append("hunts/profiles.json: expected modules 01 through 14")
        expected = set()
        for profile in profiles:
            path = root / profile["template"]
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("template path escapes hunts directory")
            expected.add(path)
            if profile["initial_state"] != "PAUSED" or profile["target_label"] != "SET_TARGET_LABEL":
                errors.append(f"hunts/profiles.json: module {profile['module']} must be paused with a scope placeholder")
            if not path.is_file() or f'artifacts=["{profile["artifact"]}"]' not in path.read_text():
                errors.append(f"hunts/profiles.json: module {profile['module']} template/collection mismatch")
        if expected != set(templates):
            errors.append("hunts/profiles.json: catalog and template files differ")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"hunts/profiles.json: invalid catalog: {exc}")
    if len(templates) != 14:
        errors.append("hunts/templates: expected 14 creation templates")
    return len(templates)


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

    notebook_count, notebook_cells = validate_notebooks(definitions, errors)
    hunt_count = validate_hunts(definitions, errors)

    print(f"Artifacts: {len(artifact_paths)}")
    print(f"Unique names: {len(definitions)}")
    print(f"Internal dependency references: {dependency_count}")
    print(f"Distinct internal dependency targets: {len(dependency_targets)}")
    print(f"Implicit artifact types: {implicit_type_count}")
    print(f"Definitions using execve(): {execve_count}")
    print(f"Definitions containing upload(): {upload_count}")
    print(f"Notebook templates: {notebook_count}")
    print(f"Ordered notebook cells: {notebook_cells}")
    print(f"Paused hunt templates: {hunt_count}")
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
