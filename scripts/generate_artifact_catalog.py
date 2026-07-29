#!/usr/bin/env python3
"""Generate docs/artifact-catalog.md from artifact YAML metadata."""

from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = REPO_ROOT / "artifacts"
OUTPUT_PATH = REPO_ROOT / "docs" / "artifact-catalog.md"

GROUP_TITLES = {
    "01-system-baseline": "System Baseline",
    "02-users-privileges": "Users, Groups & Privileges",
    "03-auth-ssh": "Authentication & SSH",
    "04-process-services": "Processes & Services",
    "05-network-connections": "Network Connections",
    "06-persistence": "Persistence",
    "07-file-timeline": "File Timeline",
    "08-log-security-events": "Logs & Security Events",
    "09-privilege-escalation": "Privilege Escalation",
    "10-rootkit-kernel": "Rootkit & Kernel",
    "11-malware-tools": "Malware & Suspicious Tools",
    "12-container-cloud": "Containers & Cloud",
    "13-data-access-exfiltration": "Data Access & Exfiltration",
    "14-configuration-secrets": "Configuration & Secrets",
}


def summary(value: object) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    if not lines:
        return "No description provided."
    return lines[0].replace("|", r"\|")


def main() -> None:
    groups: dict[str, list[tuple[Path, dict]]] = {}

    for path in sorted(ARTIFACT_ROOT.rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        groups.setdefault(path.parent.name, []).append((path, data))

    total = sum(len(items) for items in groups.values())
    lines = [
        "# Artifact Catalog",
        "",
        f"This catalog contains {total} artifact definitions across {len(groups)} domains.",
        "",
        "It is generated from the YAML metadata. Run "
        "`python3 scripts/generate_artifact_catalog.py` after changing an artifact.",
        "",
    ]

    for group_name, items in sorted(groups.items()):
        title = GROUP_TITLES.get(
            group_name,
            group_name.split("-", 1)[1].replace("-", " ").title(),
        )
        lines.extend(
            [
                f"## {group_name.split('-', 1)[0]}. {title}",
                "",
                "| Artifact | Type | Sources | Summary |",
                "| --- | --- | ---: | --- |",
            ]
        )

        for path, data in sorted(items, key=lambda item: item[1]["name"]):
            relative_link = "../" + path.relative_to(REPO_ROOT).as_posix()
            artifact_type = data.get("type") or "CLIENT (implicit)"
            source_count = len(data.get("sources") or [])
            lines.append(
                f"| [`{data['name']}`]({relative_link}) | "
                f"`{artifact_type}` | {source_count} | "
                f"{summary(data.get('description'))} |"
            )

        lines.append("")

    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
