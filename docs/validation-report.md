# Validation report

Date: 2026-10-25. Compatibility target: Velociraptor 0.76.5.

## Checks completed in the preparation environment

| Check | Result |
| --- | ---: |
| Artifact definitions / unique names | 114 / 114 |
| Internal dependency references / distinct resolved targets | 156 / 100 |
| Baseline definitions / wrapper result sources | 10 / 10 |
| Implicit artifact types | 28 |
| Definitions using execve() / containing upload() | 39 / 8 |
| Notebook source templates | 15 |
| Ordered notebook cells | 508 |
| VQL / Markdown cells | 242 / 266 |
| Paused hunt creation templates | 14 |
| Structural warnings / errors | 0 / 0 |
| VQL snippets checked for balanced quotes, comments and delimiters | 853 |
| Lexical failures / possible multi-field ORDER BY occurrences | 0 / 0 |

Structural validation covers YAML, artifact/source names and references,
notebook JSON/Markdown consistency and order, public identifiers, dependency
resolution and paused, label-guarded hunt templates. The independent lexical
review included artifact queries, legacy query lists, preconditions, exports,
report queries, notebook cells and hunt templates. It is not a VQL compiler.

All fifteen recovered notebook source JSON files and fourteen hunt templates
were retained byte for byte while moving the update into the repository root.
The two previously published root notebook documents were replaced by their
complete recovered versions. The generated artifact catalog was refreshed.

## Native verification and regression checks prepared

The CI workflow downloads the official Velociraptor 0.76.5 Linux binary and
checks its published SHA-256 before use. The verification helper wraps
operational VQL in temporary artifacts for static verification; it does not
execute hunt creation or endpoint collection.

Configured verification scope: 114 collectors, 242 notebook VQL cells,
14 hunt templates and 11 extracted report queries (381 artifact inputs).

The five regression tests cover:

- System/user cron parsing, complete commands and preserved unparsed evidence.
- Upload disabled when collecting every cron source, including both collectors.
- Bounded script content and truncation metadata.
- Local TCP/UDP socket visibility without a configured process tracker.
- Zero-risk versus critical UID-0 priority, missing collection data and evidence deduplication in Master Triage.

These native checks were NOT executed in this preparation environment: the
Velociraptor binary is unavailable locally, its direct download is blocked by
the network proxy, and the GitHub connection rejected branch creation with
HTTP 403. Git push also lacks write authentication. No CI run or successful
publication is claimed for these changes.

Run the checks after applying the patch in an environment with the binary:

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
python3 scripts/generate_artifact_catalog.py
python3 scripts/validate_vql.py --binary /usr/local/bin/velociraptor
python3 scripts/test_baseline.py --binary /usr/local/bin/velociraptor
```

## Operational limits

No production endpoint or deployed Velociraptor service was changed. Complete
an endpoint canary test before fleet deployment. Old hunts remain historical
snapshots and need fresh collection to use corrected parser/network/service
behavior. Row presence does not establish complete collection; scores do not
establish compromise. Pattern-based disclosure checks do not replace content
review. See [Baseline and Master Triage](baseline-and-triage.md).

The previous source comparison is recorded in
[Source review and October 2026 update](source-update-20261006.md).
