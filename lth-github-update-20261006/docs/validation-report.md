# Validation report

Date: 2026-10-06. Reviewed Velociraptor source version: 0.76.5.

## Structural results

| Check | Result |
| --- | ---: |
| Artifact definitions | 114 |
| Unique artifact names | 114 |
| Internal dependency references | 156 |
| Distinct resolved dependency targets | 100 |
| Implicit artifact types | 30 |
| Definitions using `execve()` | 39 |
| Definitions containing `upload()` | 8 |
| Notebook source templates | 15 |
| Ordered notebook cells | 508 |
| VQL / Markdown cells | 242 / 266 |
| Paused hunt creation templates | 14 |
| Warnings / errors | 0 / 0 |

The validator checks YAML parsing, artifact and source names, filenames, duplicate sources, dependency resolution, named-source calls and common accidental disclosure patterns. It also verifies ordered notebook inputs, matching Markdown/JSON sources, quoted notebook artifact/source references, hunt profile/template consistency and explicit paused creation with a scope-label guard.

## Additional checks

- The existing generated artifact catalog remains unchanged.
- All 20 masked public CIDR occurrences in the review copy were restored using the separately supplied inventory.
- LTH-02 identity coverage now uses the documented identity-wrapper sources and a separate baseline ID for its fleet anchor.
- The identifier check includes lowercase client IDs. Regression probes confirmed rejection of a synthetic hard-coded client ID, an unresolved notebook source and a hunt template changed to active creation.
- One hundred cached dependency snapshots and 37 wrapper snapshots were compared with the existing collector code. See [the update record](source-update-20261006.md) for provenance and comparison limits.

## Limits

This is structural/source validation. VQL was not executed against endpoints or the user's server in this preparation environment. The corrected identity coverage cell and hunt creation templates need evaluation in the intended version before operational use. Row-presence metrics do not establish complete collection; risk scores do not establish compromise. Pattern-based disclosure checks do not replace review of source content.

Reproduce the structural check with:

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
python3 scripts/generate_artifact_catalog.py
```
