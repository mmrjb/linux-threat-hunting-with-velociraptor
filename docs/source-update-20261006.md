# Source review and October 2026 update

## Reviewed inputs

The source-only notebook export covered LTH-00 through LTH-14, with 508 ordered cells (242 VQL and 266 Markdown). Hunt metadata covered 37 stopped LTH hunts and 14 collection wrappers. The artifact source review contained 100 unique cached dependency definitions with one observed variant per name, no redactions and no read errors. It did not contain original raw YAML or currently stored LTH YAML files.

## Collector comparison

The 100 cached dependency definitions matched the existing repository in VQL query tokens, exports, source names/preconditions and parameter names/defaults/types after normalizing layout, comments and keyword case. The 37 compiled wrapper snapshots also matched the repository wrapper collection calls and source sets. Descriptions and parameter choice metadata omitted from cached payloads were preserved from the repository. No collector code was replaced solely because a compiled payload used different formatting.

This comparison is a source consistency check, not an execution test or proof that all current server-side edits were recovered. Cached definitions describe the available collection snapshots. No live custom LTH YAML definitions were present in the supplied source bundle.

## Changes

- Update Master Triage from 10 to 16 VQL cells and Network Connections from 7 to 16 VQL cells.
- Add the remaining 13 dashboards and ordered source JSON for all 15 notebooks.
- Restore 20 occurrences of public special-purpose network CIDRs masked in the intermediate notebook review export.
- Correct the LTH-02 coverage cell to use Users, Groups and SudoersRules from the identity hunt and a separate baseline hunt for its fleet anchor.
- Add 14 label-scoped VQL hunt templates that create fresh paused hunts, with a fresh expiry and reviewed historical resource limits.
- Extend repository validation to notebook source references, cell order, JSON/Markdown consistency, public identifiers and paused hunt templates.

## Validation boundary

Repository validation checks structural consistency and common accidental disclosure patterns. It does not execute VQL, collect endpoints or prove detection accuracy. In particular, the corrected LTH-02 cell and new creation templates require evaluation in the intended Velociraptor version with scoped test data before operational use. Existing artifact definitions should also be checked using `velociraptor artifacts verify` with all repository definitions loaded.

No production result tables, screenshots, client records, server configuration, credentials, hunt IDs, scope-label values or compiled obfuscated query names were added to this update.
