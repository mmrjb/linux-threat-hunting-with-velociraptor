# Validation report

Date: 2026-10-25. Verified engine: Velociraptor 0.76.5, Linux amd64,
commit a58cde830. The official binary is pinned by SHA-256 in CI.

## Repository structure

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

Structural validation covers YAML, artifact/source names and references,
notebook JSON/Markdown consistency and order, public identifiers, dependency
resolution, paused label-guarded hunt templates, conflicting precondition
levels and accidentally nested update directories.

All fifteen recovered notebook source JSON files and fourteen hunt templates
were retained byte for byte while moving the update into the repository root.
The two previously published root notebook documents were replaced by their
complete recovered versions. The generated artifact catalog was refreshed.
The prepared patch was also applied to a fresh checkout and its resulting
Git tree matched the reviewed tree exactly.

## Native VQL verification: passed

Successful [GitHub Actions run](https://github.com/mmrjb/linux-threat-hunting-with-velociraptor/actions/runs/40223195727)
for source commit `37c0a7fc5acd3607954ee20d481efa11b172fad1`.

| Native verifier input | Passed |
| --- | ---: |
| Collector definitions | 114 |
| Notebook VQL cells | 242 |
| Hunt templates | 14 |
| Extracted report queries | 11 |
| Total artifact inputs | 381 |

The verification helper wraps notebook/hunt/report VQL in temporary artifacts
and uses the engine's static verifier. It does not execute operational hunts
or collect endpoints. The workflow also checks the generated catalog against
the committed version.

## Behavioral regressions: 5 passed

The same CI run executed all five tests with Velociraptor 0.76.5:

- System/user cron parsing preserves all four fixture commands, including
  regular and @reboot schedules, and retains the unparsed line and parser metadata.
- Both cron collectors return no upload rows by default, including when called
  directly for all sources; explicit source preconditions alone are insufficient
  because VQL callers can bypass them. The acquisition query has its own opt-in gate.
- Script content is bounded and truncation metadata is returned.
- Local TCP/UDP fixture sockets remain visible without a configured process
  tracker; an explicit nonmatching process filter excludes them.
- Master Triage separates zero score, a critical UID-0 score of five and missing
  collection data; repeated account evidence does not multiply its area score.

These tests use temporary fixture files, local test sockets and synthetic
hunt-result rows. They do not use production evidence or a deployed server.

## Reproduce

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
python3 scripts/generate_artifact_catalog.py
python3 scripts/validate_vql.py --binary /usr/local/bin/velociraptor
python3 scripts/test_baseline.py --binary /usr/local/bin/velociraptor
```

The helper selects the supported verifier command and uses temporary local
configuration. CI downloads the official pinned binary and checks its digest.

## Operational limits

No production endpoint or deployed Velociraptor service was changed. Complete
an endpoint canary test before fleet deployment, including distro-specific
package and service collection. Old hunts remain historical snapshots and
need fresh collection to use corrected parser/network/service behavior.
Row presence does not establish complete collection; scores do not establish
compromise. Pattern-based disclosure checks do not replace content review.
See [Baseline and Master Triage](baseline-and-triage.md).

The previous source comparison is recorded in
[Source review and October 2026 update](source-update-20261006.md).
