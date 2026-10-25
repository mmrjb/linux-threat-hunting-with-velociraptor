# Apply a repository repair without an extra parent folder

The October 6 update was uploaded under an extra parent directory, so the
repository root retained old notebooks and validation. The October 25 repair
moves the recovered files into their documented paths, removes the duplicate
package directory and corrects baseline VQL. Use the Git patch workflow for
this repair because it includes file moves and deletions as well as additions.

## Apply the prepared patch

Start from a clean checkout of the existing repository. The patch was prepared
against main commit `a1ca49d2468567bc8f0161d7122356134580c1ac`. If main changed,
review and resolve the differences; do not force the patch.

```bash
git clone https://github.com/mmrjb/linux-threat-hunting-with-velociraptor.git
cd linux-threat-hunting-with-velociraptor
git status --short
git switch -c fix/repository-baseline-20261025
git apply --check /path/to/LTH-Repair.patch
git apply /path/to/LTH-Repair.patch
```

Use a different unused branch name if needed. Replace the patch path with its
location after extracting the repair archive. Do not copy the repair archive
or its parent directory into the repository.

## Validate and publish

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
python3 scripts/generate_artifact_catalog.py
python3 scripts/validate_vql.py --binary /usr/local/bin/velociraptor
python3 scripts/test_baseline.py --binary /usr/local/bin/velociraptor
git diff --check
git diff --stat
git add -A
git commit -m "fix: integrate complete notebooks and correct Linux baseline"
git push -u origin fix/repository-baseline-20261025
```

Open a pull request to main and wait for the complete validation workflow.
Native verification and the regression suite were prepared but could not run
in the preparation environment; resolve any failures before merging. Review
[the validation report](validation-report.md) for the exact verification scope.

## Confirm the structure

- `artifacts/01-system-baseline/`: ten definitions including the wrapper.
- `notebooks/`: LTH-00 through LTH-14 and a catalog.
- `notebooks/sources/`: fifteen ordered source JSON files.
- `hunts/templates/`: fourteen paused, label-scoped creation templates.
- No `lth-github-update-20261006/` directory.

The GitHub update does not import artifacts into a running server or start a
hunt. Use the canary steps in [Baseline and Master Triage](baseline-and-triage.md)
after the repository changes pass validation.
