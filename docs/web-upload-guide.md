# Update the existing GitHub repository

The October 25 maintenance update integrates the recovered notebook and hunt
sources at the repository root. The duplicate update-package directory is
removed, and baseline VQL corrections are included in the canonical files.

## Get the complete current source

```bash
git clone https://github.com/mmrjb/linux-threat-hunting-with-velociraptor.git
cd linux-threat-hunting-with-velociraptor
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
```

For an existing clean checkout on main:

```bash
git status --short
git switch main
git pull --ff-only
python3 scripts/validate_repository.py
```

Review and commit any local edits before updating. Do not copy an extracted
parent package folder into the repository. Future updates should change the
canonical artifact, notebook, hunt and documentation paths on a branch and
use a pull request with the validation workflow.

## Verify the complete structure

- artifacts/01-system-baseline/: ten definitions including the wrapper.
- notebooks/: LTH-00 through LTH-14 and a catalog.
- notebooks/sources/: fifteen ordered source JSON files.
- hunts/templates/: fourteen paused, label-scoped creation templates.
- No lth-github-update-20261006 directory.

Native VQL and behavioral checks run in CI. They can also be run locally with
a Velociraptor binary:

```bash
python3 scripts/validate_vql.py --binary /usr/local/bin/velociraptor
python3 scripts/test_baseline.py --binary /usr/local/bin/velociraptor
```

Review [the validation report](validation-report.md) for the completed checks
and their limits. The GitHub update does not import artifacts into a running
server or start a hunt. Use the canary steps in
[Baseline and Master Triage](baseline-and-triage.md) after import.
