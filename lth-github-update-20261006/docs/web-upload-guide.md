# Update the existing GitHub repository

This guide applies to `mmrjb/linux-threat-hunting-with-velociraptor`. The October package contains changed/new files only. Existing collector definitions remain in the repository; the reviewed source snapshots did not show collection-code changes. A fresh clone or empty repository is not required for this browser workflow.

## 1. Extract the update package

Extract `lth-github-update-20261006.zip` on your own computer. Open the extracted folder. Its contents must start at the repository root: `README.md`, `notebooks/`, `hunts/`, `docs/`, `scripts/`, `.github/` and `.gitignore`.

Use only these extracted update contents. The inventory/source-review archives and live datastore files are not repository inputs. The upload replaces matching file paths and adds new paths. It does not delete existing artifact definitions.

## 2. Upload the changed files

1. Open [the existing repository](https://github.com/mmrjb/linux-threat-hunting-with-velociraptor).
2. Confirm that you are viewing the default branch and that no competing update has changed the same files since this package was prepared from commit `1237abf067b00abd5041b8fb0f9839490325accd`.
3. Select **Add file → Upload files**.
4. From inside the extracted folder, select all contents and drag them into the uploader. Preserve their relative directory paths; do not upload the ZIP or drag a parent folder that would add an extra path prefix.
5. Confirm paths such as `notebooks/00-master-triage.md`, `hunts/templates/01-system-baseline.vql` and `scripts/validate_repository.py`.
6. Enter the commit message `Update LTH notebooks and add paused hunt templates`.
7. Choose **Create a new branch for this commit and start a pull request**. Use `update/lth-notebooks-hunts` or another unused branch name.
8. Click **Propose changes**.

GitHub supports up to 100 files per browser upload. This package stays below that limit and every file is below the browser size limit. If a branch with that name already exists, use a new name; do not overwrite another update.

## 3. Review and merge

Create the pull request with this title:

```text
Update LTH-00 through LTH-14 and add paused hunt templates
```

Suggested body:

```text
Publish the complete 15-notebook source set and 14 label-scoped hunt creation templates. Update Master Triage and Network Connections, correct LTH-02 coverage sources, and restore public CIDR filter constants. Collector code matches the recovered collection snapshots and is retained.

Validation: 114 unique artifacts, 100 resolved dependency targets, 15 notebooks / 508 ordered cells, and 14 paused hunt templates; zero structural errors or warnings. The generated artifact catalog is unchanged. VQL execution on the intended server remains an operational verification step.
```

Inspect the **Files changed** tab. Confirm that the update contains source/templates/docs, no collected results or server configuration, and no extra parent folder. Wait for **Validate repository** to pass. After reviewing the diff, merge the pull request into the default branch.

## 4. Verify the published structure

Confirm `notebooks/README.md` lists modules 00 through 14; `notebooks/sources/` contains 15 ordered JSON files; `hunts/templates/` contains 14 VQL files; and `hunts/README.md` describes label selection and paused creation. The existing 114 artifact definitions should still be present.

The repository upload does not install code on a Velociraptor server or start hunts. Follow the notebook/hunt setup instructions for operational use.

References: [GitHub file uploads](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository), [GitHub pull requests](https://docs.github.com/en/pull-requests/creating-pull-requests/creating-a-pull-request).
