# Uploading to GitHub from a Web Browser

No Git installation is required.

Two upload batches are provided with the release because GitHub's browser uploader limits the number of files per upload. The batches preserve the final repository paths and remain below that limit.

## 1. Create an empty repository

Create a new GitHub repository:

```text
linux-threat-hunting-with-velociraptor
```

Recommended initial visibility:

```text
Private
```

Do not initialize it with a README, `.gitignore`, or license.

## 2. Upload batch 1

Extract:

```text
github-upload-batch-01.zip
```

Open the extracted `github-upload-batch-01` folder, select all of its contents, and drag them into:

```text
Add file → Upload files
```

Use this commit message:

```text
Add framework, documentation, and artifact domains 01-07
```

Commit directly to `main`.

## 3. Upload batch 2

Extract:

```text
github-upload-batch-02.zip
```

Select all contents of the extracted `github-upload-batch-02` folder and upload them at the repository root. GitHub will merge the additional subdirectories into `artifacts/`.

Use this commit message:

```text
Add artifact domains 08-14
```

Commit directly to `main`.

## 4. Confirm repository structure

At the repository root, confirm:

```text
README.md
LICENSE
NOTICE
SECURITY.md
CHANGELOG.md
CONTRIBUTING.md
artifacts/
docs/
notebooks/
scripts/
.github/
```

Inside `artifacts/`, confirm all directories `01-...` through `14-...` are present.

## 5. Confirm automated validation

Open the repository's **Actions** tab and confirm that **Validate artifacts** completes successfully.

If the workflow does not appear, confirm that this file exists:

```text
.github/workflows/validate.yml
```

## 6. Review before making the repository public

Search the repository for:

```text
H.
C.
password
token
private_key
BEGIN
```

The documented detection strings in `LTH.AuthSSH.PrivateKeys` are expected. Investigate any other result.

Also review:

- author and profile details;
- screenshots and image metadata;
- organization or customer names;
- internal IP addresses and hostnames;
- raw results or exported evidence.

When the review and Actions workflow are clean, change visibility from Private to Public.

