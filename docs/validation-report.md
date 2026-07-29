# Validation Report

## Scope

| Item | Value |
| --- | --- |
| Source archive | `linux-threat-hunting-with-velociraptor-20260729-152520.tar.gz` |
| Source SHA-256 | `19b898b509f525fe76ca2e5e0a947c0d580b0fbff742c4ebd15203d59d5fbf95` |
| Validation date | 2026-07-29 |
| Exporting Velociraptor version | `0.76.5` |
| Artifact definitions | 114 |

## Results

| Check | Result |
| --- | ---: |
| Safe archive paths | Pass |
| YAML files parsed | 114 / 114 |
| Unique artifact names | 114 / 114 |
| Filename-to-name matches | 114 / 114 |
| Duplicate source names | 0 |
| Multi-source artifacts with unnamed sources | 0 |
| Distinct internal `LTH.*` dependency targets resolved | 100 / 100 |
| Total internal dependency references resolved | 156 / 156 |
| Invalid named-source references | 0 |
| Hard-coded Hunt IDs | 0 |
| Hard-coded Client IDs | 0 |
| Embedded private-key material | 0 |
| Hard-coded IP addresses or email addresses | 0 |

Three strings matching private-key headers are intentional detection signatures inside `LTH.AuthSSH.PrivateKeys`; they are not key material.

## Schema observations

- 84 definitions explicitly declare `type: CLIENT`.
- 30 exported definitions use the artifact type implicitly.
- Three service artifacts use the supported legacy `queries` list rather than a singular `query` field.

These observations are warnings for maintainability, not YAML or dependency failures. The repository preserves the exported artifact code to avoid changing working collection logic without a live retest.

## Behavioral observations

- 39 definitions contain `execve()` discovery commands.
- 8 definitions contain conditional or source-specific `upload()` logic.
- Sensitive-data collectors exist for SSH, command history, cloud CLI, configuration, process environment, and secret indicators.

Review [Security Policy](../SECURITY.md) and [Installation and Import](installation.md) before deployment.

## Limitations

This validation confirms archive safety, YAML structure, naming, internal references, and common publication-hygiene checks.

It does not:

- execute every VQL source;
- prove compatibility with Velociraptor versions other than the export environment;
- measure endpoint performance;
- validate every Linux distribution or package version;
- determine whether every result is a true positive;
- replace server-side `artifacts verify` and canary collection.
