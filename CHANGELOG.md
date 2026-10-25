# Changelog

## Unreleased - 2026-10-25

- Integrate the accidentally nested October update into the repository root.
- Restore the complete baseline dashboard, all 15 notebook sources and 14 paused hunt templates to their documented paths.
- Fix the LinuxInfo report quote, distinguish system/user cron formats, retain raw/unparsed evidence, and report script-content truncation.
- Disable cron file uploads by default and explicitly in the baseline/persistence wrappers.
- Retain unresolved socket owners with default filters; collect all baseline TCP/UDP states.
- Include inactive loaded service units and disable pagination, headings and truncated unit names.
- Add native Velociraptor verification and focused baseline/triage regression commands to CI. Execution remains pending in this preparation environment.
- Reject accidentally nested update-package directories during structural validation.
- Document baseline source coverage, fresh collection requirements and verification limits.

## Unreleased - 2026-10-06

- Publish all 15 notebook source templates and extend Master Triage and Network Connections.
- Correct LTH-02 identity coverage sources and restore public CIDR filter constants.
- Add 14 label-scoped paused hunt creation templates and their settings catalog.
- Validate notebook references, cell ordering/source consistency, identifiers and hunt template settings.
- Compare 100 cached collector definitions and 37 wrapper snapshots with existing code; retain collector definitions and public metadata.


All notable changes to this project are documented in this file.

The format is based on Keep a Changelog, and the project uses semantic versioning.

## [0.1.0] - 2026-07-29

### Added

- 114 Velociraptor artifact definitions across 14 Linux threat-hunting domains.
- Wrapper artifacts for domain-level collection and analyst pivoting.
- Master Triage and Network Connections notebook templates.
- Architecture, workflow, installation, validation, and web-upload documentation.
- Automated repository validator and generated artifact catalog.
- GitHub Actions workflow for structural checks.
- Security, attribution, contribution, and licensing documentation.

### Security

- Removed environment-specific Hunt IDs, Client IDs, IP addresses, emails, and credentials.
- Documented definitions that use command execution or file upload behavior.
