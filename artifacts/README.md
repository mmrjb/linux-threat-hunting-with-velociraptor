# Artifact Definitions

The repository contains 114 Velociraptor artifacts organized into 14 Linux threat-hunting domains.

Velociraptor searches configured artifact-definition directories recursively, so these folders can be supplied together as one definition root or packaged together for import.

## Design pattern

Most domains include:

- inventory collectors for broad baseline evidence;
- focused review artifacts for higher-signal behavior;
- a wrapper artifact named `LTH.<Domain>` that exposes the domain's evidence as named sources.

Wrapper artifacts make it possible to launch a domain-level collection while retaining separate result tables for analyst pivoting.

## Safety

Review every source before collection. Some artifacts execute local discovery commands or expose optional file-upload sources. File uploads, command history, SSH material, process environment, and configuration contents can be sensitive.

The complete generated list is available in the [Artifact Catalog](../docs/artifact-catalog.md).

