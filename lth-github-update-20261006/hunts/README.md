# Reusable hunt templates

Fourteen VQL templates create fresh hunts for the fourteen collection domains. They are collection setup code, not datastore backups. `profiles.json` lists the templates and resource limits; it is a catalog, not a native import format.

## Create a hunt

1. Import all repository artifacts into the authorized Velociraptor server.
2. Assign an existing scope label to the intended Linux endpoints. Start with a small test group.
3. Open a SERVER notebook and copy the selected file from `templates/` into a VQL cell.
4. Replace `SET_TARGET_LABEL`. Review the artifacts, default parameters, upload sources, resource limits and expiry. The new expiry defaults to 24 hours from creation; historical expiry timestamps are not reused.
5. Evaluate the cell. It creates a fresh hunt in `PAUSED` state and returns the hunt object. Re-evaluating a configured cell creates another hunt; use the existing hunt after its first creation.
6. Inspect the new hunt in Hunt Manager. Start it when its scope and settings are ready. Put its fresh ID into the matching analysis notebook.

The unchanged label placeholder creates no hunt. The templates target labels; they do not combine an OS condition with a label condition. Put the label only on intended Linux endpoints and retain the collector preconditions.

`pause=TRUE` is explicit because the VQL `hunt()` function otherwise creates active hunts. See the [official function reference](https://docs.velociraptor.app/vql_reference/server/hunt/).

## Settings and provenance

The profiles reproduce the explicitly recorded resource limits from the most recently created available hunt for each wrapper. Missing limits remain omitted so server/artifact defaults apply. No per-artifact parameter overrides were recorded in the reviewed metadata; artifact defaults apply unless the operator configures a deliberate override.

Most captured profiles have a one-hour timeout; profiles without an explicit timeout retain that omission. The recorded upload cap is 1 GiB per collection. This is a historical cap, not a recommendation or an estimate of data volume. Some collectors include upload sources, file content, shell history or secret indicators. Review acquisition settings before starting a collection.

The reviewed inventory contained 37 stopped LTH hunts covering 14 wrappers. Their identities, creators, scope-label values, results and statistics are not included here. These templates create new hunts and do not restore collection history. LTH-00 and LTH-01 share the baseline collection template.
