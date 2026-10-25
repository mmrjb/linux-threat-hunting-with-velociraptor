# Complete Baseline and Master Triage

The baseline collection, its nine child definitions, its hunt template and both
analysis notebooks are kept together in this repository:

- Collection: `artifacts/01-system-baseline/` — ten artifact definitions,
  including the `LTH.SystemBaseline` wrapper and nine dependencies.
- Hunt: [01-system-baseline.vql](../hunts/templates/01-system-baseline.vql).
- Inventory and coverage: [LTH-01](../notebooks/01-system-baseline-dashboard.md)
  — 39 ordered cells.
- Investigation priority: [LTH-00](../notebooks/00-master-triage.md)
  — 33 ordered cells, including 16 VQL cells.
- Editable sources: [notebooks/sources](../notebooks/sources/).

## Baseline result contract

All result tables below use `LTH.SystemBaseline/<Source>` when queried with
`hunt_results()`. Artifact and source names remain compatible with existing
notebooks.

| Source | Collector | What it returns |
| --- | --- | --- |
| `Client_BasicInformation` | `ClientInfo/BasicInformation` | Host identity, OS, platform, architecture and agent version |
| `Client_LinuxInfo` | `ClientInfo/LinuxInfo` | System information and interfaces |
| `Mounts` | `Mounts` | Mounted filesystems |
| `Users` | `Users` | Local account information from `/etc/passwd` |
| `Processes` | `Pslist` | Snapshot processes, executable hashes and process metadata |
| `Services` | `Services` | Loaded systemd service units, including inactive units |
| `NetworkConnections` | `NetstatEnriched` | TCP/UDP socket states and available process enrichment |
| `Crontab` | `Crontab` | Parsed schedules, raw lines, parser status and bounded script content |
| `DebianPackages` | `DebianPackages` | Installed packages on applicable Debian-family systems |
| `RHELPackages` | `RHELPackages` | Installed packages on applicable RHEL-family systems |

The wrapper's nine dependencies are complete in the repository. Debian and
RHEL package sources are conditional. An empty inapplicable source is expected;
it is not a collection failure.

## Collection and analysis

1. Import all definitions and verify them with the intended Velociraptor version.
2. Assign the intended Linux clients a scope label. Configure the baseline
   hunt template; it creates a fresh paused hunt.
3. Review and start the canary hunt. Check flow completion, errors, timeouts
   and applicable source tables before expanding scope.
4. Use its fresh Hunt ID in both LTH-01 and LTH-00. The two notebooks consume
   the same baseline; Master Triage does not require a second hunt.
5. Review inventory and coverage in LTH-01, then scored evidence and unscored
   hunt leads in LTH-00. Keep `EnableLabIndicators=FALSE` for production.
6. Define a host-specific hypothesis and pivot to the corresponding domain
   notebook and targeted collection.

## Corrected collection behavior

Cron parser v2 distinguishes system files, which contain an explicit username,
from user spool files, which do not. Both regular schedules and `@reboot` retain
the complete command. `RawLine`, `ParseStatus`, `CronFormat` and `ParserVersion`
are additional evidence fields. Comments and environment assignments are
excluded; other unparsed lines remain visible for review. Separate `at` job
syntax is outside this parser's scope.

Cron scripts include `Path`, `Size` and `PotentiallyTruncated`; `Length` bounds
the returned content. Upload is disabled by default and explicitly disabled
by both collection wrappers. This does not disable bounded script-content
collection. Deliberate file acquisition uses the child collector's
`UploadFiles=TRUE` and `Uploaded` source.

Service discovery disables the pager and headings, includes inactive loaded
units and avoids truncated unit names. It is a snapshot of loaded units;
investigate unit files and timers through the persistence domain.

Baseline network collection retains all TCP/UDP states. When process
enrichment is unavailable, default process filters do not discard the socket.
Explicit process filters still require a matching enriched value. The
network/exfiltration domain collectors retain their existing `LISTEN|ESTAB`
status defaults.

## Interpretation and limits

Master Triage caps each scored area at its strongest indicator and retains
separate evidence and unscored review leads. A critical area or an aggregate
score of at least ten receives High priority. A score is an investigation
priority, not a compromise verdict.

The fleet anchor depends on returned basic-information rows. A host with no
baseline result at all will not be added to the risk table: reconcile hunt
membership and failed/incomplete flows separately. The selected-source row
counts describe observed data, not proof of complete collection.

Old hunts remain snapshots. Updating definitions does not repair old Cron
rows or re-collect previously omitted network/service data. Collect a fresh
canary baseline before comparing the corrected output with older hunts.
