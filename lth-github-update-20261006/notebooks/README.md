# Notebook source templates

The repository contains LTH-00 through LTH-14: 508 ordered cells, including 242 VQL cells and 266 Markdown cells. The Markdown files are readable cell-by-cell templates; `sources/*.json` preserves the same order and inputs for tooling. These JSON files are not native Velociraptor notebook import archives.

## Setup

1. Import the artifact definitions, create the appropriate paused hunt, review its scope and collection settings, then start the approved collection.
2. Create a notebook in Velociraptor. Copy each Markdown/VQL cell in the recorded order, using its recorded cell type.
3. Replace `HUNT_ID` consistently with the collection hunt ID shown in the table below. Keep IDs and populated notebook outputs inside your environment.
4. For LTH-02 cell 3, also replace `BASELINE_HUNT_ID` with the independent baseline hunt ID. Its Users, Groups and SudoersRules sources come from the LTH.UsersPrivileges hunt; the baseline supplies only the fleet anchor. The other LTH-02 cells use the identity hunt.
5. Evaluate cells in order, inspect errors and collection logs, and validate returned fields against your version before operational use.

Master Triage and LTH-01 both read the baseline hunt. Master Triage is an analysis notebook; it does not need a separate collection hunt. Keep `EnableLabIndicators` set to `FALSE` in production.

| Notebook | Collection artifact |
| --- | --- |
| [LTH-00: Master Triage](00-master-triage.md) | `LTH.SystemBaseline` |
| [LTH-01: System Baseline Dashboard](01-system-baseline-dashboard.md) | `LTH.SystemBaseline` |
| [LTH-02: Users Groups and Privileges Dashboard](02-users-groups-privileges-dashboard.md) | `LTH.UsersPrivileges` |
| [LTH-03: Authentication and SSH Activity Dashboard](03-authentication-ssh-dashboard.md) | `LTH.AuthSSH` |
| [LTH-04: Processes and Services Dashboard](04-processes-services-dashboard.md) | `LTH.ProcessServices` |
| [LTH-05: Network Connections Dashboard](05-network-connections-dashboard.md) | `LTH.NetworkConnections` |
| [LTH-06: Persistence Mechanisms Dashboard](06-persistence-dashboard.md) | `LTH.Persistence` |
| [LTH-07: File System and Timeline Analysis Dashboard](07-file-timeline-dashboard.md) | `LTH.FileTimeline` |
| [LTH-08: Logs and Security Events Dashboard](08-logs-security-events-dashboard.md) | `LTH.LogSecurityEvents` |
| [LTH-09: Privilege Escalation Indicators Dashboard](09-privilege-escalation-dashboard.md) | `LTH.PrivEsc` |
| [LTH-10: Rootkit and Kernel-Level Checks Dashboard](10-rootkit-kernel-dashboard.md) | `LTH.RootkitKernel` |
| [LTH-11: Malware and Suspicious Tools Dashboard](11-malware-tools-dashboard.md) | `LTH.MalwareTools` |
| [LTH-12: Containers and Cloud Workloads Dashboard](12-containers-cloud-dashboard.md) | `LTH.ContainerCloud` |
| [LTH-13: Data Access and Exfiltration Dashboard](13-data-access-exfiltration-dashboard.md) | `LTH.DataExfil` |
| [LTH-14: Configuration and Secrets Review Dashboard](14-configuration-secrets-dashboard.md) | `LTH.ConfigSecrets` |

## Interpretation

Risk scores and review leads prioritize investigation. They do not establish compromise. Empty result sources may be valid, missing, failed or inapplicable; row presence alone does not establish full coverage. Master Triage explicitly reports legacy/unparsed Cron data. The recovered collector snapshots contain the legacy Cron parser, so parser review warnings can be expected; do not assume parser-v2 fields were collected.

The October update restores the public special-purpose CIDRs `0.0.0.0/8`, `224.0.0.0/4` and `240.0.0.0/4` that the intermediate review export masked. Current cell inputs were exported without calculated results, logs or attachments. LTH-02 cell 3 was corrected for the documented wrapper source names; other exported notebook behavior was retained.
