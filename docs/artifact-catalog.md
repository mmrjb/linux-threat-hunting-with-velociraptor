# Artifact Catalog

This catalog contains 114 artifact definitions across 14 domains.

It is generated from the YAML metadata. Run `python3 scripts/generate_artifact_catalog.py` after changing an artifact.

## 01. System Baseline

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.SystemBaseline`](../artifacts/01-system-baseline/LTH.SystemBaseline.yaml) | `CLIENT` | 10 | Linux Threat Hunting - Section 2.1 System Baseline |
| [`LTH.SystemBaseline.ClientInfo`](../artifacts/01-system-baseline/LTH.SystemBaseline.ClientInfo.yaml) | `CLIENT (implicit)` | 5 | Collect basic information about the client. |
| [`LTH.SystemBaseline.Crontab`](../artifacts/01-system-baseline/LTH.SystemBaseline.Crontab.yaml) | `CLIENT (implicit)` | 3 | Displays parsed information from crontab. |
| [`LTH.SystemBaseline.DebianPackages`](../artifacts/01-system-baseline/LTH.SystemBaseline.DebianPackages.yaml) | `CLIENT (implicit)` | 2 | List all packages installed on the system, both deb packages and "snaps". |
| [`LTH.SystemBaseline.Mounts`](../artifacts/01-system-baseline/LTH.SystemBaseline.Mounts.yaml) | `CLIENT (implicit)` | 1 | List mounted filesystems by reading /proc/mounts |
| [`LTH.SystemBaseline.NetstatEnriched`](../artifacts/01-system-baseline/LTH.SystemBaseline.NetstatEnriched.yaml) | `CLIENT` | 1 | Report network connections, and enrich with process information. |
| [`LTH.SystemBaseline.Pslist`](../artifacts/01-system-baseline/LTH.SystemBaseline.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.SystemBaseline.RHELPackages`](../artifacts/01-system-baseline/LTH.SystemBaseline.RHELPackages.yaml) | `CLIENT (implicit)` | 1 | Parse packages installed from dnf or yum |
| [`LTH.SystemBaseline.Services`](../artifacts/01-system-baseline/LTH.SystemBaseline.Services.yaml) | `CLIENT (implicit)` | 1 | Parse services from systemctl |
| [`LTH.SystemBaseline.Users`](../artifacts/01-system-baseline/LTH.SystemBaseline.Users.yaml) | `CLIENT (implicit)` | 1 | Get User specific information like homedir, group, etc. from `/etc/passwd`. |

## 02. Users, Groups & Privileges

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.UsersPrivileges`](../artifacts/02-users-privileges/LTH.UsersPrivileges.yaml) | `CLIENT` | 5 | Linux Threat Hunting - Section 2.2 Users, Groups, and Privileges |
| [`LTH.UsersPrivileges.Groups`](../artifacts/02-users-privileges/LTH.UsersPrivileges.Groups.yaml) | `CLIENT (implicit)` | 1 | Get system group IDs, names and memberships from /etc/group |
| [`LTH.UsersPrivileges.InteractiveUsers`](../artifacts/02-users-privileges/LTH.UsersPrivileges.InteractiveUsers.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.2 Users, Groups, and Privileges |
| [`LTH.UsersPrivileges.RootUsers`](../artifacts/02-users-privileges/LTH.UsersPrivileges.RootUsers.yaml) | `CLIENT` | 1 | Detects users added in the `sudo` group. |
| [`LTH.UsersPrivileges.SudoersReview`](../artifacts/02-users-privileges/LTH.UsersPrivileges.SudoersReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.2 Users, Groups, and Privileges |
| [`LTH.UsersPrivileges.Users`](../artifacts/02-users-privileges/LTH.UsersPrivileges.Users.yaml) | `CLIENT (implicit)` | 1 | Get User specific information like homedir, group, etc. from `/etc/passwd`. |

## 03. Authentication & SSH

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.AuthSSH`](../artifacts/03-auth-ssh/LTH.AuthSSH.yaml) | `CLIENT` | 8 | Linux Threat Hunting - Section 2.3 Authentication and SSH Activity |
| [`LTH.AuthSSH.AuthLogReview`](../artifacts/03-auth-ssh/LTH.AuthSSH.AuthLogReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.3 Authentication and SSH Activity |
| [`LTH.AuthSSH.AuthorizedKeys`](../artifacts/03-auth-ssh/LTH.AuthSSH.AuthorizedKeys.yaml) | `CLIENT (implicit)` | 1 | Finds and parses SSH authorized keys files. |
| [`LTH.AuthSSH.KnownHosts`](../artifacts/03-auth-ssh/LTH.AuthSSH.KnownHosts.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.3 Authentication and SSH Activity |
| [`LTH.AuthSSH.LastUserLogin`](../artifacts/03-auth-ssh/LTH.AuthSSH.LastUserLogin.yaml) | `CLIENT (implicit)` | 1 | Finds and parses system WTMP files. |
| [`LTH.AuthSSH.PrivateKeys`](../artifacts/03-auth-ssh/LTH.AuthSSH.PrivateKeys.yaml) | `CLIENT (implicit)` | 1 | SSH Private keys can be either encrypted or unencrypted. Unencrypted |
| [`LTH.AuthSSH.SSHConfigReview`](../artifacts/03-auth-ssh/LTH.AuthSSH.SSHConfigReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.3 Authentication and SSH Activity |
| [`LTH.AuthSSH.SSHLogin`](../artifacts/03-auth-ssh/LTH.AuthSSH.SSHLogin.yaml) | `CLIENT` | 1 | Parses the auth logs to determine all SSH login attempts. |

## 04. Processes & Services

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.ProcessServices`](../artifacts/04-process-services/LTH.ProcessServices.yaml) | `CLIENT` | 6 | Linux Threat Hunting - Section 2.4 Processes and Services |
| [`LTH.ProcessServices.Pslist`](../artifacts/04-process-services/LTH.ProcessServices.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.ProcessServices.ServiceUnitReview`](../artifacts/04-process-services/LTH.ProcessServices.ServiceUnitReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.4 Processes and Services |
| [`LTH.ProcessServices.Services`](../artifacts/04-process-services/LTH.ProcessServices.Services.yaml) | `CLIENT (implicit)` | 1 | Parse services from systemctl |
| [`LTH.ProcessServices.SuspiciousProcesses`](../artifacts/04-process-services/LTH.ProcessServices.SuspiciousProcesses.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.4 Processes and Services |
| [`LTH.ProcessServices.SuspiciousServices`](../artifacts/04-process-services/LTH.ProcessServices.SuspiciousServices.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.4 Processes and Services |

## 05. Network Connections

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.NetworkConnections`](../artifacts/05-network-connections/LTH.NetworkConnections.yaml) | `CLIENT` | 5 | Linux Threat Hunting - Section 2.5 Network Connections |
| [`LTH.NetworkConnections.DNSConfigReview`](../artifacts/05-network-connections/LTH.NetworkConnections.DNSConfigReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.5 Network Connections |
| [`LTH.NetworkConnections.FirewallRules`](../artifacts/05-network-connections/LTH.NetworkConnections.FirewallRules.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.5 Network Connections |
| [`LTH.NetworkConnections.NetstatEnriched`](../artifacts/05-network-connections/LTH.NetworkConnections.NetstatEnriched.yaml) | `CLIENT` | 1 | Report network connections, and enrich with process information. |
| [`LTH.NetworkConnections.RoutingTable`](../artifacts/05-network-connections/LTH.NetworkConnections.RoutingTable.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.5 Network Connections |
| [`LTH.NetworkConnections.SuspiciousConnections`](../artifacts/05-network-connections/LTH.NetworkConnections.SuspiciousConnections.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.5 Network Connections |

## 06. Persistence

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.Persistence`](../artifacts/06-persistence/LTH.Persistence.yaml) | `CLIENT` | 13 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |
| [`LTH.Persistence.AuthorizedKeys`](../artifacts/06-persistence/LTH.Persistence.AuthorizedKeys.yaml) | `CLIENT (implicit)` | 1 | Finds and parses SSH authorized keys files. |
| [`LTH.Persistence.Crontab`](../artifacts/06-persistence/LTH.Persistence.Crontab.yaml) | `CLIENT (implicit)` | 3 | Displays parsed information from crontab. |
| [`LTH.Persistence.PAMReview`](../artifacts/06-persistence/LTH.Persistence.PAMReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |
| [`LTH.Persistence.Services`](../artifacts/06-persistence/LTH.Persistence.Services.yaml) | `CLIENT (implicit)` | 1 | Parse services from systemctl |
| [`LTH.Persistence.ShellProfileReview`](../artifacts/06-persistence/LTH.Persistence.ShellProfileReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |
| [`LTH.Persistence.StartupFilesReview`](../artifacts/06-persistence/LTH.Persistence.StartupFilesReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |
| [`LTH.Persistence.SystemdTimerReview`](../artifacts/06-persistence/LTH.Persistence.SystemdTimerReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |
| [`LTH.Persistence.SystemdUnitReview`](../artifacts/06-persistence/LTH.Persistence.SystemdUnitReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.6 Persistence Mechanisms |

## 07. File Timeline

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.FileTimeline`](../artifacts/07-file-timeline/LTH.FileTimeline.yaml) | `CLIENT` | 7 | Linux Threat Hunting - Section 2.7 File System and Timeline Analysis |
| [`LTH.FileTimeline.AnomalousFiles`](../artifacts/07-file-timeline/LTH.FileTimeline.AnomalousFiles.yaml) | `CLIENT` | 1 | Detects anomalous files in a Linux filesystem. |
| [`LTH.FileTimeline.ArchiveAndDumpFiles`](../artifacts/07-file-timeline/LTH.FileTimeline.ArchiveAndDumpFiles.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.7 File System and Timeline Analysis |
| [`LTH.FileTimeline.FileFinder`](../artifacts/07-file-timeline/LTH.FileTimeline.FileFinder.yaml) | `CLIENT (implicit)` | 1 | Find files on the filesystem using the filename or content. |
| [`LTH.FileTimeline.RecentSensitiveFiles`](../artifacts/07-file-timeline/LTH.FileTimeline.RecentSensitiveFiles.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.7 File System and Timeline Analysis |
| [`LTH.FileTimeline.TempExecutableFiles`](../artifacts/07-file-timeline/LTH.FileTimeline.TempExecutableFiles.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.7 File System and Timeline Analysis |
| [`LTH.FileTimeline.WebRootChanges`](../artifacts/07-file-timeline/LTH.FileTimeline.WebRootChanges.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.7 File System and Timeline Analysis |

## 08. Logs & Security Events

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.LogSecurityEvents`](../artifacts/08-log-security-events/LTH.LogSecurityEvents.yaml) | `CLIENT` | 11 | Linux Threat Hunting - Section 2.8 Logs and Security Events |
| [`LTH.LogSecurityEvents.CommandHistoryReview`](../artifacts/08-log-security-events/LTH.LogSecurityEvents.CommandHistoryReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.8 Logs and Security Events |
| [`LTH.LogSecurityEvents.LastUserLogin`](../artifacts/08-log-security-events/LTH.LogSecurityEvents.LastUserLogin.yaml) | `CLIENT (implicit)` | 1 | Finds and parses system WTMP files. |
| [`LTH.LogSecurityEvents.SSHLogin`](../artifacts/08-log-security-events/LTH.LogSecurityEvents.SSHLogin.yaml) | `CLIENT` | 1 | Parses the auth logs to determine all SSH login attempts. |
| [`LTH.LogSecurityEvents.SecurityLogReview`](../artifacts/08-log-security-events/LTH.LogSecurityEvents.SecurityLogReview.yaml) | `CLIENT` | 7 | Linux Threat Hunting - Section 2.8 Logs and Security Events |

## 09. Privilege Escalation

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.PrivEsc`](../artifacts/09-privilege-escalation/LTH.PrivEsc.yaml) | `CLIENT` | 14 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.AnomalousFiles`](../artifacts/09-privilege-escalation/LTH.PrivEsc.AnomalousFiles.yaml) | `CLIENT` | 1 | Detects anomalous files in a Linux filesystem. |
| [`LTH.PrivEsc.FileCapabilities`](../artifacts/09-privilege-escalation/LTH.PrivEsc.FileCapabilities.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.Groups`](../artifacts/09-privilege-escalation/LTH.PrivEsc.Groups.yaml) | `CLIENT (implicit)` | 1 | Get system group IDs, names and memberships from /etc/group |
| [`LTH.PrivEsc.PrivilegedGroupsReview`](../artifacts/09-privilege-escalation/LTH.PrivEsc.PrivilegedGroupsReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.Pslist`](../artifacts/09-privilege-escalation/LTH.PrivEsc.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.PrivEsc.RootProcessIndicators`](../artifacts/09-privilege-escalation/LTH.PrivEsc.RootProcessIndicators.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.SUIDSGIDFiles`](../artifacts/09-privilege-escalation/LTH.PrivEsc.SUIDSGIDFiles.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.SudoersReview`](../artifacts/09-privilege-escalation/LTH.PrivEsc.SudoersReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |
| [`LTH.PrivEsc.Users`](../artifacts/09-privilege-escalation/LTH.PrivEsc.Users.yaml) | `CLIENT (implicit)` | 1 | Get User specific information like homedir, group, etc. from `/etc/passwd`. |
| [`LTH.PrivEsc.WorldWritableReview`](../artifacts/09-privilege-escalation/LTH.PrivEsc.WorldWritableReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.9 Privilege Escalation Indicators |

## 10. Rootkit & Kernel

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.RootkitKernel`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.yaml) | `CLIENT` | 16 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.DeviceHiddenReview`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.DeviceHiddenReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.KernelLogReview`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.KernelLogReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.KernelModuleReview`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.KernelModuleReview.yaml) | `CLIENT` | 4 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.KernelSecuritySettings`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.KernelSecuritySettings.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.LDPreloadReview`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.LDPreloadReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.ProcAnomalyReview`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.ProcAnomalyReview.yaml) | `CLIENT` | 3 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |
| [`LTH.RootkitKernel.Pslist`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.RootkitKernel.RootkitScannerAvailability`](../artifacts/10-rootkit-kernel/LTH.RootkitKernel.RootkitScannerAvailability.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.10 Rootkit and Kernel-Level Checks |

## 11. Malware & Suspicious Tools

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.MalwareTools`](../artifacts/11-malware-tools/LTH.MalwareTools.yaml) | `CLIENT` | 8 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.ExecutableHashInventory`](../artifacts/11-malware-tools/LTH.MalwareTools.ExecutableHashInventory.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.FileFinder`](../artifacts/11-malware-tools/LTH.MalwareTools.FileFinder.yaml) | `CLIENT (implicit)` | 1 | Find files on the filesystem using the filename or content. |
| [`LTH.MalwareTools.Pslist`](../artifacts/11-malware-tools/LTH.MalwareTools.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.MalwareTools.ScannerAvailability`](../artifacts/11-malware-tools/LTH.MalwareTools.ScannerAvailability.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.StringIndicatorScan`](../artifacts/11-malware-tools/LTH.MalwareTools.StringIndicatorScan.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.SuspiciousPackages`](../artifacts/11-malware-tools/LTH.MalwareTools.SuspiciousPackages.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.SuspiciousProcessTools`](../artifacts/11-malware-tools/LTH.MalwareTools.SuspiciousProcessTools.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |
| [`LTH.MalwareTools.SuspiciousToolFiles`](../artifacts/11-malware-tools/LTH.MalwareTools.SuspiciousToolFiles.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.11 Malware and Suspicious Tools |

## 12. Containers & Cloud

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.ContainerCloud`](../artifacts/12-container-cloud/LTH.ContainerCloud.yaml) | `CLIENT` | 19 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.CloudWorkloadReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.CloudWorkloadReview.yaml) | `CLIENT` | 4 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.ContainerConfigReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.ContainerConfigReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.ContainerProcessReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.ContainerProcessReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.DockerReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.DockerReview.yaml) | `CLIENT` | 3 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.KubernetesReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.KubernetesReview.yaml) | `CLIENT` | 3 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.PodmanReview`](../artifacts/12-container-cloud/LTH.ContainerCloud.PodmanReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |
| [`LTH.ContainerCloud.Pslist`](../artifacts/12-container-cloud/LTH.ContainerCloud.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.ContainerCloud.RuntimeDiscovery`](../artifacts/12-container-cloud/LTH.ContainerCloud.RuntimeDiscovery.yaml) | `CLIENT` | 3 | Linux Threat Hunting - Section 2.12 Containers and Cloud Workloads |

## 13. Data Access & Exfiltration

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.DataExfil`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.yaml) | `CLIENT` | 9 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.ArchiveDumpReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.ArchiveDumpReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.CloudCliConfigReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.CloudCliConfigReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.CommandHistoryExfilReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.CommandHistoryExfilReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.FileFinder`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.FileFinder.yaml) | `CLIENT (implicit)` | 1 | Find files on the filesystem using the filename or content. |
| [`LTH.DataExfil.LargeRecentFiles`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.LargeRecentFiles.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.NetstatEnriched`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.NetstatEnriched.yaml) | `CLIENT` | 1 | Report network connections, and enrich with process information. |
| [`LTH.DataExfil.NetworkTransferReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.NetworkTransferReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.Pslist`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.Pslist.yaml) | `CLIENT (implicit)` | 1 | List processes and their running binaries. |
| [`LTH.DataExfil.SensitivePathReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.SensitivePathReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |
| [`LTH.DataExfil.TransferProcessReview`](../artifacts/13-data-access-exfiltration/LTH.DataExfil.TransferProcessReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.13 Data Access and Exfiltration |

## 14. Configuration & Secrets

| Artifact | Type | Sources | Summary |
| --- | --- | ---: | --- |
| [`LTH.ConfigSecrets`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.yaml) | `CLIENT` | 11 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.ApplicationConfigReview`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.ApplicationConfigReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.ConfigInventory`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.ConfigInventory.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.FileFinder`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.FileFinder.yaml) | `CLIENT (implicit)` | 1 | Find files on the filesystem using the filename or content. |
| [`LTH.ConfigSecrets.PermissionReview`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.PermissionReview.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.ProcessEnvironmentReview`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.ProcessEnvironmentReview.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.SecretFileInventory`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.SecretFileInventory.yaml) | `CLIENT` | 2 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
| [`LTH.ConfigSecrets.SecretIndicatorScan`](../artifacts/14-configuration-secrets/LTH.ConfigSecrets.SecretIndicatorScan.yaml) | `CLIENT` | 1 | Linux Threat Hunting - Section 2.14 Configuration and Secrets Review |
