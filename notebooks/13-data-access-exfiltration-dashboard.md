# LTH - 13 - Data Access and Exfiltration Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 13 - Data Access and Exfiltration Dashboard

This notebook analyzes Linux data access and exfiltration indicators collected by:

`LTH.DataExfil`

Main objectives:

- Review transfer-related processes
- Review network connections from transfer tools
- Identify archive, backup, dump, and encrypted staging files
- Identify large recently modified files
- Inventory sensitive and credential-like files
- Review cloud CLI and object storage indicators
- Review exfiltration-related command history
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Transfer Processes

This section reviews running processes related to data staging, compression, remote transfer, object storage, tunneling, and possible exfiltration.

Processes such as `rclone`, `scp`, `sftp`, `rsync`, `aws s3`, `gsutil`, `curl`, `wget`, `nc`, and `socat` should be reviewed based on server role.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       Ppid,
       Name,
       Username,
       Exe,
       CommandLine,
       CreatedTime,
       Deleted,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/TransferProcesses"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Network Transfer Connections

This section correlates network connections with transfer-related processes.

Outbound connections from file transfer tools, cloud CLI tools, tunneling utilities, or raw network tools may indicate data movement or exfiltration.

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Status,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ProcessName,
       ProcessPath,
       Username,
       CommandLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/NetworkTransferConnections"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Archive and Dump Files

This section identifies archive, backup, dump, database, encrypted, and staging files.

These files may indicate data collection, database dumping, compression, encryption, or preparation for exfiltration.

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/ArchiveDumpFiles"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# Large Recent Files

This section identifies large files that were recently modified in monitored paths.

Large recent files in temporary, user, web, or application directories may represent staged data or compressed collections.

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/LargeRecentFiles"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# Sensitive Files Inventory

This section inventories sensitive or credential-like files.

It does not return file contents. It only shows path, owner, mode, size, and timestamp to help identify files that may be targeted for collection or exfiltration.

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/SensitiveFilesInventory"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# High-Risk Sensitive Files

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/SensitiveFilesInventory"
)
WHERE Severity = "HIGH"
ORDER BY ClientId
```

## Cell 14 (markdown)

# Cloud CLI Config Inventory

This section reviews cloud CLI and object storage configuration locations.

AWS, GCP, Azure, rclone, and s3cmd configuration files may indicate cloud storage usage or potential exfiltration channels.

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/CloudCliConfigInventory"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Suspicious Cloud CLI Indicators

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       Indicator,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/SuspiciousCloudCliIndicators"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# Exfiltration Command History

This section reviews shell history for commands related to compression, staging, remote transfer, cloud storage upload, encryption, and raw network transfer.

Command history findings should be correlated with process, file, network, and authentication evidence.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       CommandLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.DataExfil/ExfilCommandHistory"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Finding Count by Category

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TransferProcesses <=
  SELECT ClientId,
         "Transfer Process" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/TransferProcesses"
  )
  GROUP BY ClientId

LET NetworkTransfers <=
  SELECT ClientId,
         "Network Transfer Connection" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/NetworkTransferConnections"
  )
  GROUP BY ClientId

LET ArchiveDumps <=
  SELECT ClientId,
         "Archive or Dump File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ArchiveDumpFiles"
  )
  GROUP BY ClientId

LET LargeFiles <=
  SELECT ClientId,
         "Large Recent File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/LargeRecentFiles"
  )
  GROUP BY ClientId

LET SensitiveFiles <=
  SELECT ClientId,
         "High-Risk Sensitive File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SensitiveFilesInventory"
  )
  WHERE Severity = "HIGH"
  GROUP BY ClientId

LET CloudIndicators <=
  SELECT ClientId,
         "Suspicious Cloud CLI Indicator" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SuspiciousCloudCliIndicators"
  )
  GROUP BY ClientId

LET History <=
  SELECT ClientId,
         "Exfiltration Command History" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ExfilCommandHistory"
  )
  GROUP BY ClientId

SELECT *
FROM chain(
  a=TransferProcesses,
  b=NetworkTransfers,
  c=ArchiveDumps,
  d=LargeFiles,
  e=SensitiveFiles,
  f=CloudIndicators,
  g=History
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Final Findings Detail

This section combines data access and exfiltration indicators into one findings table.

It includes transfer processes, network transfer connections, archive/dump files, large recent files, high-risk sensitive files, cloud CLI indicators, and exfiltration-related command history.

Use this table as the main evidence view for data access and exfiltration hunting.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TransferProcesses <=
  SELECT ClientId,
         Severity,
         "Transfer Process" AS Finding,
         Pid AS Evidence1,
         Exe AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/TransferProcesses"
  )

LET NetworkTransfers <=
  SELECT ClientId,
         Severity,
         "Network Transfer Connection" AS Finding,
         ProcessName AS Evidence1,
         Raddr AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/NetworkTransferConnections"
  )

LET ArchiveDumps <=
  SELECT ClientId,
         Severity,
         "Archive or Dump File" AS Finding,
         OSPath AS Evidence1,
         Size AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ArchiveDumpFiles"
  )

LET LargeFiles <=
  SELECT ClientId,
         Severity,
         "Large Recent File" AS Finding,
         OSPath AS Evidence1,
         Size AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/LargeRecentFiles"
  )

LET SensitiveFiles <=
  SELECT ClientId,
         Severity,
         "High-Risk Sensitive File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SensitiveFilesInventory"
  )
  WHERE Severity = "HIGH"

LET CloudIndicators <=
  SELECT ClientId,
         Severity,
         "Suspicious Cloud CLI Indicator" AS Finding,
         Path AS Evidence1,
         Indicator AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SuspiciousCloudCliIndicators"
  )

LET History <=
  SELECT ClientId,
         Severity,
         "Exfiltration Command History" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ExfilCommandHistory"
  )

SELECT *
FROM chain(
  a=TransferProcesses,
  b=NetworkTransfers,
  c=ArchiveDumps,
  d=LargeFiles,
  e=SensitiveFiles,
  f=CloudIndicators,
  g=History
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Clients Needing Investigation

This section summarizes data access and exfiltration findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when transfer processes, archive staging, large recent files, high-risk sensitive files, cloud CLI indicators, or exfiltration command history are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TransferProcesses <=
  SELECT ClientId,
         "Transfer Process" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/TransferProcesses"
  )

LET NetworkTransfers <=
  SELECT ClientId,
         "Network Transfer Connection" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/NetworkTransferConnections"
  )

LET ArchiveDumps <=
  SELECT ClientId,
         "Archive or Dump File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ArchiveDumpFiles"
  )

LET LargeFiles <=
  SELECT ClientId,
         "Large Recent File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/LargeRecentFiles"
  )

LET SensitiveFiles <=
  SELECT ClientId,
         "High-Risk Sensitive File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SensitiveFilesInventory"
  )
  WHERE Severity = "HIGH"

LET CloudIndicators <=
  SELECT ClientId,
         "Suspicious Cloud CLI Indicator" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/SuspiciousCloudCliIndicators"
  )

LET History <=
  SELECT ClientId,
         "Exfiltration Command History" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.DataExfil/ExfilCommandHistory"
  )

LET Findings <=
  SELECT *
  FROM chain(
    a=TransferProcesses,
    b=NetworkTransfers,
    c=ArchiveDumps,
    d=LargeFiles,
    e=SensitiveFiles,
    f=CloudIndicators,
    g=History
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 26 (markdown)

# Recommended Next Actions

Clients with data access or exfiltration indicators should be reviewed in deeper investigation.

Recommended follow-up actions:

1. Review transfer process command lines and parent processes.
2. Correlate outbound connections with process, user, and authentication activity.
3. Review archive, dump, encrypted, and large recent files for staging behavior.
4. Validate sensitive file inventory based on server role and access expectations.
5. Investigate cloud CLI and object storage configuration indicators.
6. Review command history for compression, transfer, encryption, or cloud upload activity.
7. Collect suspicious files only from prioritized clients to reduce endpoint and server load.
