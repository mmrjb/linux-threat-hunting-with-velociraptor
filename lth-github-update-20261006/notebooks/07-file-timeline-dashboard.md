# LTH - 07 - File System and Timeline Analysis Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 07 - File System and Timeline Analysis Dashboard

This notebook analyzes Linux filesystem and timeline data collected by:

`LTH.FileTimeline`

Main objectives:

- Review recently modified files in sensitive paths
- Build basic file timeline from MTime and CTime
- Identify executable files in writable or temporary paths
- Review anomalous files such as hidden, large, or SUID files
- Review recent web root changes
- Identify archive, backup, and dump files
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Recent Sensitive Files Inventory

This section reviews recently modified files in sensitive Linux paths.

Recent changes under `/etc`, `/usr/local/bin`, `/opt`, web roots, temp paths, and user home directories may indicate configuration changes, dropped tools, staging activity, or persistence preparation.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       MTime,
       CTime,
       ATime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/RecentSensitiveFiles"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Recent Sensitive File Count per Client

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS RecentSensitiveFileCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/RecentSensitiveFiles"
)
GROUP BY ClientId
ORDER BY RecentSensitiveFileCount DESC
```

## Cell 6 (markdown)

# Sensitive Timeline Events

This section creates a basic filesystem timeline using MTime and CTime events.

It helps analysts understand when sensitive files were modified or when metadata changed, which is useful for correlating with authentication, process, persistence, or network activity.

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       EventTime,
       EventType,
       OSPath,
       Size,
       Mode,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/SensitiveTimelineEvents"
)
ORDER BY EventTime
```

## Cell 8 (markdown)

# Files Modified Under /etc

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       MTime,
       CTime,
       Severity,
       "Recent change under /etc" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/RecentSensitiveFiles"
)
WHERE OSPath =~ "^/etc/"
ORDER BY ClientId
```

## Cell 10 (markdown)

# Temp Executable Files

This section identifies executable or script-like files in writable and temporary locations.

Files executed or staged under `/tmp`, `/var/tmp`, `/dev/shm`, or user home directories are commonly suspicious and should be reviewed carefully. 

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       MTime,
       CTime,
       ATime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/TempExecutableFiles"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Web Root Changes

This section reviews recently modified files under common Linux web root directories.

Recent server-side files or script changes may indicate webshells, dropped payloads, modified web applications, or attacker staging activity.

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       MTime,
       CTime,
       ATime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/WebRootChanges"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# Anomalous Files Inventory

This section reviews anomalous files detected on Linux endpoints.

Anomalous files include hidden files, large files, or files with SUID-related indicators and should be reviewed based on path, permissions, and server role.

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Host,
       OSPath,
       IsHidden,
       IsLarge,
       Size,
       Mode,
       HasSUID
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/AnomalousFiles"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Hidden Files

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Host,
       OSPath,
       Size,
       Mode,
       "MEDIUM" AS Severity,
       "Hidden file detected" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/AnomalousFiles"
)
WHERE IsHidden
ORDER BY ClientId
```

## Cell 18 (markdown)

# Large Files

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Host,
       OSPath,
       Size,
       Mode,
       "MEDIUM" AS Severity,
       "Large file detected" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/AnomalousFiles"
)
WHERE IsLarge
ORDER BY ClientId
```

## Cell 20 (markdown)

# SUID-Like Anomalous Files

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Host,
       OSPath,
       Size,
       Mode,
       "HIGH" AS Severity,
       "File with SUID indicator detected" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/AnomalousFiles"
)
WHERE HasSUID
ORDER BY ClientId
```

## Cell 22 (markdown)

# Archive and Dump Files

This section identifies archive, backup, and database dump files in monitored locations.

These files may indicate staging activity, backup exposure, database dumping, or preparation for exfiltration.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       MTime,
       CTime,
       ATime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/ArchiveAndDumpFiles"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# FileFinder Results

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       Mode,
       ATime,
       MTime,
       CTime,
       Keywords
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.FileTimeline/FileFinder"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# Final Findings Detail

This section combines suspicious filesystem and timeline indicators into one findings table.

It includes temp executable files, recent web root changes, anomalous files, recent sensitive path changes, archive/dump files, and SUID-like indicators.

Use this table as the main evidence view for filesystem and timeline hunting.

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TempExecutables <=
  SELECT ClientId,
         Severity,
         "Temp Executable File" AS Finding,
         OSPath AS Evidence1,
         Mode AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/TempExecutableFiles"
  )

LET WebRootChanges <=
  SELECT ClientId,
         Severity,
         "Recent Web Root Change" AS Finding,
         OSPath AS Evidence1,
         Reason AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/WebRootChanges"
  )

LET SUIDFiles <=
  SELECT ClientId,
         "HIGH" AS Severity,
         "SUID-Like Anomalous File" AS Finding,
         OSPath AS Evidence1,
         Mode AS Evidence2,
         Size AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/AnomalousFiles"
  )
  WHERE HasSUID

LET HiddenFiles <=
  SELECT ClientId,
         "MEDIUM" AS Severity,
         "Hidden File" AS Finding,
         OSPath AS Evidence1,
         Mode AS Evidence2,
         Size AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/AnomalousFiles"
  )
  WHERE IsHidden

LET ArchiveDumps <=
  SELECT ClientId,
         Severity,
         "Archive or Dump File" AS Finding,
         OSPath AS Evidence1,
         Size AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/ArchiveAndDumpFiles"
  )

LET SensitiveChanges <=
  SELECT ClientId,
         Severity,
         "Recent Sensitive File Change" AS Finding,
         OSPath AS Evidence1,
         Reason AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/RecentSensitiveFiles"
  )
  WHERE OSPath =~ "^/(etc|usr/local/bin|opt|var/www|srv/www|tmp|var/tmp|dev/shm)/"

SELECT *
FROM chain(
  a=TempExecutables,
  b=WebRootChanges,
  c=SUIDFiles,
  d=HiddenFiles,
  e=ArchiveDumps,
  f=SensitiveChanges
)
ORDER BY ClientId
```

## Cell 28 (markdown)

# Clients Needing Investigation

This section summarizes filesystem and timeline-related findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when temp executables, web root changes, SUID files, archive/dump files, or sensitive path changes are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TempExecutables <=
  SELECT ClientId,
         "Temp Executable File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/TempExecutableFiles"
  )

LET WebRootChanges <=
  SELECT ClientId,
         "Recent Web Root Change" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/WebRootChanges"
  )

LET SUIDFiles <=
  SELECT ClientId,
         "SUID-Like Anomalous File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/AnomalousFiles"
  )
  WHERE HasSUID

LET HiddenFiles <=
  SELECT ClientId,
         "Hidden File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/AnomalousFiles"
  )
  WHERE IsHidden

LET ArchiveDumps <=
  SELECT ClientId,
         "Archive or Dump File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/ArchiveAndDumpFiles"
  )

LET SensitiveChanges <=
  SELECT ClientId,
         "Recent Sensitive File Change" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.FileTimeline/RecentSensitiveFiles"
  )
  WHERE OSPath =~ "^/(etc|usr/local/bin|opt|var/www|srv/www|tmp|var/tmp|dev/shm)/"

LET Findings <=
  SELECT *
  FROM chain(
    a=TempExecutables,
    b=WebRootChanges,
    c=SUIDFiles,
    d=HiddenFiles,
    e=ArchiveDumps,
    f=SensitiveChanges
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 30 (markdown)

## Recommended Next Actions

Clients with filesystem or timeline findings should be reviewed in deeper hunting phases.

Recommended follow-up actions:

1. Review executable files in temporary or writable paths.
2. Investigate recent changes under `/etc`, `/usr/local/bin`, `/opt`, and web roots.
3. Validate hidden files, large files, and SUID-like files.
4. Review archive, backup, and database dump files for staging or exfiltration risk.
5. Correlate filesystem timeline events with authentication, process, network, and persistence hunts.
6. Run deeper file collection only for prioritized clients to avoid unnecessary endpoint load.
