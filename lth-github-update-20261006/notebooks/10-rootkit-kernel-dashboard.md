# LTH - 10 - Rootkit and Kernel-Level Checks Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 10 - Rootkit and Kernel-Level Checks Dashboard

This notebook analyzes Linux rootkit and kernel-level indicators collected by:

`LTH.RootkitKernel`

Main objectives:

- Review loaded kernel modules
- Identify suspicious kernel modules and module files
- Review kernel security logs and dmesg indicators
- Review LD_PRELOAD and dynamic linker configuration
- Identify deleted process executables and suspicious memory maps
- Review kernel security sysctl settings
- Identify hidden files under device and temporary paths
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Loaded Kernel Modules

This section reviews kernel modules currently loaded on Linux endpoints.

Unexpected modules, suspicious names, or modules associated with hiding, hooking, or syscall manipulation should be reviewed carefully.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Module,
       Size,
       UsedByCount,
       Dependencies,
       State,
       Address
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/KernelModules"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Suspicious Kernel Modules

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Module,
       Size,
       UsedByCount,
       Dependencies,
       State,
       Address,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/SuspiciousKernelModules"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Kernel Module Files

This section reviews kernel module files found on disk.

Kernel module files in writable or unusual locations may indicate staging or persistence for kernel-level components.

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/KernelModuleFiles"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# Suspicious Kernel Module Files

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
  artifact="LTH.RootkitKernel/SuspiciousKernelModuleFiles"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# Kernel Messages

This section reviews kernel messages collected from dmesg and common Linux log files.

Kernel messages can reveal module loading issues, kernel taint, access denials, crashes, and security-relevant warnings.

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Source,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/KernelMessages"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Suspicious Kernel Messages

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Source,
       Line,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/SuspiciousKernelMessages"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# LD_PRELOAD and Dynamic Linker Configuration

This section reviews LD_PRELOAD and dynamic linker configuration files.

Unexpected entries in `/etc/ld.so.preload` or library paths pointing to writable locations may indicate userland rootkit behavior.

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/LDPreloadLines"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Suspicious LD_PRELOAD Lines

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/SuspiciousLDPreloadLines"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# /proc Process List

This section collects process information directly from `/proc`.

It provides another view of running processes that can help during rootkit or process hiding investigations.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       Ppid,
       Uid,
       Name,
       Exe,
       CommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/ProcProcessList"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Deleted Process Executables

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       Name,
       Exe,
       CommandLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/DeletedProcExecutables"
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Suspicious Process Memory Maps

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       Name,
       MapLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/SuspiciousProcMaps"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Kernel Security Settings

This section reviews security-relevant kernel sysctl settings.

Weak settings may expose kernel symbols, allow unrestricted dmesg access, permit risky tracing behavior, or increase kernel attack surface.

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Key,
       Value
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/KernelSecuritySettings"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# Weak Kernel Security Settings

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Key,
       Value,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/WeakKernelSecuritySettings"
)
ORDER BY ClientId
```

## Cell 28 (markdown)

## Suspicious Device and Hidden Files

This section reviews suspicious hidden files and rootkit-like names in `/dev`, temporary paths, and writable locations.

Hidden objects under `/dev` or `/dev/shm` should be reviewed carefully because they are common staging locations.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       FileType,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/SuspiciousDeviceHiddenFiles"
)
ORDER BY ClientId
```

## Cell 30 (markdown)

# Rootkit Scanner Availability

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Tool,
       Status,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.RootkitKernel/ScannerAvailability"
)
ORDER BY ClientId
```

## Cell 32 (markdown)

# Final Findings Detail

This section combines rootkit and kernel-level indicators into one findings table.

It includes suspicious kernel modules, suspicious module files, kernel warning messages, LD_PRELOAD indicators, deleted executables, suspicious memory maps, weak kernel settings, and hidden device files.

Use this table as the main evidence view for rootkit and kernel-level hunting.

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SuspiciousModules <=
  SELECT ClientId,
         Severity,
         "Suspicious Kernel Module" AS Finding,
         Module AS Evidence1,
         State AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelModules"
  )

LET SuspiciousModuleFiles <=
  SELECT ClientId,
         Severity,
         "Suspicious Kernel Module File" AS Finding,
         OSPath AS Evidence1,
         Owner AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelModuleFiles"
  )

LET SuspiciousKernelLogs <=
  SELECT ClientId,
         Severity,
         "Suspicious Kernel Message" AS Finding,
         Source AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelMessages"
  )

LET LDPreload <=
  SELECT ClientId,
         Severity,
         "Suspicious LD_PRELOAD Configuration" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousLDPreloadLines"
  )

LET DeletedExecutables <=
  SELECT ClientId,
         Severity,
         "Deleted Process Executable" AS Finding,
         Pid AS Evidence1,
         Exe AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/DeletedProcExecutables"
  )

LET ProcMaps <=
  SELECT ClientId,
         Severity,
         "Suspicious Process Memory Map" AS Finding,
         Pid AS Evidence1,
         Name AS Evidence2,
         MapLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousProcMaps"
  )
  LIMIT 200

LET WeakSettings <=
  SELECT ClientId,
         Severity,
         "Weak Kernel Security Setting" AS Finding,
         Key AS Evidence1,
         Value AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/WeakKernelSecuritySettings"
  )

LET HiddenFiles <=
  SELECT ClientId,
         Severity,
         "Suspicious Hidden Device File" AS Finding,
         OSPath AS Evidence1,
         FileType AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousDeviceHiddenFiles"
  )

SELECT *
FROM chain(
  a=SuspiciousModules,
  b=SuspiciousModuleFiles,
  c=SuspiciousKernelLogs,
  d=LDPreload,
  e=DeletedExecutables,
  f=ProcMaps,
  g=WeakSettings,
  h=HiddenFiles
)
ORDER BY ClientId
```

## Cell 34 (markdown)

# Clients Needing Investigation

This section summarizes rootkit and kernel-level findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when suspicious kernel modules, deleted executables, suspicious memory maps, LD_PRELOAD entries, or kernel warnings are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 35 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SuspiciousModules <=
  SELECT ClientId,
         "Suspicious Kernel Module" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelModules"
  )
  GROUP BY ClientId

LET SuspiciousModuleFiles <=
  SELECT ClientId,
         "Suspicious Kernel Module File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelModuleFiles"
  )
  GROUP BY ClientId

LET SuspiciousKernelLogs <=
  SELECT ClientId,
         "Suspicious Kernel Message" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousKernelMessages"
  )
  GROUP BY ClientId

LET LDPreload <=
  SELECT ClientId,
         "Suspicious LD_PRELOAD Configuration" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousLDPreloadLines"
  )
  GROUP BY ClientId

LET DeletedExecutables <=
  SELECT ClientId,
         "Deleted Process Executable" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/DeletedProcExecutables"
  )
  GROUP BY ClientId

LET ProcMaps <=
  SELECT ClientId,
         "Suspicious Process Memory Map" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousProcMaps"
  )
  GROUP BY ClientId

LET WeakSettings <=
  SELECT ClientId,
         "Weak Kernel Security Setting" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/WeakKernelSecuritySettings"
  )
  GROUP BY ClientId

LET HiddenFiles <=
  SELECT ClientId,
         "Suspicious Hidden Device File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.RootkitKernel/SuspiciousDeviceHiddenFiles"
  )
  GROUP BY ClientId

LET Findings <=
  SELECT *
  FROM chain(
    a=SuspiciousModules,
    b=SuspiciousModuleFiles,
    c=SuspiciousKernelLogs,
    d=LDPreload,
    e=DeletedExecutables,
    f=ProcMaps,
    g=WeakSettings,
    h=HiddenFiles
  )

SELECT ClientId,
       count() AS FindingCategoryCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCategoryCount DESC
```

## Cell 36 (markdown)

# Recommended Next Actions

Clients with rootkit or kernel-level findings should be reviewed in deeper investigation.

Recommended follow-up actions:

1. Review suspicious kernel modules and module files.
2. Investigate kernel taint, unsigned modules, or suspicious dmesg messages.
3. Validate LD_PRELOAD and dynamic linker configuration.
4. Investigate deleted executables and suspicious memory maps.
5. Review weak kernel security settings and hardening gaps.
6. Inspect hidden files under `/dev`, `/dev/shm`, and temporary paths.
7. Correlate findings with process, persistence, filesystem, authentication, and network hunts.
