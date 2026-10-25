# LTH - 01 - System Baseline Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 01 - System Baseline Dashboard

This notebook analyzes Linux system baseline data collected by:

`LTH.SystemBaseline`

Main objectives:

- Review Linux endpoint inventory
- Identify OS and kernel distribution
- Review users, processes, services, mounts, packages, and scheduled tasks
- Identify suspicious processes, services, network connections, and cron jobs
- Detect baseline outliers across Linux clients
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Client Inventory

This section provides the main Linux endpoint inventory collected by the baseline hunt.

It helps analysts understand which clients participated in the hunt and review basic system information such as hostname, OS, platform version, architecture, and kernel version.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Hostname,
       Fqdn,
       OS,
       Architecture,
       Platform,
       PlatformVersion,
       KernelVersion
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Baseline Collection Coverage

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET CoverageRows <=
SELECT *
FROM chain(
  client_info={
    SELECT ClientId,
           Fqdn,
           "Client Information" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Client_BasicInformation"
    )
    GROUP BY ClientId
  },

  users={
    SELECT ClientId,
           Fqdn,
           "Users" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Users"
    )
    GROUP BY ClientId
  },

  processes={
    SELECT ClientId,
           Fqdn,
           "Processes" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Processes"
    )
    GROUP BY ClientId
  },

  services={
    SELECT ClientId,
           Fqdn,
           "Services" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Services"
    )
    GROUP BY ClientId
  },

  network={
    SELECT ClientId,
           Fqdn,
           "Network" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/NetworkConnections"
    )
    GROUP BY ClientId
  },

  cron={
    SELECT ClientId,
           Fqdn,
           "Cron" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Crontab"
    )
    GROUP BY ClientId
  }
)

LET CoverageCounts <=
SELECT ClientId,
       Fqdn,

       sum(
         item=if(
           condition=Dataset = "Client Information",
           then=RowCount,
           else=0
         )
       ) AS ClientInfoRows,

       sum(
         item=if(
           condition=Dataset = "Users",
           then=RowCount,
           else=0
         )
       ) AS UserRows,

       sum(
         item=if(
           condition=Dataset = "Processes",
           then=RowCount,
           else=0
         )
       ) AS ProcessRows,

       sum(
         item=if(
           condition=Dataset = "Services",
           then=RowCount,
           else=0
         )
       ) AS ServiceRows,

       sum(
         item=if(
           condition=Dataset = "Network",
           then=RowCount,
           else=0
         )
       ) AS NetworkRows,

       sum(
         item=if(
           condition=Dataset = "Cron",
           then=RowCount,
           else=0
         )
       ) AS CronRows

FROM CoverageRows
GROUP BY ClientId

LET CoverageScore <=
SELECT *,

       if(
         condition=ClientInfoRows > 0,
         then=1,
         else=0
       )
       +
       if(
         condition=UserRows > 0,
         then=1,
         else=0
       )
       +
       if(
         condition=ProcessRows > 0,
         then=1,
         else=0
       )
       +
       if(
         condition=ServiceRows > 0,
         then=1,
         else=0
       )
       +
       if(
         condition=NetworkRows > 0,
         then=1,
         else=0
       )
       +
       if(
         condition=CronRows > 0,
         then=1,
         else=0
       ) AS CollectedSources

FROM CoverageCounts

SELECT ClientId,
       Fqdn,

       if(
         condition=ClientInfoRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[ClientInfoRows]
         ),
         else="No Rows"
       ) AS ClientInformation,

       if(
         condition=UserRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[UserRows]
         ),
         else="No Rows"
       ) AS Users,

       if(
         condition=ProcessRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[ProcessRows]
         ),
         else="No Rows"
       ) AS Processes,

       if(
         condition=ServiceRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[ServiceRows]
         ),
         else="No Rows"
       ) AS Services,

       if(
         condition=NetworkRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[NetworkRows]
         ),
         else="No Rows"
       ) AS Network,

       if(
         condition=CronRows > 0,
         then=format(
           format="Collected (%v rows)",
           args=[CronRows]
         ),
         else="No Rows"
       ) AS Cron,

       CollectedSources,
       6 AS ExpectedSources,

       format(
         format="%v%%",
         args=[CollectedSources * 100 / 6]
       ) AS Coverage,

       if(
         condition=CollectedSources = 6,
         then="Complete",
         else=if(
           condition=CollectedSources >= 4,
           then="Review No-Row Sources",
           else="Incomplete"
         )
       ) AS CollectionStatus

FROM CoverageScore
ORDER BY Fqdn
```

## Cell 6 (markdown)

# Baseline Summary per Client

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SummaryRows <=
SELECT *
FROM chain(
  fleet={
    SELECT ClientId,
           Fqdn,
           "Fleet" AS Dataset,
           1 AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Client_BasicInformation"
    )
    GROUP BY ClientId, Fqdn
  },

  mounts={
    SELECT ClientId,
           Fqdn,
           "Mounts" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Mounts"
    )
    GROUP BY ClientId, Fqdn
  },

  users={
    SELECT ClientId,
           Fqdn,
           "Users" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Users"
    )
    GROUP BY ClientId, Fqdn
  },

  processes={
    SELECT ClientId,
           Fqdn,
           "Processes" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Processes"
    )
    GROUP BY ClientId, Fqdn
  },

  services={
    SELECT ClientId,
           Fqdn,
           "Services" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Services"
    )
    GROUP BY ClientId, Fqdn
  },

  listening_ports={
    SELECT ClientId,
           Fqdn,
           "Listening Ports" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/NetworkConnections"
    )
    WHERE Status =~ "(?i)^LISTEN$"
    GROUP BY ClientId, Fqdn
  },

  established_connections={
    SELECT ClientId,
           Fqdn,
           "Established Connections" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/NetworkConnections"
    )
    WHERE Status =~ "(?i)^ESTABLISHED$"
    GROUP BY ClientId, Fqdn
  },

  cron={
    SELECT ClientId,
           Fqdn,
           "Cron Jobs" AS Dataset,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Crontab"
    )
    GROUP BY ClientId, Fqdn
  }
)

SELECT ClientId,
       Fqdn,

       sum(
         item=if(
           condition=Dataset = "Mounts",
           then=RowCount,
           else=0
         )
       ) AS MountCount,

       sum(
         item=if(
           condition=Dataset = "Users",
           then=RowCount,
           else=0
         )
       ) AS UserCount,

       sum(
         item=if(
           condition=Dataset = "Processes",
           then=RowCount,
           else=0
         )
       ) AS ProcessCount,

       sum(
         item=if(
           condition=Dataset = "Services",
           then=RowCount,
           else=0
         )
       ) AS ServiceCount,

       sum(
         item=if(
           condition=Dataset = "Listening Ports",
           then=RowCount,
           else=0
         )
       ) AS ListeningPortCount,

       sum(
         item=if(
           condition=Dataset = "Established Connections",
           then=RowCount,
           else=0
         )
       ) AS EstablishedConnectionCount,

       sum(
         item=if(
           condition=Dataset = "Cron Jobs",
           then=RowCount,
           else=0
         )
       ) AS CronJobCount

FROM SummaryRows
GROUP BY ClientId, Fqdn
ORDER BY Fqdn
```

## Cell 8 (markdown)

# OS and Kernel Distribution

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT Platform,
       PlatformVersion,
       KernelVersion,
       count() AS HostCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)
GROUP BY Platform, PlatformVersion, KernelVersion
ORDER BY HostCount DESC
```

## Cell 10 (markdown)

# Linux System Information

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET LinuxInfo <=
SELECT ClientId,
       Fqdn,
       `Computer Info` AS ComputerInfo,
       `Network Info` AS NetworkInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_LinuxInfo"
)

SELECT ClientId,
       Fqdn,

       humanize(
         bytes=ComputerInfo.TotalPhysicalMemory
       ) AS TotalMemory,

       humanize(
         bytes=ComputerInfo.TotalFreeMemory
       ) AS FreeMemory,

       humanize(
         bytes=ComputerInfo.TotalSharedMemory
       ) AS SharedMemory,

       humanize(
         bytes=ComputerInfo.TotalSwap
       ) AS TotalSwap,

       humanize(
         bytes=ComputerInfo.FreeSwap
       ) AS FreeSwap,

       join(
         array=NetworkInfo.Name,
         sep=", "
       ) AS NetworkInterfaces,

       join(
         array=NetworkInfo.MACAddress,
         sep=", "
       ) AS MACAddresses,

       join(
         array=NetworkInfo.IPAddresses,
         sep=", "
       ) AS IPAddresses

FROM LinuxInfo
ORDER BY Fqdn
```

## Cell 12 (markdown)

# Mounted Filesystems Inventory

This section reviews mounted filesystems across Linux clients.

Unusual mounts, temporary filesystems, external storage, or unexpected network mounts can indicate abnormal system state, attacker staging, or persistence locations.

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       Device,
       Mount,
       FSType,
       join(
         array=Options,
         sep=", "
       ) AS MountOptions
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Mounts"
)
ORDER BY Fqdn
```

## Cell 14 (markdown)

# Mount Count per Client

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       count() AS MountCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Mounts"
)
GROUP BY ClientId, Fqdn
ORDER BY MountCount DESC
```

## Cell 16 (markdown)

# Users Inventory

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       User,
       Description,
       Uid,
       Gid,
       Homedir,
       Shell
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)
ORDER BY Fqdn
```

## Cell 18 (markdown)

# User Count per Client

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS TotalUsers
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)
GROUP BY ClientId
ORDER BY TotalUsers DESC
```

## Cell 20 (markdown)

# Processes Inventory

This section reviews running processes collected during baseline hunting.

It helps analysts identify unusual process names, execution paths, deleted binaries, suspicious command lines, and abnormal process activity across Linux endpoints.

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       Pid,
       Ppid,
       Name,
       Username,
       Exe,
       CommandLine,
       CreatedTime,
       RSS,
       Deleted
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)
ORDER BY Fqdn
```

## Cell 22 (markdown)

# Process Count per Client

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessCountRows <=
SELECT *
FROM chain(
  fleet={
    SELECT ClientId,
           Fqdn,
           0 AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Client_BasicInformation"
    )
    GROUP BY ClientId
  },

  processes={
    SELECT ClientId,
           Fqdn,
           count() AS RowCount
    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/Processes"
    )
    GROUP BY ClientId
  }
)

LET ProcessCounts <=
SELECT ClientId,
       Fqdn,
       sum(item=RowCount) AS ProcessCount
FROM ProcessCountRows
GROUP BY ClientId

SELECT ClientId,
       Fqdn,
       ProcessCount,
       if(
         condition=ProcessCount > 0,
         then="Collected",
         else="No Rows - Review Collection"
       ) AS CollectionStatus
FROM ProcessCounts
ORDER BY ProcessCount DESC
```

## Cell 24 (markdown)

# Services Inventory

This section reviews Linux services and their current state.

Unexpected active services, suspicious service names, or services related to tunneling, mining, or remote shells should be reviewed further.

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       Unit,
       Load,
       Active,
       Sub,
       Description
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)
ORDER BY Fqdn
```

## Cell 26 (markdown)

# Active Service Count per Client

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       count() AS ActiveServiceCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)
WHERE Active =~ "(?i)^active$"
GROUP BY ClientId
ORDER BY ActiveServiceCount DESC
```

## Cell 28 (markdown)

# Listening Ports Inventory

This section reviews listening network ports and maps them to related processes.

It helps analysts identify unexpected exposed services, suspicious listeners, and processes accepting inbound connections.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       Status,
       Laddr,
       Lport,
       Pid,
       ProcInfo.Name AS ProcessName,
       ProcInfo.Exe AS ProcessPath,
       ProcInfo.Username AS Username,
       ProcInfo.CommandLine AS CommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)
WHERE Status =~ "(?i)^LISTEN$"
ORDER BY Fqdn
```

## Cell 30 (markdown)

# Established Network Connections

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       Status,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ProcInfo.Name AS ProcessName,
       ProcInfo.Exe AS ProcessPath,
       ProcInfo.Username AS Username,
       ProcInfo.CommandLine AS CommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)
WHERE Status =~ "(?i)^ESTABLISHED$"
ORDER BY Fqdn
```

## Cell 32 (markdown)

# Listening Port Count per Client

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       count() AS ListeningPortCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)
WHERE Status =~ "(?i)^LISTEN$"
GROUP BY ClientId
ORDER BY ListeningPortCount DESC
```

## Cell 34 (markdown)

# Cron Jobs Inventory

This section reviews scheduled tasks collected from Linux clients.

Cron jobs are important for baseline hunting because attackers often use scheduled tasks for persistence, command execution, downloaders, or recurring backdoor activity.

## Cell 35 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET CronRows <=
SELECT *
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)
WHERE Command

SELECT ClientId,
       Fqdn,
       User,
       Path,
       Event,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       Command
FROM CronRows
ORDER BY Fqdn
```

## Cell 36 (markdown)

# Cron Job Count per Client

## Cell 37 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET CronRows <=
SELECT *
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)
WHERE Command

SELECT ClientId,
       Fqdn,
       count() AS CronJobCount
FROM CronRows
GROUP BY ClientId
ORDER BY CronJobCount DESC
```

## Cell 38 (markdown)

# Package Inventory

This section reviews installed packages collected from Debian/Ubuntu and RHEL-based systems.

Package baseline helps identify unexpected tools such as scanners, tunneling utilities, password cracking tools, offensive tools, compilers, or miners.

## Cell 39 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET PackageRows <=
SELECT *
FROM chain(
  debian={
    SELECT ClientId,
           Fqdn,

           if(
             condition=get(item=scope(), member="Package"),
             then="dpkg",
             else="snap"
           ) AS PackageManager,

           if(
             condition=get(item=scope(), member="Package"),
             then=get(item=scope(), member="Package"),
             else=if(
               condition=get(item=scope(), member="Name"),
               then=get(item=scope(), member="Name"),
               else=get(item=scope(), member="PackageId")
             )
           ) AS PackageName,

           if(
             condition=get(item=scope(), member="State"),
             then=get(item=scope(), member="State"),
             else=get(item=scope(), member="Status")
           ) AS PackageStatus,

           get(item=scope(), member="Version") AS Version,
           get(item=scope(), member="InstalledSize") AS InstalledSize,
           get(item=scope(), member="Architecture") AS Architecture,

           if(
             condition=get(item=scope(), member="Source"),
             then=get(item=scope(), member="Source"),
             else=get(item=scope(), member="Publisher")
           ) AS SourceOrRepository,

           get(item=scope(), member="Channel") AS Channel

    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/DebianPackages"
    )
  },

  rhel={
    SELECT ClientId,
           Fqdn,
           "dnf/yum" AS PackageManager,
           get(item=scope(), member="Package") AS PackageName,
           "installed" AS PackageStatus,
           get(item=scope(), member="Version") AS Version,
           NULL AS InstalledSize,
           NULL AS Architecture,
           get(item=scope(), member="Repository") AS SourceOrRepository,
           NULL AS Channel

    FROM hunt_results(
      hunt_id=HuntId,
      artifact="LTH.SystemBaseline/RHELPackages"
    )
  }
)

SELECT ClientId,
       Fqdn,
       PackageManager,
       PackageName,
       PackageStatus,
       Version,
       InstalledSize,
       Architecture,
       SourceOrRepository,
       Channel
FROM PackageRows
WHERE PackageName
ORDER BY Fqdn
```
