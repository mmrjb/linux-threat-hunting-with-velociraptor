# LTH - 04 - Processes and Services Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 04 - Processes and Services Dashboard

This notebook analyzes Linux process and service data collected by:

`LTH.ProcessServices`

Main objectives:

- Review running processes across Linux endpoints
- Review active services and service state
- Identify deleted process executables
- Detect process execution from writable or temporary paths
- Identify suspicious command lines
- Review systemd service unit configuration
- Detect suspicious service unit lines
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Processes Inventory — Snapshot Review

This section reviews running processes collected from Linux endpoints.

It helps analysts identify process names, users, execution paths, command lines, parent-child relationships, memory usage, and deleted executables.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

SELECT
  ClientId,
  Fqdn AS EndpointHostname,

  format(
    format="%v:%v",
    args=[ClientId, Pid]
  ) AS ProcessKey,

  Pid,
  Ppid,
  Name,
  Username,
  Exe,
  CommandLine,
  CreatedTime,
  RSS,

  get(
    item=Hash,
    member="SHA256"
  ) AS SHA256,

  Deleted

FROM ProcessResults

ORDER BY
  ClientId
```

## Cell 4 (markdown)

# Process Count per Client — Snapshot Baseline

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

SELECT
  ClientId,
  Fqdn AS EndpointHostname,
  count() AS ObservedProcessCount

FROM ProcessResults

GROUP BY
  ClientId,
  Fqdn

ORDER BY
  ObservedProcessCount DESC
```

## Cell 6 (markdown)

# Top Memory Processes — Snapshot Context

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *,
         atoi(string=RSS) AS RSSBytes
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

SELECT
  ClientId,
  Fqdn AS EndpointHostname,
  Pid,
  Ppid,
  Name,
  Username,
  Exe,
  CommandLine,
  RSSBytes,
  RSSBytes / 1024 / 1024 AS RSSMiB

FROM ProcessResults

WHERE RSSBytes > 0

ORDER BY RSSBytes DESC

LIMIT 100
```

## Cell 8 (markdown)

# Deleted Executable Processes

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

LET DeletedBase <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,

    format(
      format="%v:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,

    Pid,
    Ppid,
    Name,
    Username,
    Exe,
    CommandLine,
    CreatedTime,

    get(
      item=Hash,
      member="SHA256"
    ) AS SHA256,

    Deleted,

    (
      Name =~ "(?i)^lth_deleted_" OR
      Exe =~ "(?i)^/tmp/lth_deleted_" OR
      CommandLine =~ "(?i)^/tmp/lth_deleted_"
    ) AS IsKnownLabTest,

    Exe =~ "(?i)^/(tmp|var/tmp|dev/shm)/"
      AS IsTemporaryPath,

    Exe =~ "(?i)^/(usr/(bin|sbin|lib|libexec)|bin|sbin|lib|lib64)/"
      AS IsSystemPath

  FROM ProcessResults

  WHERE Deleted


SELECT
  ClientId,
  EndpointHostname,
  ProcessKey,
  Pid,
  Ppid,
  Name,
  Username,
  Exe,
  CommandLine,
  CreatedTime,
  SHA256,
  Deleted,

  if(
    condition=IsKnownLabTest,
    then="LAB_TEST_EVIDENCE",
    else="DELETED_EXECUTABLE_PROCESS"
  ) AS FindingClass,

  if(
    condition=IsKnownLabTest,
    then="CONTROLLED_LAB_TEST",
    else=if(
      condition=IsTemporaryPath,
      then="TEMP_PATH_DELETED_EXECUTABLE",
      else=if(
        condition=IsSystemPath,
        then="SYSTEM_BINARY_REPLACEMENT_REVIEW",
        else="NON_BASELINE_PATH_REVIEW"
      )
    )
  ) AS FindingSubtype,

  if(
    condition=IsKnownLabTest,
    then="INFO",
    else=if(
      condition=IsTemporaryPath,
      then="HIGH",
      else="MEDIUM"
    )
  ) AS Severity,

  if(
    condition=IsKnownLabTest,
    then=FALSE,
    else=if(
      condition=IsSystemPath,
      then=FALSE,
      else=TRUE
    )
  ) AS RiskScoreEligible,

  if(
    condition=IsKnownLabTest,
    then="Expected controlled validation process",
    else=if(
      condition=IsTemporaryPath,
      then="Running executable was deleted from a temporary path",
      else=if(
        condition=IsSystemPath,
        then="Deleted system executable requires package and update validation",
        else="Deleted executable from a non-baseline path requires investigation"
      )
    )
  ) AS Reason,

  if(
    condition=IsKnownLabTest,
    then="KNOWN_LAB_TEST",
    else=if(
      condition=IsTemporaryPath,
      then="PRIORITY_INVESTIGATION",
      else=if(
        condition=IsSystemPath,
        then="VALIDATE_PACKAGE_OR_SOFTWARE_REPLACEMENT",
        else="VALIDATE_PATH_OWNER_AND_EXECUTION_CONTEXT"
      )
    )
  ) AS TriageStatus

FROM DeletedBase

ORDER BY
  Severity DESC
```

## Cell 10 (markdown)

# Processes Running from Temporary or User-Controlled Paths

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

LET PathFindings <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,

    format(
      format="%v:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,

    Pid,
    Ppid,
    Name,
    Username,
    Exe,
    CommandLine,
    CreatedTime,

    get(
      item=Hash,
      member="SHA256"
    ) AS SHA256,

    Deleted,

    Exe =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
      AS IsTemporaryPath,

    Exe =~ "(?i)^/run/user/[0-9]+(/|$)"
      AS IsUserRuntimePath,

    Exe =~ "(?i)^/(home|root)(/|$)"
      AS IsHomePath,

    (
      Name =~ "(?i)^lth_(sleep|deleted_sleep)$"
      AND
      Exe =~ "(?i)^/tmp/lth_(sleep|deleted_sleep)( \\(deleted\\))?$"
      AND
      CommandLine =~ "(?i)^/tmp/lth_(sleep|deleted_sleep) 600$"
    ) AS IsKnownLabTest

  FROM ProcessResults

  WHERE Exe =~ "(?i)^/(tmp|var/tmp|dev/shm|run/user/[0-9]+|home|root)(/|$)"


SELECT
  ClientId,
  EndpointHostname,
  ProcessKey,
  Pid,
  Ppid,
  Name,
  Username,
  Exe,
  CommandLine,
  CreatedTime,
  SHA256,
  Deleted,

  if(
    condition=IsTemporaryPath,
    then="TEMPORARY_PATH",
    else=if(
      condition=IsUserRuntimePath,
      then="USER_RUNTIME_PATH",
      else="USER_HOME_PATH"
    )
  ) AS PathCategory,

  if(
    condition=IsKnownLabTest,
    then="LAB_TEST_EVIDENCE",
    else="WRITABLE_OR_TEMP_PATH_PROCESS"
  ) AS FindingClass,

  if(
    condition=IsKnownLabTest,
    then="CONTROLLED_LAB_TEST",
    else=if(
      condition=Deleted AND IsTemporaryPath,
      then="DELETED_TEMPORARY_EXECUTABLE",
      else=if(
        condition=Username =~ "(?i)^root$" AND IsTemporaryPath,
        then="PRIVILEGED_TEMPORARY_EXECUTION",
        else=if(
          condition=IsTemporaryPath,
          then="TEMPORARY_PATH_EXECUTION",
          else=if(
            condition=IsUserRuntimePath,
            then="USER_RUNTIME_EXECUTION",
            else="USER_HOME_EXECUTION"
          )
        )
      )
    )
  ) AS FindingSubtype,

  if(
    condition=IsKnownLabTest,
    then="INFO",
    else=if(
      condition=Deleted AND IsTemporaryPath,
      then="HIGH",
      else=if(
        condition=Username =~ "(?i)^root$" AND IsTemporaryPath,
        then="HIGH",
        else="MEDIUM"
      )
    )
  ) AS Severity,

  if(
    condition=IsKnownLabTest,
    then=FALSE,
    else=if(
      condition=IsTemporaryPath OR IsUserRuntimePath,
      then=TRUE,
      else=FALSE
    )
  ) AS RiskScoreEligible,

  if(
    condition=IsKnownLabTest,
    then="Expected controlled validation process",
    else=if(
      condition=Deleted AND IsTemporaryPath,
      then="Executable ran from a temporary path and was subsequently deleted",
      else=if(
        condition=Username =~ "(?i)^root$" AND IsTemporaryPath,
        then="Privileged process executed from a temporary path",
        else=if(
          condition=IsTemporaryPath,
          then="Process executed from a commonly writable temporary location",
          else="Process executed from a user-controlled location and requires baseline validation"
        )
      )
    )
  ) AS Reason,

  if(
    condition=IsKnownLabTest,
    then="KNOWN_LAB_TEST",
    else=if(
      condition=Deleted,
      then="CORRELATE_WITH_DELETED_EXECUTABLE_PROCESS",
      else=if(
        condition=IsHomePath,
        then="VALIDATE_APPROVED_USER_SOFTWARE",
        else="INVESTIGATE_EXECUTION_ORIGIN"
      )
    )
  ) AS TriageStatus,

  if(
    condition=IsKnownLabTest,
    then=0,
    else=if(
      condition=Deleted AND IsTemporaryPath,
      then=3,
      else=if(
        condition=Username =~ "(?i)^root$" AND IsTemporaryPath,
        then=3,
        else=2
      )
    )
  ) AS TriagePriority

FROM PathFindings

ORDER BY
  TriagePriority DESC
```

## Cell 12 (markdown)

# Suspicious Command Lines

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )


LET CommandSignals <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,

    format(
      format="%v:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,

    Pid,
    Ppid,
    Name,
    Username,
    Exe,
    CommandLine,
    CreatedTime,

    get(
      item=Hash,
      member="SHA256"
    ) AS SHA256,

    Deleted,

    CommandLine =~
      "(?i)/dev/(tcp|udp)/[^[:space:]]+/[0-9]+"
        AS IsReverseShell,

    (
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?(nc|ncat|netcat)([[:space:]]|$).*[[:space:]]-(e|c)([[:space:]]|/)"
      OR
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?socat([[:space:]]|$).*(EXEC|SYSTEM):"
    ) AS IsNetworkShellExecution,

    CommandLine =~
      "(?i)(^|[[:space:]])([^[:space:]]*/)?(xmrig|minerd|cpuminer|cpuminer-multi|ethminer|miner)([[:space:]]|$)"
        AS IsCryptoMinerTool,

    CommandLine =~
      "(?i)(^|[[:space:]])([^[:space:]]*/)?(chisel|ngrok|frpc|frps)([[:space:]]|$)"
        AS IsTunnelTool,

    (
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?(curl|wget)([[:space:]]|$)"
      AND
      CommandLine =~
        "(?i)\\|[[:space:]]*([^[:space:]]*/)?(bash|sh|zsh|ksh)([[:space:]]|$)"
    ) AS IsDownloadPipeShell,

    (
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?base64([[:space:]]|$).*[[:space:]](-d|--decode)([[:space:]]|$)"
      AND
      CommandLine =~
        "(?i)\\|[[:space:]]*([^[:space:]]*/)?(bash|sh|zsh|ksh)([[:space:]]|$)"
    ) AS IsDecodePipeShell,

    (
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?python([0-9]+(\\.[0-9]+)?)?([[:space:]]|$).*[[:space:]]-c([[:space:]]|$)"
      OR
      CommandLine =~
        "(?i)(^|[[:space:]])([^[:space:]]*/)?(perl|ruby)([[:space:]]|$).*[[:space:]]-e([[:space:]]|$)"
    ) AS IsInterpreterOneLiner,

    CommandLine =~
      "(?i)(^|[[:space:]])([^[:space:]]*/)?(bash|sh|zsh|ksh)([[:space:]]|$).*[[:space:]]-i([[:space:]]|$)"
        AS IsInteractiveShell,

    CommandLine =~
      "(?i)(^|[[:space:]])([^[:space:]]*/)?chmod([[:space:]]|$).*\\+x.*(^|[[:space:]])/(tmp|var/tmp|dev/shm)/"
        AS IsTempPathChmod

  FROM ProcessResults

  WHERE CommandLine


LET ClassifiedFindings <=
  SELECT
    *,

    if(
      condition=IsReverseShell,
      then="REVERSE_SHELL_COMMAND",
      else=if(
        condition=IsNetworkShellExecution,
        then="NETWORK_UTILITY_SHELL_EXECUTION",
        else=if(
          condition=IsDownloadPipeShell,
          then="DOWNLOAD_AND_SHELL_EXECUTION",
          else=if(
            condition=IsDecodePipeShell,
            then="DECODE_AND_SHELL_EXECUTION",
            else=if(
              condition=IsCryptoMinerTool,
              then="CRYPTO_MINER_TOOL",
              else=if(
                condition=IsTunnelTool,
                then="TUNNEL_OR_PROXY_TOOL",
                else=if(
                  condition=IsInterpreterOneLiner,
                  then="INTERPRETER_ONE_LINER",
                  else=if(
                    condition=IsTempPathChmod,
                    then="TEMPORARY_FILE_PERMISSION_CHANGE",
                    else="INTERACTIVE_SHELL_REVIEW"
                  )
                )
              )
            )
          )
        )
      )
    ) AS FindingSubtype,

    if(
      condition=(
        IsReverseShell
        OR IsNetworkShellExecution
        OR IsDownloadPipeShell
        OR IsDecodePipeShell
        OR IsCryptoMinerTool
      ),
      then="HIGH",
      else=if(
        condition=(
          IsTunnelTool
          OR IsInterpreterOneLiner
          OR IsTempPathChmod
        ),
        then="MEDIUM",
        else="LOW"
      )
    ) AS Severity,

    if(
      condition=(
        IsReverseShell
        OR IsNetworkShellExecution
        OR IsDownloadPipeShell
        OR IsDecodePipeShell
        OR IsCryptoMinerTool
      ),
      then=TRUE,
      else=FALSE
    ) AS RiskScoreEligible,

    if(
      condition=(
        IsReverseShell
        OR IsNetworkShellExecution
        OR IsDownloadPipeShell
        OR IsDecodePipeShell
        OR IsCryptoMinerTool
      ),
      then=3,
      else=if(
        condition=(
          IsTunnelTool
          OR IsInterpreterOneLiner
          OR IsTempPathChmod
        ),
        then=2,
        else=1
      )
    ) AS TriagePriority

  FROM CommandSignals

  WHERE
    IsReverseShell
    OR IsNetworkShellExecution
    OR IsCryptoMinerTool
    OR IsTunnelTool
    OR IsDownloadPipeShell
    OR IsDecodePipeShell
    OR IsInterpreterOneLiner
    OR IsInteractiveShell
    OR IsTempPathChmod


SELECT
  ClientId,
  EndpointHostname,
  ProcessKey,
  Pid,
  Ppid,
  Name,
  Username,
  Exe,
  CommandLine,
  CreatedTime,
  SHA256,
  Deleted,
  "SUSPICIOUS_COMMAND_LINE" AS FindingClass,
  FindingSubtype,
  Severity,
  RiskScoreEligible,
  TriagePriority,

  if(
    condition=Severity = "HIGH",
    then="High-confidence command-line behavior requires immediate investigation",
    else=if(
      condition=Severity = "MEDIUM",
      then="Potentially dual-use command requires authorization and context validation",
      else="Interactive shell requires session and user-context validation"
    )
  ) AS Reason,

  if(
    condition=Severity = "HIGH",
    then="PRIORITY_INVESTIGATION",
    else=if(
      condition=FindingSubtype = "TUNNEL_OR_PROXY_TOOL",
      then="VALIDATE_AUTHORIZED_REMOTE_ACCESS",
      else="CORRELATE_WITH_PARENT_FILE_NETWORK_AND_LOG_EVIDENCE"
    )
  ) AS TriageStatus

FROM ClassifiedFindings

ORDER BY
  TriagePriority DESC
```

## Cell 14 (markdown)

# Suspicious Process Parent-Child Relationships 

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET ProcessResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )


-- Materialized lookup table for resolving parent processes.
LET ProcessLookup <=
  SELECT
    format(
      format="%v:%v",
      args=[ClientId, Pid]
    ) AS LookupProcessKey,

    Pid AS LookupPid,
    Name AS LookupName,
    Username AS LookupUsername,
    Exe AS LookupExe,
    CommandLine AS LookupCommandLine,
    CreatedTime AS LookupCreatedTime,
    Deleted AS LookupDeleted

  FROM ProcessResults


-- Resolve the parent of each observed child process.
LET ParentResolved <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,

    format(
      format="%v:%v",
      args=[ClientId, Pid]
    ) AS ChildProcessKey,

    format(
      format="%v:%v",
      args=[ClientId, Ppid]
    ) AS ParentProcessKey,

    Pid AS ChildPid,
    Ppid AS ParentPid,
    Name AS ChildName,
    Username AS ChildUsername,
    Exe AS ChildExe,
    CommandLine AS ChildCommandLine,
    CreatedTime AS ChildCreatedTime,

    get(
      item=Hash,
      member="SHA256"
    ) AS ChildSHA256,

    Deleted AS ChildDeleted,

    {
      SELECT
        LookupPid AS ResolvedParentPid,
        LookupName AS ParentName,
        LookupUsername AS ParentUsername,
        LookupExe AS ParentExe,
        LookupCommandLine AS ParentCommandLine,
        LookupCreatedTime AS ParentCreatedTime,
        LookupDeleted AS ParentDeleted

      FROM ProcessLookup

      WHERE LookupProcessKey = format(
        format="%v:%v",
        args=[ClientId, Ppid]
      )

      LIMIT 1
    } AS ParentInfo

  FROM ProcessResults

  WHERE Pid > 0
    AND Ppid > 0


LET Relationships <=
  SELECT
    ClientId,
    EndpointHostname,
    ChildProcessKey,
    ParentProcessKey,

    ParentPid,

    get(
      item=ParentInfo,
      member="ParentName"
    ) AS ParentName,

    get(
      item=ParentInfo,
      member="ParentUsername"
    ) AS ParentUsername,

    get(
      item=ParentInfo,
      member="ParentExe"
    ) AS ParentExe,

    get(
      item=ParentInfo,
      member="ParentCommandLine"
    ) AS ParentCommandLine,

    get(
      item=ParentInfo,
      member="ParentCreatedTime"
    ) AS ParentCreatedTime,

    get(
      item=ParentInfo,
      member="ParentDeleted"
    ) AS ParentDeleted,

    ChildPid,
    ChildName,
    ChildUsername,
    ChildExe,
    ChildCommandLine,
    ChildCreatedTime,
    ChildSHA256,
    ChildDeleted

  FROM ParentResolved

  WHERE get(
    item=ParentInfo,
    member="ParentName"
  )


-- Identify parent and child characteristics.
LET RelationshipAttributes <=
  SELECT
    *,

    ParentName =~
      "(?i)^(nginx|apache2|httpd|lighttpd|caddy|php-fpm([0-9.]*)?)$"
        AS IsWebServiceParent,

    ParentName =~
      "(?i)^(sh|bash|dash|zsh|ksh|fish)$"
        AS IsShellParent,

    ParentName =~
      "(?i)^(systemd|init|cron|crond|atd)$"
        AS IsServiceManagerParent,

    ParentExe =~
      "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
        AS IsTemporaryParent,

    ChildName =~
      "(?i)^(sh|bash|dash|zsh|ksh|fish)$"
        AS IsShellChild,

    ChildName =~
      "(?i)^(python([0-9]+(\\.[0-9]+)?)?|perl|ruby|php|node|lua)$"
        AS IsInterpreterChild,

    ChildName =~
      "(?i)^(nc|ncat|netcat|socat|chisel|ngrok|frpc|frps)$"
        AS IsNetworkToolChild,

    ChildName =~
      "(?i)^(curl|wget)$"
        AS IsDownloaderChild,

    ChildExe =~
      "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
        AS IsTemporaryChild,

    ChildCommandLine =~
      "(?i)(^|[[:space:]])(-o|--output|-p|--directory-prefix)(=|[[:space:]])?/(tmp|var/tmp|dev/shm)(/|[[:space:]]|$)"
        AS DownloadsToTemporaryPath,

    (
      ChildName =~ "(?i)^lth_(sleep|deleted_sleep)$"
      AND
      ChildExe =~
        "(?i)^/tmp/lth_(sleep|deleted_sleep)( \\(deleted\\))?$"
    ) AS IsKnownLabTest

  FROM Relationships


LET RelationshipSignals <=
  SELECT
    *,

    IsWebServiceParent
      AND IsShellChild
        AS IsWebServiceSpawnedShell,

    IsWebServiceParent
      AND (
        IsInterpreterChild
        OR IsNetworkToolChild
        OR IsDownloaderChild
      )
        AS IsWebServiceSpawnedTool,

    IsTemporaryParent
      AND (
        IsShellChild
        OR IsInterpreterChild
        OR IsNetworkToolChild
        OR IsDownloaderChild
      )
        AS IsTemporaryParentSpawnedTool,

    IsShellParent
      AND IsTemporaryChild
        AS IsShellSpawnedTemporaryExecutable,

    IsServiceManagerParent
      AND IsTemporaryChild
        AS IsServiceManagerSpawnedTemporaryExecutable,

    IsShellParent
      AND IsNetworkToolChild
        AS IsShellSpawnedNetworkTool,

    IsShellParent
      AND IsDownloaderChild
      AND DownloadsToTemporaryPath
        AS IsShellDownloadToTemporaryPath

  FROM RelationshipAttributes


LET ClassifiedFindings <=
  SELECT
    *,

    if(
      condition=IsKnownLabTest,
      then="CONTROLLED_LAB_TEST",
      else=if(
        condition=IsWebServiceSpawnedShell,
        then="WEB_SERVICE_SPAWNED_SHELL",
        else=if(
          condition=IsTemporaryParentSpawnedTool,
          then="TEMPORARY_PARENT_SPAWNED_TOOL",
          else=if(
            condition=IsShellSpawnedTemporaryExecutable,
            then="SHELL_SPAWNED_TEMPORARY_EXECUTABLE",
            else=if(
              condition=IsServiceManagerSpawnedTemporaryExecutable,
              then="SERVICE_MANAGER_SPAWNED_TEMPORARY_EXECUTABLE",
              else=if(
                condition=IsWebServiceSpawnedTool,
                then="WEB_SERVICE_SPAWNED_DUAL_USE_TOOL",
                else=if(
                  condition=IsShellSpawnedNetworkTool,
                  then="SHELL_SPAWNED_NETWORK_OR_TUNNEL_TOOL",
                  else="SHELL_DOWNLOAD_TO_TEMPORARY_PATH"
                )
              )
            )
          )
        )
      )
    ) AS FindingSubtype,

    if(
      condition=IsKnownLabTest,
      then="INFO",
      else=if(
        condition=(
          IsWebServiceSpawnedShell
          OR IsTemporaryParentSpawnedTool
          OR IsShellSpawnedTemporaryExecutable
          OR IsServiceManagerSpawnedTemporaryExecutable
        ),
        then="HIGH",
        else="MEDIUM"
      )
    ) AS Severity

  FROM RelationshipSignals

  WHERE
    IsKnownLabTest
    OR IsWebServiceSpawnedShell
    OR IsWebServiceSpawnedTool
    OR IsTemporaryParentSpawnedTool
    OR IsShellSpawnedTemporaryExecutable
    OR IsServiceManagerSpawnedTemporaryExecutable
    OR IsShellSpawnedNetworkTool
    OR IsShellDownloadToTemporaryPath


SELECT
  ClientId,
  EndpointHostname,

  ParentProcessKey,
  ParentPid,
  ParentName,
  ParentUsername,
  ParentExe,
  ParentCommandLine,
  ParentCreatedTime,
  ParentDeleted,

  ChildProcessKey,
  ChildPid,
  ChildName,
  ChildUsername,
  ChildExe,
  ChildCommandLine,
  ChildCreatedTime,
  ChildSHA256,
  ChildDeleted,

  "SUSPICIOUS_PARENT_CHILD_RELATIONSHIP" AS FindingClass,
  FindingSubtype,
  Severity,

  if(
    condition=Severity = "HIGH",
    then=TRUE,
    else=FALSE
  ) AS RiskScoreEligible,

  if(
    condition=Severity = "HIGH",
    then=3,
    else=if(
      condition=Severity = "MEDIUM",
      then=2,
      else=0
    )
  ) AS TriagePriority,

  if(
    condition=IsKnownLabTest,
    then="Expected controlled validation relationship",
    else=if(
      condition=IsWebServiceSpawnedShell,
      then="Web-facing service spawned an interactive or command shell",
      else=if(
        condition=IsTemporaryParentSpawnedTool,
        then="Process running from a temporary path spawned a sensitive tool",
        else=if(
          condition=IsShellSpawnedTemporaryExecutable,
          then="Shell spawned an executable from a temporary location",
          else=if(
            condition=IsServiceManagerSpawnedTemporaryExecutable,
            then="Service manager spawned an executable from a temporary location",
            else="Unusual parent-child relationship requires contextual validation"
          )
        )
      )
    )
  ) AS Reason,

  if(
    condition=IsKnownLabTest,
    then="KNOWN_LAB_TEST",
    else=if(
      condition=Severity = "HIGH",
      then="PRIORITY_INVESTIGATION",
      else="VALIDATE_COMMAND_USER_PATH_AND_NETWORK_CONTEXT"
    )
  ) AS TriageStatus

FROM ClassifiedFindings

ORDER BY
  TriagePriority DESC
```

## Cell 16 (markdown)

# Suspicious Processes — Consolidated Summary

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET SuspiciousRaw <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousProcesses"
  )


LET SuspiciousAttributes <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,

    Pid,
    Ppid,
    Name,
    Username,
    Exe,
    CommandLine,
    CreatedTime,
    Deleted,

    Severity AS ArtifactSeverity,
    Reason AS ArtifactReason,

    (
      Name =~ "(?i)^lth_(sleep|deleted_sleep)$"
      AND
      Exe =~ "(?i)^/tmp/lth_(sleep|deleted_sleep)( \\(deleted\\))?$"
      AND
      CommandLine =~ "(?i)^/tmp/lth_(sleep|deleted_sleep) 600$"
    ) AS IsKnownLabTest,

    (
      Deleted
      OR
      Exe =~ "(?i) \\(deleted\\)$"
      OR
      Reason =~ "(?i)deleted.*executable"
    ) AS IsDeletedExecutable,

    (
      Exe =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
      OR
      Reason =~ "(?i)(temporary|writable).*path"
    ) AS IsTemporaryPathExecution,

    Reason =~
      "(?i)(command.line|reverse[[:space:]]*shell|network[[:space:]]*shell|miner|tunnel|download|decode)"
        AS IsCommandLineFinding,

    Reason =~
      "(?i)(parent.child|parent.*process|spawned)"
        AS IsParentChildFinding,

    Reason =~
      "(?i)(masquerad|name.*mismatch|path.*mismatch|hidden.*process|process.*identity)"
        AS IsIdentityFinding

  FROM SuspiciousRaw


LET ClassifiedBase <=
  SELECT
    *,

    if(
      condition=IsKnownLabTest,
      then="CONTROLLED_LAB_TEST",
      else=if(
        condition=IsDeletedExecutable,
        then="DELETED_EXECUTABLE_PROCESS",
        else=if(
          condition=IsTemporaryPathExecution,
          then="TEMPORARY_OR_WRITABLE_PATH_EXECUTION",
          else=if(
            condition=IsCommandLineFinding,
            then="SUSPICIOUS_COMMAND_LINE",
            else=if(
              condition=IsParentChildFinding,
              then="SUSPICIOUS_PARENT_CHILD_RELATIONSHIP",
              else=if(
                condition=IsIdentityFinding,
                then="PROCESS_IDENTITY_ANOMALY",
                else="ARTIFACT_DEFINED_SUSPICIOUS_PROCESS"
              )
            )
          )
        )
      )
    ) AS FindingSubtype,

    if(
      condition=IsKnownLabTest,
      then="INFO",
      else=if(
        condition=ArtifactSeverity =~ "(?i)^critical$",
        then="CRITICAL",
        else=if(
          condition=ArtifactSeverity =~ "(?i)^high$",
          then="HIGH",
          else=if(
            condition=ArtifactSeverity =~ "(?i)^medium$",
            then="MEDIUM",
            else=if(
              condition=ArtifactSeverity =~ "(?i)^low$",
              then="LOW",
              else="MEDIUM"
            )
          )
        )
      )
    ) AS NormalizedSeverity

  FROM SuspiciousAttributes


LET ClassifiedFindings <=
  SELECT
    *,

    if(
      condition=NormalizedSeverity = "CRITICAL",
      then=4,
      else=if(
        condition=NormalizedSeverity = "HIGH",
        then=3,
        else=if(
          condition=NormalizedSeverity = "MEDIUM",
          then=2,
          else=if(
            condition=NormalizedSeverity = "LOW",
            then=1,
            else=0
          )
        )
      )
    ) AS TriagePriority,

    if(
      condition=IsKnownLabTest,
      then="KNOWN_LAB_TEST",
      else=if(
        condition=NormalizedSeverity =~ "(?i)^(critical|high)$",
        then="PIVOT_TO_DETAILED_EVIDENCE",
        else="REVIEW_ARTIFACT_REASON_AND_BASELINE"
      )
    ) AS TriageStatus

  FROM ClassifiedBase


SELECT
  ClientId,
  EndpointHostname,

  "SUSPICIOUS_PROCESS_SUMMARY" AS FindingClass,
  FindingSubtype,

  NormalizedSeverity AS Severity,
  TriagePriority,

  count() AS FindingCount,

  FALSE AS RiskScoreEligible,

  "Summary only; score findings in the corresponding detailed evidence cell"
    AS RiskScorePolicy,

  TriageStatus

FROM ClassifiedFindings

GROUP BY
  ClientId,
  EndpointHostname,
  FindingSubtype,
  NormalizedSeverity,
  TriagePriority,
  TriageStatus

ORDER BY
  TriagePriority DESC
```

## Cell 18 (markdown)

# Services Inventory

This section reviews Linux services and their current state.

Unexpected active services, suspicious service names, or services related to tunneling, mining, reverse shells, or backdoors should be reviewed further.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET ServiceResults <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Services"
  )


SELECT
  ClientId,

  format(
    format="%v:%v",
    args=[ClientId, Unit]
  ) AS ServiceKey,

  Unit,
  Load,
  Active,
  Sub,
  Description,

  if(
    condition=Active = "failed" OR Sub = "failed",
    then="FAILED",
    else=if(
      condition=Load =~ "(?i)^(not-found|error|bad-setting)$",
      then="LOAD_ERROR",
      else=if(
        condition=Active = "active" AND Sub = "running",
        then="ACTIVE_RUNNING",
        else=if(
          condition=Active = "active" AND Sub = "exited",
          then="ACTIVE_COMPLETED",
          else=if(
            condition=Active = "inactive",
            then="INACTIVE",
            else="OTHER"
          )
        )
      )
    )
  ) AS StateCategory,

  if(
    condition=(
      Active = "failed"
      OR Sub = "failed"
      OR Load =~ "(?i)^(not-found|error|bad-setting)$"
    ),
    then=TRUE,
    else=FALSE
  ) AS OperationalReviewRequired,

  "SERVICE_INVENTORY" AS FindingClass,

  FALSE AS RiskScoreEligible,

  if(
    condition=Active = "failed" OR Sub = "failed",
    then="REVIEW_SERVICE_FAILURE",
    else=if(
      condition=Load =~ "(?i)^(not-found|error|bad-setting)$",
      then="REVIEW_SERVICE_LOAD_ERROR",
      else=if(
        condition=Active = "active",
        then="BASELINE_ACTIVE_SERVICE",
        else="INVENTORY_ONLY"
      )
    )
  ) AS TriageStatus

FROM ServiceResults

ORDER BY
  ClientId
```

## Cell 20 (markdown)

# Active Service Count per Client

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET ActiveServices <=
  SELECT
    ClientId,
    Unit,
    Load,
    Active,
    Sub,
    Description

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Services"
  )

  WHERE Active =~ "(?i)^active$"


SELECT
  ClientId,

  count() AS ActiveServiceCount,

  "ACTIVE_SERVICE_COUNT" AS MetricType,

  FALSE AS RiskScoreEligible,

  "BASELINE_METRIC" AS TriageStatus

FROM ActiveServices

GROUP BY ClientId

ORDER BY ActiveServiceCount DESC
```

## Cell 22 (markdown)

# Service Unit Execution Configuration — Review View

This section reviews important systemd service unit configuration lines.

It focuses on execution commands, service users, working directories, environment variables, and restart behavior that may be relevant for service-based persistence or suspicious execution.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ProcessServices/ServiceUnitConfig"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Suspicious Service Unit Lines

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET ServiceUnitRaw <=
  SELECT
    ClientId,
    Path,
    Line,
    Severity AS ArtifactSeverity,
    Reason AS ArtifactReason

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServiceUnitLines"
  )

  WHERE Path
    AND Line


LET ServiceUnitAttributes <=
  SELECT
    ClientId,
    Path,
    Line,
    ArtifactSeverity,
    ArtifactReason,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*='''
        AS IsExecutionDirective,

    Line =~
      '''(?i)^[[:space:]]*(Environment|EnvironmentFile)[[:space:]]*='''
        AS IsEnvironmentDirective,

    Path =~
      '''(?i)^(/home/[^/]+|/root)/[.]config/systemd/user/'''
        AS IsUserUnitLocation,

    Path =~
      '''(?i)^/run/user/[0-9]+/systemd/'''
        AS IsRuntimeUserUnitLocation,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(tmp|var/tmp|dev/shm|run/user/[0-9]+)(/|[[:space:]]|$)'''
        AS IsTemporaryPathExecution,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(usr/)?bin/(sh|bash|dash|zsh|ksh)[[:space:]].*-[[:alnum:]]*c[[:space:]].*(/tmp/|/var/tmp/|/dev/shm/|/run/user/|/dev/(tcp|udp)/|curl|wget|ncat|netcat|socat|base64|authorized_keys|useradd|usermod|setcap)'''
        AS IsSuspiciousShellChain,

    Line =~
      '''(?i)(curl|wget).*(\[|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadPipeToShell,

    Line =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|bash[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(nc|ncat|netcat|socat|chisel|ngrok|frpc|frps)([[:space:]]|$)'''
        AS IsNetworkOrTunnelTool,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(curl|wget)([[:space:]]|$)'''
        AS IsDirectDownloader,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(python([0-9]+([.][0-9]+)?)?|perl|ruby|php|node|lua)[[:space:]].*([[:space:]]-(c|e|r))([[:space:]]|$)'''
        AS IsInlineInterpreter,

    Line =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d)'''
        AS IsEncodedExecution,

    Line =~
      '''(?i)(authorized_keys|/etc/sudoers|(^|[[:space:]])(useradd|usermod|passwd|setcap)([[:space:]]|$)|chmod[[:space:]]+([uU][+])?[sS])'''
        AS IsAccountOrPrivilegeChange,

    Line =~
      '''(?i)^[[:space:]]*Environment[[:space:]]*=.*(LD_PRELOAD[[:space:]]*=|LD_LIBRARY_PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm)|PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm))'''
        AS IsDangerousEnvironment,

    Line =~
      '''(?i)^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*-?/(tmp|var/tmp|dev/shm)(/|[[:space:]]|$)'''
        AS IsTemporaryEnvironmentFile

  FROM ServiceUnitRaw


LET CandidateFindings <=
  SELECT *

  FROM ServiceUnitAttributes

  WHERE
    IsTemporaryPathExecution
    OR IsSuspiciousShellChain
    OR IsDownloadPipeToShell
    OR IsReverseShellSyntax
    OR IsNetworkOrTunnelTool
    OR IsDirectDownloader
    OR IsInlineInterpreter
    OR IsEncodedExecution
    OR IsAccountOrPrivilegeChange
    OR IsDangerousEnvironment
    OR IsTemporaryEnvironmentFile
    OR (
      IsExecutionDirective
      AND (
        IsUserUnitLocation
        OR IsRuntimeUserUnitLocation
      )
    )


LET ClassifiedFindings <=
  SELECT
    *,

    if(
      condition=IsReverseShellSyntax,
      then="REVERSE_SHELL_SYNTAX",
      else=if(
        condition=IsDownloadPipeToShell,
        then="DOWNLOAD_AND_SHELL_EXECUTION",
        else=if(
          condition=IsTemporaryPathExecution,
          then="TEMPORARY_PATH_EXECUTION",
          else=if(
            condition=IsNetworkOrTunnelTool,
            then="NETWORK_OR_TUNNEL_TOOL_SERVICE",
            else=if(
              condition=IsSuspiciousShellChain,
              then="SUSPICIOUS_SHELL_COMMAND_CHAIN",
              else=if(
                condition=IsAccountOrPrivilegeChange,
                then="ACCOUNT_OR_PRIVILEGE_MODIFICATION",
                else=if(
                  condition=IsDangerousEnvironment OR IsTemporaryEnvironmentFile,
                  then="SUSPICIOUS_SERVICE_ENVIRONMENT",
                  else=if(
                    condition=IsEncodedExecution,
                    then="ENCODED_OR_DECODED_EXECUTION",
                    else=if(
                      condition=IsDirectDownloader,
                      then="DIRECT_DOWNLOADER_EXECUTION",
                      else=if(
                        condition=IsInlineInterpreter,
                        then="INLINE_INTERPRETER_EXECUTION",
                        else="USER_OR_RUNTIME_SERVICE_EXECUTION"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS FindingSubtype,

    if(
      condition=IsReverseShellSyntax OR IsDownloadPipeToShell,
      then="CRITICAL",
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsSuspiciousShellChain
          OR IsNetworkOrTunnelTool
          OR IsAccountOrPrivilegeChange
          OR IsDangerousEnvironment
          OR IsTemporaryEnvironmentFile
        ),
        then="HIGH",
        else="MEDIUM"
      )
    ) AS NormalizedSeverity

  FROM CandidateFindings


LET PrioritizedFindings <=
  SELECT
    *,

    if(
      condition=NormalizedSeverity = "CRITICAL",
      then=4,
      else=if(
        condition=NormalizedSeverity = "HIGH",
        then=3,
        else=2
      )
    ) AS TriagePriority

  FROM ClassifiedFindings


SELECT
  ClientId,

  format(
    format="%v:%v",
    args=[ClientId, Path]
  ) AS ServiceUnitKey,

  Path,
  Line,

  "SUSPICIOUS_SERVICE_UNIT_CONFIGURATION" AS FindingClass,
  FindingSubtype,
  NormalizedSeverity AS Severity,
  TriagePriority,

  if(
    condition=NormalizedSeverity =~ "^(CRITICAL|HIGH)$",
    then=TRUE,
    else=FALSE
  ) AS RiskScoreEligible,

  format(
    format="%v:%v",
    args=[ClientId, Path]
  ) AS RiskScoreKey,

  "Score a maximum of one finding per service unit using its highest severity"
    AS RiskScorePolicy,

  ArtifactSeverity,
  ArtifactReason,

  if(
    condition=NormalizedSeverity = "CRITICAL",
    then="IMMEDIATE_INVESTIGATION",
    else=if(
      condition=NormalizedSeverity = "HIGH",
      then="PRIORITY_INVESTIGATION",
      else="VALIDATE_OWNER_PACKAGE_PATH_HASH_AND_COMMAND"
    )
  ) AS TriageStatus

FROM PrioritizedFindings

ORDER BY
  TriagePriority DESC
```

## Cell 26 (markdown)

# Suspicious Services

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"


LET ServiceRaw <=
  SELECT
    ClientId,
    Unit,
    Load,
    Active,
    Sub,
    Description,
    Severity AS ArtifactSeverity,
    Reason AS ArtifactReason

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServices"
  )

  WHERE Unit =~ ".+"


LET ServiceAttributes <=
  SELECT
    *,

    (
      Load =~ "(?i)^loaded$"
      AND
      (
        (
          Unit =~ "(?i)^irqbalance[.]service$"
          AND
          Description =~ "(?i)^irqbalance daemon$"
        )
        OR
        (
          Unit =~ "(?i)^ssh[.]service$"
          AND
          Description =~ "(?i)^OpenBSD Secure Shell server$"
        )
        OR
        (
          Unit =~ "(?i)^systemd-timesyncd[.]service$"
          AND
          Description =~ "(?i)^Network Time Synchronization$"
        )
        OR
        (
          Unit =~ "(?i)^ufw[.]service$"
          AND
          Description =~ "(?i)^Uncomplicated firewall$"
        )
      )
    ) AS IsExpectedBaselineSignature,

    Unit =~
      '''(?i)^(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|miner)([-_.@][^.]+)?[.]service$'''
        AS IsMinerServiceName,

    Unit =~
      '''(?i)^(chisel|ligolo|ligolo-proxy|ligolo-agent|ngrok|frpc|frps|gost|dnscat2|iodine|socat|netcat|ncat)([-_.@][^.]+)?[.]service$'''
        AS IsTunnelOrRelayName,

    Unit =~
      '''(?i)^(reverse[-_.]?shell|bind[-_.]?shell|backdoor|rootshell|c2|c2[-_.]agent|c2[-_.]beacon)([-_.@][^.]+)?[.]service$'''
        AS IsBackdoorServiceName,

    Description =~
      '''(?i)(reverse[[:space:]_-]*shell|bind[[:space:]_-]*shell|cryptocurrency[[:space:]_-]*miner|crypto[[:space:]_-]*miner|command[[:space:]_-]*and[[:space:]_-]*control|c2[[:space:]_-]*(agent|beacon)|backdoor)'''
        AS IsStrongSuspiciousDescription,

    Unit =~
      '''(?i)^[.][^/]+[.]service$'''
        AS IsHiddenLookingUnit

  FROM ServiceRaw


LET ClassifiedServices <=
  SELECT
    *,

    if(
      condition=IsExpectedBaselineSignature,
      then="EXPECTED_BASELINE_SERVICE",
      else=if(
        condition=IsBackdoorServiceName,
        then="BACKDOOR_OR_REMOTE_SHELL_SERVICE_NAME",
        else=if(
          condition=IsMinerServiceName,
          then="CRYPTO_MINER_SERVICE_NAME",
          else=if(
            condition=IsTunnelOrRelayName,
            then="TUNNEL_OR_RELAY_SERVICE_NAME",
            else=if(
              condition=IsStrongSuspiciousDescription,
              then="STRONG_SUSPICIOUS_DESCRIPTION",
              else=if(
                condition=IsHiddenLookingUnit,
                then="HIDDEN_LOOKING_SERVICE_NAME",
                else="UNVERIFIED_ARTIFACT_MATCH"
              )
            )
          )
        )
      )
    ) AS FindingSubtype,

    if(
      condition=IsExpectedBaselineSignature,
      then="INFO",
      else=if(
        condition=(
          IsBackdoorServiceName
          OR IsMinerServiceName
          OR IsStrongSuspiciousDescription
          OR IsHiddenLookingUnit
        ),
        then="HIGH",
        else=if(
          condition=IsTunnelOrRelayName,
          then="MEDIUM",
          else="LOW"
        )
      )
    ) AS NormalizedSeverity

  FROM ServiceAttributes


LET PrioritizedServices <=
  SELECT
    *,

    if(
      condition=NormalizedSeverity = "HIGH",
      then=3,
      else=if(
        condition=NormalizedSeverity = "MEDIUM",
        then=2,
        else=if(
          condition=NormalizedSeverity = "LOW",
          then=1,
          else=0
        )
      )
    ) AS TriagePriority,

    if(
      condition=IsExpectedBaselineSignature,
      then="EXPECTED_BASELINE_NO_ACTION",
      else=if(
        condition=NormalizedSeverity = "HIGH",
        then="PIVOT_TO_SERVICE_UNIT_CONFIG_IMMEDIATELY",
        else=if(
          condition=IsTunnelOrRelayName,
          then="VALIDATE_TOOL_OWNER_PATH_AND_APPROVAL",
          else="REVIEW_ARTIFACT_MATCH_AND_EXECSTART"
        )
      )
    ) AS TriageStatus

  FROM ClassifiedServices


SELECT
  ClientId,

  format(
    format="%v:%v",
    args=[ClientId, Unit]
  ) AS ServiceReviewKey,

  Unit,
  Load,
  Active,
  Sub,
  Description,

  "SUSPICIOUS_SERVICE_IDENTITY" AS FindingClass,
  FindingSubtype,
  NormalizedSeverity AS Severity,
  TriagePriority,

  "SUPPORTING" AS TelemetryCompatibility,

  FALSE AS RiskScoreEligible,

  "Service name and description are supporting indicators only; score confirmed behavior in the service execution configuration cell"
    AS RiskScorePolicy,

  ArtifactSeverity,
  ArtifactReason,
  TriageStatus

FROM PrioritizedServices

WHERE TriagePriority > 0

ORDER BY
  TriagePriority DESC
```

## Cell 28 (markdown)

# Process and Service Collection Coverage

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"


-- One flow represents the collection executed for each client.
LET HuntClients <=
  SELECT
    Flow.client_id AS CoverageClientId,
    Flow.session_id AS FlowId,
    Flow.state AS FlowState

  FROM hunt_flows(hunt_id=HuntId)

  WHERE Flow.client_id

  GROUP BY CoverageClientId


-- ============================================================
-- Row counts per artifact source and client
-- ============================================================

LET ProcessCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

  GROUP BY ClientId


LET SuspiciousProcessCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousProcesses"
  )

  GROUP BY ClientId


LET ServiceCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Services"
  )

  GROUP BY ClientId


LET ServiceConfigCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/ServiceUnitConfig"
  )

  GROUP BY ClientId


LET SuspiciousUnitLineCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServiceUnitLines"
  )

  GROUP BY ClientId


LET SuspiciousServiceCounts <=
  SELECT
    ClientId AS CountClientId,
    count() AS SourceRows

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServices"
  )

  GROUP BY ClientId


-- ============================================================
-- Create one coverage row for every source on every client
-- ============================================================

LET CoverageBase <=
  SELECT *

  FROM foreach(
    row=HuntClients,
    query={
      SELECT *

      FROM chain(
        Processes={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/Processes" AS ArtifactSource,
            "PROCESS_INVENTORY" AS CollectionArea,
            "BASELINE_REQUIRED" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM ProcessCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM ProcessCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        },

        SuspiciousProcesses={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/SuspiciousProcesses" AS ArtifactSource,
            "SUSPICIOUS_PROCESS_DETECTION" AS CollectionArea,
            "DETECTION_OUTPUT" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM SuspiciousProcessCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM SuspiciousProcessCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        },

        Services={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/Services" AS ArtifactSource,
            "SERVICE_INVENTORY" AS CollectionArea,
            "BASELINE_REQUIRED" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM ServiceCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM ServiceCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        },

        ServiceUnitConfig={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/ServiceUnitConfig" AS ArtifactSource,
            "SERVICE_UNIT_CONFIGURATION" AS CollectionArea,
            "BASELINE_REQUIRED" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM ServiceConfigCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM ServiceConfigCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        },

        SuspiciousServiceUnitLines={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/SuspiciousServiceUnitLines"
              AS ArtifactSource,

            "SUSPICIOUS_SERVICE_CONFIGURATION"
              AS CollectionArea,

            "DETECTION_OUTPUT" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM SuspiciousUnitLineCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM SuspiciousUnitLineCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        },

        SuspiciousServices={
          SELECT
            CoverageClientId AS ClientId,
            FlowId,
            FlowState,

            "LTH.ProcessServices/SuspiciousServices" AS ArtifactSource,
            "SUSPICIOUS_SERVICE_IDENTITY" AS CollectionArea,
            "DETECTION_OUTPUT" AS SourceRole,

            if(
              condition={
                SELECT *
                FROM SuspiciousServiceCounts
                WHERE CountClientId = CoverageClientId
              },
              then={
                SELECT SourceRows
                FROM SuspiciousServiceCounts
                WHERE CountClientId = CoverageClientId
              },
              else=0
            ) AS RowCount

          FROM scope()
        }
      )
    }
  )


-- ============================================================
-- Final coverage classification
-- ============================================================

SELECT
  ClientId,
  FlowId,
  FlowState,
  CollectionArea,
  ArtifactSource,
  SourceRole,
  RowCount,

  if(
    condition=FlowState =~ "(?i)(error|failed)",
    then="FLOW_ERROR",
    else=if(
      condition=RowCount > 0,
      then=if(
        condition=SourceRole = "DETECTION_OUTPUT",
        then="FINDINGS_RETURNED",
        else="COLLECTED_WITH_DATA"
      ),
      else=if(
        condition=SourceRole = "BASELINE_REQUIRED",
        then="NO_BASELINE_DATA_REVIEW_REQUIRED",
        else=if(
          condition=FlowState =~ "(?i)(finished|completed)",
          then="NO_FINDINGS_RETURNED",
          else="COLLECTION_NOT_CONFIRMED"
        )
      )
    )
  ) AS CoverageStatus,

  if(
    condition=(
      FlowState =~ "(?i)(error|failed)"
      OR (
        SourceRole = "BASELINE_REQUIRED"
        AND RowCount = 0
      )
    ),
    then=3,
    else=if(
      condition=(
        SourceRole = "DETECTION_OUTPUT"
        AND RowCount > 0
      ),
      then=2,
      else=0
    )
  ) AS ReviewPriority,

  "COLLECTION_COVERAGE" AS MetricClass,

  FALSE AS RiskScoreEligible,

  if(
    condition=FlowState =~ "(?i)(error|failed)",
    then="REVIEW_CLIENT_FLOW_AND_COLLECTION_LOGS",
    else=if(
      condition=(
        SourceRole = "BASELINE_REQUIRED"
        AND RowCount = 0
      ),
      then="INVESTIGATE_MISSING_BASELINE_RESULTS",
      else=if(
        condition=(
          SourceRole = "DETECTION_OUTPUT"
          AND RowCount > 0
        ),
        then="REVIEW_RETURNED_FINDINGS",
        else="COVERAGE_OK"
      )
    )
  ) AS TriageStatus

FROM CoverageBase

ORDER BY
  ReviewPriority DESC
```

## Cell 30 (markdown)

# Clients Needing Investigation

This section summarizes process and service-related findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when deleted executables, temporary path execution, suspicious services, or suspicious systemd unit lines are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Process behavior analysis
-- ============================================================

LET ProcessRaw <=
  SELECT
    ClientId,
    Pid,
    Name,
    Exe,
    CommandLine,
    Deleted

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

  WHERE Pid


LET ProcessSignals <=
  SELECT
    *,

    format(
      format="%v:PROCESS:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,


    Deleted AS IsDeletedExecutable,


    Exe =~
      '''(?i)^/(tmp|var/tmp|dev/shm)/'''
        AS IsTemporaryPathExecution,


    (
      Exe =~
        '''(?i)(^|/)(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''

      OR

      Name =~
        '''(?i)^(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''
    ) AS IsMinerOrTunnelTool,


    CommandLine =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|/(usr/)?bin/(bash|sh|dash|zsh|ksh)[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,


    CommandLine =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,


    CommandLine =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d).*([|]|;|&&).*(sh|bash|dash|zsh|ksh|chmod|/tmp/|/var/tmp/|/dev/shm/)'''
        AS IsEncodedExecutionChain,


    CommandLine =~
      '''(?i)(python([0-9]+([.][0-9]+)?)?[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|php[[:space:]]+-r|node[[:space:]]+-e).*(socket|connect|http|/tmp/|/var/tmp/|/dev/shm/|subprocess|system|exec|base64)'''
        AS IsSuspiciousInterpreterChain

  FROM ProcessRaw


LET ProcessCandidates <=
  SELECT
    ClientId,
    ProcessKey,

    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsMinerOrTunnelTool
          OR IsEncodedExecutionChain
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight

  FROM ProcessSignals

  WHERE
    IsDeletedExecutable
    OR IsTemporaryPathExecution
    OR IsMinerOrTunnelTool
    OR IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsEncodedExecutionChain
    OR IsSuspiciousInterpreterChain


-- One finding per process using its highest weight.
LET ProcessEvidence <=
  SELECT
    ClientId,
    ProcessKey AS FindingKey,
    "PROCESS_BEHAVIOR" AS FindingClass,
    max(item=FindingWeight) AS FindingWeight

  FROM ProcessCandidates

  GROUP BY ProcessKey


-- ============================================================
-- 2. Context-aware service-unit behavior analysis
-- ============================================================

LET ServiceUnitRaw <=
  SELECT
    ClientId,
    Path,
    Line

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServiceUnitLines"
  )

  WHERE Path
    AND Line


LET ServiceUnitSignals <=
  SELECT
    *,

    format(
      format="%v:SERVICE_UNIT:%v",
      args=[ClientId, Path]
    ) AS ServiceUnitKey,


    Line =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|bash[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,


    Line =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(tmp|var/tmp|dev/shm|run/user/[0-9]+)(/|[[:space:]]|$)'''
        AS IsTemporaryPathExecution,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(nc|ncat|netcat|socat|chisel|ngrok|frpc|frps|ligolo|gost|dnscat2|iodine)([[:space:]]|$)'''
        AS IsNetworkOrTunnelTool,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(usr/)?bin/(sh|bash|dash|zsh|ksh)[[:space:]].*-[[:alnum:]]*c[[:space:]].*(/tmp/|/var/tmp/|/dev/shm/|/run/user/|curl|wget|base64|authorized_keys|useradd|usermod|setcap)'''
        AS IsSuspiciousShellChain,


    Line =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d)'''
        AS IsEncodedExecution,


    Line =~
      '''(?i)(authorized_keys|/etc/sudoers|(^|[[:space:]])(useradd|usermod|passwd|setcap)([[:space:]]|$)|chmod[[:space:]]+([uU][+])?[sS])'''
        AS IsPrivilegeModification,


    Line =~
      '''(?i)^[[:space:]]*Environment[[:space:]]*=.*(LD_PRELOAD[[:space:]]*=|LD_LIBRARY_PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm)|PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm))'''
        AS IsDangerousEnvironment,


    Line =~
      '''(?i)^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*-?/(tmp|var/tmp|dev/shm)(/|[[:space:]]|$)'''
        AS IsTemporaryEnvironmentFile,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(curl|wget)([[:space:]]|$)'''
        AS IsDirectDownloader,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(python([0-9]+([.][0-9]+)?)?|perl|ruby|php|node|lua)[[:space:]].*([[:space:]]-(c|e|r))([[:space:]]|$)'''
        AS IsInlineInterpreter

  FROM ServiceUnitRaw


LET ServiceUnitCandidates <=
  SELECT
    ClientId,
    ServiceUnitKey,

    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsNetworkOrTunnelTool
          OR IsSuspiciousShellChain
          OR IsEncodedExecution
          OR IsPrivilegeModification
          OR IsDangerousEnvironment
          OR IsTemporaryEnvironmentFile
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight

  FROM ServiceUnitSignals

  WHERE
    IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsTemporaryPathExecution
    OR IsNetworkOrTunnelTool
    OR IsSuspiciousShellChain
    OR IsEncodedExecution
    OR IsPrivilegeModification
    OR IsDangerousEnvironment
    OR IsTemporaryEnvironmentFile
    OR IsDirectDownloader
    OR IsInlineInterpreter


-- One finding per service unit using its highest weight.
LET ServiceUnitEvidence <=
  SELECT
    ClientId,
    ServiceUnitKey AS FindingKey,
    "SERVICE_UNIT_BEHAVIOR" AS FindingClass,
    max(item=FindingWeight) AS FindingWeight

  FROM ServiceUnitCandidates

  GROUP BY ServiceUnitKey


-- ============================================================
-- 3. Merge deduplicated evidence
-- ============================================================

LET DeduplicatedFindings <=
  SELECT *

  FROM chain(
    ProcessFindings=ProcessEvidence,
    ServiceUnitFindings=ServiceUnitEvidence
  )


-- ============================================================
-- 4. Aggregate findings per client
-- ============================================================

LET ClientSummary <=
  SELECT
    ClientId,

    count() AS DeduplicatedFindingCount,

    sum(
      item=if(
        condition=FindingClass = "PROCESS_BEHAVIOR",
        then=1,
        else=0
      )
    ) AS ProcessFindingCount,

    sum(
      item=if(
        condition=FindingClass = "SERVICE_UNIT_BEHAVIOR",
        then=1,
        else=0
      )
    ) AS ServiceUnitFindingCount,

    sum(
      item=if(
        condition=FindingWeight = 4,
        then=1,
        else=0
      )
    ) AS CriticalCount,

    sum(
      item=if(
        condition=FindingWeight = 3,
        then=1,
        else=0
      )
    ) AS HighCount,

    sum(
      item=if(
        condition=FindingWeight = 2,
        then=1,
        else=0
      )
    ) AS MediumCount,

    max(item=FindingWeight) AS HighestWeight

  FROM DeduplicatedFindings

  GROUP BY ClientId


LET ClassifiedSummary <=
  SELECT
    *,

    CriticalCount + HighCount
      AS RiskScoreEligibleFindingCount,

    if(
      condition=HighestWeight = 4,
      then="CRITICAL",
      else=if(
        condition=HighestWeight = 3,
        then="HIGH",
        else="MEDIUM"
      )
    ) AS HighestSeverity

  FROM ClientSummary


-- ============================================================
-- 5. Final investigation summary
-- ============================================================

SELECT
  ClientId,
  DeduplicatedFindingCount,
  ProcessFindingCount,
  ServiceUnitFindingCount,
  CriticalCount,
  HighCount,
  MediumCount,
  RiskScoreEligibleFindingCount,
  HighestSeverity,

  "PROCESS_AND_SERVICE_TRIAGE_SUMMARY"
    AS FindingClass,

  FALSE AS RiskScoreEligible,

  "This summary must not itself be scored; score its deduplicated High and Critical evidence records"
    AS RiskScorePolicy,

  if(
    condition=CriticalCount > 0,
    then="IMMEDIATE_INVESTIGATION",
    else=if(
      condition=HighCount > 0,
      then="PRIORITY_INVESTIGATION",
      else="CONTEXTUAL_REVIEW"
    )
  ) AS TriageStatus

FROM ClassifiedSummary

ORDER BY
  HighestWeight DESC
```

## Cell 32 (markdown)

# Final Findings Detail — Deduplicated Actionable Evidence

This table presents one actionable evidence record per process PID or service-unit path. Findings are classified using behavior-aware detection logic, deduplicated by entity, and assigned severity based on the strongest observed signal. Only High and Critical findings are eligible for the Master Risk Score.

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Process inventory
-- ============================================================

LET ProcessRaw <=
  SELECT
    ClientId,
    Pid,
    Name,
    Exe,
    CommandLine,
    Deleted

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

  WHERE Pid


-- ============================================================
-- 2. Process behavior signals
-- ============================================================

LET ProcessSignals <=
  SELECT
    *,

    format(
      format="%v:PROCESS:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,


    Deleted AS IsDeletedExecutable,


    Exe =~
      '''(?i)^/(tmp|var/tmp|dev/shm)/'''
        AS IsTemporaryPathExecution,


    (
      Exe =~
        '''(?i)(^|/)(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''

      OR

      Name =~
        '''(?i)^(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''
    ) AS IsMinerOrTunnelTool,


    CommandLine =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|/(usr/)?bin/(bash|sh|dash|zsh|ksh)[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,


    CommandLine =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,


    CommandLine =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d).*([|]|;|&&).*(sh|bash|dash|zsh|ksh|chmod|/tmp/|/var/tmp/|/dev/shm/)'''
        AS IsEncodedExecutionChain,


    CommandLine =~
      '''(?i)(python([0-9]+([.][0-9]+)?)?[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|php[[:space:]]+-r|node[[:space:]]+-e).*(socket|connect|http|/tmp/|/var/tmp/|/dev/shm/|subprocess|system|exec|base64)'''
        AS IsSuspiciousInterpreterChain

  FROM ProcessRaw


-- ============================================================
-- 3. Classify process findings
-- ============================================================

LET ProcessCandidates <=
  SELECT
    ClientId,
    ProcessKey,
    Pid,
    Name,
    Exe,
    CommandLine,


    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsMinerOrTunnelTool
          OR IsEncodedExecutionChain
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight,


    if(
      condition=IsReverseShellSyntax,
      then="Reverse Shell Process Behavior",

      else=if(
        condition=IsDownloadAndShellExecution,
        then="Download and Shell Execution",

        else=if(
          condition=IsMinerOrTunnelTool,
          then="Miner or Tunnel Tool",

          else=if(
            condition=IsEncodedExecutionChain,
            then="Encoded Execution Chain",

            else=if(
              condition=(
                IsTemporaryPathExecution
                AND IsDeletedExecutable
              ),
              then="Deleted Executable From Temporary Path",

              else=if(
                condition=IsTemporaryPathExecution,
                then="Process From Temporary Writable Path",

                else=if(
                  condition=IsSuspiciousInterpreterChain,
                  then="Suspicious Inline Interpreter Chain",

                  else="Deleted Executable Process"
                )
              )
            )
          )
        )
      )
    ) AS Finding,


    if(
      condition=IsReverseShellSyntax,
      then="Command line contains reverse-shell syntax",

      else=if(
        condition=IsDownloadAndShellExecution,
        then="Downloader output is piped or chained into a shell",

        else=if(
          condition=IsMinerOrTunnelTool,
          then="Process name or executable matches a known miner or tunneling tool",

          else=if(
            condition=IsEncodedExecutionChain,
            then="Encoded content is decoded and chained into execution",

            else=if(
              condition=(
                IsTemporaryPathExecution
                AND IsDeletedExecutable
              ),
              then="Deleted executable is still running from a temporary writable directory",

              else=if(
                condition=IsTemporaryPathExecution,
                then="Executable is running from /tmp, /var/tmp, or /dev/shm",

                else=if(
                  condition=IsSuspiciousInterpreterChain,
                  then="Inline interpreter command contains execution or network behavior",

                  else="Executable was deleted while its process remains active; package-update activity must be considered"
                )
              )
            )
          )
        )
      )
    ) AS DetectionReason

  FROM ProcessSignals

  WHERE
    IsDeletedExecutable
    OR IsTemporaryPathExecution
    OR IsMinerOrTunnelTool
    OR IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsEncodedExecutionChain
    OR IsSuspiciousInterpreterChain


-- One record per ClientId + PID.
LET ProcessDeduplicated <=
  SELECT
    ClientId,
    ProcessKey AS FindingKey,
    Pid,
    Name,
    Exe,
    CommandLine,
    Finding,
    DetectionReason,
    max(item=FindingWeight) AS FindingWeight

  FROM ProcessCandidates

  GROUP BY ProcessKey


LET ProcessEvidence <=
  SELECT
    ClientId,
    "PROCESS_BEHAVIOR" AS FindingClass,
    Finding,
    FindingKey,
    Pid AS Evidence1,
    Exe AS Evidence2,
    CommandLine AS Evidence3,
    DetectionReason,
    FindingWeight

  FROM ProcessDeduplicated


-- ============================================================
-- 4. Service-unit raw evidence
-- ============================================================

LET ServiceUnitRaw <=
  SELECT
    ClientId,
    Path,
    Line

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServiceUnitLines"
  )

  WHERE Path
    AND Line


-- ============================================================
-- 5. Context-aware service-unit signals
-- ============================================================

LET ServiceUnitSignals <=
  SELECT
    *,

    format(
      format="%v:SERVICE_UNIT:%v",
      args=[ClientId, Path]
    ) AS ServiceUnitKey,


    Line =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|bash[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,


    Line =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(tmp|var/tmp|dev/shm|run/user/[0-9]+)(/|[[:space:]]|$)'''
        AS IsTemporaryPathExecution,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(nc|ncat|netcat|socat|chisel|ngrok|frpc|frps|ligolo|gost|dnscat2|iodine)([[:space:]]|$)'''
        AS IsNetworkOrTunnelTool,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(usr/)?bin/(sh|bash|dash|zsh|ksh)[[:space:]].*-[[:alnum:]]*c[[:space:]].*(/tmp/|/var/tmp/|/dev/shm/|/run/user/|curl|wget|base64|authorized_keys|useradd|usermod|setcap)'''
        AS IsSuspiciousShellChain,


    Line =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d)'''
        AS IsEncodedExecution,


    Line =~
      '''(?i)(authorized_keys|/etc/sudoers|(^|[[:space:]])(useradd|usermod|passwd|setcap)([[:space:]]|$)|chmod[[:space:]]+([uU][+])?[sS])'''
        AS IsPrivilegeModification,


    Line =~
      '''(?i)^[[:space:]]*Environment[[:space:]]*=.*(LD_PRELOAD[[:space:]]*=|LD_LIBRARY_PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm)|PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm))'''
        AS IsDangerousEnvironment,


    Line =~
      '''(?i)^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*-?/(tmp|var/tmp|dev/shm)(/|[[:space:]]|$)'''
        AS IsTemporaryEnvironmentFile,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(curl|wget)([[:space:]]|$)'''
        AS IsDirectDownloader,


    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(python([0-9]+([.][0-9]+)?)?|perl|ruby|php|node|lua)[[:space:]].*([[:space:]]-(c|e|r))([[:space:]]|$)'''
        AS IsInlineInterpreter

  FROM ServiceUnitRaw


-- ============================================================
-- 6. Classify service-unit findings
-- ============================================================

LET ServiceUnitCandidates <=
  SELECT
    ClientId,
    ServiceUnitKey,
    Path,
    Line,


    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,

      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsNetworkOrTunnelTool
          OR IsSuspiciousShellChain
          OR IsEncodedExecution
          OR IsPrivilegeModification
          OR IsDangerousEnvironment
          OR IsTemporaryEnvironmentFile
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight,


    if(
      condition=IsReverseShellSyntax,
      then="Service Unit Reverse Shell Behavior",

      else=if(
        condition=IsDownloadAndShellExecution,
        then="Service Unit Download and Shell Execution",

        else=if(
          condition=IsNetworkOrTunnelTool,
          then="Network or Tunnel Tool in Service Unit",

          else=if(
            condition=IsTemporaryPathExecution,
            then="Service Unit Executes From Temporary Path",

            else=if(
              condition=IsSuspiciousShellChain,
              then="Suspicious Service Unit Shell Chain",

              else=if(
                condition=IsEncodedExecution,
                then="Encoded Service Unit Execution",

                else=if(
                  condition=IsPrivilegeModification,
                  then="Service Unit Privilege Modification",

                  else=if(
                    condition=IsDangerousEnvironment,
                    then="Dangerous Service Unit Environment",

                    else=if(
                      condition=IsTemporaryEnvironmentFile,
                      then="Temporary Service Environment File",

                      else=if(
                        condition=IsDirectDownloader,
                        then="Direct Downloader in Service Unit",

                        else="Inline Interpreter in Service Unit"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS Finding,


    if(
      condition=IsReverseShellSyntax,
      then="Service configuration contains reverse-shell syntax",

      else=if(
        condition=IsDownloadAndShellExecution,
        then="Service downloads content and immediately executes it through a shell",

        else=if(
          condition=IsNetworkOrTunnelTool,
          then="Service executes a known network tunneling or relay tool",

          else=if(
            condition=IsTemporaryPathExecution,
            then="Service executes a binary from a temporary writable directory",

            else=if(
              condition=IsSuspiciousShellChain,
              then="Service shell command combines execution with suspicious paths or commands",

              else=if(
                condition=IsEncodedExecution,
                then="Service configuration contains encoded-content decoding behavior",

                else=if(
                  condition=IsPrivilegeModification,
                  then="Service configuration modifies users, privileges, capabilities, or SSH authorization",

                  else=if(
                    condition=IsDangerousEnvironment,
                    then="Service environment introduces preload or writable-path execution risk",

                    else=if(
                      condition=IsTemporaryEnvironmentFile,
                      then="Service loads its environment from a temporary writable path",

                      else=if(
                        condition=IsDirectDownloader,
                        then="Service directly launches curl or wget",

                        else="Service executes inline interpreter code"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS DetectionReason

  FROM ServiceUnitSignals

  WHERE
    IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsTemporaryPathExecution
    OR IsNetworkOrTunnelTool
    OR IsSuspiciousShellChain
    OR IsEncodedExecution
    OR IsPrivilegeModification
    OR IsDangerousEnvironment
    OR IsTemporaryEnvironmentFile
    OR IsDirectDownloader
    OR IsInlineInterpreter


-- Determine the highest severity found for each service-unit path.
LET ServiceUnitMax <=
  SELECT
    ClientId AS MaxClientId,
    ServiceUnitKey AS MaxServiceUnitKey,
    max(item=FindingWeight) AS MaxFindingWeight

  FROM ServiceUnitCandidates

  GROUP BY ServiceUnitKey


-- Retain only evidence lines matching the highest severity per unit.
LET ServiceUnitEvidence <=
  SELECT *

  FROM foreach(
    row=ServiceUnitMax,

    query={
      SELECT
        MaxClientId AS ClientId,
        "SERVICE_UNIT_BEHAVIOR" AS FindingClass,
        "Suspicious Service Unit Behavior" AS Finding,
        MaxServiceUnitKey AS FindingKey,
        Path AS Evidence1,
        enumerate(items=Finding) AS Evidence2,
        enumerate(items=Line) AS Evidence3,
        enumerate(items=DetectionReason) AS DetectionReason,
        max(item=FindingWeight) AS FindingWeight

      FROM ServiceUnitCandidates

      WHERE ServiceUnitKey = MaxServiceUnitKey
        AND FindingWeight = MaxFindingWeight

      GROUP BY ServiceUnitKey
    }
  )


-- ============================================================
-- 7. Consolidate all deduplicated evidence
-- ============================================================

LET ConsolidatedEvidence <=
  SELECT *

  FROM chain(
    ProcessFindings=ProcessEvidence,
    ServiceUnitFindings=ServiceUnitEvidence
  )


-- ============================================================
-- 8. Final findings detail
-- ============================================================

SELECT
  ClientId,

  if(
    condition=FindingWeight = 4,
    then="CRITICAL",
    else=if(
      condition=FindingWeight = 3,
      then="HIGH",
      else="MEDIUM"
    )
  ) AS Severity,

  FindingClass,
  Finding,
  FindingKey,
  Evidence1,
  Evidence2,
  Evidence3,
  DetectionReason,

  FindingWeight AS RiskWeight,

  FindingWeight >= 3 AS RiskScoreEligible,

  if(
    condition=FindingWeight = 4,
    then="IMMEDIATE_INVESTIGATION",
    else=if(
      condition=FindingWeight = 3,
      then="PRIORITY_INVESTIGATION",
      else="CONTEXTUAL_REVIEW"
    )
  ) AS TriageStatus

FROM ConsolidatedEvidence

ORDER BY
  RiskWeight DESC
```

## Cell 34 (markdown)

# Investigation Pivot Queue --- Dynamic Processes and Services Evidence Routes

## Cell 35 (vql)

```vql
-- ============================================================
-- Investigation Pivot Queue
-- Processes and Services
--
-- Standalone version:
--   * No NotebookId
--   * No FinalFindingsCellId
--   * No PivotGuideCellId
--   * Reads directly from Hunt results
--   * Rebuilds the Final Findings logic in this cell
--   * Embeds all 19 investigation routes in this cell
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Process inventory and behavior signals
-- ============================================================

LET ProcessRaw <=
  SELECT
    ClientId,
    Pid,
    Name,
    Exe,
    CommandLine,
    Deleted

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/Processes"
  )

  WHERE Pid


LET ProcessSignals <=
  SELECT
    *,

    format(
      format="%v:PROCESS:%v",
      args=[ClientId, Pid]
    ) AS ProcessKey,

    Deleted AS IsDeletedExecutable,

    Exe =~
      '''(?i)^/(tmp|var/tmp|dev/shm)/'''
        AS IsTemporaryPathExecution,

    (
      Exe =~
        '''(?i)(^|/)(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''

      OR

      Name =~
        '''(?i)^(xmrig|kinsing|kdevtmpfsi|watchbog|cryptominer|crypto-miner|chisel|ngrok|frpc|frps|ligolo|ligolo-agent|gost|dnscat2|iodine)$'''
    ) AS IsMinerOrTunnelTool,

    CommandLine =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|/(usr/)?bin/(bash|sh|dash|zsh|ksh)[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,

    CommandLine =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,

    CommandLine =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d).*([|]|;|&&).*(sh|bash|dash|zsh|ksh|chmod|/tmp/|/var/tmp/|/dev/shm/)'''
        AS IsEncodedExecutionChain,

    CommandLine =~
      '''(?i)(python([0-9]+([.][0-9]+)?)?[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|php[[:space:]]+-r|node[[:space:]]+-e).*(socket|connect|http|/tmp/|/var/tmp/|/dev/shm/|subprocess|system|exec|base64)'''
        AS IsSuspiciousInterpreterChain

  FROM ProcessRaw


-- ============================================================
-- 2. Classify and deduplicate process findings
-- ============================================================

LET ProcessCandidates <=
  SELECT
    ClientId,
    ProcessKey,
    Pid,
    Name,
    Exe,
    CommandLine,

    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsMinerOrTunnelTool
          OR IsEncodedExecutionChain
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight,

    if(
      condition=IsReverseShellSyntax,
      then="Reverse Shell Process Behavior",
      else=if(
        condition=IsDownloadAndShellExecution,
        then="Download and Shell Execution",
        else=if(
          condition=IsMinerOrTunnelTool,
          then="Miner or Tunnel Tool",
          else=if(
            condition=IsEncodedExecutionChain,
            then="Encoded Execution Chain",
            else=if(
              condition=(
                IsTemporaryPathExecution
                AND IsDeletedExecutable
              ),
              then="Deleted Executable From Temporary Path",
              else=if(
                condition=IsTemporaryPathExecution,
                then="Process From Temporary Writable Path",
                else=if(
                  condition=IsSuspiciousInterpreterChain,
                  then="Suspicious Inline Interpreter Chain",
                  else="Deleted Executable Process"
                )
              )
            )
          )
        )
      )
    ) AS Finding,

    if(
      condition=IsReverseShellSyntax,
      then="Command line contains reverse-shell syntax",
      else=if(
        condition=IsDownloadAndShellExecution,
        then="Downloader output is piped or chained into a shell",
        else=if(
          condition=IsMinerOrTunnelTool,
          then="Process name or executable matches a known miner or tunneling tool",
          else=if(
            condition=IsEncodedExecutionChain,
            then="Encoded content is decoded and chained into execution",
            else=if(
              condition=(
                IsTemporaryPathExecution
                AND IsDeletedExecutable
              ),
              then="Deleted executable is still running from a temporary writable directory",
              else=if(
                condition=IsTemporaryPathExecution,
                then="Executable is running from /tmp, /var/tmp, or /dev/shm",
                else=if(
                  condition=IsSuspiciousInterpreterChain,
                  then="Inline interpreter command contains execution or network behavior",
                  else="Executable was deleted while its process remains active; package-update activity must be considered"
                )
              )
            )
          )
        )
      )
    ) AS DetectionReason

  FROM ProcessSignals

  WHERE
    IsDeletedExecutable
    OR IsTemporaryPathExecution
    OR IsMinerOrTunnelTool
    OR IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsEncodedExecutionChain
    OR IsSuspiciousInterpreterChain


LET ProcessDeduplicated <=
  SELECT
    ClientId,
    ProcessKey,
    Pid,
    Name,
    Exe,
    CommandLine,
    Finding,
    DetectionReason,
    max(item=FindingWeight) AS FindingWeight

  FROM ProcessCandidates

  GROUP BY ProcessKey


LET ActualProcessFindings <=
  SELECT
    ClientId AS ActualClientId,
    "PROCESS_BEHAVIOR" AS ActualFindingClass,
    Finding AS ActualFinding,
    ProcessKey AS BaseFindingKey,
    ProcessKey AS QueueFindingKey,

    Pid AS Evidence1,
    Exe AS Evidence2,
    CommandLine AS Evidence3,
    DetectionReason,

    FindingWeight AS RiskWeight,

    if(
      condition=FindingWeight = 4,
      then="CRITICAL",
      else=if(
        condition=FindingWeight = 3,
        then="HIGH",
        else="MEDIUM"
      )
    ) AS ActualSeverity,

    FindingWeight >= 3 AS ActualRiskScoreEligible,

    if(
      condition=FindingWeight = 4,
      then="IMMEDIATE_INVESTIGATION",
      else=if(
        condition=FindingWeight = 3,
        then="PRIORITY_INVESTIGATION",
        else="CONTEXTUAL_REVIEW"
      )
    ) AS ActualTriageStatus,

    if(
      condition=FindingWeight >= 3,
      then="Final Findings Detail - count BaseFindingKey once",
      else="NONE - contextual evidence is not directly scored"
    ) AS RiskScoreOwner

  FROM ProcessDeduplicated


-- ============================================================
-- 3. Service-unit raw evidence and behavior signals
-- ============================================================

LET ServiceUnitRaw <=
  SELECT
    ClientId,
    Path,
    Line

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ProcessServices/SuspiciousServiceUnitLines"
  )

  WHERE Path
    AND Line


LET ServiceUnitSignals <=
  SELECT
    *,

    format(
      format="%v:SERVICE_UNIT:%v",
      args=[ClientId, Path]
    ) AS ServiceUnitKey,

    Line =~
      '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(nc|ncat|netcat)[[:space:]].*(-e|--exec)([[:space:]]|=)|socat.*EXEC:|bash[[:space:]]+-i([[:space:]]|$))'''
        AS IsReverseShellSyntax,

    Line =~
      '''(?i)(curl|wget).*([|]|;|&&)[[:space:]]*(/(usr/)?bin/)?(sh|bash|dash|zsh|ksh)([[:space:]]|$)'''
        AS IsDownloadAndShellExecution,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(tmp|var/tmp|dev/shm|run/user/[0-9]+)(/|[[:space:]]|$)'''
        AS IsTemporaryPathExecution,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(nc|ncat|netcat|socat|chisel|ngrok|frpc|frps|ligolo|gost|dnscat2|iodine)([[:space:]]|$)'''
        AS IsNetworkOrTunnelTool,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*/(usr/)?bin/(sh|bash|dash|zsh|ksh)[[:space:]].*-[[:alnum:]]*c[[:space:]].*(/tmp/|/var/tmp/|/dev/shm/|/run/user/|curl|wget|base64|authorized_keys|useradd|usermod|setcap)'''
        AS IsSuspiciousShellChain,

    Line =~
      '''(?i)(base64.*(-d|--decode)|b64decode|openssl[[:space:]]+enc.*-d)'''
        AS IsEncodedExecution,

    Line =~
      '''(?i)(authorized_keys|/etc/sudoers|(^|[[:space:]])(useradd|usermod|passwd|setcap)([[:space:]]|$)|chmod[[:space:]]+([uU][+])?[sS])'''
        AS IsPrivilegeModification,

    Line =~
      '''(?i)^[[:space:]]*Environment[[:space:]]*=.*(LD_PRELOAD[[:space:]]*=|LD_LIBRARY_PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm)|PATH[[:space:]]*=.*(/tmp|/var/tmp|/dev/shm))'''
        AS IsDangerousEnvironment,

    Line =~
      '''(?i)^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*-?/(tmp|var/tmp|dev/shm)(/|[[:space:]]|$)'''
        AS IsTemporaryEnvironmentFile,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(curl|wget)([[:space:]]|$)'''
        AS IsDirectDownloader,

    Line =~
      '''(?i)^[[:space:]]*Exec(Start|StartPre|StartPost|Condition)[[:space:]]*=[[:space:]]*[-+!:@|]*[[:space:]]*[^[:space:]]*/(python([0-9]+([.][0-9]+)?)?|perl|ruby|php|node|lua)[[:space:]].*([[:space:]]-(c|e|r))([[:space:]]|$)'''
        AS IsInlineInterpreter

  FROM ServiceUnitRaw


-- ============================================================
-- 4. Classify service-unit evidence
-- ============================================================

LET ServiceUnitCandidates <=
  SELECT
    ClientId,
    ServiceUnitKey,
    Path,
    Line,

    if(
      condition=(
        IsReverseShellSyntax
        OR IsDownloadAndShellExecution
      ),
      then=4,
      else=if(
        condition=(
          IsTemporaryPathExecution
          OR IsNetworkOrTunnelTool
          OR IsSuspiciousShellChain
          OR IsEncodedExecution
          OR IsPrivilegeModification
          OR IsDangerousEnvironment
          OR IsTemporaryEnvironmentFile
        ),
        then=3,
        else=2
      )
    ) AS FindingWeight,

    if(
      condition=IsReverseShellSyntax,
      then="Service Unit Reverse Shell Behavior",
      else=if(
        condition=IsDownloadAndShellExecution,
        then="Service Unit Download and Shell Execution",
        else=if(
          condition=IsNetworkOrTunnelTool,
          then="Network or Tunnel Tool in Service Unit",
          else=if(
            condition=IsTemporaryPathExecution,
            then="Service Unit Executes From Temporary Path",
            else=if(
              condition=IsSuspiciousShellChain,
              then="Suspicious Service Unit Shell Chain",
              else=if(
                condition=IsEncodedExecution,
                then="Encoded Service Unit Execution",
                else=if(
                  condition=IsPrivilegeModification,
                  then="Service Unit Privilege Modification",
                  else=if(
                    condition=IsDangerousEnvironment,
                    then="Dangerous Service Unit Environment",
                    else=if(
                      condition=IsTemporaryEnvironmentFile,
                      then="Temporary Service Environment File",
                      else=if(
                        condition=IsDirectDownloader,
                        then="Direct Downloader in Service Unit",
                        else="Inline Interpreter in Service Unit"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS Finding,

    if(
      condition=IsReverseShellSyntax,
      then="Service configuration contains reverse-shell syntax",
      else=if(
        condition=IsDownloadAndShellExecution,
        then="Service downloads content and immediately executes it through a shell",
        else=if(
          condition=IsNetworkOrTunnelTool,
          then="Service executes a known network tunneling or relay tool",
          else=if(
            condition=IsTemporaryPathExecution,
            then="Service executes a binary from a temporary writable directory",
            else=if(
              condition=IsSuspiciousShellChain,
              then="Service shell command combines execution with suspicious paths or commands",
              else=if(
                condition=IsEncodedExecution,
                then="Service configuration contains encoded-content decoding behavior",
                else=if(
                  condition=IsPrivilegeModification,
                  then="Service configuration modifies users, privileges, capabilities, or SSH authorization",
                  else=if(
                    condition=IsDangerousEnvironment,
                    then="Service environment introduces preload or writable-path execution risk",
                    else=if(
                      condition=IsTemporaryEnvironmentFile,
                      then="Service loads its environment from a temporary writable path",
                      else=if(
                        condition=IsDirectDownloader,
                        then="Service directly launches curl or wget",
                        else="Service executes inline interpreter code"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS DetectionReason

  FROM ServiceUnitSignals

  WHERE
    IsReverseShellSyntax
    OR IsDownloadAndShellExecution
    OR IsTemporaryPathExecution
    OR IsNetworkOrTunnelTool
    OR IsSuspiciousShellChain
    OR IsEncodedExecution
    OR IsPrivilegeModification
    OR IsDangerousEnvironment
    OR IsTemporaryEnvironmentFile
    OR IsDirectDownloader
    OR IsInlineInterpreter


LET ServiceUnitMax <=
  SELECT
    ClientId AS MaxClientId,
    ServiceUnitKey AS MaxServiceUnitKey,
    max(item=FindingWeight) AS MaxFindingWeight

  FROM ServiceUnitCandidates

  GROUP BY ServiceUnitKey


-- One route row per highest-priority behavior type in the unit.
-- BaseFindingKey remains one per unit for Risk Score ownership.
LET ActualServiceUnitFindings <=
  SELECT *

  FROM foreach(
    row=ServiceUnitMax,

    query={
      SELECT
        MaxClientId AS ActualClientId,
        "SERVICE_UNIT_BEHAVIOR" AS ActualFindingClass,
        Finding AS ActualFinding,
        MaxServiceUnitKey AS BaseFindingKey,

        format(
          format="%v|%v",
          args=[
            MaxServiceUnitKey,
            Finding
          ]
        ) AS QueueFindingKey,

        Path AS Evidence1,
        enumerate(items=Finding) AS Evidence2,
        enumerate(items=Line) AS Evidence3,
        enumerate(items=DetectionReason) AS DetectionReason,

        max(item=FindingWeight) AS RiskWeight,

        if(
          condition=MaxFindingWeight = 4,
          then="CRITICAL",
          else=if(
            condition=MaxFindingWeight = 3,
            then="HIGH",
            else="MEDIUM"
          )
        ) AS ActualSeverity,

        MaxFindingWeight >= 3 AS ActualRiskScoreEligible,

        if(
          condition=MaxFindingWeight = 4,
          then="IMMEDIATE_INVESTIGATION",
          else=if(
            condition=MaxFindingWeight = 3,
            then="PRIORITY_INVESTIGATION",
            else="CONTEXTUAL_REVIEW"
          )
        ) AS ActualTriageStatus,

        if(
          condition=MaxFindingWeight >= 3,
          then="Final Findings Detail - count BaseFindingKey once",
          else="NONE - contextual evidence is not directly scored"
        ) AS RiskScoreOwner

      FROM ServiceUnitCandidates

      WHERE ServiceUnitKey = MaxServiceUnitKey
        AND FindingWeight = MaxFindingWeight

      GROUP BY Finding
    }
  )


-- ============================================================
-- 5. Consolidate actual process and service findings
-- ============================================================

LET ActualProcessServiceFindings <=
  SELECT *

  FROM chain(
    processes=ActualProcessFindings,
    services=ActualServiceUnitFindings
  )


-- ============================================================
-- 6. Embedded investigation route catalog
--
-- The catalog mirrors the Processes and Services Pivot Guide.
-- It is local to this cell and never requires a Guide Cell ID.
-- ============================================================

LET ProcessServiceRouteCatalogRaw <=
  SELECT *

  FROM parse_csv(
    accessor="data",

    filename='''PriorityOrder,FindingClass,Finding,DefaultSeverity,MasterRiskScore,TriageStatus,PrimaryEvidence,PivotRoute,InvestigationObjective,EscalationCriteria
1,PROCESS_BEHAVIOR,"Reverse Shell Process Behavior",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","PID | Exe | CommandLine | User | Parent PID | Network Connections","Network Connections -> Authentication and SSH -> Process Ancestry -> Persistence -> File Timeline -> Logs and Security Events","Identify the remote destination; execution source; responsible user; parent process; and persistence mechanism","Escalate immediately and determine whether the process created additional processes; files; users; keys; or persistence"
1,PROCESS_BEHAVIOR,"Download and Shell Execution",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","PID | Exe | CommandLine | URL | Remote Host | Download Path","File Timeline -> Malware and Suspicious Tools -> Network Connections -> Persistence -> Logs and Security Events","Identify the downloaded payload; calculate its hash; confirm execution; and locate related persistence","Escalate immediately when downloader output is piped or chained directly into a shell"
2,PROCESS_BEHAVIOR,"Miner or Tunnel Tool",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Process Name | Exe | CommandLine | Hash | Remote IP and Port","Network Connections -> Malware and Suspicious Tools -> File Timeline -> Persistence -> Processes and Services","Determine whether the binary is an authorized tool; cryptominer; proxy; relay; or command-and-control tunnel","Validate tool ownership and approved usage; escalate unauthorized binaries or unexplained external connections"
2,PROCESS_BEHAVIOR,"Encoded Execution Chain",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Exe | CommandLine | Decoding Method | Decoded Target","File Timeline -> Malware and Suspicious Tools -> Persistence -> Network Connections -> Logs and Security Events","Determine what content was decoded; where it was written; and whether it was executed","Escalate when decoding is chained to a shell; chmod; temporary file; interpreter; or network activity"
2,PROCESS_BEHAVIOR,"Deleted Executable From Temporary Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Deleted Exe | CommandLine | Start Time | Open Connections","File Timeline -> Malware and Suspicious Tools -> Network Connections -> Persistence -> Logs and Security Events","Recover or identify the deleted binary and determine how and when it was executed","Escalate when the process remains active from /tmp; /var/tmp; or /dev/shm after its executable was deleted"
2,PROCESS_BEHAVIOR,"Process From Temporary Writable Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Exe | Owner | CommandLine | Hash | File Timestamps","File Timeline -> Malware and Suspicious Tools -> Persistence -> Network Connections","Determine whether execution from a temporary writable directory is expected or represents staged execution","Escalate when combined with external communication; deletion; persistence; suspicious parentage; or an unknown hash"
3,PROCESS_BEHAVIOR,"Suspicious Inline Interpreter Chain",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","PID | Interpreter | CommandLine | Parent PID | User | Network Activity","Process Ancestry -> File Timeline -> Network Connections -> Logs and Security Events","Determine whether inline interpreter activity represents automation; administration; or malicious execution","Escalate only when correlated with networking; temporary files; encoded content; persistence; or an unexpected user"
3,PROCESS_BEHAVIOR,"Deleted Executable Process",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","PID | Exe | CommandLine | Process Start Time | Package Update Time","Package History -> Service Restarts -> Software Deployment -> File Timeline -> Network Connections","Determine whether the executable was replaced during a legitimate package update or deployment","Escalate only when accompanied by suspicious command-line; user; network; path; hash; or persistence evidence"
1,SERVICE_UNIT_BEHAVIOR,"Service Unit Reverse Shell Behavior",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","Unit Path | Suspicious Line | Running Process | Remote Destination | Creation Time","Full Service Unit -> Running Process -> Network Connections -> File Timeline -> Logs and Security Events -> Authentication and SSH","Identify the unit creator; activation time; executed shell; remote destination; and persistence scope","Escalate immediately when reverse-shell syntax is present in an active or enabled service unit"
1,SERVICE_UNIT_BEHAVIOR,"Service Unit Download and Shell Execution",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","Unit Path | Exec Line | URL | Download Path | Running Process","Full Service Unit -> File Timeline -> Malware and Suspicious Tools -> Network Connections -> Systemd Journal","Identify the payload; source URL; execution path; activation method; and related processes","Escalate immediately when downloaded content is directly executed through a shell"
2,SERVICE_UNIT_BEHAVIOR,"Network or Tunnel Tool in Service Unit",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Tool Path | Arguments | Running Process | Remote IP and Port","Network Connections -> Processes and Services -> Malware and Suspicious Tools -> File Timeline -> Persistence","Determine whether the service provides an authorized network function or unauthorized tunneling","Escalate unauthorized tools; unknown destinations; unusual listening ports; or hidden relay activity"
2,SERVICE_UNIT_BEHAVIOR,"Service Unit Executes From Temporary Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Exec Path | File Owner | Hash | Timestamps | Running Process","Service Metadata -> File Timeline -> Malware and Suspicious Tools -> Running Process -> Persistence","Determine who created the service and temporary executable and whether they exist on other clients","Escalate execution from /tmp; /var/tmp; /dev/shm; or temporary user runtime paths"
2,SERVICE_UNIT_BEHAVIOR,"Suspicious Service Unit Shell Chain",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Exec Line | Shell | Referenced Files | Running Process","Full Service Unit -> Running Process -> File Timeline -> Persistence -> Logs and Security Events","Determine which commands and files are executed by the service shell chain","Escalate when the chain references temporary paths; downloaders; encoded data; SSH keys; user changes; or capabilities"
2,SERVICE_UNIT_BEHAVIOR,"Encoded Service Unit Execution",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Encoded Content | Decoder | Execution Target | Running Process","Full Service Unit -> File Timeline -> Malware and Suspicious Tools -> Persistence -> Systemd Journal","Decode the content and identify the resulting command; file; or payload","Escalate when decoded content is executed or creates files; users; keys; network connections; or persistence"
2,SERVICE_UNIT_BEHAVIOR,"Service Unit Privilege Modification",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Modification Command | Target User or File | Activation Time","Users Groups and Privileges -> Authentication and SSH -> Sudoers -> Authorized Keys -> Privilege-Escalation Indicators -> Logs","Identify account; sudo; capability; SUID; password; and SSH authorization changes","Escalate unauthorized user creation; sudo access; capability changes; SUID changes; or SSH-key modification"
2,SERVICE_UNIT_BEHAVIOR,"Dangerous Service Unit Environment",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Environment Line | Referenced Library or Directory | File Owner | Hash","Full Service Unit -> Configuration and Secrets -> Privilege-Escalation Indicators -> File Timeline -> Malware and Suspicious Tools","Determine whether environment manipulation enables library hijacking; command hijacking; or privilege escalation","Escalate LD_PRELOAD; untrusted LD_LIBRARY_PATH; or writable directories placed in PATH"
2,SERVICE_UNIT_BEHAVIOR,"Temporary Service Environment File",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | EnvironmentFile Path | File Content | Owner | Permissions | Timestamps","Full Service Unit -> Configuration and Secrets -> File Timeline -> Persistence -> Malware and Suspicious Tools","Determine who created the environment file and which variables or commands it introduces","Escalate environment files loaded from /tmp; /var/tmp; or /dev/shm"
3,SERVICE_UNIT_BEHAVIOR,"Direct Downloader in Service Unit",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","Unit Path | Downloader | URL | Destination | Running Process","Full Service Unit -> File Timeline -> Network Connections -> Systemd Journal","Determine whether curl or wget is part of an approved update or deployment workflow","Escalate when combined with shell execution; temporary output; unknown URL; encoded content; or persistence"
3,SERVICE_UNIT_BEHAVIOR,"Inline Interpreter in Service Unit",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","Unit Path | Interpreter | Inline Code | User | Running Process","Full Service Unit -> Process Ancestry -> File Timeline -> Network Connections -> Systemd Journal","Determine whether inline interpreter code is approved automation or suspicious execution","Escalate when inline code performs networking; decoding; command execution; credential access; or file staging"
'''
  )


LET ProcessServiceRouteCatalog <=
  SELECT
    PriorityOrder AS RoutePriorityOrder,
    FindingClass AS RouteFindingClass,
    Finding AS RouteFinding,
    DefaultSeverity AS RouteDefaultSeverity,
    MasterRiskScore AS RouteMasterRiskScore,
    TriageStatus AS RouteTriageStatus,
    PrimaryEvidence AS RequiredEvidence,
    PivotRoute,
    InvestigationObjective,
    EscalationCriteria,

    if(
      condition=DefaultSeverity = "CRITICAL",
      then=100,
      else=if(
        condition=DefaultSeverity = "HIGH",
        then=70,
        else=40
      )
    ) AS RouteRank

  FROM ProcessServiceRouteCatalogRaw


-- ============================================================
-- 7. Match every actual finding to its embedded route
-- ============================================================

LET RoutedProcessServiceFindingsRaw <=
  SELECT *

  FROM foreach(
    row=ActualProcessServiceFindings,

    query={
      SELECT
        ActualSeverity AS InvestigationPriority,
        ActualClientId AS ClientId,
        ActualFindingClass AS FindingClass,
        ActualFinding AS Finding,

        Evidence1,
        Evidence2,
        Evidence3,
        DetectionReason,

        RiskWeight,
        ActualRiskScoreEligible AS RiskScoreEligible,
        ActualTriageStatus AS TriageStatus,
        RiskScoreOwner,

        RequiredEvidence,
        PivotRoute,
        InvestigationObjective,
        EscalationCriteria,

        BaseFindingKey,
        QueueFindingKey AS FindingKey,

        RoutePriorityOrder,
        RouteRank,
        RouteDefaultSeverity,
        RouteMasterRiskScore,
        RouteTriageStatus,

        if(
          condition=ActualRiskScoreEligible,
          then="Count BaseFindingKey once in Final Findings Detail",
          else="NONE - contextual review only"
        ) AS RiskScoreImpact

      FROM ProcessServiceRouteCatalog

      WHERE RouteFindingClass = ActualFindingClass
        AND RouteFinding = ActualFinding
    }
  )


LET RankedProcessServiceQueue <=
  SELECT *

  FROM RoutedProcessServiceFindingsRaw

  ORDER BY RouteRank DESC


LET UniqueProcessServiceQueue <=
  SELECT *

  FROM RankedProcessServiceQueue

  GROUP BY FindingKey


-- ============================================================
-- 8. Final analyst-facing queue
-- ============================================================

SELECT
  InvestigationPriority,
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  FindingClass,
  Finding,

  Evidence1,
  Evidence2,
  Evidence3,
  DetectionReason,

  RiskWeight,
  RiskScoreEligible,
  TriageStatus,
  RiskScoreOwner,

  RequiredEvidence,
  PivotRoute,
  InvestigationObjective,
  EscalationCriteria,

  "Open" AS InvestigationState,
  BaseFindingKey,
  FindingKey,
  RiskScoreImpact

FROM UniqueProcessServiceQueue

ORDER BY
  RouteRank DESC
```

## Cell 36 (markdown)

# Investigation Pivot Guide — Processes and Services Evidence Routes

## Cell 37 (vql)

```vql
-- ============================================================
-- Investigation Pivot Guide
-- Processes and Services Evidence Routes
-- ============================================================
--
-- Process findings:
--   Match the route using the Finding column.
--
-- Service-unit findings:
--   Match the route using the specific finding types shown
--   inside Evidence2 in Final Findings Detail.
--
-- This guide is static and does not require HuntId.
-- ============================================================


LET PivotGuide <=
  SELECT *

  FROM parse_csv(
    accessor="data",

    filename='''PriorityOrder,FindingClass,MatchUsing,Finding,DefaultSeverity,MasterRiskScore,TriageStatus,PrimaryEvidence,PivotRoute,InvestigationObjective,EscalationCriteria
1,PROCESS_BEHAVIOR,Finding,"Reverse Shell Process Behavior",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","PID | Exe | CommandLine | User | Parent PID | Network Connections","Network Connections -> Authentication and SSH -> Process Ancestry -> Persistence -> File Timeline -> Logs and Security Events","Identify the remote destination; execution source; responsible user; parent process; and persistence mechanism","Escalate immediately and determine whether the process created additional processes; files; users; keys; or persistence"
1,PROCESS_BEHAVIOR,Finding,"Download and Shell Execution",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","PID | Exe | CommandLine | URL | Remote Host | Download Path","File Timeline -> Malware and Suspicious Tools -> Network Connections -> Persistence -> Logs and Security Events","Identify the downloaded payload; calculate its hash; confirm execution; and locate related persistence","Escalate immediately when downloader output is piped or chained directly into a shell"
2,PROCESS_BEHAVIOR,Finding,"Miner or Tunnel Tool",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Process Name | Exe | CommandLine | Hash | Remote IP and Port","Network Connections -> Malware and Suspicious Tools -> File Timeline -> Persistence -> Processes and Services","Determine whether the binary is an authorized tool; cryptominer; proxy; relay; or command-and-control tunnel","Validate tool ownership and approved usage; escalate unauthorized binaries or unexplained external connections"
2,PROCESS_BEHAVIOR,Finding,"Encoded Execution Chain",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Exe | CommandLine | Decoding Method | Decoded Target","File Timeline -> Malware and Suspicious Tools -> Persistence -> Network Connections -> Logs and Security Events","Determine what content was decoded; where it was written; and whether it was executed","Escalate when decoding is chained to a shell; chmod; temporary file; interpreter; or network activity"
2,PROCESS_BEHAVIOR,Finding,"Deleted Executable From Temporary Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Deleted Exe | CommandLine | Start Time | Open Connections","File Timeline -> Malware and Suspicious Tools -> Network Connections -> Persistence -> Logs and Security Events","Recover or identify the deleted binary and determine how and when it was executed","Escalate when the process remains active from /tmp; /var/tmp; or /dev/shm after its executable was deleted"
2,PROCESS_BEHAVIOR,Finding,"Process From Temporary Writable Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","PID | Exe | Owner | CommandLine | Hash | File Timestamps","File Timeline -> Malware and Suspicious Tools -> Persistence -> Network Connections","Determine whether execution from a temporary writable directory is expected or represents staged execution","Escalate when combined with external communication; deletion; persistence; suspicious parentage; or an unknown hash"
3,PROCESS_BEHAVIOR,Finding,"Suspicious Inline Interpreter Chain",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","PID | Interpreter | CommandLine | Parent PID | User | Network Activity","Process Ancestry -> File Timeline -> Network Connections -> Logs and Security Events","Determine whether inline interpreter activity represents automation; administration; or malicious execution","Escalate only when correlated with networking; temporary files; encoded content; persistence; or an unexpected user"
3,PROCESS_BEHAVIOR,Finding,"Deleted Executable Process",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","PID | Exe | CommandLine | Process Start Time | Package Update Time","Package History -> Service Restarts -> Software Deployment -> File Timeline -> Network Connections","Determine whether the executable was replaced during a legitimate package update or deployment","Escalate only when accompanied by suspicious command-line; user; network; path; hash; or persistence evidence"
1,SERVICE_UNIT_BEHAVIOR,Evidence2,"Service Unit Reverse Shell Behavior",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","Unit Path | Suspicious Line | Running Process | Remote Destination | Creation Time","Full Service Unit -> Running Process -> Network Connections -> File Timeline -> Logs and Security Events -> Authentication and SSH","Identify the unit creator; activation time; executed shell; remote destination; and persistence scope","Escalate immediately when reverse-shell syntax is present in an active or enabled service unit"
1,SERVICE_UNIT_BEHAVIOR,Evidence2,"Service Unit Download and Shell Execution",CRITICAL,"Eligible","IMMEDIATE_INVESTIGATION","Unit Path | Exec Line | URL | Download Path | Running Process","Full Service Unit -> File Timeline -> Malware and Suspicious Tools -> Network Connections -> Systemd Journal","Identify the payload; source URL; execution path; activation method; and related processes","Escalate immediately when downloaded content is directly executed through a shell"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Network or Tunnel Tool in Service Unit",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Tool Path | Arguments | Running Process | Remote IP and Port","Network Connections -> Processes and Services -> Malware and Suspicious Tools -> File Timeline -> Persistence","Determine whether the service provides an authorized network function or unauthorized tunneling","Escalate unauthorized tools; unknown destinations; unusual listening ports; or hidden relay activity"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Service Unit Executes From Temporary Path",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Exec Path | File Owner | Hash | Timestamps | Running Process","Service Metadata -> File Timeline -> Malware and Suspicious Tools -> Running Process -> Persistence","Determine who created the service and temporary executable and whether they exist on other clients","Escalate execution from /tmp; /var/tmp; /dev/shm; or temporary user runtime paths"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Suspicious Service Unit Shell Chain",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Exec Line | Shell | Referenced Files | Running Process","Full Service Unit -> Running Process -> File Timeline -> Persistence -> Logs and Security Events","Determine which commands and files are executed by the service shell chain","Escalate when the chain references temporary paths; downloaders; encoded data; SSH keys; user changes; or capabilities"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Encoded Service Unit Execution",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Encoded Content | Decoder | Execution Target | Running Process","Full Service Unit -> File Timeline -> Malware and Suspicious Tools -> Persistence -> Systemd Journal","Decode the content and identify the resulting command; file; or payload","Escalate when decoded content is executed or creates files; users; keys; network connections; or persistence"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Service Unit Privilege Modification",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Modification Command | Target User or File | Activation Time","Users Groups and Privileges -> Authentication and SSH -> Sudoers -> Authorized Keys -> Privilege-Escalation Indicators -> Logs","Identify account; sudo; capability; SUID; password; and SSH authorization changes","Escalate unauthorized user creation; sudo access; capability changes; SUID changes; or SSH-key modification"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Dangerous Service Unit Environment",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | Environment Line | Referenced Library or Directory | File Owner | Hash","Full Service Unit -> Configuration and Secrets -> Privilege-Escalation Indicators -> File Timeline -> Malware and Suspicious Tools","Determine whether environment manipulation enables library hijacking; command hijacking; or privilege escalation","Escalate LD_PRELOAD; untrusted LD_LIBRARY_PATH; or writable directories placed in PATH"
2,SERVICE_UNIT_BEHAVIOR,Evidence2,"Temporary Service Environment File",HIGH,"Eligible","PRIORITY_INVESTIGATION","Unit Path | EnvironmentFile Path | File Content | Owner | Permissions | Timestamps","Full Service Unit -> Configuration and Secrets -> File Timeline -> Persistence -> Malware and Suspicious Tools","Determine who created the environment file and which variables or commands it introduces","Escalate environment files loaded from /tmp; /var/tmp; or /dev/shm"
3,SERVICE_UNIT_BEHAVIOR,Evidence2,"Direct Downloader in Service Unit",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","Unit Path | Downloader | URL | Destination | Running Process","Full Service Unit -> File Timeline -> Network Connections -> Systemd Journal","Determine whether curl or wget is part of an approved update or deployment workflow","Escalate when combined with shell execution; temporary output; unknown URL; encoded content; or persistence"
3,SERVICE_UNIT_BEHAVIOR,Evidence2,"Inline Interpreter in Service Unit",MEDIUM,"Not Eligible","CONTEXTUAL_REVIEW","Unit Path | Interpreter | Inline Code | User | Running Process","Full Service Unit -> Process Ancestry -> File Timeline -> Network Connections -> Systemd Journal","Determine whether inline interpreter code is approved automation or suspicious execution","Escalate when inline code performs networking; decoding; command execution; credential access; or file staging"
'''
  )


SELECT
  PriorityOrder,
  FindingClass,
  MatchUsing,
  Finding,
  DefaultSeverity,
  MasterRiskScore,
  TriageStatus,
  PrimaryEvidence,
  PivotRoute,
  InvestigationObjective,
  EscalationCriteria

FROM PivotGuide

ORDER BY
  PriorityOrder
```
