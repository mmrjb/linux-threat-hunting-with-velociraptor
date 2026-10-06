# LTH - 06 - Persistence Mechanisms Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 06 - Persistence Mechanisms Dashboard

This notebook analyzes Linux persistence data collected by:

`LTH.Persistence`

Main objectives:

- Review cron jobs and scheduled tasks
- Review SSH authorized_keys entries
- Review systemd services and timers
- Review startup scripts and shell profile files
- Review PAM configuration
- Identify suspicious persistence mechanisms
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Persistence Collection and Coverage Summary

## Cell 3 (vql)

```vql
-- ============================================================
-- Persistence Collection and Coverage Summary
--
-- Purpose:
--   1. Verify Hunt execution per client
--   2. Separate collection status from returned evidence
--   3. Count rows for each persistence mechanism
--
-- Risk Score Impact:
--   NONE - Coverage and collection health only
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve Hunt flow status
-- ============================================================

LET PersistenceFlows <=
  SELECT
    ClientId AS FlowClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    basename(
      path=Flow.Urn
    ) AS FlowId,

    format(
      format="%v",
      args=[Flow.FlowContext.state]
    ) AS FlowState,

    format(
      format="%v",
      args=[Flow.FlowContext.artifacts]
    ) AS RequestedArtifacts,

    Flow.FlowContext.status AS FlowMessage,

    int(
      int=Flow.FlowContext.total_collected_rows
    ) AS FlowTotalRows

  FROM hunt_flows(
    hunt_id=HuntId
  )


-- ============================================================
-- 2. Retrieve all Persistence result rows
--
-- _Source allows this cell to detect the actual source names.
-- ============================================================

LET PersistenceResults <=
  SELECT
    ClientId,
    _Source

  FROM hunt_results(
    hunt_id=HuntId
  )

  WHERE _Source =~
    '''(?i)^LTH[.]Persistence/'''


-- ============================================================
-- 3. Count result rows per persistence mechanism
-- ============================================================

LET PersistenceCoverageCounts <=
  SELECT
    FlowClientId AS ClientId,
    Fqdn,
    FlowId,
    FlowState,
    RequestedArtifacts,
    FlowMessage,
    FlowTotalRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/(Cron|Crontab|CronJobs?)(Lines?)?$'''
      }
    ) AS CronRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/.*Authorized.*Keys?.*$'''
      }
    ) AS AuthorizedKeyRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/Services?$'''
      }
    ) AS ServiceRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/Systemd.*(Service|Unit).*$'''
          AND NOT _Source =~
            '''(?i)Timer'''
      }
    ) AS SystemdUnitRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/Systemd.*Timer.*$'''
      }
    ) AS SystemdTimerRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/Startup.*$'''
      }
    ) AS StartupFileRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/Shell.*Profile.*$'''
      }
    ) AS ShellProfileRows,

    int(
      int={
        SELECT count() AS RowCount
        FROM PersistenceResults
        WHERE
          ClientId = FlowClientId
          AND _Source =~
            '''(?i)/PAM.*$'''
      }
    ) AS PAMRows

  FROM PersistenceFlows

-- ============================================================
-- 4. Calculate coverage statistics
-- ============================================================

LET PersistenceCoverageSummary <=
  SELECT
    *,

    (
      if(
        condition=CronRows > 0,
        then=1,
        else=0
      )

      +

      if(
        condition=AuthorizedKeyRows > 0,
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
        condition=SystemdUnitRows > 0,
        then=1,
        else=0
      )

      +

      if(
        condition=SystemdTimerRows > 0,
        then=1,
        else=0
      )

      +

      if(
        condition=StartupFileRows > 0,
        then=1,
        else=0
      )

      +

      if(
        condition=ShellProfileRows > 0,
        then=1,
        else=0
      )

      +

      if(
        condition=PAMRows > 0,
        then=1,
        else=0
      )
    ) AS SourcesWithData,

    (
      CronRows
      + AuthorizedKeyRows
      + ServiceRows
      + SystemdUnitRows
      + SystemdTimerRows
      + StartupFileRows
      + ShellProfileRows
      + PAMRows
    ) AS TotalPersistenceRows

  FROM PersistenceCoverageCounts


-- ============================================================
-- 5. Final analyst-facing coverage table
-- ============================================================

SELECT
  ClientId,
  Fqdn,
  FlowId,
  FlowState,

  8 AS ExpectedPersistenceSources,

  SourcesWithData,

  8 - SourcesWithData
    AS SourcesWithoutRows,

  CronRows,
  AuthorizedKeyRows,
  ServiceRows,
  SystemdUnitRows,
  SystemdTimerRows,
  StartupFileRows,
  ShellProfileRows,
  PAMRows,

  TotalPersistenceRows,

  if(
    condition=RequestedArtifacts =~
      '''(?i)LTH[.]Persistence''',

    then=if(
      condition=FlowState =~
        '''(?i)^FINISHED$''',

      then=if(
        condition=TotalPersistenceRows > 0,
        then="COLLECTION_COMPLETE_WITH_DATA",
        else="COLLECTION_COMPLETE_NO_ROWS"
      ),

      else=if(
        condition=FlowState =~
          '''(?i)ERROR''',

        then="COLLECTION_ERROR",

        else=if(
          condition=FlowState =~
            '''(?i)(RUNNING|WAITING)''',

          then="COLLECTION_IN_PROGRESS",
          else="COLLECTION_NOT_COMPLETE"
        )
      )
    ),

    else="PERSISTENCE_ARTIFACT_NOT_REQUESTED"
  ) AS CollectionStatus,

  if(
    condition=
      RequestedArtifacts =~
        '''(?i)LTH[.]Persistence'''

      AND

      FlowState =~
        '''(?i)^FINISHED$''',

    then=100,
    else=0
  ) AS CollectionCoveragePercent,

  FlowMessage,

  "Coverage only - no Risk Score impact"
    AS RiskScoreImpact

FROM PersistenceCoverageSummary

ORDER BY
  CollectionCoveragePercent
```

## Cell 4 (markdown)

# Cron Jobs Inventory

This section inventories scheduled tasks collected from Linux clients.
Each Cron entry is enriched with its source, execution context and normalized
schedule. These results provide context for the Suspicious Cron Jobs cell and
do not independently affect the endpoint Risk Score.

## Cell 5 (vql)

```vql
-- ============================================================
-- Cron Jobs Inventory
--
-- Purpose:
--   Inventory and normalize Cron entries collected by the Hunt.
--
-- Detection:
--   NONE - Detection is handled in Suspicious Cron Jobs.
--
-- Risk Score Impact:
--   NONE
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve raw Cron results
-- ============================================================

LET RawCronRows <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/Crontab"
  )


-- ============================================================
-- 2. Normalize raw Artifact fields
--
-- get(field="...") reads the field from the current VQL scope.
-- ============================================================

LET NormalizedCronRows <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    get(field="User") AS CronUser,
    get(field="Path") AS CronPath,
    get(field="Event") AS CronEvent,

    get(field="Minute") AS CronMinute,
    get(field="Hour") AS CronHour,
    get(field="DayOfMonth") AS CronDayOfMonth,
    get(field="Month") AS CronMonth,
    get(field="DayOfWeek") AS CronDayOfWeek,

    get(field="Command") AS CronCommand

  FROM RawCronRows


-- ============================================================
-- 3. Keep valid Cron entries
-- ============================================================

LET ValidCronRows <=
  SELECT *
  FROM NormalizedCronRows

  WHERE
    CronUser
    AND CronCommand


-- ============================================================
-- 4. Add analyst-facing context
-- ============================================================

LET EnrichedCronRows <=
  SELECT
    ClientId,
    Fqdn,

    CronUser,
    CronPath,
    CronEvent,

    CronMinute,
    CronHour,
    CronDayOfMonth,
    CronMonth,
    CronDayOfWeek,

    CronCommand,

    if(
      condition=CronEvent =~ '''^@''',
      then="EVENT_BASED",
      else="STANDARD_CRON"
    ) AS ScheduleType,

    if(
      condition=CronEvent =~ '''^@''',

      then=CronEvent,

      else=format(
        format="%v %v %v %v %v",
        args=[
          CronMinute,
          CronHour,
          CronDayOfMonth,
          CronMonth,
          CronDayOfWeek
        ]
      )
    ) AS Schedule,

    if(
      condition=CronPath =~
        '''(?i)^/etc/crontab$''',

      then="SYSTEM_CRONTAB",

      else=if(
        condition=CronPath =~
          '''(?i)^/etc/cron[.]d/''',

        then="SYSTEM_CRON_D",

        else=if(
          condition=CronPath =~
            '''(?i)^/var/spool/cron(/crontabs)?/''',

          then="USER_CRONTAB",
          else="OTHER_CRON_SOURCE"
        )
      )
    ) AS CronSourceType,

    if(
      condition=CronUser = "root",
      then="PRIVILEGED_CONTEXT",
      else="USER_CONTEXT"
    ) AS ExecutionContext,

    format(
      format="CRON|%v|%v|%v|%v|%v",
      args=[
        ClientId,
        CronPath,
        CronUser,
        CronEvent,
        CronCommand
      ]
    ) AS InventoryKey

  FROM ValidCronRows


-- ============================================================
-- 5. Final inventory table
-- ============================================================

SELECT
  ClientId,
  Fqdn,

  CronSourceType,
  CronPath AS Path,
  CronUser,

  ExecutionContext,
  ScheduleType,
  Schedule,

  CronEvent AS Event,

  CronMinute AS Minute,
  CronHour AS Hour,
  CronDayOfMonth AS DayOfMonth,
  CronMonth AS Month,
  CronDayOfWeek AS DayOfWeek,

  CronCommand AS Command,

  InventoryKey,

  "Inventory only - no Risk Score impact"
    AS RiskScoreImpact

FROM EnrichedCronRows

ORDER BY
  Fqdn
```

## Cell 6 (markdown)

# Suspicious Cron Jobs

This section detects suspicious commands configured through Cron and classifies
each result by persistence behavior, severity and confidence. A result confirms
that the command is scheduled, but does not independently prove successful
execution. Findings are deduplicated and scored later in Final Findings Detail.

## Cell 7 (vql)

```vql
-- ============================================================
-- Suspicious Cron Jobs
--
-- Purpose:
--   Detect suspicious persistence behavior in collected Cron jobs.
--
-- ATT&CK:
--   T1053.003 - Scheduled Task/Job: Cron
--
-- Evidence:
--   Scheduled configuration evidence.
--   This proves the command is configured, not that it executed.
--
-- Risk Score:
--   Candidate findings are deduplicated and scored later by
--   Final Findings Detail.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Detection patterns
-- ============================================================

LET ReverseShellRegex <=
  '''(?i)(/dev/(tcp|udp)/|(^|[^[:alnum:]_])(bash|sh)[[:space:]]+-i([^[:alnum:]_]|$)|mkfifo.*(nc|ncat|netcat)|(^|[^[:alnum:]_])(nc|ncat|netcat)[[:space:]].*[[:space:]](-e|--exec)([[:space:]]|$)|socat[[:space:]].*(exec:|pty))'''

LET DownloadExecuteRegex <=
  '''(?i)(curl|wget).*(\||&&|;).*([^[:alnum:]_]|^)(sh|bash|dash|python3?|perl)([^[:alnum:]_]|$)'''

LET EncodedExecutionRegex <=
  '''(?i)(base64[[:space:]]+(-d|--decode)|openssl[[:space:]]+enc.*-d).*(\||>|eval|sh|bash|python|perl)'''

LET TempPermissionRegex <=
  '''(?i)(chmod[[:space:]].*\+x.*(/tmp/|/var/tmp/|/dev/shm/)|chmod[[:space:]].*(/tmp/|/var/tmp/|/dev/shm/).*\+x)'''

LET RemoteFetchToTempRegex <=
  '''(?i)(curl|wget).*(/tmp/|/var/tmp/|/dev/shm/)'''

LET InterpreterOneLinerRegex <=
  '''(?i)((^|[^[:alnum:]_])python3?[[:space:]]+-c([[:space:]]|$)|(^|[^[:alnum:]_])perl[[:space:]]+-e([[:space:]]|$))'''

LET TempPathRegex <=
  '''(?i)(/tmp/|/var/tmp/|/dev/shm/)'''


-- ============================================================
-- 2. Retrieve valid Cron rows
-- ============================================================

LET CronRows <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/Crontab"
  )
  WHERE
    User
    AND Command


-- ============================================================
-- 3. Normalize fields
-- ============================================================

LET NormalizedCronRows <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    User AS CronUser,
    Path AS CronPath,
    Event AS CronEvent,

    Minute AS CronMinute,
    Hour AS CronHour,
    DayOfMonth AS CronDayOfMonth,
    Month AS CronMonth,
    DayOfWeek AS CronDayOfWeek,

    Command AS CronCommand

  FROM CronRows


-- ============================================================
-- 4. Keep only suspicious Cron entries
-- ============================================================

LET SuspiciousCronRows <=
  SELECT *
  FROM NormalizedCronRows
  WHERE
    CronCommand =~ ReverseShellRegex

    OR CronCommand =~ DownloadExecuteRegex

    OR CronCommand =~ EncodedExecutionRegex

    OR CronCommand =~ TempPermissionRegex

    OR CronCommand =~ RemoteFetchToTempRegex

    OR CronCommand =~ InterpreterOneLinerRegex

    OR CronCommand =~ TempPathRegex


-- ============================================================
-- 5. Assign DetectionClass
--
-- Classification order matters: stronger behavior is evaluated
-- before generic temporary-path activity.
-- ============================================================

LET ClassifiedCronRows <=
  SELECT
    *,

    if(
      condition=CronCommand =~ ReverseShellRegex,

      then="CRON_REVERSE_SHELL",

      else=if(
        condition=CronCommand =~ DownloadExecuteRegex,

        then="CRON_DOWNLOAD_AND_EXECUTE",

        else=if(
          condition=CronCommand =~ EncodedExecutionRegex,

          then="CRON_ENCODED_EXECUTION",

          else=if(
            condition=CronCommand =~ TempPermissionRegex,

            then="CRON_TEMP_EXECUTABLE_STAGING",

            else=if(
              condition=
                CronEvent =~ '''(?i)^@reboot$'''
                AND CronCommand =~ TempPathRegex,

              then="CRON_REBOOT_TEMP_PATH_ACTIVITY",

              else=if(
                condition=CronCommand =~ RemoteFetchToTempRegex,

                then="CRON_REMOTE_FETCH_TO_TEMP",

                else=if(
                  condition=CronCommand =~ InterpreterOneLinerRegex,

                  then="CRON_INTERPRETER_ONE_LINER",

                  else="CRON_TEMP_PATH_ACTIVITY"
                )
              )
            )
          )
        )
      )
    ) AS DetectionClass

  FROM SuspiciousCronRows


-- ============================================================
-- 6. Assign severity, confidence and reason
-- ============================================================

LET ScoredCronRows <=
  SELECT
    *,

    if(
      condition=DetectionClass = "CRON_REVERSE_SHELL",

      then="CRITICAL",

      else=if(
        condition=DetectionClass =~
          '''^CRON_(DOWNLOAD_AND_EXECUTE|ENCODED_EXECUTION|TEMP_EXECUTABLE_STAGING|REBOOT_TEMP_PATH_ACTIVITY|REMOTE_FETCH_TO_TEMP)$''',

        then="HIGH",
        else="MEDIUM"
      )
    ) AS Severity,

    if(
      condition=DetectionClass =~
        '''^CRON_(REVERSE_SHELL|DOWNLOAD_AND_EXECUTE|ENCODED_EXECUTION)$''',

      then="HIGH",

      else=if(
        condition=DetectionClass = "CRON_TEMP_PATH_ACTIVITY",
        then="LOW",
        else="MEDIUM"
      )
    ) AS Confidence,

    if(
      condition=DetectionClass = "CRON_REVERSE_SHELL",

      then="Cron command contains reverse-shell indicators",

      else=if(
        condition=DetectionClass = "CRON_DOWNLOAD_AND_EXECUTE",

        then="Cron command downloads content and passes or chains it to an interpreter",

        else=if(
          condition=DetectionClass = "CRON_ENCODED_EXECUTION",

          then="Cron command decodes or deobfuscates content before execution",

          else=if(
            condition=DetectionClass = "CRON_TEMP_EXECUTABLE_STAGING",

            then="Cron command makes a file executable in a volatile temporary path",

            else=if(
              condition=DetectionClass = "CRON_REBOOT_TEMP_PATH_ACTIVITY",

              then="Cron executes at reboot and references a volatile temporary path",

              else=if(
                condition=DetectionClass = "CRON_REMOTE_FETCH_TO_TEMP",

                then="Cron downloads content into a volatile temporary path",

                else=if(
                  condition=DetectionClass = "CRON_INTERPRETER_ONE_LINER",

                  then="Cron uses an interpreter one-liner requiring review",

                  else="Cron command references a volatile temporary path"
                )
              )
            )
          )
        )
      )
    ) AS Reason

  FROM ClassifiedCronRows


-- ============================================================
-- 7. Final analyst-facing result
-- ============================================================

SELECT
  ClientId,
  Fqdn,

  CronUser AS User,

  if(
    condition=CronUser = "root",
    then="PRIVILEGED_CONTEXT",
    else="USER_CONTEXT"
  ) AS ExecutionContext,

  CronPath AS Path,

  if(
    condition=CronEvent =~ '''^@''',

    then=CronEvent,

    else=format(
      format="%v %v %v %v %v",
      args=[
        CronMinute,
        CronHour,
        CronDayOfMonth,
        CronMonth,
        CronDayOfWeek
      ]
    )
  ) AS Schedule,

  CronEvent AS Event,

  CronMinute AS Minute,
  CronHour AS Hour,
  CronDayOfMonth AS DayOfMonth,
  CronMonth AS Month,
  CronDayOfWeek AS DayOfWeek,

  CronCommand AS Command,

  DetectionClass,
  Severity,
  Confidence,
  Reason,

  "T1053.003 - Scheduled Task/Job: Cron"
    AS MITRETechnique,

  "SCHEDULED_CONFIGURATION_EVIDENCE"
    AS EvidenceType,

  if(
    condition=Severity =~ '''^(CRITICAL|HIGH)$''',
    then="IMMEDIATE_REVIEW",
    else="REVIEW_REQUIRED"
  ) AS Disposition,

  format(
    format="CRON|%v|%v|%v|%v|%v",
    args=[
      ClientId,
      CronPath,
      CronUser,
      CronEvent,
      CronCommand
    ]
  ) AS FindingKey,

  "Candidate - score once in Final Findings Detail"
    AS RiskScoreImpact

FROM ScoredCronRows

ORDER BY
  Severity
```

## Cell 8 (markdown)

# Services Inventory

This section inventories systemd service units collected across Linux endpoints.
Each service is enriched with its unit type, load state, runtime state and an
analyst-facing interpretation. These results represent collected runtime state
and do not independently prove that a service is malicious or persistent.
Suspicious service behavior is evaluated in the next detection cell.

## Cell 9 (vql)

```vql
-- ============================================================
-- Services Inventory
--
-- Purpose:
--   Inventory collected systemd service units and normalize
--   their runtime states for analyst review.
--
-- Detection:
--   NONE - Suspicious services are evaluated in the next cell.
--
-- ATT&CK Context:
--   T1543.002 - System Services: Systemd Service
--
-- Risk Score Impact:
--   NONE - Inventory and operational context only.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve raw service results
-- ============================================================

LET RawServiceRows <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/Services"
  )


-- ============================================================
-- 2. Normalize Artifact fields
-- ============================================================

LET NormalizedServiceRows <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    Unit AS ServiceUnit,
    Load AS LoadState,
    Active AS ActiveState,
    Sub AS SubState,
    Description AS ServiceDescription

  FROM RawServiceRows


-- ============================================================
-- 3. Keep valid service entries
-- ============================================================

LET ValidServiceRows <=
  SELECT *
  FROM NormalizedServiceRows

  WHERE ServiceUnit


-- ============================================================
-- 4. Classify unit type and runtime state
-- ============================================================

LET ContextualizedServiceRows <=
  SELECT
    *,

    if(
      condition=ServiceUnit =~ '''(?i)[.]service$''',

      then="SERVICE",

      else=if(
        condition=ServiceUnit =~ '''(?i)[.]socket$''',

        then="SOCKET",

        else=if(
          condition=ServiceUnit =~ '''(?i)[.]timer$''',

          then="TIMER",

          else=if(
            condition=ServiceUnit =~ '''(?i)[.]path$''',

            then="PATH",

            else=if(
              condition=ServiceUnit =~ '''(?i)[.]mount$''',

              then="MOUNT",

              else=if(
                condition=ServiceUnit =~ '''(?i)[.]target$''',

                then="TARGET",
                else="OTHER_UNIT"
              )
            )
          )
        )
      )
    ) AS UnitType,

    if(
      condition=LoadState =~ '''(?i)^loaded$''',

      then="UNIT_DEFINITION_LOADED",

      else=if(
        condition=LoadState =~ '''(?i)^masked$''',

        then="UNIT_MASKED",

        else=if(
          condition=LoadState =~
            '''(?i)^(not-found|bad-setting|error)$''',

          then="UNIT_LOAD_ISSUE",
          else="OTHER_LOAD_STATE"
        )
      )
    ) AS LoadContext,

    if(
      condition=
        ActiveState =~ '''(?i)^failed$'''
        OR SubState =~ '''(?i)^failed$''',

      then="FAILED",

      else=if(
        condition=
          ActiveState =~ '''(?i)^active$'''
          AND SubState =~ '''(?i)^running$''',

        then="ACTIVE_RUNNING",

        else=if(
          condition=
            ActiveState =~ '''(?i)^active$'''
            AND SubState =~ '''(?i)^exited$''',

          then="ACTIVE_EXITED",

          else=if(
            condition=
              ActiveState =~ '''(?i)^active$'''
              AND SubState =~ '''(?i)^waiting$''',

            then="ACTIVE_WAITING",

            else=if(
              condition=
                ActiveState =~ '''(?i)^active$'''
                AND SubState =~ '''(?i)^listening$''',

              then="ACTIVE_LISTENING",

              else=if(
                condition=ActiveState =~
                  '''(?i)^activating$''',

                then="ACTIVATING",

                else=if(
                  condition=ActiveState =~
                    '''(?i)^deactivating$''',

                  then="DEACTIVATING",

                  else=if(
                    condition=
                      ActiveState =~ '''(?i)^inactive$'''
                      AND SubState =~ '''(?i)^dead$''',

                    then="INACTIVE_DEAD",

                    else=if(
                      condition=ActiveState =~
                        '''(?i)^active$''',

                      then="ACTIVE_OTHER",
                      else="OTHER_STATE"
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS RuntimeContext

  FROM ValidServiceRows


-- ============================================================
-- 5. Add analyst-facing interpretation and keys
-- ============================================================

LET EnrichedServiceRows <=
  SELECT
    *,

    if(
      condition=RuntimeContext = "FAILED",

      then="Unit is in a failed state; inspect service status and journal",

      else=if(
        condition=RuntimeContext = "ACTIVE_RUNNING",

        then="Unit is currently active with a running service process",

        else=if(
          condition=RuntimeContext = "ACTIVE_EXITED",

          then="Unit remains active after its service process exited; common for oneshot or RemainAfterExit units",

          else=if(
            condition=RuntimeContext = "INACTIVE_DEAD",

            then="Unit is not currently active",

            else=if(
              condition=RuntimeContext = "ACTIVATING",

              then="Unit was transitioning into the active state during collection",

              else=if(
                condition=RuntimeContext = "DEACTIVATING",

                then="Unit was transitioning into the inactive state during collection",

                else="Use the raw Load, Active and Sub fields for interpretation"
              )
            )
          )
        )
      )
    ) AS StateInterpretation,

    format(
      format="SERVICE|%v|%v",
      args=[
        ClientId,
        ServiceUnit
      ]
    ) AS ServiceKey,

    format(
      format="SERVICE_STATE|%v|%v|%v|%v|%v",
      args=[
        ClientId,
        ServiceUnit,
        LoadState,
        ActiveState,
        SubState
      ]
    ) AS StateSnapshotKey

  FROM ContextualizedServiceRows


-- ============================================================
-- 6. Final analyst-facing inventory
-- ============================================================

SELECT
  ClientId,
  Fqdn,

  ServiceUnit AS Unit,
  UnitType,

  LoadState AS Load,
  LoadContext,

  ActiveState AS Active,
  SubState AS Sub,
  RuntimeContext,

  ServiceDescription AS Description,
  StateInterpretation,

  "T1543.002 - System Services: Systemd Service"
    AS MITREContext,

  "SERVICE_RUNTIME_STATE"
    AS EvidenceType,

  "Collected runtime state only"
    AS CollectionScope,

  ServiceKey,
  StateSnapshotKey,

  "Inventory only - no Risk Score impact"
    AS RiskScoreImpact

FROM EnrichedServiceRows

ORDER BY
  Fqdn
```

## Cell 10 (markdown)

# Systemd Service Unit Configuration Inventory

This section inventories important directives from collected systemd service
unit files. Each unit is summarized into a single row containing its execution
commands, service account, working directory, environment configuration,
restart policy and installation target. These results represent configuration
state only and do not independently prove service execution or malicious
persistence. Suspicious directives are evaluated in the next detection cell.

## Cell 11 (vql)

```vql
-- ============================================================
-- Systemd Service Unit Configuration Inventory
--
-- Purpose:
--   Extract important systemd directives without using expensive
--   correlated subqueries.
--
-- Detection:
--   NONE - Inventory and configuration context only.
--
-- ATT&CK:
--   T1543.002 - System Services: Systemd Service
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve collected unit-file lines
-- ============================================================

LET RawUnitLines =
  SELECT
    ClientId,
    Path AS UnitFilePath,
    Line AS RawLine

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SystemdServiceUnitLines"
  )

  WHERE
    ClientId
    AND Path
    AND Line


-- ============================================================
-- 2. Parse Directive=Value
-- ============================================================

LET ParsedUnitLines =
  SELECT
    ClientId,
    UnitFilePath,
    RawLine,

    parse_string_with_regex(
      string=RawLine,
      regex='''^\s*(?P<Directive>[^=\s]+)\s*=(?P<DirectiveValue>.*)$'''
    ) AS Parsed

  FROM RawUnitLines


-- ============================================================
-- 3. Keep important directives
-- ============================================================

LET ImportantUnitLines =
  SELECT
    ClientId,
    UnitFilePath,
    RawLine,

    Parsed.Directive AS Directive,
    Parsed.DirectiveValue AS DirectiveValue

  FROM ParsedUnitLines

  WHERE
    Parsed.Directive
    AND Parsed.Directive =~
      '''(?i)^(Description|ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop|User|Group|WorkingDirectory|Environment|EnvironmentFile|Restart|WantedBy|RequiredBy|OnCalendar)$'''


-- ============================================================
-- 4. Aggregate once per unit file and directive
--
-- This replaces the repeated subqueries from the previous VQL.
-- Multiple ExecStart or Environment values are preserved.
-- ============================================================

LET GroupedUnitDirectives =
  SELECT
    ClientId,
    UnitFilePath,
    Directive,

    enumerate(
      items=DirectiveValue
    ) AS Values,

    count() AS ValueCount

  FROM ImportantUnitLines

  GROUP BY
    ClientId,
    UnitFilePath,
    Directive


-- ============================================================
-- 5. Final analyst-facing result
-- ============================================================

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.fqdn AS Fqdn,

  if(
    condition=UnitFilePath =~
      '''(?i)^/etc/systemd/system/''',

    then="ADMIN_DEFINED_OR_OVERRIDE_UNIT",

    else=if(
      condition=UnitFilePath =~
        '''(?i)^/run/systemd/system/''',

      then="RUNTIME_UNIT",

      else=if(
        condition=UnitFilePath =~
          '''(?i)^/usr/local/lib/systemd/system/''',

        then="ADMIN_INSTALLED_UNIT",

        else=if(
          condition=UnitFilePath =~
            '''(?i)^/(lib|usr/lib)/systemd/system/''',

          then="DISTRIBUTION_OR_PACKAGE_UNIT",

          else=if(
            condition=UnitFilePath =~
              '''(?i)^(/home/[^/]+|/root)/[.]config/systemd/user/''',

            then="USER_LEVEL_UNIT",
            else="OTHER_UNIT_LOCATION"
          )
        )
      )
    )
  ) AS UnitFileContext,

  UnitFilePath AS Path,

  Directive,
  Values,
  ValueCount,

  if(
    condition=Directive =~
      '''(?i)^(ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop)$''',

    then="EXECUTION_CONFIGURATION",

    else=if(
      condition=Directive =~
        '''(?i)^(User|Group)$''',

      then="EXECUTION_IDENTITY",

      else=if(
        condition=Directive =~
          '''(?i)^(Environment|EnvironmentFile|WorkingDirectory)$''',

        then="EXECUTION_ENVIRONMENT",

        else=if(
          condition=Directive =~
            '''(?i)^(WantedBy|RequiredBy)$''',

          then="INSTALL_CONFIGURATION",

          else="SERVICE_CONFIGURATION"
        )
      )
    )
  ) AS DirectiveContext,

  "T1543.002 - Systemd Service"
    AS MITREContext,

  "SYSTEMD_UNIT_CONFIGURATION_SNAPSHOT"
    AS EvidenceType,

  "Configuration present; execution not proven"
    AS EvidenceInterpretation,

  "Inventory only - no Risk Score impact"
    AS RiskScoreImpact

FROM GroupedUnitDirectives

ORDER BY
  Fqdn
```

## Cell 12 (markdown)

# Suspicious Systemd Unit Directives

This section identifies suspicious execution and environment directives in
collected systemd unit files. Detection focuses on reverse-shell behavior,
download-and-execute chains, execution from temporary or user-controlled
locations, dynamic-linker manipulation and obfuscated commands. Standard
package services and generic systemd directives are excluded. A finding
represents suspicious configuration and must be correlated with runtime,
file metadata and service journal evidence before escalation.

## Cell 13 (vql)

```vql
-- ============================================================
-- Suspicious Systemd Unit Directives
--
-- Purpose:
--   Detect high-value suspicious behavior inside collected
--   systemd service unit directives.
--
-- ATT&CK:
--   T1543.002 - Systemd Service
--
-- Important:
--   Configuration presence does not independently prove execution.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Read raw systemd unit-file lines
--
-- We intentionally use the raw Artifact instead of
-- SuspiciousSystemdUnitLines because its existing classification
-- produces excessive false positives.
-- ============================================================

LET RawUnitLines =
  SELECT
    ClientId,
    Path AS UnitFilePath,
    Line AS RawLine

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SystemdServiceUnitLines"
  )

  WHERE
    ClientId
    AND Path
    AND Line


-- ============================================================
-- 2. Parse Directive=Value
-- ============================================================

LET ParsedRows =
  SELECT
    ClientId,
    UnitFilePath,
    RawLine,

    parse_string_with_regex(
      string=RawLine,
      regex='''^\s*(?P<Directive>[^=\s]+)\s*=(?P<DirectiveValue>.*)$'''
    ) AS Parsed

  FROM RawUnitLines


LET UnitLines =
  SELECT
    ClientId,
    UnitFilePath,
    RawLine,

    Parsed.Directive AS Directive,
    Parsed.DirectiveValue AS DirectiveValue

  FROM ParsedRows

  WHERE Parsed.Directive


-- ============================================================
-- 3. Classify suspicious behavior
--
-- Strong behavioral conditions are evaluated first.
-- Normal package paths and generic systemd directives are not
-- treated as suspicious.
-- ============================================================

LET ClassifiedUnitLines =
  SELECT
    *,

    if(
      condition=
        Directive =~
          '''(?i)^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)$'''
        AND DirectiveValue =~
          '''(?i)(/dev/(tcp|udp)/|(^|\s)(bash|sh)\s+-i|(^|\s)nc(at)?\s+.*\s(-e|--exec)(\s|$)|(^|\s)socat\s+.*(exec:|system:)|(^|\s)curl\s+[^|]+[|]\s*(sudo\s+)?(ba)?sh(\s|$)|(^|\s)wget\s+[^|]+[|]\s*(sudo\s+)?(ba)?sh(\s|$))''',

      then="NETWORK_SHELL_OR_PIPE_TO_SHELL",

      else=if(
        condition=
          Directive =~
            '''(?i)^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)$'''
          AND DirectiveValue =~
            '''(?i)/(tmp|var/tmp|dev/shm)/''',

        then="EXECUTION_FROM_TEMP_LOCATION",

        else=if(
          condition=
            Directive =~ '''(?i)^EnvironmentFile$'''
            AND DirectiveValue =~
              '''(?i)/(tmp|var/tmp|dev/shm)/''',

          then="ENVIRONMENT_FILE_FROM_TEMP_LOCATION",

          else=if(
            condition=
              Directive =~ '''(?i)^Environment$'''
              AND DirectiveValue =~
                '''(?i)(^|\s|")LD_PRELOAD\s*=''',

            then="LD_PRELOAD_CONFIGURATION",

            else=if(
              condition=
                Directive =~
                  '''(?i)^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)$'''
                AND DirectiveValue =~
                  '''(?i)(base64\s+(-d|--decode)|openssl\s+(enc\s+)?-d|xxd\s+-r|eval\s+[$(])''',

              then="OBFUSCATED_OR_DECODED_EXECUTION",

              else=if(
                condition=
                  Directive =~
                    '''(?i)^Exec(Start|StartPre|StartPost|Condition)$'''
                  AND DirectiveValue =~
                    '''(?i)systemctl\s+(enable|reenable)\s+''',

                then="PERSISTENCE_CHAINING_COMMAND",

                else=if(
                  condition=
                    UnitFilePath =~
                      '''(?i)/(system-update-lab|backup-sync-lab|remote-support-lab)[.]service$'''
                    AND Directive =~
                      '''(?i)^Exec(Start|StartPre|StartPost)$''',

                  then="KNOWN_LAB_PERSISTENCE_UNIT",

                  else=if(
                    condition=
                      Directive =~
                        '''(?i)^Exec(Start|StartPre|StartPost|Condition)$'''
                      AND DirectiveValue =~
                        '''(?i)(/home/|/root/|/[.]cache/|/[.]local/bin/)''',

                    then="EXECUTION_FROM_USER_CONTROLLED_LOCATION",

                    else=if(
                      condition=
                        Directive =~
                          '''(?i)^Exec(Start|StartPre|StartPost|Condition)$'''
                        AND DirectiveValue =~
                          '''(?i)(^|\s)(curl|wget)\s+''',

                      then="DIRECT_NETWORK_DOWNLOAD",

                      else=if(
                        condition=
                          Directive =~ '''(?i)^Environment$'''
                          AND DirectiveValue =~
                            '''(?i)(^|\s|")LD_LIBRARY_PATH\s*=''',

                        then="LD_LIBRARY_PATH_OVERRIDE",

                        else=if(
                          condition=
                            UnitFilePath =~
                              '''(?i)/[.][^/]+[.]service$'''
                            AND Directive =~
                              '''(?i)^Exec(Start|StartPre|StartPost)$''',

                          then="HIDDEN_UNIT_FILENAME",
                          else="NONE"
                        )
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS DetectionCategory

  FROM UnitLines


-- ============================================================
-- 4. Keep only actual detection candidates
-- ============================================================

LET DetectionCandidates =
  SELECT
    *,

    if(
      condition=
        DetectionCategory =
          "NETWORK_SHELL_OR_PIPE_TO_SHELL",

      then="CRITICAL",

      else=if(
        condition=DetectionCategory =~
          '''^(EXECUTION_FROM_TEMP_LOCATION|ENVIRONMENT_FILE_FROM_TEMP_LOCATION|LD_PRELOAD_CONFIGURATION|OBFUSCATED_OR_DECODED_EXECUTION|PERSISTENCE_CHAINING_COMMAND|KNOWN_LAB_PERSISTENCE_UNIT)$''',

        then="HIGH",
        else="MEDIUM"
      )
    ) AS Severity,

    if(
      condition=
        DetectionCategory =
          "NETWORK_SHELL_OR_PIPE_TO_SHELL",

      then="Systemd execution directive contains reverse-shell or download-and-execute behavior",

      else=if(
        condition=
          DetectionCategory =
            "EXECUTION_FROM_TEMP_LOCATION",

        then="Systemd executes a file from a temporary or shared-memory location",

        else=if(
          condition=
            DetectionCategory =
              "ENVIRONMENT_FILE_FROM_TEMP_LOCATION",

          then="Systemd loads environment configuration from a temporary location",

          else=if(
            condition=
              DetectionCategory =
                "LD_PRELOAD_CONFIGURATION",

            then="Service configures LD_PRELOAD and may influence dynamic library loading",

            else=if(
              condition=
                DetectionCategory =
                  "OBFUSCATED_OR_DECODED_EXECUTION",

              then="Execution directive contains decoding, deobfuscation or dynamic evaluation behavior",

              else=if(
                condition=
                  DetectionCategory =
                    "PERSISTENCE_CHAINING_COMMAND",

                then="Service attempts to enable another systemd unit",

                else=if(
                  condition=
                    DetectionCategory =
                      "KNOWN_LAB_PERSISTENCE_UNIT",

                  then="Unit matches a known lab persistence simulation",

                  else=if(
                    condition=
                      DetectionCategory =
                        "EXECUTION_FROM_USER_CONTROLLED_LOCATION",

                    then="Service executes content from a user-controlled or user-profile location",

                    else=if(
                      condition=
                        DetectionCategory =
                          "DIRECT_NETWORK_DOWNLOAD",

                      then="Service directly invokes a network download utility",

                      else=if(
                        condition=
                          DetectionCategory =
                            "LD_LIBRARY_PATH_OVERRIDE",

                        then="Service overrides the dynamic library search path",

                        else="Systemd unit uses a hidden service filename"
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ) AS Reason

  FROM ClassifiedUnitLines

  WHERE DetectionCategory != "NONE"


-- ============================================================
-- 5. Add ATT&CK and investigation context
-- ============================================================

LET EnrichedCandidates =
  SELECT
    *,

    if(
      condition=UnitFilePath =~
        '''(?i)^/etc/systemd/system/''',

      then="ADMIN_DEFINED_OR_OVERRIDE_UNIT",

      else=if(
        condition=UnitFilePath =~
          '''(?i)^/run/systemd/system/''',

        then="RUNTIME_UNIT",

        else=if(
          condition=UnitFilePath =~
            '''(?i)^/(lib|usr/lib)/systemd/system/''',

          then="DISTRIBUTION_OR_PACKAGE_UNIT",

          else=if(
            condition=UnitFilePath =~
              '''(?i)^(/home/[^/]+|/root)/[.]config/systemd/user/''',

            then="USER_LEVEL_UNIT",
            else="OTHER_UNIT_LOCATION"
          )
        )
      )
    ) AS UnitFileContext,

    if(
      condition=
        DetectionCategory =
          "NETWORK_SHELL_OR_PIPE_TO_SHELL",

      then="T1543.002 + T1059.004 + T1105",

      else=if(
        condition=
          DetectionCategory =
            "DIRECT_NETWORK_DOWNLOAD",

        then="T1543.002 + T1105",

        else=if(
          condition=
            DetectionCategory =
              "OBFUSCATED_OR_DECODED_EXECUTION",

          then="T1543.002 + T1027",

          else=if(
            condition=DetectionCategory =~
              '''^(LD_PRELOAD_CONFIGURATION|LD_LIBRARY_PATH_OVERRIDE)$''',

            then="T1543.002 + T1574.006",
            else="T1543.002"
          )
        )
      )
    ) AS MITREContext,

    if(
      condition=Severity = "CRITICAL",
      then=5,

      else=if(
        condition=Severity = "HIGH",
        then=4,
        else=2
      )
    ) AS SuggestedRiskWeight,

    format(
      format="SYSTEMD_FINDING|%v|%v|%v",
      args=[
        ClientId,
        UnitFilePath,
        DetectionCategory
      ]
    ) AS FindingKey

  FROM DetectionCandidates


-- ============================================================
-- 6. Final analyst-facing findings
-- ============================================================

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.fqdn AS Fqdn,

  Severity,
  DetectionCategory,
  Reason,

  UnitFileContext,
  UnitFilePath AS Path,

  Directive,
  DirectiveValue,
  RawLine AS Evidence,

  MITREContext,
  SuggestedRiskWeight,

  "Systemd unit configuration observed"
    AS EvidenceType,

  "Configuration present; execution not proven"
    AS EvidenceInterpretation,

  FindingKey,

  "Score maximum finding per ClientId and Path; do not sum every line"
    AS RiskScoreGuidance

FROM EnrichedCandidates

ORDER BY
  Severity
```

## Cell 14 (markdown)

# Systemd Timer Configuration Inventory

This section inventories scheduling, target mapping and execution semantics from
collected systemd timer unit files. Repeated trigger directives are preserved,
and each configuration item is classified by its role and file location.
Timer presence does not independently indicate malicious persistence or prove
that the associated service executed. Suspicious timers are evaluated in the
next detection cell and must be correlated with their target service unit.

## Cell 15 (vql)

```vql
-- ============================================================
-- Systemd Timer Configuration Inventory
--
-- Purpose:
--   Normalize important systemd timer directives collected
--   across the Linux fleet.
--
-- Detection:
--   NONE - Inventory and scheduling context only.
--
-- ATT&CK:
--   T1053.006 - Scheduled Task/Job: Systemd Timers
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve raw timer configuration lines
-- ============================================================

LET RawTimerLines =
  SELECT
    ClientId,
    Path AS TimerFilePath,
    Line AS RawLine

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SystemdTimerLines"
  )

  WHERE
    ClientId
    AND Path
    AND Line


-- ============================================================
-- 2. Parse Directive=Value
--
-- Additional "=" characters inside values are preserved.
-- Section headers such as [Unit] and [Timer] are excluded later.
-- ============================================================

LET ParsedTimerLines =
  SELECT
    ClientId,
    TimerFilePath,
    RawLine,

    parse_string_with_regex(
      string=RawLine,
      regex='''^\s*(?P<Directive>[^=\s]+)\s*=(?P<DirectiveValue>.*)$'''
    ) AS Parsed

  FROM RawTimerLines


-- ============================================================
-- 3. Keep analyst-relevant timer directives
-- ============================================================

LET ImportantTimerLines =
  SELECT
    ClientId,
    TimerFilePath,
    RawLine,

    Parsed.Directive AS Directive,
    Parsed.DirectiveValue AS DirectiveValue

  FROM ParsedTimerLines

  WHERE
    Parsed.Directive
    AND Parsed.Directive =~
      '''(?i)^(Description|OnCalendar|OnActiveSec|OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec|AccuracySec|RandomizedDelaySec|FixedRandomDelay|Persistent|WakeSystem|RemainAfterElapse|Unit|WantedBy|RequiredBy)$'''


-- ============================================================
-- 4. Group repeated values
--
-- A timer may legitimately contain multiple OnCalendar
-- directives. They are preserved in the Values array.
-- ============================================================

LET GroupedTimerDirectives =
  SELECT
    ClientId,
    TimerFilePath,
    Directive,

    enumerate(
      items=DirectiveValue
    ) AS Values,

    count() AS ValueCount

  FROM ImportantTimerLines

  GROUP BY
    ClientId,
    TimerFilePath,
    Directive


-- ============================================================
-- 5. Add timer path and directive context
-- ============================================================

LET EnrichedTimerDirectives =
  SELECT
    *,

    if(
      condition=TimerFilePath =~
        '''(?i)^/etc/systemd/system/''',

      then="ADMIN_DEFINED_OR_OVERRIDE_TIMER",

      else=if(
        condition=TimerFilePath =~
          '''(?i)^/run/systemd/system/''',

        then="RUNTIME_TIMER",

        else=if(
          condition=TimerFilePath =~
            '''(?i)^/usr/local/lib/systemd/system/''',

          then="ADMIN_INSTALLED_TIMER",

          else=if(
            condition=TimerFilePath =~
              '''(?i)^/(lib|usr/lib)/systemd/system/''',

            then="DISTRIBUTION_OR_PACKAGE_TIMER",

            else=if(
              condition=TimerFilePath =~
                '''(?i)^(/home/[^/]+|/root)/[.]config/systemd/user/''',

              then="USER_LEVEL_TIMER",
              else="OTHER_TIMER_LOCATION"
            )
          )
        )
      )
    ) AS TimerFileContext,

    if(
      condition=Directive =~
        '''(?i)^(OnCalendar|OnActiveSec|OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec)$''',

      then="TRIGGER_CONFIGURATION",

      else=if(
        condition=Directive =~
          '''(?i)^(AccuracySec|RandomizedDelaySec|FixedRandomDelay)$''',

        then="TIMING_BEHAVIOR",

        else=if(
          condition=Directive =~
            '''(?i)^Unit$''',

          then="TARGET_SERVICE_MAPPING",

          else=if(
            condition=Directive =~
              '''(?i)^(Persistent|WakeSystem|RemainAfterElapse)$''',

            then="EXECUTION_SEMANTICS",

            else=if(
              condition=Directive =~
                '''(?i)^(WantedBy|RequiredBy)$''',

              then="INSTALL_CONFIGURATION",
              else="TIMER_METADATA"
            )
          )
        )
      )
    ) AS DirectiveContext,

    if(
      condition=Directive =~ '''(?i)^OnCalendar$''',
      then="CALENDAR_TRIGGER",

      else=if(
        condition=Directive =~
          '''(?i)^(OnBootSec|OnStartupSec)$''',

        then="BOOT_OR_STARTUP_RELATIVE_TRIGGER",

        else=if(
          condition=Directive =~
            '''(?i)^OnActiveSec$''',

          then="TIMER_ACTIVATION_RELATIVE_TRIGGER",

          else=if(
            condition=Directive =~
              '''(?i)^(OnUnitActiveSec|OnUnitInactiveSec)$''',

            then="RECURRING_UNIT_RELATIVE_TRIGGER",
            else="NOT_A_TRIGGER_DIRECTIVE"
          )
        )
      )
    ) AS TriggerType

  FROM GroupedTimerDirectives


-- ============================================================
-- 6. Final analyst-facing inventory
-- ============================================================

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.fqdn AS Fqdn,

  TimerFileContext,
  TimerFilePath AS Path,

  Directive,
  Values,
  ValueCount,

  DirectiveContext,
  TriggerType,

  "T1053.006 - Systemd Timers"
    AS MITREContext,

  "SYSTEMD_TIMER_CONFIGURATION_SNAPSHOT"
    AS EvidenceType,

  "Timer configuration present; activation and execution not proven"
    AS EvidenceInterpretation,

  "Correlate the timer with its associated service unit"
    AS InvestigationGuidance,

  "Inventory only - no Risk Score impact"
    AS RiskScoreImpact

FROM EnrichedTimerDirectives

ORDER BY
  Fqdn
```

## Cell 16 (markdown)

# Suspicious Systemd Timer Configuration

## Cell 17 (vql)

```vql
-- ============================================================
-- Suspicious Systemd Timer Configuration
--
-- Purpose:
--   Detect high-value suspicious scheduling characteristics
--   in systemd timer configuration.
--
-- ATT&CK:
--   T1053.006 - Scheduled Task/Job: Systemd Timers
--
-- Important:
--   Timer configuration proves scheduling capability,
--   not activation or execution of the target service.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Read raw systemd timer lines
--
-- The raw Artifact is used because the existing
-- SuspiciousSystemdTimerLines Artifact classifies normal
-- OnCalendar and Persistent directives as suspicious.
-- ============================================================

LET RawTimerLines =
  SELECT
    ClientId,
    Path AS TimerFilePath,
    Line AS RawLine

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SystemdTimerLines"
  )

  WHERE
    ClientId
    AND Path
    AND Line


-- ============================================================
-- 2. Parse Directive=Value
-- ============================================================

LET ParsedTimerRows =
  SELECT
    ClientId,
    TimerFilePath,
    RawLine,

    parse_string_with_regex(
      string=RawLine,
      regex='''^\s*(?P<Directive>[^=\s]+)\s*=(?P<DirectiveValue>.*)$'''
    ) AS Parsed

  FROM RawTimerLines


LET TimerLines =
  SELECT
    ClientId,
    TimerFilePath,
    RawLine,

    Parsed.Directive AS Directive,
    Parsed.DirectiveValue AS DirectiveValue

  FROM ParsedTimerRows

  WHERE Parsed.Directive


-- ============================================================
-- 3. Add file-location and target-service context
--
-- timers.target.wants and other *.wants/*.requires directories
-- are treated as enablement links, not administrator-authored
-- timer definitions.
-- ============================================================

LET EnrichedTimerLines =
  SELECT
    *,

    if(
      condition=TimerFilePath =~
        '''(?i)^/etc/systemd/system/[^/]+[.](wants|requires)/''',

      then="ENABLEMENT_SYMLINK",

      else=if(
        condition=TimerFilePath =~
          '''(?i)^/run/systemd/(system|transient)/''',

        then="RUNTIME_TIMER",

        else=if(
          condition=TimerFilePath =~
            '''(?i)^/usr/local/lib/systemd/system/''',

          then="ADMIN_INSTALLED_TIMER",

          else=if(
            condition=TimerFilePath =~
              '''(?i)^/etc/systemd/system/''',

            then="ADMIN_DEFINED_OR_OVERRIDE_TIMER",

            else=if(
              condition=TimerFilePath =~
                '''(?i)^/(lib|usr/lib)/systemd/system/''',

              then="DISTRIBUTION_OR_PACKAGE_TIMER",

              else=if(
                condition=TimerFilePath =~
                  '''(?i)^((/home/[^/]+|/root)/[.]config/systemd/user/|/etc/systemd/user/)''',

                then="USER_LEVEL_TIMER",
                else="OTHER_TIMER_LOCATION"
              )
            )
          )
        )
      )
    ) AS TimerFileContext,

    regex_replace(
      source=regex_replace(
        source=TimerFilePath,
        re='''^.*/''',
        replace=""
      ),
      re='''[.]timer$''',
      replace=".service"
    ) AS DefaultTargetService

  FROM TimerLines


-- ============================================================
-- 4. Classify suspicious timer characteristics
--
-- Generic OnCalendar and Persistent=true lines are excluded.
-- Fast schedules are evaluated only for non-package timers.
-- ============================================================

LET ClassifiedTimerLines =
  SELECT
    *,

    if(
      condition=
        TimerFilePath =~
          '''(?i)/(system-update-lab|backup-sync-lab|remote-support-lab)[.]timer$'''
        AND Directive =~
          '''(?i)^(OnCalendar|OnActiveSec|OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec|Unit)$''',

      then="KNOWN_LAB_PERSISTENCE_TIMER",

      else=if(
        condition=
          TimerFilePath =~
            '''(?i)/[.][^/]+[.]timer$'''
          AND Directive =~
            '''(?i)^(OnCalendar|OnActiveSec|OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec|Unit)$''',

        then="HIDDEN_TIMER_FILENAME",

        else=if(
          condition=
            Directive =~ '''(?i)^Unit$'''
            AND DirectiveValue =~
              '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)[.]service$''',

          then="SUSPICIOUS_EXPLICIT_TARGET",

          else=if(
            condition=
              Directive =~
                '''(?i)^(OnActiveSec|OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec)$'''

              AND DirectiveValue =~
                '''(?i)^\s*([0-9]{1,4}(ms|us)|([1-9]|[1-5][0-9])\s*(s|sec|secs|second|seconds))\s*$'''

              AND TimerFileContext =~
                '''^(RUNTIME_TIMER|ADMIN_INSTALLED_TIMER|ADMIN_DEFINED_OR_OVERRIDE_TIMER|USER_LEVEL_TIMER|OTHER_TIMER_LOCATION)$''',

            then="FAST_CUSTOM_TIMER_TRIGGER",

            else=if(
              condition=
                Directive =~ '''(?i)^OnCalendar$'''

                AND DirectiveValue =~
                  '''(?i)^\s*(minutely|([*]-[*]-[*]\s+)?[*]:[*](:00)?)\s*$'''

                AND TimerFileContext =~
                  '''^(RUNTIME_TIMER|ADMIN_INSTALLED_TIMER|ADMIN_DEFINED_OR_OVERRIDE_TIMER|USER_LEVEL_TIMER|OTHER_TIMER_LOCATION)$''',

              then="EVERY_MINUTE_CUSTOM_TIMER",
              else="NONE"
            )
          )
        )
      )
    ) AS DetectionCategory

  FROM EnrichedTimerLines


-- ============================================================
-- 5. Keep and explain detection candidates
-- ============================================================

LET DetectionCandidates =
  SELECT
    *,

    if(
      condition=DetectionCategory =~
        '''^(KNOWN_LAB_PERSISTENCE_TIMER|HIDDEN_TIMER_FILENAME|SUSPICIOUS_EXPLICIT_TARGET)$''',

      then="HIGH",
      else="MEDIUM"
    ) AS Severity,

    if(
      condition=
        DetectionCategory =
          "KNOWN_LAB_PERSISTENCE_TIMER",

      then="Timer matches a known controlled persistence simulation",

      else=if(
        condition=
          DetectionCategory =
            "HIDDEN_TIMER_FILENAME",

        then="Timer uses a hidden filename and requires investigation",

        else=if(
          condition=
            DetectionCategory =
              "SUSPICIOUS_EXPLICIT_TARGET",

          then="Timer explicitly targets a known suspicious or lab service",

          else=if(
            condition=
              DetectionCategory =
                "FAST_CUSTOM_TIMER_TRIGGER",

            then="Non-package timer is configured to trigger in less than one minute",

            else="Non-package timer is configured with an every-minute calendar schedule"
          )
        )
      )
    ) AS Reason

  FROM ClassifiedTimerLines

  WHERE DetectionCategory != "NONE"


-- ============================================================
-- 6. Final analyst-facing findings
-- ============================================================

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.fqdn AS Fqdn,

  Severity,
  DetectionCategory,
  Reason,

  TimerFileContext,
  TimerFilePath AS Path,

  Directive,
  DirectiveValue,
  RawLine AS Evidence,

  if(
    condition=Directive =~ '''(?i)^Unit$''',
    then=DirectiveValue,
    else=DefaultTargetService
  ) AS TargetServiceCandidate,

  if(
    condition=Directive =~ '''(?i)^Unit$''',
    then="EXPLICIT_UNIT_MAPPING",
    else="SAME_NAME_SERVICE_INFERENCE"
  ) AS TargetMappingType,

  "T1053.006 - Systemd Timers"
    AS MITREContext,

  if(
    condition=Severity = "HIGH",
    then=4,
    else=2
  ) AS SuggestedRiskWeight,

  "Systemd timer configuration observed"
    AS EvidenceType,

  "Scheduling configuration present; activation and execution not proven"
    AS EvidenceInterpretation,

  "Pivot to the target service in Suspicious Systemd Unit Directives and verify ExecStart, process and journal evidence"
    AS InvestigationGuidance,

  format(
    format="SYSTEMD_TIMER_FINDING|%v|%v|%v",
    args=[
      ClientId,
      TimerFilePath,
      DetectionCategory
    ]
  ) AS FindingKey,

  "Score only the maximum finding per ClientId and timer Path"
    AS RiskScoreGuidance

FROM DetectionCandidates

ORDER BY
  Severity
```

## Cell 18 (markdown)

# Startup Files Inventory

This section reviews common Linux startup files such as rc.local, init.d scripts, profile.d files, and cron directories.

These files can be abused to execute commands automatically during boot, login, or scheduled execution.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/StartupFileLines"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Suspicious Startup File Lines

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/SuspiciousStartupFileLines"
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Shell Profile Lines

This section reviews user shell startup files such as `.bashrc`, `.profile`, `.bash_profile`, and `.zshrc`.

Attackers may abuse these files to execute commands when a user opens a shell or logs in.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/ShellProfileLines"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Suspicious Shell Profile Lines

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/SuspiciousShellProfileLines"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# Authorized SSH Keys Inventory

This section inventories SSH public keys configured across Linux endpoints.
Each entry is enriched with account context, key type, key options and comment
availability. The presence of an authorized key is not independently suspicious.
Unexpected keys and potentially risky options are evaluated in the next detection
cell and correlated with authentication and file modification evidence.

## Cell 27 (vql)

```vql
-- ============================================================
-- Authorized SSH Keys Inventory
--
-- Purpose:
--   Inventory SSH public keys configured for Linux accounts.
--
-- Detection:
--   NONE - Risky options and unexpected keys are evaluated
--   in the next detection cell.
--
-- ATT&CK Context:
--   T1098.004 - Account Manipulation: SSH Authorized Keys
--
-- Risk Score Impact:
--   NONE - Inventory and investigation context only.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Retrieve raw Authorized Keys results
-- ============================================================

LET RawAuthorizedKeyRows <=
  SELECT *
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/AuthorizedKeys"
  )


-- ============================================================
-- 2. Normalize Artifact fields
-- ============================================================

LET AuthorizedKeyRows <=
  SELECT
    ClientId,
    Fqdn,

    OSPath AS AuthorizedKeysPath,
    keytype AS KeyType,
    options AS KeyOptions,
    comment AS KeyComment

  FROM RawAuthorizedKeyRows

  WHERE
    OSPath
    AND keytype


-- ============================================================
-- 3. Add analyst-facing context
-- ============================================================

LET EnrichedAuthorizedKeyRows <=
  SELECT
    *,

    if(
      condition=AuthorizedKeysPath =~
        '''(?i)^/root/[.]ssh/authorized_keys''',

      then="ROOT_ACCOUNT",

      else=if(
        condition=AuthorizedKeysPath =~
          '''(?i)^/home/[^/]+/[.]ssh/authorized_keys''',

        then="USER_ACCOUNT",
        else="CUSTOM_OR_SYSTEM_PATH"
      )
    ) AS AccountContext,

    if(
      condition=KeyOptions,
      then="KEY_OPTIONS_PRESENT",
      else="NO_EXPLICIT_KEY_OPTIONS"
    ) AS KeyOptionState,

    if(
      condition=KeyComment,
      then="COMMENT_PRESENT",
      else="COMMENT_MISSING"
    ) AS CommentState,

    format(
      format="AUTHORIZED_KEY|%v|%v|%v|%v|%v",
      args=[
        ClientId,
        AuthorizedKeysPath,
        KeyType,
        KeyComment,
        KeyOptions
      ]
    ) AS InventoryKey

  FROM AuthorizedKeyRows


-- ============================================================
-- 4. Final analyst-facing inventory
-- ============================================================

SELECT
  ClientId,
  Fqdn,

  AccountContext,
  AuthorizedKeysPath,

  KeyType,
  KeyOptions,
  KeyOptionState,

  KeyComment,
  CommentState,

  "T1098.004 - SSH Authorized Keys"
    AS MITREContext,

  "AUTHORIZED_KEY_CONFIGURATION"
    AS EvidenceType,

  InventoryKey,

  "Inventory only - no Risk Score impact"
    AS RiskScoreImpact

FROM EnrichedAuthorizedKeyRows

ORDER BY
  Fqdn
```

## Cell 28 (markdown)

# Risky Authorized Keys

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       keytype AS KeyType,
       options AS Options,
       comment AS Comment,
       Fqdn,
       "HIGH" AS Severity,
       if(condition=options =~ "(?i)command=",
          then="Authorized key with forced command option",
          else=if(condition=options =~ "(?i)permitopen|tunnel|environment",
                  then="Authorized key with risky SSH option",
                  else="Authorized key requires review")) AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/AuthorizedKeys"
)
WHERE options =~ "(?i)(command=|permitopen|tunnel|environment)"
ORDER BY ClientId
```

## Cell 30 (markdown)

# PAM Configuration Lines

This section reviews PAM configuration files under `/etc/pam.d`.

PAM configuration is sensitive because attackers can abuse authentication modules for stealthy login persistence.

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/PAMLines"
)
ORDER BY ClientId
```

## Cell 32 (markdown)

# Suspicious PAM Lines

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence/SuspiciousPAMLines"
)
ORDER BY ClientId
```

## Cell 34 (markdown)

# Final Findings Detail

This section combines suspicious persistence indicators into one findings table.

It includes suspicious cron jobs, risky authorized SSH keys, suspicious systemd units, timers, startup files, shell profiles, and PAM configuration.

Use this table as the main evidence view for persistence hunting.

## Cell 35 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SuspiciousCron <=
  SELECT ClientId,
         "MEDIUM" AS Severity,
         "Suspicious Cron Job" AS Finding,
         User AS Evidence1,
         Path AS Evidence2,
         Command AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/Crontab"
  )
  WHERE User
    AND Command =~ "(?i)(curl|wget|bash -c|bash -i|/dev/tcp|nc |ncat|netcat|socat|python -c|python3 -c|perl -e|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/)"

LET RiskyAuthorizedKeys <=
  SELECT ClientId,
         "HIGH" AS Severity,
         "Risky Authorized Key" AS Finding,
         OSPath AS Evidence1,
         options AS Evidence2,
         comment AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/AuthorizedKeys"
  )
  WHERE options =~ "(?i)(command=|permitopen|tunnel|environment)"

LET SuspiciousSystemdUnits <=
  SELECT ClientId,
         Severity,
         "Suspicious Systemd Unit Line" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousSystemdUnitLines"
  )

LET SuspiciousTimers <=
  SELECT ClientId,
         Severity,
         "Suspicious Systemd Timer Line" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousSystemdTimerLines"
  )

LET SuspiciousStartupFiles <=
  SELECT ClientId,
         Severity,
         "Suspicious Startup File Line" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousStartupFileLines"
  )

LET SuspiciousShellProfiles <=
  SELECT ClientId,
         Severity,
         "Suspicious Shell Profile Line" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousShellProfileLines"
  )

LET SuspiciousPAM <=
  SELECT ClientId,
         Severity,
         "Suspicious PAM Line" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousPAMLines"
  )

SELECT *
FROM chain(
  a=SuspiciousCron,
  b=RiskyAuthorizedKeys,
  c=SuspiciousSystemdUnits,
  d=SuspiciousTimers,
  e=SuspiciousStartupFiles,
  f=SuspiciousShellProfiles,
  g=SuspiciousPAM
)
ORDER BY ClientId
```

## Cell 36 (markdown)

# Clients Needing Investigation

This section summarizes persistence-related findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when suspicious cron jobs, systemd units, SSH keys, shell profiles, startup files, or PAM configuration are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 37 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SuspiciousCron <=
  SELECT ClientId,
         "Suspicious Cron Job" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/Crontab"
  )
  WHERE User
    AND Command =~ "(?i)(curl|wget|bash -c|bash -i|/dev/tcp|nc |ncat|netcat|socat|python -c|python3 -c|perl -e|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/)"

LET RiskyAuthorizedKeys <=
  SELECT ClientId,
         "Risky Authorized Key" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/AuthorizedKeys"
  )
  WHERE options =~ "(?i)(command=|permitopen|tunnel|environment)"

LET SuspiciousSystemdUnits <=
  SELECT ClientId,
         "Suspicious Systemd Unit Line" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousSystemdUnitLines"
  )

LET SuspiciousTimers <=
  SELECT ClientId,
         "Suspicious Systemd Timer Line" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousSystemdTimerLines"
  )

LET SuspiciousStartupFiles <=
  SELECT ClientId,
         "Suspicious Startup File Line" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousStartupFileLines"
  )

LET SuspiciousShellProfiles <=
  SELECT ClientId,
         "Suspicious Shell Profile Line" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousShellProfileLines"
  )

LET SuspiciousPAM <=
  SELECT ClientId,
         "Suspicious PAM Line" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.Persistence/SuspiciousPAMLines"
  )

LET Findings <=
  SELECT *
  FROM chain(
    a=SuspiciousCron,
    b=RiskyAuthorizedKeys,
    c=SuspiciousSystemdUnits,
    d=SuspiciousTimers,
    e=SuspiciousStartupFiles,
    f=SuspiciousShellProfiles,
    g=SuspiciousPAM
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 38 (markdown)

# Recommended Next Actions

Clients with persistence-related findings should be reviewed in deeper hunting phases.

Recommended follow-up actions:

1. Review suspicious cron jobs and scheduled execution.
2. Validate authorized_keys entries and risky SSH key options.
3. Review systemd service and timer files.
4. Investigate startup scripts and shell profile modifications.
5. Review PAM configuration for suspicious modules or unusual paths.
6. Correlate persistence findings with process, network, authentication, and privilege escalation hunts.
