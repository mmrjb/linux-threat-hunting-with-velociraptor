# LTH - 00 - Master Triage

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# Linux Threat Hunting — Master Triage

## Objective

This notebook correlates Linux hunt results across multiple
endpoints to identify and prioritize suspicious clients.

## Workflow

1. Collect broad baseline information from Linux endpoints.
2. Identify suspicious users, processes, services, ports, and scheduled tasks.
3. Assign weighted risk indicators.
4. Rank clients by risk score.
5. Pivot to section-specific notebooks for deeper investigation.

## Important Note

A risk score is used for prioritization only.
It does not prove that a client is compromised.
Final conclusions require evidence correlation and timeline analysis.

## Cell 2 (markdown)

# Baseline Hunt Client Inventory

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Fqdn,
       count() AS ResultRows
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)
GROUP BY ClientId
ORDER BY Fqdn
```

## Cell 4 (markdown)

# Suspicious Users

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET UserResults <= SELECT
       ClientId,
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

SELECT ClientId,
       Fqdn,
       User,
       Description,
       Uid,
       Gid,
       Homedir,
       Shell,
       "Additional account with UID 0" AS Indicator,
       "A non-root account has UID 0 and therefore possesses root-level privileges." AS Reason,
       "Critical" AS Severity,
       "High" AS Confidence,
       "UID=0 AND User!=root" AS MatchedIndicators,
       "No" AS AllowlistHit,
       "Validate the account in /etc/passwd and /etc/shadow. Confirm its owner and disable or remove it if unauthorized." AS AnalystAction,
       5 AS Weight
FROM UserResults
WHERE str(str=Uid) = "0"
  AND str(str=User) != "root"
ORDER BY Fqdn
```

## Cell 6 (markdown)

# Suspicious Processes

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ProcessResults <= SELECT
       ClientId,
       Fqdn,
       Pid,
       Ppid,
       Name,
       CommandLine,
       Exe,
       Username,
       Hash
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)

LET ClassifiedProcesses <= SELECT *,
       Exe =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
           AS TempExecution,

       Exe =~ "(?i)^/run/user/[0-9]+(/|$)"
           AS UserRuntimeExecution,

       CommandLine =~
         "(?i)(curl|wget)[^|]{0,500}[|]\\s*(sudo\\s+)?(ba|da|z|k)?sh(\\s|$)"
           AS DownloadPipeShell,

       CommandLine =~
         "(?i)(base64\\s+(-d|--decode)|openssl\\s+enc\\s+-d)[^|]{0,500}[|]\\s*(ba|da|z|k)?sh(\\s|$)"
           AS DecodePipeShell,

       CommandLine =~
         "(?i)(^|\\s|/)(nc|ncat)(\\s|$).*(\\s-e\\s|\\s-c\\s|--exec(=|\\s)|--sh-exec(=|\\s))"
           AS NetcatExec,

       CommandLine =~
         "(?i)(^|\\s|/)socat(\\s|$).*(EXEC|SYSTEM):"
           AS SocatExec,

       CommandLine =~
         "(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+"
           AS DevTcpShell,

       CommandLine =~
         "(?i)python[0-9.]*\\s+-m\\s+(http\\.server|SimpleHTTPServer)(\\s|$)"
           AS PythonWebServer,

       (
         Name =~ "(?i)^(xmrig|minerd|kinsing|kdevtmpfsi)$"
         OR
         CommandLine =~ "(?i)(xmrig|stratum\\+tcp)"
       ) AS MiningPattern

FROM ProcessResults

SELECT ClientId,
       Fqdn,
       Pid,
       Ppid,
       Name,
       CommandLine,
       Exe,
       Username,
       Hash,

       if(
         condition=DownloadPipeShell,
         then="Downloaded content piped directly to a shell",
         else=if(
           condition=DecodePipeShell,
           then="Decoded content piped directly to a shell",
           else=if(
             condition=NetcatExec OR SocatExec OR DevTcpShell,
             then="Possible reverse-shell execution pattern",
             else=if(
               condition=MiningPattern,
               then="Known cryptocurrency-mining process pattern",
               else=if(
                 condition=(TempExecution OR UserRuntimeExecution)
                           AND PythonWebServer,
                 then="Python web server executing from a writable location",
                 else=if(
                   condition=TempExecution OR UserRuntimeExecution,
                   then="Executable running from a user-writable location",
                   else="Python HTTP server detected"
                 )
               )
             )
           )
         )
       ) AS Indicator,

       if(
         condition=DownloadPipeShell,
         then="The command downloads remote content and sends it directly to a shell without first validating the file.",
         else=if(
           condition=DecodePipeShell,
           then="Encoded content is decoded and executed directly by a shell.",
           else=if(
             condition=NetcatExec OR SocatExec OR DevTcpShell,
             then="The command contains execution options commonly associated with interactive or reverse shells.",
             else=if(
               condition=MiningPattern,
               then="The process name or command line matches known cryptocurrency-mining patterns.",
               else=if(
                 condition=(TempExecution OR UserRuntimeExecution)
                           AND PythonWebServer,
                 then="A temporary web server is running from a writable location and may be used for payload staging.",
                 else=if(
                   condition=TempExecution OR UserRuntimeExecution,
                   then="The executable is running from a location commonly writable by non-privileged users.",
                   else="A Python HTTP server is active and should be validated against approved administrative activity."
                 )
               )
             )
           )
         )
       ) AS Reason,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then="Critical",
         else=if(
           condition=MiningPattern
                     OR (
                       (TempExecution OR UserRuntimeExecution)
                       AND PythonWebServer
                     ),
           then="High",
           else="Medium"
         )
       ) AS Severity,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell
                   OR MiningPattern,
         then="High",
         else="Medium"
       ) AS Confidence,

       if(
         condition=DownloadPipeShell,
         then="curl/wget + pipe + shell",
         else=if(
           condition=DecodePipeShell,
           then="decoder + pipe + shell",
           else=if(
             condition=NetcatExec,
             then="nc/ncat + command execution option",
             else=if(
               condition=SocatExec,
               then="socat + EXEC/SYSTEM",
               else=if(
                 condition=DevTcpShell,
                 then="/dev/tcp or /dev/udp shell pattern",
                 else=if(
                   condition=MiningPattern,
                   then="miner name or stratum protocol",
                   else=if(
                     condition=(TempExecution OR UserRuntimeExecution)
                               AND PythonWebServer,
                     then="writable path + Python HTTP server",
                     else=if(
                       condition=TempExecution,
                       then="temporary executable path",
                       else=if(
                         condition=UserRuntimeExecution,
                         then="user runtime executable path",
                         else="Python HTTP server"
                       )
                     )
                   )
                 )
               )
             )
           )
         )
       ) AS MatchedIndicators,

       "Not evaluated" AS AllowlistHit,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then="Preserve the process tree and network evidence, verify the executable hash and isolate the host if the activity is unauthorized.",
         else=if(
           condition=MiningPattern,
           then="Check CPU usage, persistence, outbound mining connections and the origin of the executable.",
           else=if(
             condition=TempExecution OR UserRuntimeExecution,
             then="Validate the executable owner, hash, creation time, parent process and associated network connections.",
             else="Confirm whether the Python web server, user, directory and listening port are authorized."
           )
         )
       ) AS AnalystAction,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then=5,
         else=if(
           condition=MiningPattern
                     OR (
                       (TempExecution OR UserRuntimeExecution)
                       AND PythonWebServer
                     ),
           then=4,
           else=if(
             condition=TempExecution OR UserRuntimeExecution,
             then=3,
             else=2
           )
         )
       ) AS Weight

FROM ClassifiedProcesses

WHERE TempExecution
   OR UserRuntimeExecution
   OR DownloadPipeShell
   OR DecodePipeShell
   OR NetcatExec
   OR SocatExec
   OR DevTcpShell
   OR PythonWebServer
   OR MiningPattern

ORDER BY Fqdn
```

## Cell 8 (markdown)

# Suspicious Services

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ServiceResults <= SELECT
       ClientId,
       Fqdn,
       str(str=Unit) AS Unit,
       str(str=Description) AS Description,
       str(str=Active) AS Active,
       str(str=Load) AS Load,
       str(str=Sub) AS Sub
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)

LET ClassifiedServices <= SELECT *,

       Unit =~
         "(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\\.service$"
         AS KnownLabName,

       Description =~
         "(?i)(lab persistence|temporary update service|remote support lab)"
         AS KnownLabDescription,

       Unit =~
         "(?i)^(kinsing|xmrig|kdevtmpfsi|watchbog)([-_.@][a-z0-9_.@-]+)?\\.service$"
         AS ThreatAssociatedName,

       Description =~
         "(?i)(cryptocurrency[ -](miner|mining)|reverse[ -]shell|backdoor[ -]service|unauthorized[ -]remote[ -]access)"
         AS HighRiskDescription

FROM ServiceResults

SELECT ClientId,
       Fqdn,
       Unit,
       Description,
       Active,
       Load,
       Sub,

       if(
         condition=ThreatAssociatedName,
         then="Threat-associated systemd service name",
         else=if(
           condition=HighRiskDescription,
           then="High-risk systemd service description",
           else="Controlled suspicious-service lab indicator"
         )
       ) AS Indicator,

       if(
         condition=ThreatAssociatedName,
         then="The unit name matches a service naming pattern associated with Linux malware or cryptocurrency miners.",
         else=if(
           condition=HighRiskDescription,
           then="The service description contains terminology associated with backdoor, reverse-shell or mining activity.",
           else="The service matches an indicator intentionally created for LTH validation."
         )
       ) AS Reason,

       if(
         condition=ThreatAssociatedName,
         then="Critical",
         else="High"
       ) AS Severity,

       if(
         condition=HighRiskDescription
                   AND NOT ThreatAssociatedName
                   AND NOT KnownLabName
                   AND NOT KnownLabDescription,
         then="Medium",
         else="High"
       ) AS Confidence,

       if(
         condition=ThreatAssociatedName,
         then="threat-associated unit name",
         else=if(
           condition=HighRiskDescription,
           then="high-risk service description",
           else=if(
             condition=KnownLabName AND KnownLabDescription,
             then="lab unit name + lab description",
             else=if(
               condition=KnownLabName,
               then="lab unit name",
               else="lab service description"
             )
           )
         )
       ) AS MatchedIndicators,

       "Not evaluated" AS AllowlistHit,

       if(
         condition=ThreatAssociatedName OR HighRiskDescription,
         then="Inspect the unit file, ExecStart directives, service user, binary path, hash, timestamps, persistence links and related network activity.",
         else="Confirm that this is an authorized LTH validation service and remove it after completing the test."
       ) AS AnalystAction,

       "T1543.002 - Systemd Service" AS MITRETechnique,

       if(
         condition=ThreatAssociatedName,
         then=5,
         else=4
       ) AS Weight

FROM ClassifiedServices

WHERE KnownLabName
   OR KnownLabDescription
   OR ThreatAssociatedName
   OR HighRiskDescription

ORDER BY Fqdn
```

## Cell 10 (markdown)

# Suspicious Network Activity

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET NetworkResults <= SELECT
       ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       str(str=Status) AS ConnStatus,
       ProcInfo,
       str(str=get(
         item=ProcInfo,
         member="Name"
       )) AS ProcName,
       str(str=get(
         item=ProcInfo,
         member="Exe"
       )) AS ProcExe,
       str(str=get(
         item=ProcInfo,
         member="CommandLine"
       )) AS ProcCommandLine,
       str(str=get(
         item=ProcInfo,
         member="Username"
       )) AS ProcUsername,
       CallChain
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)

LET NetworkSignals <= SELECT *,

       ConnStatus =~ "(?i)^LISTEN$"
         AS IsListening,

       ConnStatus =~ "(?i)^(ESTAB|ESTABLISHED)$"
         AS IsEstablished,

       str(str=Laddr) =~
         "(?i)^(127\\.|::1$)"
         AS LoopbackBind,

       str(str=Laddr) =~
         "(?i)^(0\\.0\\.0\\.0|::|\\[::\\])$"
         AS WildcardBind,

       str(str=Lport) =~
         "^(4444|5555)$"
         AS HighRiskPort,

       ProcExe =~
         "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
         AS WritablePathExe,

       ProcCommandLine =~
         "(?i)(^|\\s)/(tmp|var/tmp|dev/shm)/[^\\s]+"
         AS WritablePathCommand,

       (
         ProcName =~ "(?i)^(nc|ncat)$"
         OR
         ProcCommandLine =~
           "(?i)(^|\\s|/)(nc|ncat)(\\s|$)"
       ) AS NetcatTool,

       (
         ProcName =~ "(?i)^socat$"
         OR
         ProcCommandLine =~
           "(?i)(^|\\s|/)socat(\\s|$)"
       ) AS SocatTool,

       ProcCommandLine =~
         "(?i)(^|\\s|/)(nc|ncat)(\\s|$).*(\\s-e(\\s|$)|\\s-c(\\s|$)|--exec(=|\\s)|--sh-exec(=|\\s))"
         AS NetcatExec,

       ProcCommandLine =~
         "(?i)(^|\\s|/)socat(\\s|$).*(EXEC|SYSTEM):"
         AS SocatExec,

       ProcCommandLine =~
         "(?i)python[0-9.]*\\s+-m\\s+(http\\.server|SimpleHTTPServer)(\\s|$)"
         AS PythonHTTPServer

FROM NetworkResults

LET ClassifiedNetwork <= SELECT *,

       NetcatExec OR SocatExec
         AS CommandExecutionSocket,

       (
         (IsListening OR IsEstablished)
         AND
         (WritablePathExe OR WritablePathCommand)
       ) AS WritablePathSocket,

       (
         IsListening
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolListener,

       (
         IsEstablished
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolConnection,

       (
         IsListening
         AND
         PythonHTTPServer
       ) AS PythonListener,

       (
         IsListening
         AND
         HighRiskPort
         AND
         NOT LoopbackBind
       ) AS RiskyPortListener

FROM NetworkSignals

SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus AS Status,
       ProcName,
       ProcExe,
       ProcCommandLine,
       ProcUsername,
       CallChain,
       WildcardBind,
       LoopbackBind,

       if(
         condition=CommandExecutionSocket,
         then="Network utility with command-execution options",
         else=if(
           condition=WritablePathSocket,
           then="Network socket owned by writable-path execution",
           else=if(
             condition=PythonListener AND RiskyPortListener,
             then="Python HTTP server on a high-risk exposed port",
             else=if(
               condition=NetworkToolListener,
               then="Netcat or Socat listening socket",
               else=if(
                 condition=NetworkToolConnection,
                 then="Active Netcat or Socat connection",
                 else=if(
                   condition=PythonListener,
                   then="Python HTTP server detected",
                   else="Unusual non-loopback listening port"
                 )
               )
             )
           )
         )
       ) AS Indicator,

       if(
         condition=CommandExecutionSocket,
         then="The network utility command line contains an option capable of executing a command or shell.",
         else=if(
           condition=WritablePathSocket,
           then="The socket is associated with an executable or command located in a user-writable temporary path.",
           else=if(
             condition=PythonListener AND RiskyPortListener,
             then="A Python HTTP server is listening on port 4444 or 5555 and is not restricted to loopback.",
             else=if(
               condition=NetworkToolListener,
               then="Netcat or Socat is accepting network connections and should be validated against authorized administration activity.",
               else=if(
                 condition=NetworkToolConnection,
                 then="Netcat or Socat has an established connection that may represent tunneling, file transfer or interactive access.",
                 else=if(
                   condition=PythonListener,
                   then="A Python HTTP server is active and may be used for legitimate administration or payload staging.",
                   else="A service is listening on port 4444 or 5555 through a non-loopback interface."
                 )
               )
             )
           )
         )
       ) AS Reason,

       if(
         condition=CommandExecutionSocket,
         then="Critical",
         else=if(
           condition=WritablePathSocket
                     OR (PythonListener AND RiskyPortListener),
           then="High",
           else=if(
             condition=NetworkToolListener,
             then="High",
             else="Medium"
           )
         )
       ) AS Severity,

       if(
         condition=CommandExecutionSocket
                   OR WritablePathSocket,
         then="High",
         else=if(
           condition=RiskyPortListener
                     AND NOT PythonListener
                     AND NOT NetworkToolListener,
           then="Low",
           else="Medium"
         )
       ) AS Confidence,

       if(
         condition=CommandExecutionSocket,
         then="network utility + command execution option",
         else=if(
           condition=WritablePathSocket,
           then="network socket + writable execution path",
           else=if(
             condition=PythonListener AND RiskyPortListener,
             then="Python HTTP server + exposed port 4444/5555",
             else=if(
               condition=NetworkToolListener,
               then="nc/ncat/socat + listening socket",
               else=if(
                 condition=NetworkToolConnection,
                 then="nc/ncat/socat + established connection",
                 else=if(
                   condition=PythonListener,
                   then="Python HTTP server + listening socket",
                   else="port 4444/5555 + non-loopback listener"
                 )
               )
             )
           )
         )
       ) AS MatchedIndicators,

       "Not evaluated" AS AllowlistHit,

       if(
         condition=CommandExecutionSocket,
         then="Preserve the process tree and network evidence, inspect the remote endpoint and isolate the host if the command is unauthorized.",
         else=if(
           condition=WritablePathSocket,
           then="Inspect the executable hash, file timestamps, owner, parent process, remote address and related persistence.",
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then="Validate the user, command line, parent process, local and remote endpoints and approved administrative purpose.",
             else=if(
               condition=PythonListener,
               then="Confirm the user, served directory, listening interface, port and business justification.",
               else="Identify the owning application and confirm that the listening port is expected for this host role."
             )
           )
         )
       ) AS AnalystAction,

       if(
         condition=CommandExecutionSocket,
         then=5,
         else=if(
           condition=WritablePathSocket
                     OR (PythonListener AND RiskyPortListener),
           then=4,
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then=3,
             else=2
           )
         )
       ) AS Weight

FROM ClassifiedNetwork

WHERE CommandExecutionSocket
   OR WritablePathSocket
   OR NetworkToolListener
   OR NetworkToolConnection
   OR PythonListener
   OR RiskyPortListener

ORDER BY Fqdn
```

## Cell 12 (markdown)

# Suspicious Cron Jobs

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

-- ============================================================
-- 1. Stage 1 — Safely extract dynamic fields from hunt_results()
-- ============================================================
LET CronFields <=
SELECT
       ClientId,
       Fqdn,

       str(str=get(
         item=scope(),
         member="User"
       )) AS User,

       str(str=get(
         item=scope(),
         member="Event"
       )) AS Event,

       str(str=get(
         item=scope(),
         member="Minute"
       )) AS Minute,

       str(str=get(
         item=scope(),
         member="Hour"
       )) AS Hour,

       str(str=get(
         item=scope(),
         member="DayOfMonth"
       )) AS DayOfMonth,

       str(str=get(
         item=scope(),
         member="Month"
       )) AS Month,

       str(str=get(
         item=scope(),
         member="DayOfWeek"
       )) AS DayOfWeek,

       str(str=get(
         item=scope(),
         member="Path"
       )) AS Path,

       str(str=get(
         item=scope(),
         member="Command"
       )) AS CommandValue,

       str(str=get(
         item=scope(),
         member="$Query"
       )) AS QueryValue

FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)

-- ============================================================
-- 2. Stage 2 — Normalize Cron command
-- ============================================================

LET CronResults <=
SELECT
       ClientId,
       Fqdn,
       User,
       Event,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       Path,

       if(
         condition=CommandValue,
         then=CommandValue,
         else=QueryValue
       ) AS CronCommand

FROM CronFields

-- ============================================================
-- 3. Stage 3 — Extract detection signals
-- ============================================================

LET CronSignals <=
SELECT *,

       /*
        * curl/wget output sent directly to a shell
        */
       CronCommand =~
         "(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\\s*(sudo\\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\\s|$)"
         AS DownloadPipeShell,

       /*
        * Encoded content decoded and piped to a shell
        */
       CronCommand =~
         "(?i)(base64\\s+(-d|--decode)|openssl\\s+enc\\s+-d)[^|]{0,1000}[|]\\s*(sudo\\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\\s|$)"
         AS DecodePipeShell,

       /*
        * Netcat with command-execution options
        */
       CronCommand =~
         "(?i)(^|\\s|/)(nc|ncat)(\\s|$).*(\\s-e(\\s|$)|\\s-c(\\s|$)|--exec(=|\\s)|--sh-exec(=|\\s))"
         AS NetcatExec,

       /*
        * Socat executing a command or shell
        */
       CronCommand =~
         "(?i)(^|\\s|/)socat(\\s|$).*(EXEC|SYSTEM):"
         AS SocatExec,

       /*
        * Bash /dev/tcp or /dev/udp reverse-shell pattern
        */
       CronCommand =~
         "(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+"
         AS DevTcpShell,

       /*
        * Direct execution from /tmp, /var/tmp or /dev/shm
        *
        * The second branch supports @reboot entries where the
        * username may remain at the beginning of Command.
        */
       (
         CronCommand =~
           "(?i)(^\\s*|[;&|]\\s*)(sudo\\s+)?(nohup\\s+)?/(tmp|var/tmp|dev/shm)/[^\\s;&|]+"

         OR

         (
           Event =~ "(?i)^@reboot$"
           AND
           CronCommand =~
             "(?i)^\\s*[A-Za-z_][A-Za-z0-9_-]*\\s+(sudo\\s+)?(nohup\\s+)?/(tmp|var/tmp|dev/shm)/[^\\s;&|]+"
         )
       ) AS DirectWritableExecution,

       /*
        * Interpreter executing a script from a writable path
        */
       (
         CronCommand =~
           "(?i)(^\\s*|[;&|]\\s*)(sudo\\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\\s+/(tmp|var/tmp|dev/shm)/[^\\s;&|]+"

         OR

         (
           Event =~ "(?i)^@reboot$"
           AND
           CronCommand =~
             "(?i)^\\s*[A-Za-z_][A-Za-z0-9_-]*\\s+(sudo\\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\\s+/(tmp|var/tmp|dev/shm)/[^\\s;&|]+"
         )
       ) AS InterpretedWritableExecution,

       /*
        * Inline Python, Perl, PHP or Ruby execution
        */
       (
         CronCommand =~
           "(?i)(^\\s*|[;&|]\\s*)(sudo\\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\\s+-c|perl\\s+-e|php\\s+-r|ruby\\s+-e)(\\s|$)"

         OR

         (
           Event =~ "(?i)^@reboot$"
           AND
           CronCommand =~
             "(?i)^\\s*[A-Za-z_][A-Za-z0-9_-]*\\s+(sudo\\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\\s+-c|perl\\s+-e|php\\s+-r|ruby\\s+-e)(\\s|$)"
         )
       ) AS InlineInterpreter,

       /*
        * curl/wget retrieving content from a remote URL
        */
       CronCommand =~
         "(?i)(^|[;&|]\\s*|\\s)(/usr/bin/|/bin/)?(curl|wget)(\\s|$)[^\\r\\n]{0,1000}(https?|ftp)://"
         AS ScheduledRemoteFetch,

       /*
        * Startup persistence
        */
       Event =~
         "(?i)^@reboot$"
         AS AtReboot,

       /*
        * Cron configured to run every minute
        */
       (
         Minute =~ "^(\\*|\\*/1)$"
         AND
         Hour = "*"
       ) AS EveryMinute

FROM CronResults

-- ============================================================
-- 4. Stage 4 — Correlate related signals
-- ============================================================

LET ClassifiedCron <=
SELECT *,

       (
         DirectWritableExecution
         OR
         InterpretedWritableExecution
       ) AS WritablePathExecution,

       (
         AtReboot
         AND
         (
           DirectWritableExecution
           OR
           InterpretedWritableExecution
         )
       ) AS RebootWritablePath,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR
           InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR
           EveryMinute
         )
       ) AS RepeatedRemoteFetch

FROM CronSignals

-- ============================================================
-- 5. Stage 5 — Identify critical behavior chains
-- ============================================================

LET ScoredCron <=
SELECT *,

       (
         DownloadPipeShell
         OR
         DecodePipeShell
         OR
         NetcatExec
         OR
         SocatExec
         OR
         DevTcpShell
         OR
         DownloadThenWritableExecution
       ) AS CriticalCommand

FROM ClassifiedCron

-- ============================================================
-- 6. Stage 6 — Final analyst output
-- ============================================================

SELECT
       ClientId,
       Fqdn,
       User,
       Event,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronCommand AS Command,
       Path,
       AtReboot,
       EveryMinute,

       if(
         condition=DownloadPipeShell,
         then="Remote content piped directly to a shell",
         else=if(
           condition=DecodePipeShell,
           then="Decoded content piped directly to a shell",
           else=if(
             condition=NetcatExec
                       OR SocatExec
                       OR DevTcpShell,
             then="Possible scheduled reverse-shell command",
             else=if(
               condition=DownloadThenWritableExecution,
               then="Remote content downloaded and executed from a writable path",
               else=if(
                 condition=WritablePathExecution,
                 then="Cron execution from a writable temporary path",
                 else=if(
                   condition=RepeatedRemoteFetch,
                   then="Recurring or startup remote-content retrieval",
                   else=if(
                     condition=InlineInterpreter,
                     then="Inline interpreter execution from Cron",
                     else="Scheduled remote-content retrieval"
                   )
                 )
               )
             )
           )
         )
       ) AS Indicator,

       if(
         condition=CriticalCommand,
         then="The Cron command contains a high-confidence execution chain commonly associated with payload delivery, decoding or reverse-shell activity.",
         else=if(
           condition=WritablePathExecution,
           then="Cron is configured to execute a file or script from a directory writable by non-privileged users.",
           else=if(
             condition=RepeatedRemoteFetch,
             then="Remote content is retrieved at startup or every minute, which may indicate recurring payload delivery.",
             else=if(
               condition=InlineInterpreter,
               then="Cron executes inline interpreted code that requires validation against approved automation.",
               else="Cron retrieves remote content and should be validated against an authorized update or administrative workflow."
             )
           )
         )
       ) AS Reason,

       if(
         condition=CriticalCommand,
         then="Critical",
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then="High",
           else="Medium"
         )
       ) AS Severity,

       if(
         condition=CriticalCommand,
         then="High",
         else="Medium"
       ) AS Confidence,

       if(
         condition=DownloadPipeShell,
         then="curl/wget + pipe + shell",
         else=if(
           condition=DecodePipeShell,
           then="decoder + pipe + shell",
           else=if(
             condition=NetcatExec,
             then="nc/ncat + command execution option",
             else=if(
               condition=SocatExec,
               then="socat + EXEC/SYSTEM",
               else=if(
                 condition=DevTcpShell,
                 then="/dev/tcp or /dev/udp shell pattern",
                 else=if(
                   condition=DownloadThenWritableExecution,
                   then="remote fetch + writable-path execution",
                   else=if(
                     condition=WritablePathExecution,
                     then="scheduled writable-path execution",
                     else=if(
                       condition=RepeatedRemoteFetch,
                       then="remote fetch + @reboot/every-minute schedule",
                       else=if(
                         condition=InlineInterpreter,
                         then="inline interpreter command",
                         else="curl/wget + remote URL"
                       )
                     )
                   )
                 )
               )
             )
           )
         )
       ) AS MatchedIndicators,

       "Not evaluated" AS AllowlistHit,

       if(
         condition=CriticalCommand,
         then="Preserve the crontab file and related scripts, inspect downloaded content, network destinations, file hashes and process evidence, and isolate the host if unauthorized.",
         else=if(
           condition=WritablePathExecution,
           then="Inspect the referenced file, owner, permissions, timestamps and hash. Confirm why Cron executes content from a writable path.",
           else=if(
             condition=ScheduledRemoteFetch,
             then="Validate the URL, destination, owner, execution frequency and business purpose. Apply an allowlist only to a verified command and destination.",
             else="Validate the inline code and confirm that it belongs to approved automation."
           )
         )
       ) AS AnalystAction,

       "T1053.003 - Cron" AS MITRETechnique,

       if(
         condition=CriticalCommand,
         then=5,
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then=4,
           else=if(
             condition=InlineInterpreter,
             then=3,
             else=2
           )
         )
       ) AS Weight

FROM ScoredCron

WHERE CriticalCommand
   OR WritablePathExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter
   OR ScheduledRemoteFetch

ORDER BY Fqdn
```

## Cell 14 (markdown)

## Administrative Process Review

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"
LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET AdminProcessSignals <= SELECT *,
  ProcName =~ '''(?i)^ssh$''' AS RemoteClient,
  ProcName =~ '''(?i)^(scp|sftp|rsync|rclone)$''' AS TransferTool,
  ProcName =~ '''(?i)^(curl|wget)$''' AS FetchTool,
  ProcName =~ '''(?i)^(nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS NetworkUtility,
  (ProcUsername="root" AND ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS RootShell,
  ProcName =~ '''(?i)^(sudo|su|doas)$''' AS PrivilegeUtility,
  ProcCommandLine =~ '''(?i)(^|\s|/)(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)''' AS InlineCode,
  (ProcName =~ '''(?i)^(screen|tmux|nohup)$'''
   OR ProcCommandLine =~ '''(?i)^\s*(sudo\s+)?nohup\s''') AS BackgroundSession,
  ProcExe =~ '''^/(usr/local|opt|srv|home|root|mnt|media)/''' AS ApplicationPathExe,
  (ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby)$'''
   AND ProcCommandLine =~ '''\s/(usr/local|opt|srv|home|root|mnt|media)/[^\s;&|]+''') AS InterpreterPathReference
FROM ProcessFields

LET AdministrativeProcessLeads <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "review_administrative_process" AS SignalId,
  "Administrative, application-path or interpreter process to validate" AS Indicator,
  0 AS FindingWeight,
  if(condition=RootShell OR PrivilegeUtility OR InlineCode OR TransferTool OR RemoteClient,then=2,else=1) AS ReviewPriority,
  dict(Pid=ProcPid,Ppid=ProcPpid,Name=ProcName,Username=ProcUsername,FlowId=RowFlowId) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(RemoteClient=RemoteClient,TransferTool=TransferTool,FetchTool=FetchTool,NetworkUtility=NetworkUtility,
    RootShell=RootShell,PrivilegeUtility=PrivilegeUtility,InlineCode=InlineCode,BackgroundSession=BackgroundSession,
    ApplicationPathExe=ApplicationPathExe,InterpreterPathReference=InterpreterPathReference) AS Evidence4,
  format(format="%v|%v|review_process|%v|%v|%v",args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this observed command, account, path and peer fit the approved administration or application workflow?" AS Hypothesis,
  "Identify the process owner and approved task; read parent and network context; validate the script or binary when needed" AS SuggestedChecks,
  "Current process snapshot only. Root shell is not proof of an interactive session; an interpreter argument may reference data rather than executed code" AS ObservationLimit,
  "LTH - 04 / LTH - 03 / LTH - 05" AS RecommendedNotebook
FROM AdminProcessSignals
WHERE RemoteClient OR TransferTool OR FetchTool OR NetworkUtility OR RootShell OR PrivilegeUtility
   OR InlineCode OR BackgroundSession OR ApplicationPathExe OR InterpreterPathReference

SELECT ClientId,Fqdn,Category AS HuntingArea,Indicator,FindingWeight AS Weight,ReviewPriority,
  "Hunt Lead" AS EvidenceKind,"Unreviewed" AS ReviewState,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM AdministrativeProcessLeads GROUP BY EvidenceKey
ORDER BY ReviewPriority DESC

```

## Cell 16 (markdown)

## Accounts and Scheduled Work Review

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"
LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))

LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"

LET CronScriptFiles <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=get(item=scope(),field="OSPath")) AS ScriptPath,
  TextOrEmpty(X=get(item=scope(),field="Content")) AS ScriptContent,
  get(item=scope(),field="Mtime") AS ScriptMtime,
  get(item=scope(),field="FileSize") AS ScriptFileSize,
  get(item=scope(),field="ContentLimit") AS ScriptContentLimit,
  get(item=scope(),field="PotentiallyTruncated") AS ScriptPotentiallyTruncated
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Crontab")
WHERE ScriptPath!="" AND ScriptContent!=""


LET ReviewAccountSignals <= SELECT *,
  (UserUid!="0" AND UserUid!="" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS NonRootShellAccount,
  (UserUid!="0" AND UserUid!="" AND HomeDir =~ '''^/(root|opt|srv)(/|$)''') AS ApplicationHomeAccount
FROM UserFields
LET ReviewAccountLeads <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "review_account_role" AS SignalId,"Account shell or application home requires role confirmation" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,dict(Shell=UserShell,Home=HomeDir) AS Evidence3,
  dict(NonRootShellAccount=NonRootShellAccount,ApplicationHomeAccount=ApplicationHomeAccount) AS Evidence4,
  format(format="%v|review_account|%v|%v|%v|%v",args=[ClientId,UserName,UserUid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this account, shell and home required by a named person or application?" AS Hypothesis,
  "Identify the account owner and intended role; request authentication or group evidence only if the hypothesis requires it" AS SuggestedChecks,
  "Passwd snapshot: configured shell is not proof of login, and primary GID is not supplementary group membership" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook
FROM ReviewAccountSignals WHERE NonRootShellAccount OR ApplicationHomeAccount

LET ScheduledTaskLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_scheduled_command" AS SignalId,"Scheduled command for administrative-workflow review" AS Indicator,
  0 AS FindingWeight,
  if(condition=CronUser="root" OR CronEvent="@reboot" OR (Minute IN ("*","*/1") AND Hour="*"),then=2,else=1) AS ReviewPriority,
  CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParserVersion=CronParserVersion,ParseStatus=CronParseStatus) AS Evidence4,
  format(format="%v|review_cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,CronPath,CronUser,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this scheduled command, execution account and frequency belong to an approved job?" AS Hypothesis,
  "Identify the job owner; validate its script and destination; use execution logs if proof of a run is needed" AS SuggestedChecks,
  "Shows every nonempty parsed command, including legitimate maintenance. Legacy cron parsing may have lost the real command or user" AS ObservationLimit,
  "LTH - 06 / LTH - 04" AS RecommendedNotebook
FROM CronResults

LET ScheduledScriptLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_cron_script" AS SignalId,"Periodic cron script content for purpose and ownership review" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ScriptPath AS Evidence1,ScriptContent AS Evidence2,
  ScriptMtime AS Evidence3,dict(FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated) AS Evidence4,
  format(format="%v|review_cron_script|%v|%v",args=[ClientId,ScriptPath,ScriptContent]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script expected in a periodic cron directory, and is it actually invoked by the configured scheduler?" AS Hypothesis,
  "Review the collected content and owner; confirm run-parts eligibility and scheduler configuration if execution matters" AS SuggestedChecks,
  "Only a collected content prefix; placement and Mtime do not prove execution or identify the modifier" AS ObservationLimit,
  "LTH - 06" AS RecommendedNotebook
FROM CronScriptFiles

LET AccountScheduledLeads <= SELECT * FROM chain(accounts=ReviewAccountLeads,commands=ScheduledTaskLeads,scripts=ScheduledScriptLeads)

SELECT ClientId,Fqdn,Category AS HuntingArea,Indicator,FindingWeight AS Weight,ReviewPriority,
  "Hunt Lead" AS EvidenceKind,"Unreviewed" AS ReviewState,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM AccountScheduledLeads GROUP BY EvidenceKey
ORDER BY ReviewPriority DESC

```

## Cell 18 (markdown)

## Listeners and Administrative Peers

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"
LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))


-- Edit to include your actual internal networks, including internally routed public ranges.
-- A peer outside this list is not automatically Internet traffic or malicious.
LET ReviewInternalCIDRs <= split(string="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",sep=",")
LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="CallChain")) AS RawCallChain,
       TextOrEmpty(X=get(item=scope(), member="Laddr")) AS Laddr,
       TextOrEmpty(X=get(item=scope(), member="Lport")) AS Lport,
       TextOrEmpty(X=get(item=scope(), member="Raddr")) AS Raddr,
       TextOrEmpty(X=get(item=scope(), member="Rport")) AS Rport,
       TextOrEmpty(X=get(item=scope(), member="Pid")) AS Pid,
       TextOrEmpty(X=get(item=scope(), member="Status")) AS ConnStatus,
       get(item=scope(), member="ProcInfo") AS ProcInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET NetworkResults <=
SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus,
       RawCallChain AS CallChain,
       TextOrEmpty(X=get(item=ProcInfo,field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="CommandLine")
         ||
         get(item=ProcInfo, member="cmdline")
       )) AS ProcCommandLine
FROM NetworkFields


LET ReviewNetworkFields <= SELECT *,
  regex_replace(source=Laddr,re='''^\[|\]$''',replace="") AS ReviewLocalIP,
  regex_replace(source=Raddr,re='''^\[|\]$''',replace="") AS ReviewPeerIP,
  ConnStatus =~ '''(?i)^LISTEN(ING)?$''' AS ReviewListening,
  ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$''' AS ReviewEstablished,
  ProcName =~ '''(?i)^(ssh|scp|sftp|rsync|rclone|curl|wget|nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS ReviewAdministrativeTool
FROM NetworkResults
LET ReviewNetworkSignals <= SELECT *,
  (ReviewListening AND cidr_contains(ip=ReviewLocalIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewLocalIP,ranges=["127.0.0.0/8","::1/128"])) AS NonLoopbackListener,
  (ReviewEstablished AND ReviewAdministrativeTool
    AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["127.0.0.0/8","::1/128","0.0.0.0/8","::/128"])) AS AdministrativeConnection,
  (ReviewEstablished AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fe80::/10","ff00::/8"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=ReviewInternalCIDRs)) AS PeerOutsideConfiguredNetworks
FROM ReviewNetworkFields
LET NetworkReviewLeads <= SELECT ClientId,Fqdn,"Network" AS Category,
  "review_socket_role" AS SignalId,"Listener or established peer for role and administration review" AS Indicator,
  0 AS FindingWeight,
  if(condition=AdministrativeConnection OR PeerOutsideConfiguredNetworks,then=2,else=1) AS ReviewPriority,
  dict(Pid=Pid,Name=ProcName,Username=ProcUsername) AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,CallChain=CallChain,
    NonLoopbackListener=NonLoopbackListener,AdministrativeConnection=AdministrativeConnection,
    PeerOutsideConfiguredNetworks=PeerOutsideConfiguredNetworks) AS Evidence4,
  format(format="%v|review_socket|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,Pid,Laddr,Lport,Raddr,Rport,ConnStatus,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this process need this listening address or peer for its approved service or administrative task?" AS Hypothesis,
  "Identify service and destination owners; confirm intended exposure and peer; correlate with the process and approved task" AS SuggestedChecks,
  "Established sockets do not establish initiation direction. Wildcard listening does not prove Internet reachability; configured CIDRs are not a reputation check" AS ObservationLimit,
  "LTH - 05 / LTH - 04" AS RecommendedNotebook
FROM ReviewNetworkSignals
WHERE NonLoopbackListener OR AdministrativeConnection OR PeerOutsideConfiguredNetworks

SELECT ClientId,Fqdn,Category AS HuntingArea,Indicator,FindingWeight AS Weight,ReviewPriority,
  "Hunt Lead" AS EvidenceKind,"Unreviewed" AS ReviewState,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM NetworkReviewLeads GROUP BY EvidenceKey
ORDER BY ReviewPriority DESC

```

## Cell 20 (markdown)

## Baseline Prevalence Review

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))


LET ReviewMinCohortHosts <= 4
LET ReviewMaxRareHosts <= 2
LET ReviewMaxRarePercent <= 25
LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)

LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"


LET ReviewPlatforms <= SELECT ClientId,
  (TextOrEmpty(X=get(item=scope(),field="Platform")) || "Unknown") AS ReviewCohort
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET ReviewPlatformIndex <= memoize(query={SELECT * FROM ReviewPlatforms},key="ClientId")

-- Denominator is distinct clients that returned usable rows for this source,
-- not all 16 scoped clients when some source results are missing.
LET ReviewSourceClients <= SELECT * FROM chain(
  processes={SELECT ClientId,"Process executable" AS Family FROM ProcessFields WHERE ProcExe!="" GROUP BY ClientId},
  services={SELECT ClientId,"Service unit" AS Family FROM ServiceFields WHERE ServiceUnit!="" GROUP BY ClientId},
  users={SELECT ClientId,"Shell account" AS Family FROM UserFields WHERE UserName!="" GROUP BY ClientId},
  cron={SELECT ClientId,"Cron command" AS Family FROM CronResults GROUP BY ClientId}
)
LET ReviewSourceCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewSourceClients
LET ReviewCoverage <= SELECT Family,ReviewCohort,count() AS CoveredHosts,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewSourceCohorts GROUP BY CohortKey
LET ReviewCoverageIndex <= memoize(query={SELECT * FROM ReviewCoverage},key="CohortKey")

LET ReviewObservations <= SELECT * FROM chain(
  processes={SELECT ClientId,Fqdn,"Processes" AS Category,"Process executable" AS Family,
    regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS Entity,
    "LTH.SystemBaseline/Processes" AS ObservationSource FROM ProcessFields WHERE ProcExe!=""},
  services={SELECT ClientId,Fqdn,"Services and Persistence" AS Category,"Service unit" AS Family,
    ServiceUnit AS Entity,"LTH.SystemBaseline/Services" AS ObservationSource FROM ServiceFields WHERE ServiceUnit!=""},
  users={SELECT ClientId,Fqdn,"Users and Privileges" AS Category,"Shell account" AS Family,
    UserName+"|"+UserShell AS Entity,"LTH.SystemBaseline/Users" AS ObservationSource
    FROM UserFields WHERE UserUid!="0" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$'''},
  cron={SELECT ClientId,Fqdn,"Persistence" AS Category,"Cron command" AS Family,
    CronUser+"|"+CronCommand AS Entity,"LTH.SystemBaseline/Crontab" AS ObservationSource FROM CronResults}
)
LET ReviewObservedCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewObservations
LET ReviewUniqueHostEntities <= SELECT *,
  format(format="%v|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS HostEntityKey,
  format(format="%v|%v|%v",args=[ReviewCohort,Family,Entity]) AS PrevalenceKey,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewObservedCohorts GROUP BY HostEntityKey
LET ReviewPrevalence <= SELECT PrevalenceKey,count() AS HostsWithEntity
FROM ReviewUniqueHostEntities GROUP BY PrevalenceKey
LET ReviewPrevalenceIndex <= memoize(query={SELECT * FROM ReviewPrevalence},key="PrevalenceKey")
LET ReviewPrevalenceRows <= SELECT *,
  get(item=ReviewCoverageIndex,field=CohortKey).CoveredHosts AS CoveredHosts,
  get(item=ReviewPrevalenceIndex,field=PrevalenceKey).HostsWithEntity AS HostsWithEntity
FROM ReviewUniqueHostEntities
LET RareBaselineLeads <= SELECT ClientId,Fqdn,Category,
  "review_low_prevalence" AS SignalId,"Low-prevalence baseline entity in the observed platform cohort" AS Indicator,
  0 AS FindingWeight,2 AS ReviewPriority,Family AS Evidence1,Entity AS Evidence2,
  dict(PlatformCohort=ReviewCohort,HostsWithEntity=HostsWithEntity,CoveredHosts=CoveredHosts) AS Evidence3,
  "Compare approved roles before treating rarity as an anomaly; do not interpret as newly created" AS Evidence4,
  format(format="%v|review_prevalence|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS EvidenceKey,
  ObservationSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this uncommon executable, unit, account or scheduled command explained by this host's approved role?" AS Hypothesis,
  "Compare with hosts having the same business role; identify owner and deployment purpose; inspect related baseline evidence" AS SuggestedChecks,
  "One-Hunt prevalence among clients with source rows. Platform is not a business-role cohort; exact cron commands may contain host-specific values" AS ObservationLimit,
  "LTH - 01 / the notebook for the observed family" AS RecommendedNotebook
FROM ReviewPrevalenceRows
WHERE ReviewCohort!="Unknown" AND CoveredHosts>=ReviewMinCohortHosts
  AND HostsWithEntity<=ReviewMaxRareHosts
  AND (HostsWithEntity * 100)<= (CoveredHosts * ReviewMaxRarePercent)

SELECT ClientId,Fqdn,Category AS HuntingArea,Indicator,FindingWeight AS Weight,ReviewPriority,
  "Hunt Lead" AS EvidenceKind,"Unreviewed" AS ReviewState,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM RareBaselineLeads GROUP BY EvidenceKey
ORDER BY ReviewPriority DESC

```

## Cell 22 (markdown)

## Active Service Role Review

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))

LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")


LET ReviewServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(ssh|sshd|xrdp|xrdp-sesman|vncserver|tigervnc|telnet|rsh)([-.@][^ ]*)?\.service$''' AS RemoteAccessService,
  ServiceUnit =~ '''(?i)^(docker|containerd|crio|cri-o|podman|kubelet)([-.@][^ ]*)?\.service$''' AS ContainerService,
  ServiceUnit =~ '''(?i)^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|postgres|redis|redis-server|mongod|mongodb|elasticsearch)([-.@][^ ]*)?\.service$''' AS ApplicationDataService,
  ServiceUnit =~ '''(?i)^(nfs|nfs-server|rpcbind|smb|smbd|nmb|nmbd|vsftpd|proftpd|pure-ftpd)([-.@][^ ]*)?\.service$''' AS FileSharingService
FROM ServiceFields
LET ActiveServiceLeads <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "review_active_service_role" AS SignalId,"Active access, application, container or file-sharing service" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(RemoteAccessService=RemoteAccessService,ContainerService=ContainerService,
    ApplicationDataService=ApplicationDataService,FileSharingService=FileSharingService) AS Evidence4,
  format(format="%v|review_service|%v|%v|%v",args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this active service required for the host role and is its access or data exposure intended?" AS Hypothesis,
  "Confirm the service owner and purpose; inspect related listeners; collect unit configuration only for the selected hypothesis" AS SuggestedChecks,
  "Observed loaded service state and naming only; no ExecStart, enablement, installed-package ownership or exposure proof" AS ObservationLimit,
  "LTH - 04 / LTH - 05 / LTH - 12" AS RecommendedNotebook
FROM ReviewServiceSignals
WHERE ServiceLoad="loaded" AND ServiceActive="active"
  AND (RemoteAccessService OR ContainerService OR ApplicationDataService OR FileSharingService)

SELECT ClientId,Fqdn,Category AS HuntingArea,Indicator,FindingWeight AS Weight,ReviewPriority,
  "Hunt Lead" AS EvidenceKind,"Unreviewed" AS ReviewState,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM ActiveServiceLeads GROUP BY EvidenceKey
ORDER BY ReviewPriority DESC

```

## Cell 24 (markdown)

## Hunt Starting Points

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))
-- Keep this FALSE on the production server, consistently in all cells.
LET EnableLabIndicators <= FALSE


LET Fleet <= SELECT ClientId,Fqdn,"Coverage" AS Category,"Basic information source returned rows" AS Indicator,
  0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)


LET UserMatches <=
SELECT *,
       format(
         format="%v|uid0|%v|%v",
         args=[ClientId, UserName, HomeDir]
       ) AS EvidenceKey,
       5 AS FindingWeight
FROM UserFields
WHERE UserUid = "0"
  AND NOT UserName =~ '''^root$'''
  AND NOT (
    UserName = ""
    AND HomeDir = "/root"
  )

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET ProcessSignals <=
SELECT *,
       ProcCommandLine =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       ProcCommandLine =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       ProcExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer,
       ProcExe =~ '''(?i)^/run/user/[0-9]+/''' AS UserRuntimeExecution,
       (ProcName =~ '''(?i)^(xmrig|minerd|kinsing|kdevtmpfsi)$'''
        OR ProcCommandLine =~ '''(?i)(xmrig|stratum\+tcp)''') AS MiningPattern
FROM ProcessFields


LET ProcessMatches <=
SELECT *,
       format(
         format="%v|process|%v|%v|%v",
         args=[ClientId, ProcPid, ProcExe, ProcCommandLine]
       ) AS EvidenceKey,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then=5,
         else=if(
           condition=WritablePathExe
                     OR WritablePathExecution
                     OR MiningPattern
                     OR (UserRuntimeExecution AND PythonHTTPServer),
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool
                       OR UserRuntimeExecution,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ProcessSignals
WHERE DownloadPipeShell
   OR DecodePipeShell
   OR NetcatExec
   OR SocatExec
   OR DevTcpShell
   OR WritablePathExe
   OR WritablePathExecution
   OR NetcatTool
   OR SocatTool
   OR PythonHTTPServer
   OR UserRuntimeExecution
   OR MiningPattern


LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")

LET ServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(kinsing|xmrig|kdevtmpfsi|watchbog)([-_.@][a-z0-9_.@-]+)?\.service$''' AS ThreatAssociatedName,
  ServiceDescription =~ '''(?i)(cryptocurrency[ -](miner|mining)|reverse[ -]shell|backdoor[ -]service|unauthorized[ -]remote[ -]access)''' AS HighRiskDescription,
  (EnableLabIndicators AND
   (ServiceUnit =~ '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
    OR ServiceDescription =~ '''(?i)(lab persistence|temporary update service|remote support lab)''')) AS KnownLabService
FROM ServiceFields

LET ServiceMatches <= SELECT *,
  format(format="%v|service|%v|%v|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceDescription,ServiceLoad,ServiceActive,ServiceSub]) AS EvidenceKey,
  if(condition=ThreatAssociatedName,then=5,else=4) AS FindingWeight
FROM ServiceSignals
WHERE ThreatAssociatedName OR HighRiskDescription OR KnownLabService

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="CallChain")) AS RawCallChain,
       TextOrEmpty(X=get(item=scope(), member="Laddr")) AS Laddr,
       TextOrEmpty(X=get(item=scope(), member="Lport")) AS Lport,
       TextOrEmpty(X=get(item=scope(), member="Raddr")) AS Raddr,
       TextOrEmpty(X=get(item=scope(), member="Rport")) AS Rport,
       TextOrEmpty(X=get(item=scope(), member="Pid")) AS Pid,
       TextOrEmpty(X=get(item=scope(), member="Status")) AS ConnStatus,
       get(item=scope(), member="ProcInfo") AS ProcInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET NetworkResults <=
SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus,
       RawCallChain AS CallChain,
       TextOrEmpty(X=get(item=ProcInfo,field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="CommandLine")
         ||
         get(item=ProcInfo, member="cmdline")
       )) AS ProcCommandLine
FROM NetworkFields


LET NetworkSignals <=
SELECT *,
       ConnStatus =~ '''(?i)^(LISTEN|LISTENING)$'''
         AS IsListening,

       ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$'''
         AS IsEstablished,

       Laddr =~ '''^(127\.|::1$|\[::1\]$)'''
         AS LoopbackBind,

       Lport =~ '''^(4444|5555)$'''
         AS HighRiskPort,

       ProcExe =~ '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer
FROM NetworkResults


LET ClassifiedNetwork <=
SELECT *,
       NetcatExec
       OR SocatExec
         AS CommandExecutionSocket,

       (
         (IsListening OR IsEstablished)
         AND
         (WritablePathExe OR WritablePathExecution)
       ) AS WritablePathSocket,

       (
         IsListening
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolListener,

       (
         IsEstablished
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolConnection,

       (
         IsListening
         AND
         PythonHTTPServer
       ) AS PythonListener,

       (
         IsListening
         AND
         HighRiskPort
         AND
         NOT LoopbackBind
       ) AS RiskyPortListener
FROM NetworkSignals


LET NetworkMatches <=
SELECT *,
       format(
         format="%v|network|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           Pid,
           Laddr,
           Lport,
           Raddr,
           Rport,
           ConnStatus
         ]
       ) AS EvidenceKey,

       if(
         condition=CommandExecutionSocket,
         then=5,
         else=if(
           condition=WritablePathSocket
                     OR (
                       PythonListener
                       AND RiskyPortListener
                     ),
           then=4,
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ClassifiedNetwork
WHERE CommandExecutionSocket
   OR WritablePathSocket
   OR NetworkToolListener
   OR NetworkToolConnection
   OR PythonListener
   OR RiskyPortListener

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"


LET CronSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM CronResults


LET ClassifiedCron <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM CronSignals


LET ScoredCron <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedCron


LET CronMatches <=
SELECT *,
       format(
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
           CronUser,
           CronEvent,
           Minute,
           Hour,
           DayOfMonth,
           Month,
           DayOfWeek,
           CronCommand
         ]
       ) AS EvidenceKey,

       if(
         condition=CriticalCommand,
         then=5,
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then=4,
           else=if(
             condition=InlineInterpreter,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ScoredCron
WHERE CriticalCommand
   OR WritablePathExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter
   OR ScheduledRemoteFetch


LET UserDetail <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_additional_uid0" AS SignalId,"Additional UID 0 account" AS Indicator,
  FindingWeight,EvidenceKey,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,HomeDir AS Evidence3,UserShell AS Evidence4,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this additional UID 0 identity authorized for this server?" AS Hypothesis,
  "Passwd configuration only; no proof of login or privilege use" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook,
  UserName AS User,UserDescription AS Description,UserUid AS Uid,UserGid AS Gid,
  HomeDir AS Homedir,UserShell AS Shell
FROM UserMatches

LET ProcessDetail <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_behavior" AS SignalId,
  if(condition=DownloadPipeShell,then="Downloaded content piped to a shell",
    else=if(condition=DecodePipeShell,then="Decoded content piped to a shell",
      else=if(condition=NetcatExec OR SocatExec OR DevTcpShell,then="Command contains a shell/socket execution pattern",
        else=if(condition=MiningPattern,then="Mining-related name or command pattern",
          else=if(condition=WritablePathExe OR WritablePathExecution,then="Execution from a temporary path",
            else=if(condition=UserRuntimeExecution,then="Execution from a user runtime path",
              else=if(condition=NetcatTool OR SocatTool,then="Network utility in process command",
                else="Python HTTP server command"))))))) AS Indicator,
  FindingWeight,EvidenceKey,dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Name=ProcName,Hash=ProcHash,FlowId=RowFlowId,DownloadPipeShell=DownloadPipeShell,DecodePipeShell=DecodePipeShell,
    NetcatExec=NetcatExec,SocatExec=SocatExec,DevTcpShell=DevTcpShell,MiningPattern=MiningPattern,
    WritablePathExe=WritablePathExe,WritablePathExecution=WritablePathExecution,
    UserRuntimeExecution=UserRuntimeExecution,NetcatTool=NetcatTool,SocatTool=SocatTool,
    PythonHTTPServer=PythonHTTPServer) AS Evidence4,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate executable origin, server role and whether this command was authorized" AS Hypothesis,
  "Command/name regex on a process snapshot; not a shell parser or confirmation of compromise" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook,
  ProcPid AS Pid,ProcPpid AS Ppid,ProcName AS Name,ProcExe AS Exe,ProcCommandLine AS CommandLine,
  ProcUsername AS Username,ProcHash AS Hash
FROM ProcessMatches

LET ServiceDetail <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_service_name_description" AS SignalId,
  if(condition=ThreatAssociatedName,then="Service name matches a threat-associated watchlist",
    else=if(condition=HighRiskDescription,then="Service description matches suspicious terminology",
      else="Explicitly enabled lab service indicator")) AS Indicator,
  FindingWeight,EvidenceKey,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(ThreatAssociatedName=ThreatAssociatedName,HighRiskDescription=HighRiskDescription,KnownLabService=KnownLabService) AS Evidence4,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this service name/description correspond to an unauthorized installed service?" AS Hypothesis,
  "Only name, description and state are available. Priority weight is not confidence; collect the unit and executable to validate" AS ObservationLimit,
  "LTH - 04 / LTH - 06" AS RecommendedNotebook,
  ServiceUnit AS Unit,ServiceDescription AS Description,ServiceLoad AS Load,
  ServiceActive AS Active,ServiceSub AS Sub
FROM ServiceMatches

LET NetworkDetail <= SELECT ClientId,Fqdn,"Network" AS Category,
  "baseline_process_socket" AS SignalId,
  if(condition=CommandExecutionSocket,then="Socket-owning process has a command execution pattern",
    else=if(condition=WritablePathSocket,then="Active socket with temporary-path execution context",
      else=if(condition=NetworkToolListener OR NetworkToolConnection,then="Network utility listener or connection",
        else=if(condition=PythonListener,then="Python HTTP listener",else="Non-loopback listener on a configured review port")))) AS Indicator,
  FindingWeight,EvidenceKey,Pid AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,
    Username=ProcUsername,CallChain=CallChain,
    CommandExecutionSocket=CommandExecutionSocket,WritablePathSocket=WritablePathSocket,
    NetworkToolListener=NetworkToolListener,NetworkToolConnection=NetworkToolConnection,
    PythonListener=PythonListener,RiskyPortListener=RiskyPortListener) AS Evidence4,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this socket, associated command and peer expected for this host role?" AS Hypothesis,
  "Socket snapshot; a port number does not identify a protocol or prove command-and-control" AS ObservationLimit,
  "LTH - 05 - Network Connections Dashboard" AS RecommendedNotebook,
  Laddr,Lport,Raddr,Rport,Pid,ConnStatus AS Status,ProcName,ProcExe,ProcCommandLine,ProcUsername,CallChain
FROM NetworkMatches

LET CronDetail <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_command" AS SignalId,
  if(condition=CriticalCommand,then="Cron declares a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron declares execution from a temporary path",
      else=if(condition=RepeatedRemoteFetch,then="Cron declares remote fetch at reboot or every minute",
        else=if(condition=InlineInterpreter,then="Cron declares inline interpreter code",else="Cron declares remote fetch")))) AS Indicator,
  FindingWeight,EvidenceKey,CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParseStatus=CronParseStatus,ParserVersion=CronParserVersion,
    CriticalCommand=CriticalCommand,WritablePathExecution=WritablePathExecution,
    RepeatedRemoteFetch=RepeatedRemoteFetch,InlineInterpreter=InlineInterpreter,ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this scheduled command authorized and is there separate evidence it executed?" AS Hypothesis,
  "Declared command only; legacy parser rows may be incomplete. No cron runtime or complete shell semantics" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook,
  CronUser,CronPath,CronCommand,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek
FROM CronMatches

LET AccountSignals <= SELECT *,
  UserShell =~ '''^/(tmp|var/tmp|dev/shm)/''' AS TemporaryShell,
  (UserName="root" AND HomeDir =~ '''^/(tmp|var/tmp|dev/shm)/''') AS TemporaryRootHome,
  (UserGid="0" AND UserUid!="0" AND UserUid!="") AS PrimaryRootGroup,
  (UserName =~ '''^(www-data|apache|nginx|mysql|mariadb|postgres|redis|memcached|nobody)$'''
   AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS ServiceInteractiveShell
FROM UserFields

LET AccountMatches <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_account_configuration" AS SignalId,
  if(condition=TemporaryShell,then="Account declares a shell under a temporary directory",
    else=if(condition=TemporaryRootHome,then="Root account declares a temporary home directory",
      else=if(condition=PrimaryRootGroup,then="Non-root UID has primary GID 0",
        else="Named service account has an interactive shell"))) AS Indicator,
  if(condition=TemporaryShell,then=4,else=if(condition=TemporaryRootHome,then=3,else=2)) AS FindingWeight,
  UserName AS Evidence1,dict(Uid=UserUid,Gid=UserGid) AS Evidence2,
  UserShell AS Evidence3,dict(Home=HomeDir,TemporaryShell=TemporaryShell,
    TemporaryRootHome=TemporaryRootHome,PrimaryRootGroup=PrimaryRootGroup,
    ServiceInteractiveShell=ServiceInteractiveShell) AS Evidence4,
  format(format="%v|account_config|%v|%v|%v|%v|%v",
    args=[ClientId,UserName,UserUid,UserGid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate account role and whether this shell, group or home was authorized" AS Hypothesis,
  "Configuration snapshot; does not establish a login or privilege use" AS ObservationLimit,
  "LTH - 02 - Users Groups and Privileges Dashboard" AS RecommendedNotebook
FROM AccountSignals
WHERE TemporaryShell OR TemporaryRootHome OR PrimaryRootGroup OR ServiceInteractiveShell

LET ProcessExtraFields <= SELECT *,
  format(format="%v|%v|%v",args=[ClientId,RowFlowId,ProcPid]) AS ProcessLookupKey,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS CleanExe,
  (ProcDeleted=TRUE OR ProcExe =~ '''\(deleted\)$''') AS IsDeleted,
  ProcExe =~ '''^/?memfd:''' AS IsMemfd
FROM ProcessFields

LET ProcessIndex <= memoize(query={SELECT * FROM ProcessExtraFields},key="ProcessLookupKey")
LET ProcessWithParent <= SELECT *,
  get(item=ProcessIndex,field=format(format="%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPpid])) AS ParentProcess
FROM ProcessExtraFields

LET NewProcessSignals <= SELECT *,
  (ParentProcess.ProcName =~ '''^(nginx|apache2|httpd|php-fpm[0-9.]*|uwsgi|gunicorn[0-9.: -]*)$'''
   AND CleanExe =~ '''/(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php[0-9.]*)$'''
   AND ProcPpid!="0" AND ProcPpid!="") AS WebServiceChild,
  (CleanExe =~ '''/ssh$'''
   AND ProcCommandLine =~ '''(^|\s)(-(R|D)(\s|[0-9*\[:/])|-o\s*(RemoteForward|DynamicForward)\s*=)''') AS SSHForwarding
FROM ProcessWithParent

LET ExtraProcessMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_context" AS SignalId,
  if(condition=IsMemfd,then="Process executable is backed by memfd",
    else=if(condition=WebServiceChild,then="Shell or interpreter has a web-service parent in this snapshot",
      else=if(condition=SSHForwarding,then="SSH process declares remote or dynamic forwarding",
        else="Process executable is marked deleted"))) AS Indicator,
  if(condition=IsMemfd,then=4,else=if(condition=WebServiceChild,then=3,else=2)) AS FindingWeight,
  dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername,CreatedTime=ProcCreatedTime) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Deleted=IsDeleted,Memfd=IsMemfd,SSHForwarding=SSHForwarding,
    WebServiceChild=WebServiceChild,ParentName=ParentProcess.ProcName,
    ParentExe=ParentProcess.ProcExe,ParentCommandLine=ParentProcess.ProcCommandLine,
    FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|process_context|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the executable, parent application behavior and authorized forwarding or updates" AS Hypothesis,
  "Snapshot correlation; not historical process-creation evidence. Deleted binaries can follow normal updates" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook
FROM NewProcessSignals
WHERE IsMemfd OR WebServiceChild OR SSHForwarding OR IsDeleted

LET CronScriptFiles <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=get(item=scope(),field="OSPath")) AS ScriptPath,
  TextOrEmpty(X=get(item=scope(),field="Content")) AS ScriptContent,
  get(item=scope(),field="Mtime") AS ScriptMtime,
  get(item=scope(),field="FileSize") AS ScriptFileSize,
  get(item=scope(),field="ContentLimit") AS ScriptContentLimit,
  get(item=scope(),field="PotentiallyTruncated") AS ScriptPotentiallyTruncated
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Crontab")
WHERE ScriptPath!="" AND ScriptContent!=""

LET ScriptResults <= SELECT * FROM foreach(row=CronScriptFiles,query={
  SELECT ClientId,Fqdn,ScriptPath,ScriptMtime,ScriptFileSize,ScriptContentLimit,ScriptPotentiallyTruncated,
    _value AS CronCommand,(_key + 1) AS ScriptLineNumber,"" AS CronEvent,"" AS Minute,"" AS Hour
  FROM items(item=split(string=ScriptContent,sep="\n"))
})
WHERE NOT CronCommand =~ '''^\s*(#|$)'''

LET ScriptSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM ScriptResults


LET ClassifiedScript <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM ScriptSignals


LET ScoredScript <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedScript



LET CronScriptMatches <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_script_content" AS SignalId,
  if(condition=CriticalCommand,then="Cron script line contains a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron script line declares temporary-path execution",
      else=if(condition=InlineInterpreter,then="Cron script line declares inline interpreter code",
        else="Cron script line declares remote fetch"))) AS Indicator,
  if(condition=CriticalCommand,then=5,else=if(condition=WritablePathExecution,then=4,
    else=if(condition=InlineInterpreter,then=3,else=2))) AS FindingWeight,
  ScriptPath AS Evidence1,ScriptLineNumber AS Evidence2,CronCommand AS Evidence3,
  dict(Mtime=ScriptMtime,FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated,CriticalCommand=CriticalCommand,
    WritablePathExecution=WritablePathExecution,InlineInterpreter=InlineInterpreter,
    ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  format(format="%v|cron_script|%v|%v|%v",args=[ClientId,ScriptPath,ScriptLineNumber,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script invoked by cron/run-parts, and is the declared behavior authorized?" AS Hypothesis,
  "Content prefix and line regex only; comments skipped, but strings/dead code may match. Existence does not prove execution" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook
FROM ScoredScript
WHERE CriticalCommand OR WritablePathExecution OR InlineInterpreter OR ScheduledRemoteFetch

LET MountFields <= SELECT ClientId,Fqdn,Device,Mount,FSType,Options,
  TextOrEmpty(X=(get(item=scope(),field="FlowId") || get(item=scope(),field="_FlowId"))) AS MountFlowId,
  regex_replace(source=TextOrEmpty(X=Mount),re="/+$",replace="") AS MountPrefix
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Mounts")

-- Resolve the longest matching mount, including normal nested mounts.
-- Encoded mount paths require decoding before they can be correlated safely.
LET MountFor(C,F,E) = SELECT *,len(list=MountPrefix) AS PrefixLength
FROM MountFields
WHERE ClientId=C AND MountFlowId=F AND TextOrEmpty(X=Mount)!=""
  AND NOT TextOrEmpty(X=Mount) =~ '''\\[0-7]{3}'''
  AND (E=MountPrefix OR split(string=E,sep_string=MountPrefix+"/")[0]="")
ORDER BY PrefixLength DESC LIMIT 1

LET MountProcessPaths <= SELECT *,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS ExecutablePath
FROM ProcessFields
WHERE ProcExe =~ '''^/(mnt|media|home|srv|opt|run/user)/'''

LET ExecutableMounts <= SELECT *,
  MountFor(C=ClientId,F=RowFlowId,E=ExecutablePath)[0] AS BackingMount
FROM MountProcessPaths
WHERE NOT ExecutablePath =~ '''[\s\\]'''

LET MountExecutionMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_network_mount_execution" AS SignalId,
  "Process executable path resolves to a network filesystem in this snapshot" AS Indicator,
  2 AS FindingWeight,dict(Pid=ProcPid,Ppid=ProcPpid) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Mount=BackingMount.Mount,Device=BackingMount.Device,FSType=BackingMount.FSType,
    Options=BackingMount.Options,SupportingArtifact="LTH.SystemBaseline/Mounts",FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|mounted_exe|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,BackingMount.Mount]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is executable code on this network share expected for this server role?" AS Hypothesis,
  "Path-based, non-atomic snapshot correlation; process mount namespaces and mounts may differ" AS ObservationLimit,
  "LTH - 01 / LTH - 04" AS RecommendedNotebook
FROM ExecutableMounts
WHERE BackingMount.FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountContext <= SELECT ClientId,Fqdn,"Mount Review" AS Category,
  "baseline_network_mount_inventory" AS SignalId,
  "Network filesystem available for hypothesis review" AS Indicator,
  0 AS FindingWeight,Mount AS Evidence1,Device AS Evidence2,FSType AS Evidence3,
  dict(Options=Options,FlowId=MountFlowId) AS Evidence4,
  format(format="%v|%v|mount_context|%v|%v",args=[ClientId,MountFlowId,Mount,Device]) AS EvidenceKey,
  "LTH.SystemBaseline/Mounts" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the share owner, purpose and which applications use it" AS Hypothesis,
  "Mount inventory alone has weight zero and does not establish malicious use" AS ObservationLimit,
  "LTH - 01 - System Baseline Dashboard" AS RecommendedNotebook
FROM MountFields WHERE FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountReview <= SELECT * FROM chain(execution=MountExecutionMatches,context=MountContext)

LET PackageRaw <= SELECT * FROM chain(
  debian={SELECT *,"Debian" AS PackageFamily,"LTH.SystemBaseline/DebianPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/DebianPackages")},
  rhel={SELECT *,"RHEL" AS PackageFamily,"LTH.SystemBaseline/RHELPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/RHELPackages")}
)
LET PackageFields <= SELECT ClientId,Fqdn,PackageFamily,PackageSource,
  TextOrEmpty(X=(get(item=scope(),field="Package") || get(item=scope(),field="Name"))) AS PackageName,
  TextOrEmpty(X=get(item=scope(),field="Version")) AS PackageVersion,
  TextOrEmpty(X=(get(item=scope(),field="State") || get(item=scope(),field="Status"))) AS PackageState,
  TextOrEmpty(X=get(item=scope(),field="Repository")) AS PackageRepository
FROM PackageRaw
LET InstalledPackages <= SELECT *,
  regex_replace(source=PackageName,
    re='''(\.(x86_64|i[3-6]86|noarch|aarch64|armv[0-9]+[a-z]*|ppc64le|s390x)|:[a-z0-9_-]+)$''',replace="") AS NormalizedPackage
FROM PackageFields
WHERE PackageName!="" AND (PackageFamily="RHEL" OR PackageState IN ("installed","active"))
LET PackageContext <= SELECT ClientId,Fqdn,"Package Review" AS Category,
  "baseline_dual_use_package_inventory" AS SignalId,
  "Installed network, proxy or remote-access tooling for role review" AS Indicator,
  0 AS FindingWeight,PackageName AS Evidence1,PackageVersion AS Evidence2,
  dict(Family=PackageFamily,State=PackageState,Repository=PackageRepository) AS Evidence3,
  "Installed software inventory does not establish execution, compromise, file ownership or vulnerability" AS Evidence4,
  format(format="%v|package_context|%v|%v|%v",args=[ClientId,PackageSource,PackageName,PackageVersion]) AS EvidenceKey,
  PackageSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this tool expected for the server role, and do process/network findings show relevant use?" AS Hypothesis,
  "RHEL package names include architecture; removed Debian entries are excluded. No version-to-CVE inference" AS ObservationLimit,
  "LTH - 01 / LTH - 04 / LTH - 05" AS RecommendedNotebook
FROM InstalledPackages
WHERE NormalizedPackage =~ '''^(nmap|nmap-ncat|ncat|netcat|netcat-openbsd|netcat-traditional|socat|masscan|proxychains|proxychains4|chisel|ngrok|frp|frpc|frps|rclone|openssh-clients|openssh-client)$'''

LET SecurityServiceMatches <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_security_service_state" AS SignalId,
  "A listed logging/audit service has an inactive or failed state" AS Indicator,
  2 AS FindingWeight,ServiceUnit AS Evidence1,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence2,
  ServiceDescription AS Evidence3,
  "Review maintenance, configured logging architecture and service diagnostics" AS Evidence4,
  format(format="%v|security_service_state|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this observed service state expected, or has logging continuity been affected?" AS Hypothesis,
  "Only an existing row is evaluated; absence does not mean disabled. State does not establish tampering" AS ObservationLimit,
  "LTH - 04 / LTH - 08" AS RecommendedNotebook
FROM ServiceFields
WHERE ServiceLoad="loaded" AND ServiceUnit =~ '''^(auditd|rsyslog|systemd-journald)\.service$'''
  AND (ServiceActive IN ("failed","inactive") OR ServiceSub="failed")
LET SourceCoverage <=
SELECT *
FROM chain(
  users={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Users source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM UserFields
    GROUP BY ClientId
  },
  processes={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Processes source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ProcessFields
    GROUP BY ClientId
  },
  services={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Services source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ServiceFields
    GROUP BY ClientId
  },
  network={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Network source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM NetworkFields
    GROUP BY ClientId
  },
  cron={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Cron source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM CronFields
    WHERE CommandValue!="" OR CronContent!=""
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
LET InventoryPlatform <= SELECT ClientId,Fqdn,TextOrEmpty(X=get(item=scope(),field="Platform")) AS Platform
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET PlatformFamilies <= SELECT *,
  if(condition=Platform =~ '''(?i)^(ubuntu|debian|linuxmint|kali|raspbian|pop)$''',then="Debian",
    else=if(condition=Platform =~ '''(?i)^(alma|almalinux|rocky|rhel|redhat|red hat.*|centos|ol|oracle|oraclelinux|fedora)$''',then="RHEL",else="Unknown")) AS ExpectedPackageFamily
FROM InventoryPlatform
LET PlatformIndex <= memoize(query={SELECT * FROM PlatformFamilies},key="ClientId")
LET ApplicablePackages <= SELECT *,get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily AS ExpectedFamily
FROM InstalledPackages
WHERE PackageFamily=ExpectedFamily

LET ExtraCoverage <= SELECT * FROM chain(
  mounts={SELECT ClientId,Fqdn,"Coverage" AS Category,"Mounts source returned rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM MountFields GROUP BY ClientId},
  packages={SELECT ClientId,Fqdn,"Coverage" AS Category,"Applicable package family returned installed rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM ApplicablePackages GROUP BY ClientId}
)

LET SelectedScope <= SELECT ClientId,Fqdn FROM chain(
  inventory=Fleet,users=UserFields,processes=ProcessFields,services=ServiceFields,
  network=NetworkFields,cron=CronFields,mounts=MountFields,packages=PackageFields
) GROUP BY ClientId

LET CronQuality <= SELECT ClientId,
  sum(item=if(condition=CommandValue!="" AND CronParserVersion!=2,then=1,else=0)) AS LegacyCronRows,
  sum(item=if(condition=CronParseStatus="Unparsed",then=1,else=0)) AS UnparsedCronRows,
  sum(item=if(condition=CronPotentiallyTruncated=TRUE,then=1,else=0)) AS TruncatedCronScripts
FROM CronFields GROUP BY ClientId
LET CronQualityIndex <= memoize(query={SELECT * FROM CronQuality},key="ClientId")

LET AllEvidenceCandidates <= SELECT * FROM chain(
  users=UserDetail,processes=ProcessDetail,services=ServiceDetail,network=NetworkDetail,cron=CronDetail,
  accounts=AccountMatches,process_context=ExtraProcessMatches,cron_scripts=CronScriptMatches,
  mounts=MountReview,packages=PackageContext,security_services=SecurityServiceMatches
)
LET AllEvidence <= SELECT * FROM AllEvidenceCandidates GROUP BY EvidenceKey
LET PositiveEvidence <= SELECT * FROM AllEvidence WHERE FindingWeight>0

-- Original five categories; cap each category at its highest matched weight.
LET RiskAreas <= SELECT ClientId,Fqdn,Category,
  "Highest matched weight in this existing area" AS Indicator,
  max(item=FindingWeight) AS Weight,count() AS EvidenceCount,0 AS SourceCollected,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM PositiveEvidence GROUP BY AreaKey
LET Findings <= SELECT * FROM chain(
  all_clients={SELECT ClientId,Fqdn,"Coverage" AS Category,"Client has selected baseline data" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,0 AS SourceCollected FROM SelectedScope},
  inventory=Fleet,source_coverage=SourceCoverage,added_coverage=ExtraCoverage,areas=RiskAreas
)

-- Edit to include your actual internal networks, including internally routed public ranges.
-- A peer outside this list is not automatically Internet traffic or malicious.
LET ReviewInternalCIDRs <= split(string="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",sep=",")

LET ReviewMinCohortHosts <= 4
LET ReviewMaxRareHosts <= 2
LET ReviewMaxRarePercent <= 25

LET AdminProcessSignals <= SELECT *,
  ProcName =~ '''(?i)^ssh$''' AS RemoteClient,
  ProcName =~ '''(?i)^(scp|sftp|rsync|rclone)$''' AS TransferTool,
  ProcName =~ '''(?i)^(curl|wget)$''' AS FetchTool,
  ProcName =~ '''(?i)^(nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS NetworkUtility,
  (ProcUsername="root" AND ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS RootShell,
  ProcName =~ '''(?i)^(sudo|su|doas)$''' AS PrivilegeUtility,
  ProcCommandLine =~ '''(?i)(^|\s|/)(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)''' AS InlineCode,
  (ProcName =~ '''(?i)^(screen|tmux|nohup)$'''
   OR ProcCommandLine =~ '''(?i)^\s*(sudo\s+)?nohup\s''') AS BackgroundSession,
  ProcExe =~ '''^/(usr/local|opt|srv|home|root|mnt|media)/''' AS ApplicationPathExe,
  (ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby)$'''
   AND ProcCommandLine =~ '''\s/(usr/local|opt|srv|home|root|mnt|media)/[^\s;&|]+''') AS InterpreterPathReference
FROM ProcessFields

LET AdministrativeProcessLeads <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "review_administrative_process" AS SignalId,
  "Administrative, application-path or interpreter process to validate" AS Indicator,
  0 AS FindingWeight,
  if(condition=RootShell OR PrivilegeUtility OR InlineCode OR TransferTool OR RemoteClient,then=2,else=1) AS ReviewPriority,
  dict(Pid=ProcPid,Ppid=ProcPpid,Name=ProcName,Username=ProcUsername,FlowId=RowFlowId) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(RemoteClient=RemoteClient,TransferTool=TransferTool,FetchTool=FetchTool,NetworkUtility=NetworkUtility,
    RootShell=RootShell,PrivilegeUtility=PrivilegeUtility,InlineCode=InlineCode,BackgroundSession=BackgroundSession,
    ApplicationPathExe=ApplicationPathExe,InterpreterPathReference=InterpreterPathReference) AS Evidence4,
  format(format="%v|%v|review_process|%v|%v|%v",args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this observed command, account, path and peer fit the approved administration or application workflow?" AS Hypothesis,
  "Identify the process owner and approved task; read parent and network context; validate the script or binary when needed" AS SuggestedChecks,
  "Current process snapshot only. Root shell is not proof of an interactive session; an interpreter argument may reference data rather than executed code" AS ObservationLimit,
  "LTH - 04 / LTH - 03 / LTH - 05" AS RecommendedNotebook
FROM AdminProcessSignals
WHERE RemoteClient OR TransferTool OR FetchTool OR NetworkUtility OR RootShell OR PrivilegeUtility
   OR InlineCode OR BackgroundSession OR ApplicationPathExe OR InterpreterPathReference

LET ReviewAccountSignals <= SELECT *,
  (UserUid!="0" AND UserUid!="" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS NonRootShellAccount,
  (UserUid!="0" AND UserUid!="" AND HomeDir =~ '''^/(root|opt|srv)(/|$)''') AS ApplicationHomeAccount
FROM UserFields
LET ReviewAccountLeads <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "review_account_role" AS SignalId,"Account shell or application home requires role confirmation" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,dict(Shell=UserShell,Home=HomeDir) AS Evidence3,
  dict(NonRootShellAccount=NonRootShellAccount,ApplicationHomeAccount=ApplicationHomeAccount) AS Evidence4,
  format(format="%v|review_account|%v|%v|%v|%v",args=[ClientId,UserName,UserUid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this account, shell and home required by a named person or application?" AS Hypothesis,
  "Identify the account owner and intended role; request authentication or group evidence only if the hypothesis requires it" AS SuggestedChecks,
  "Passwd snapshot: configured shell is not proof of login, and primary GID is not supplementary group membership" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook
FROM ReviewAccountSignals WHERE NonRootShellAccount OR ApplicationHomeAccount

LET ScheduledTaskLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_scheduled_command" AS SignalId,"Scheduled command for administrative-workflow review" AS Indicator,
  0 AS FindingWeight,
  if(condition=CronUser="root" OR CronEvent="@reboot" OR (Minute IN ("*","*/1") AND Hour="*"),then=2,else=1) AS ReviewPriority,
  CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParserVersion=CronParserVersion,ParseStatus=CronParseStatus) AS Evidence4,
  format(format="%v|review_cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,CronPath,CronUser,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this scheduled command, execution account and frequency belong to an approved job?" AS Hypothesis,
  "Identify the job owner; validate its script and destination; use execution logs if proof of a run is needed" AS SuggestedChecks,
  "Shows every nonempty parsed command, including legitimate maintenance. Legacy cron parsing may have lost the real command or user" AS ObservationLimit,
  "LTH - 06 / LTH - 04" AS RecommendedNotebook
FROM CronResults

LET ScheduledScriptLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_cron_script" AS SignalId,"Periodic cron script content for purpose and ownership review" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ScriptPath AS Evidence1,ScriptContent AS Evidence2,
  ScriptMtime AS Evidence3,dict(FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated) AS Evidence4,
  format(format="%v|review_cron_script|%v|%v",args=[ClientId,ScriptPath,ScriptContent]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script expected in a periodic cron directory, and is it actually invoked by the configured scheduler?" AS Hypothesis,
  "Review the collected content and owner; confirm run-parts eligibility and scheduler configuration if execution matters" AS SuggestedChecks,
  "Only a collected content prefix; placement and Mtime do not prove execution or identify the modifier" AS ObservationLimit,
  "LTH - 06" AS RecommendedNotebook
FROM CronScriptFiles

LET AccountScheduledLeads <= SELECT * FROM chain(accounts=ReviewAccountLeads,commands=ScheduledTaskLeads,scripts=ScheduledScriptLeads)

LET ReviewNetworkFields <= SELECT *,
  regex_replace(source=Laddr,re='''^\[|\]$''',replace="") AS ReviewLocalIP,
  regex_replace(source=Raddr,re='''^\[|\]$''',replace="") AS ReviewPeerIP,
  ConnStatus =~ '''(?i)^LISTEN(ING)?$''' AS ReviewListening,
  ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$''' AS ReviewEstablished,
  ProcName =~ '''(?i)^(ssh|scp|sftp|rsync|rclone|curl|wget|nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS ReviewAdministrativeTool
FROM NetworkResults
LET ReviewNetworkSignals <= SELECT *,
  (ReviewListening AND cidr_contains(ip=ReviewLocalIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewLocalIP,ranges=["127.0.0.0/8","::1/128"])) AS NonLoopbackListener,
  (ReviewEstablished AND ReviewAdministrativeTool
    AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["127.0.0.0/8","::1/128","0.0.0.0/8","::/128"])) AS AdministrativeConnection,
  (ReviewEstablished AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fe80::/10","ff00::/8"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=ReviewInternalCIDRs)) AS PeerOutsideConfiguredNetworks
FROM ReviewNetworkFields
LET NetworkReviewLeads <= SELECT ClientId,Fqdn,"Network" AS Category,
  "review_socket_role" AS SignalId,"Listener or established peer for role and administration review" AS Indicator,
  0 AS FindingWeight,
  if(condition=AdministrativeConnection OR PeerOutsideConfiguredNetworks,then=2,else=1) AS ReviewPriority,
  dict(Pid=Pid,Name=ProcName,Username=ProcUsername) AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,CallChain=CallChain,
    NonLoopbackListener=NonLoopbackListener,AdministrativeConnection=AdministrativeConnection,
    PeerOutsideConfiguredNetworks=PeerOutsideConfiguredNetworks) AS Evidence4,
  format(format="%v|review_socket|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,Pid,Laddr,Lport,Raddr,Rport,ConnStatus,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this process need this listening address or peer for its approved service or administrative task?" AS Hypothesis,
  "Identify service and destination owners; confirm intended exposure and peer; correlate with the process and approved task" AS SuggestedChecks,
  "Established sockets do not establish initiation direction. Wildcard listening does not prove Internet reachability; configured CIDRs are not a reputation check" AS ObservationLimit,
  "LTH - 05 / LTH - 04" AS RecommendedNotebook
FROM ReviewNetworkSignals
WHERE NonLoopbackListener OR AdministrativeConnection OR PeerOutsideConfiguredNetworks

LET ReviewServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(ssh|sshd|xrdp|xrdp-sesman|vncserver|tigervnc|telnet|rsh)([-.@][^ ]*)?\.service$''' AS RemoteAccessService,
  ServiceUnit =~ '''(?i)^(docker|containerd|crio|cri-o|podman|kubelet)([-.@][^ ]*)?\.service$''' AS ContainerService,
  ServiceUnit =~ '''(?i)^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|postgres|redis|redis-server|mongod|mongodb|elasticsearch)([-.@][^ ]*)?\.service$''' AS ApplicationDataService,
  ServiceUnit =~ '''(?i)^(nfs|nfs-server|rpcbind|smb|smbd|nmb|nmbd|vsftpd|proftpd|pure-ftpd)([-.@][^ ]*)?\.service$''' AS FileSharingService
FROM ServiceFields
LET ActiveServiceLeads <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "review_active_service_role" AS SignalId,"Active access, application, container or file-sharing service" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(RemoteAccessService=RemoteAccessService,ContainerService=ContainerService,
    ApplicationDataService=ApplicationDataService,FileSharingService=FileSharingService) AS Evidence4,
  format(format="%v|review_service|%v|%v|%v",args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this active service required for the host role and is its access or data exposure intended?" AS Hypothesis,
  "Confirm the service owner and purpose; inspect related listeners; collect unit configuration only for the selected hypothesis" AS SuggestedChecks,
  "Observed loaded service state and naming only; no ExecStart, enablement, installed-package ownership or exposure proof" AS ObservationLimit,
  "LTH - 04 / LTH - 05 / LTH - 12" AS RecommendedNotebook
FROM ReviewServiceSignals
WHERE ServiceLoad="loaded" AND ServiceActive="active"
  AND (RemoteAccessService OR ContainerService OR ApplicationDataService OR FileSharingService)

LET ReviewPlatforms <= SELECT ClientId,
  (TextOrEmpty(X=get(item=scope(),field="Platform")) || "Unknown") AS ReviewCohort
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET ReviewPlatformIndex <= memoize(query={SELECT * FROM ReviewPlatforms},key="ClientId")

-- Denominator is distinct clients that returned usable rows for this source,
-- not all 16 scoped clients when some source results are missing.
LET ReviewSourceClients <= SELECT * FROM chain(
  processes={SELECT ClientId,"Process executable" AS Family FROM ProcessFields WHERE ProcExe!="" GROUP BY ClientId},
  services={SELECT ClientId,"Service unit" AS Family FROM ServiceFields WHERE ServiceUnit!="" GROUP BY ClientId},
  users={SELECT ClientId,"Shell account" AS Family FROM UserFields WHERE UserName!="" GROUP BY ClientId},
  cron={SELECT ClientId,"Cron command" AS Family FROM CronResults GROUP BY ClientId}
)
LET ReviewSourceCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewSourceClients
LET ReviewCoverage <= SELECT Family,ReviewCohort,count() AS CoveredHosts,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewSourceCohorts GROUP BY CohortKey
LET ReviewCoverageIndex <= memoize(query={SELECT * FROM ReviewCoverage},key="CohortKey")

LET ReviewObservations <= SELECT * FROM chain(
  processes={SELECT ClientId,Fqdn,"Processes" AS Category,"Process executable" AS Family,
    regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS Entity,
    "LTH.SystemBaseline/Processes" AS ObservationSource FROM ProcessFields WHERE ProcExe!=""},
  services={SELECT ClientId,Fqdn,"Services and Persistence" AS Category,"Service unit" AS Family,
    ServiceUnit AS Entity,"LTH.SystemBaseline/Services" AS ObservationSource FROM ServiceFields WHERE ServiceUnit!=""},
  users={SELECT ClientId,Fqdn,"Users and Privileges" AS Category,"Shell account" AS Family,
    UserName+"|"+UserShell AS Entity,"LTH.SystemBaseline/Users" AS ObservationSource
    FROM UserFields WHERE UserUid!="0" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$'''},
  cron={SELECT ClientId,Fqdn,"Persistence" AS Category,"Cron command" AS Family,
    CronUser+"|"+CronCommand AS Entity,"LTH.SystemBaseline/Crontab" AS ObservationSource FROM CronResults}
)
LET ReviewObservedCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewObservations
LET ReviewUniqueHostEntities <= SELECT *,
  format(format="%v|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS HostEntityKey,
  format(format="%v|%v|%v",args=[ReviewCohort,Family,Entity]) AS PrevalenceKey,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewObservedCohorts GROUP BY HostEntityKey
LET ReviewPrevalence <= SELECT PrevalenceKey,count() AS HostsWithEntity
FROM ReviewUniqueHostEntities GROUP BY PrevalenceKey
LET ReviewPrevalenceIndex <= memoize(query={SELECT * FROM ReviewPrevalence},key="PrevalenceKey")
LET ReviewPrevalenceRows <= SELECT *,
  get(item=ReviewCoverageIndex,field=CohortKey).CoveredHosts AS CoveredHosts,
  get(item=ReviewPrevalenceIndex,field=PrevalenceKey).HostsWithEntity AS HostsWithEntity
FROM ReviewUniqueHostEntities
LET RareBaselineLeads <= SELECT ClientId,Fqdn,Category,
  "review_low_prevalence" AS SignalId,"Low-prevalence baseline entity in the observed platform cohort" AS Indicator,
  0 AS FindingWeight,2 AS ReviewPriority,Family AS Evidence1,Entity AS Evidence2,
  dict(PlatformCohort=ReviewCohort,HostsWithEntity=HostsWithEntity,CoveredHosts=CoveredHosts) AS Evidence3,
  "Compare approved roles before treating rarity as an anomaly; do not interpret as newly created" AS Evidence4,
  format(format="%v|review_prevalence|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS EvidenceKey,
  ObservationSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this uncommon executable, unit, account or scheduled command explained by this host's approved role?" AS Hypothesis,
  "Compare with hosts having the same business role; identify owner and deployment purpose; inspect related baseline evidence" AS SuggestedChecks,
  "One-Hunt prevalence among clients with source rows. Platform is not a business-role cohort; exact cron commands may contain host-specific values" AS ObservationLimit,
  "LTH - 01 / the notebook for the observed family" AS RecommendedNotebook
FROM ReviewPrevalenceRows
WHERE ReviewCohort!="Unknown" AND CoveredHosts>=ReviewMinCohortHosts
  AND HostsWithEntity<=ReviewMaxRareHosts
  AND (HostsWithEntity * 100)<= (CoveredHosts * ReviewMaxRarePercent)

LET AdditionalReviewCandidates <= SELECT * FROM chain(
  admin=AdministrativeProcessLeads,account_cron=AccountScheduledLeads,
  network=NetworkReviewLeads,services=ActiveServiceLeads,prevalence=RareBaselineLeads
)
LET EnhancedEvidenceCandidates <= SELECT * FROM chain(existing=AllEvidence,review=AdditionalReviewCandidates)
LET EnhancedEvidence <= SELECT *,
  if(condition=FindingWeight>0,then="Risk Indicator",else="Hunt Lead") AS EvidenceKind,
  "Unreviewed" AS ReviewState,
  if(condition=FindingWeight>=4,then=3,else=if(condition=FindingWeight>0,then=2,
    else=(get(item=scope(),field="ReviewPriority") || 1))) AS ReviewPriority,
  (get(item=scope(),field="SuggestedChecks") || Hypothesis) AS SuggestedChecks
FROM EnhancedEvidenceCandidates GROUP BY EvidenceKey

LET HuntLeadSummary <= SELECT ClientId,count() AS HuntLeadCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority
FROM EnhancedEvidence GROUP BY ClientId
LET HuntLeadIndex <= memoize(query={SELECT * FROM HuntLeadSummary},key="ClientId")
LET FirstHuntLead(C) = SELECT Hypothesis FROM EnhancedEvidence WHERE ClientId=C ORDER BY ReviewPriority DESC LIMIT 1

LET EvidenceAreas <= SELECT ClientId,Fqdn,Category,
  max(item=FindingWeight) AS Weight,
  sum(item=if(condition=FindingWeight>0,then=1,else=0)) AS EvidenceCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM EnhancedEvidence GROUP BY AreaKey
LET HostScores <=
SELECT ClientId,
       Fqdn,
       sum(
         item=if(
           condition=Weight > 0,
           then=1,
           else=0
         )
       ) AS TriggeredAreaCount,
       sum(item=Weight) AS RiskScore,
       sum(item=EvidenceCount) AS FindingEvidenceCount,
       sum(
         item=if(
           condition=Weight = 5,
           then=1,
           else=0
         )
       ) AS CriticalAreaCount,
       sum(item=SourceCollected) AS CollectedSourceCount
FROM Findings
GROUP BY ClientId

LET ExtendedHostScores <=
SELECT ClientId,
       Fqdn,
       TriggeredAreaCount,
       RiskScore,
       (get(item=HuntLeadIndex,field=ClientId).HuntLeadCount || 0) AS HuntLeadCount,
       (get(item=HuntLeadIndex,field=ClientId).ReviewLeadCount || 0) AS ReviewLeadCount,
       (get(item=HuntLeadIndex,field=ClientId).HighestReviewPriority || 0) AS HighestReviewPriority,
       if(condition=RiskScore>0,then="Risk Indicators Found",
         else=if(condition=get(item=HuntLeadIndex,field=ClientId).ReviewLeadCount>0,
           then="Review Leads Available",else="Planned Hunt Needed")) AS HuntStatus,
       (FirstHuntLead(C=ClientId)[0].Hypothesis || "Confirm host role and collection coverage; select a role-based hypothesis even when this snapshot has no lead") AS TopHuntHypothesis,
       FindingEvidenceCount,
       CriticalAreaCount,
       CollectedSourceCount,
       8 AS ExpectedSourceCount,
       get(item=PlatformIndex,field=ClientId).Platform AS Platform,
       (get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily || "Unknown") AS ExpectedPackageFamily,
       (get(item=CronQualityIndex,field=ClientId).LegacyCronRows || 0) AS LegacyCronRows,
       (get(item=CronQualityIndex,field=ClientId).UnparsedCronRows || 0) AS UnparsedCronRows,
       (get(item=CronQualityIndex,field=ClientId).TruncatedCronScripts || 0) AS TruncatedCronScripts,
       if(condition=get(item=CronQualityIndex,field=ClientId).LegacyCronRows>0
           OR get(item=CronQualityIndex,field=ClientId).UnparsedCronRows>0,
         then="Cron parser review required; read RawLine or recollect with parser v2",
         else="No detected parser warning; row presence does not establish complete collection") AS DataQualityStatus,
       if(
         condition=CollectedSourceCount = 8,
         then="Selected sources returned rows; inspect collection logs for errors",
         else=format(
           format="Validate empty sources - %v of 8 selected source groups returned rows",
           args=[CollectedSourceCount]
         )
       ) AS CollectionStatus,
       if(
         condition=RiskScore = 0
                   AND (CollectedSourceCount < 8
                     OR get(item=CronQualityIndex,field=ClientId).LegacyCronRows>0
                     OR get(item=CronQualityIndex,field=ClientId).UnparsedCronRows>0),
         then="Collection Review",
         else=if(
           condition=RiskScore = 0,
           then="No Matched Finding",
           else=if(
             condition=CriticalAreaCount > 0
                   OR RiskScore >= 10,
             then="High",
             else=if(
               condition=RiskScore >= 6,
               then="Suspicious",
               else=if(
                 condition=RiskScore >= 3,
                 then="Review",
                 else="Low"
               )
             )
           )
         )
       ) AS RiskLevel
FROM HostScores

-- Full evidence remains in cell 15. This view shows a short starting list per host.
LET TopHostLeads(C) = SELECT * FROM EnhancedEvidence WHERE ClientId=C ORDER BY ReviewPriority DESC LIMIT 5
LET HostStartingPoints <= SELECT * FROM chain(
  profiles={SELECT ClientId,Fqdn,"Host Review" AS EntryType,0 AS ReviewPriority,0 AS Weight,
    RiskScore,HuntLeadCount,ReviewLeadCount,HuntStatus,CollectionStatus,
    "Confirm host role, collection health and the first hypothesis to investigate" AS Indicator,
    TopHuntHypothesis AS Hypothesis,
    "Use the entries below for this client; if none exist, choose a role-based hypothesis and identify the missing evidence" AS SuggestedChecks,
    dict(CollectedSourceCount=CollectedSourceCount,ExpectedSourceCount=ExpectedSourceCount,DataQualityStatus=DataQualityStatus) AS Evidence1,
    NULL AS Evidence2,NULL AS Evidence3,NULL AS Evidence4,
    "This row is a host review task, not an observed finding. A client with no result at all is not visible in hunt_results" AS ObservationLimit,
    format(format="%v|host_review",args=[ClientId]) AS FindingKey,HuntId AS SourceHuntId,"LTH.SystemBaseline" AS SourceArtifact
    FROM ExtendedHostScores},
  leads={SELECT * FROM foreach(row=ExtendedHostScores,query={
    SELECT ClientId,Fqdn,EvidenceKind AS EntryType,ReviewPriority,FindingWeight AS Weight,
      RiskScore,HuntLeadCount,ReviewLeadCount,HuntStatus,CollectionStatus,
      Indicator,Hypothesis,SuggestedChecks,Evidence1,Evidence2,Evidence3,Evidence4,ObservationLimit,
      EvidenceKey AS FindingKey,SourceHuntId,SourceArtifact
    FROM TopHostLeads(C=ClientId)
  })}
)
SELECT * FROM HostStartingPoints ORDER BY ReviewPriority DESC

```

## Cell 26 (markdown)

# Master Risk Score

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))
-- Keep this FALSE on the production server, consistently in all cells.
LET EnableLabIndicators <= FALSE


LET Fleet <= SELECT ClientId,Fqdn,"Coverage" AS Category,"Basic information source returned rows" AS Indicator,
  0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)


LET UserMatches <=
SELECT *,
       format(
         format="%v|uid0|%v|%v",
         args=[ClientId, UserName, HomeDir]
       ) AS EvidenceKey,
       5 AS FindingWeight
FROM UserFields
WHERE UserUid = "0"
  AND NOT UserName =~ '''^root$'''
  AND NOT (
    UserName = ""
    AND HomeDir = "/root"
  )

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET ProcessSignals <=
SELECT *,
       ProcCommandLine =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       ProcCommandLine =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       ProcExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer,
       ProcExe =~ '''(?i)^/run/user/[0-9]+/''' AS UserRuntimeExecution,
       (ProcName =~ '''(?i)^(xmrig|minerd|kinsing|kdevtmpfsi)$'''
        OR ProcCommandLine =~ '''(?i)(xmrig|stratum\+tcp)''') AS MiningPattern
FROM ProcessFields


LET ProcessMatches <=
SELECT *,
       format(
         format="%v|process|%v|%v|%v",
         args=[ClientId, ProcPid, ProcExe, ProcCommandLine]
       ) AS EvidenceKey,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then=5,
         else=if(
           condition=WritablePathExe
                     OR WritablePathExecution
                     OR MiningPattern
                     OR (UserRuntimeExecution AND PythonHTTPServer),
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool
                       OR UserRuntimeExecution,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ProcessSignals
WHERE DownloadPipeShell
   OR DecodePipeShell
   OR NetcatExec
   OR SocatExec
   OR DevTcpShell
   OR WritablePathExe
   OR WritablePathExecution
   OR NetcatTool
   OR SocatTool
   OR PythonHTTPServer
   OR UserRuntimeExecution
   OR MiningPattern


LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")

LET ServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(kinsing|xmrig|kdevtmpfsi|watchbog)([-_.@][a-z0-9_.@-]+)?\.service$''' AS ThreatAssociatedName,
  ServiceDescription =~ '''(?i)(cryptocurrency[ -](miner|mining)|reverse[ -]shell|backdoor[ -]service|unauthorized[ -]remote[ -]access)''' AS HighRiskDescription,
  (EnableLabIndicators AND
   (ServiceUnit =~ '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
    OR ServiceDescription =~ '''(?i)(lab persistence|temporary update service|remote support lab)''')) AS KnownLabService
FROM ServiceFields

LET ServiceMatches <= SELECT *,
  format(format="%v|service|%v|%v|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceDescription,ServiceLoad,ServiceActive,ServiceSub]) AS EvidenceKey,
  if(condition=ThreatAssociatedName,then=5,else=4) AS FindingWeight
FROM ServiceSignals
WHERE ThreatAssociatedName OR HighRiskDescription OR KnownLabService

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="CallChain")) AS RawCallChain,
       TextOrEmpty(X=get(item=scope(), member="Laddr")) AS Laddr,
       TextOrEmpty(X=get(item=scope(), member="Lport")) AS Lport,
       TextOrEmpty(X=get(item=scope(), member="Raddr")) AS Raddr,
       TextOrEmpty(X=get(item=scope(), member="Rport")) AS Rport,
       TextOrEmpty(X=get(item=scope(), member="Pid")) AS Pid,
       TextOrEmpty(X=get(item=scope(), member="Status")) AS ConnStatus,
       get(item=scope(), member="ProcInfo") AS ProcInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET NetworkResults <=
SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus,
       RawCallChain AS CallChain,
       TextOrEmpty(X=get(item=ProcInfo,field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="CommandLine")
         ||
         get(item=ProcInfo, member="cmdline")
       )) AS ProcCommandLine
FROM NetworkFields


LET NetworkSignals <=
SELECT *,
       ConnStatus =~ '''(?i)^(LISTEN|LISTENING)$'''
         AS IsListening,

       ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$'''
         AS IsEstablished,

       Laddr =~ '''^(127\.|::1$|\[::1\]$)'''
         AS LoopbackBind,

       Lport =~ '''^(4444|5555)$'''
         AS HighRiskPort,

       ProcExe =~ '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer
FROM NetworkResults


LET ClassifiedNetwork <=
SELECT *,
       NetcatExec
       OR SocatExec
         AS CommandExecutionSocket,

       (
         (IsListening OR IsEstablished)
         AND
         (WritablePathExe OR WritablePathExecution)
       ) AS WritablePathSocket,

       (
         IsListening
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolListener,

       (
         IsEstablished
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolConnection,

       (
         IsListening
         AND
         PythonHTTPServer
       ) AS PythonListener,

       (
         IsListening
         AND
         HighRiskPort
         AND
         NOT LoopbackBind
       ) AS RiskyPortListener
FROM NetworkSignals


LET NetworkMatches <=
SELECT *,
       format(
         format="%v|network|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           Pid,
           Laddr,
           Lport,
           Raddr,
           Rport,
           ConnStatus
         ]
       ) AS EvidenceKey,

       if(
         condition=CommandExecutionSocket,
         then=5,
         else=if(
           condition=WritablePathSocket
                     OR (
                       PythonListener
                       AND RiskyPortListener
                     ),
           then=4,
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ClassifiedNetwork
WHERE CommandExecutionSocket
   OR WritablePathSocket
   OR NetworkToolListener
   OR NetworkToolConnection
   OR PythonListener
   OR RiskyPortListener

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"


LET CronSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM CronResults


LET ClassifiedCron <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM CronSignals


LET ScoredCron <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedCron


LET CronMatches <=
SELECT *,
       format(
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
           CronUser,
           CronEvent,
           Minute,
           Hour,
           DayOfMonth,
           Month,
           DayOfWeek,
           CronCommand
         ]
       ) AS EvidenceKey,

       if(
         condition=CriticalCommand,
         then=5,
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then=4,
           else=if(
             condition=InlineInterpreter,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ScoredCron
WHERE CriticalCommand
   OR WritablePathExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter
   OR ScheduledRemoteFetch


LET UserDetail <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_additional_uid0" AS SignalId,"Additional UID 0 account" AS Indicator,
  FindingWeight,EvidenceKey,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,HomeDir AS Evidence3,UserShell AS Evidence4,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this additional UID 0 identity authorized for this server?" AS Hypothesis,
  "Passwd configuration only; no proof of login or privilege use" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook,
  UserName AS User,UserDescription AS Description,UserUid AS Uid,UserGid AS Gid,
  HomeDir AS Homedir,UserShell AS Shell
FROM UserMatches

LET ProcessDetail <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_behavior" AS SignalId,
  if(condition=DownloadPipeShell,then="Downloaded content piped to a shell",
    else=if(condition=DecodePipeShell,then="Decoded content piped to a shell",
      else=if(condition=NetcatExec OR SocatExec OR DevTcpShell,then="Command contains a shell/socket execution pattern",
        else=if(condition=MiningPattern,then="Mining-related name or command pattern",
          else=if(condition=WritablePathExe OR WritablePathExecution,then="Execution from a temporary path",
            else=if(condition=UserRuntimeExecution,then="Execution from a user runtime path",
              else=if(condition=NetcatTool OR SocatTool,then="Network utility in process command",
                else="Python HTTP server command"))))))) AS Indicator,
  FindingWeight,EvidenceKey,dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Name=ProcName,Hash=ProcHash,FlowId=RowFlowId,DownloadPipeShell=DownloadPipeShell,DecodePipeShell=DecodePipeShell,
    NetcatExec=NetcatExec,SocatExec=SocatExec,DevTcpShell=DevTcpShell,MiningPattern=MiningPattern,
    WritablePathExe=WritablePathExe,WritablePathExecution=WritablePathExecution,
    UserRuntimeExecution=UserRuntimeExecution,NetcatTool=NetcatTool,SocatTool=SocatTool,
    PythonHTTPServer=PythonHTTPServer) AS Evidence4,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate executable origin, server role and whether this command was authorized" AS Hypothesis,
  "Command/name regex on a process snapshot; not a shell parser or confirmation of compromise" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook,
  ProcPid AS Pid,ProcPpid AS Ppid,ProcName AS Name,ProcExe AS Exe,ProcCommandLine AS CommandLine,
  ProcUsername AS Username,ProcHash AS Hash
FROM ProcessMatches

LET ServiceDetail <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_service_name_description" AS SignalId,
  if(condition=ThreatAssociatedName,then="Service name matches a threat-associated watchlist",
    else=if(condition=HighRiskDescription,then="Service description matches suspicious terminology",
      else="Explicitly enabled lab service indicator")) AS Indicator,
  FindingWeight,EvidenceKey,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(ThreatAssociatedName=ThreatAssociatedName,HighRiskDescription=HighRiskDescription,KnownLabService=KnownLabService) AS Evidence4,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this service name/description correspond to an unauthorized installed service?" AS Hypothesis,
  "Only name, description and state are available. Priority weight is not confidence; collect the unit and executable to validate" AS ObservationLimit,
  "LTH - 04 / LTH - 06" AS RecommendedNotebook,
  ServiceUnit AS Unit,ServiceDescription AS Description,ServiceLoad AS Load,
  ServiceActive AS Active,ServiceSub AS Sub
FROM ServiceMatches

LET NetworkDetail <= SELECT ClientId,Fqdn,"Network" AS Category,
  "baseline_process_socket" AS SignalId,
  if(condition=CommandExecutionSocket,then="Socket-owning process has a command execution pattern",
    else=if(condition=WritablePathSocket,then="Active socket with temporary-path execution context",
      else=if(condition=NetworkToolListener OR NetworkToolConnection,then="Network utility listener or connection",
        else=if(condition=PythonListener,then="Python HTTP listener",else="Non-loopback listener on a configured review port")))) AS Indicator,
  FindingWeight,EvidenceKey,Pid AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,
    Username=ProcUsername,CallChain=CallChain,
    CommandExecutionSocket=CommandExecutionSocket,WritablePathSocket=WritablePathSocket,
    NetworkToolListener=NetworkToolListener,NetworkToolConnection=NetworkToolConnection,
    PythonListener=PythonListener,RiskyPortListener=RiskyPortListener) AS Evidence4,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this socket, associated command and peer expected for this host role?" AS Hypothesis,
  "Socket snapshot; a port number does not identify a protocol or prove command-and-control" AS ObservationLimit,
  "LTH - 05 - Network Connections Dashboard" AS RecommendedNotebook,
  Laddr,Lport,Raddr,Rport,Pid,ConnStatus AS Status,ProcName,ProcExe,ProcCommandLine,ProcUsername,CallChain
FROM NetworkMatches

LET CronDetail <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_command" AS SignalId,
  if(condition=CriticalCommand,then="Cron declares a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron declares execution from a temporary path",
      else=if(condition=RepeatedRemoteFetch,then="Cron declares remote fetch at reboot or every minute",
        else=if(condition=InlineInterpreter,then="Cron declares inline interpreter code",else="Cron declares remote fetch")))) AS Indicator,
  FindingWeight,EvidenceKey,CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParseStatus=CronParseStatus,ParserVersion=CronParserVersion,
    CriticalCommand=CriticalCommand,WritablePathExecution=WritablePathExecution,
    RepeatedRemoteFetch=RepeatedRemoteFetch,InlineInterpreter=InlineInterpreter,ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this scheduled command authorized and is there separate evidence it executed?" AS Hypothesis,
  "Declared command only; legacy parser rows may be incomplete. No cron runtime or complete shell semantics" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook,
  CronUser,CronPath,CronCommand,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek
FROM CronMatches

LET AccountSignals <= SELECT *,
  UserShell =~ '''^/(tmp|var/tmp|dev/shm)/''' AS TemporaryShell,
  (UserName="root" AND HomeDir =~ '''^/(tmp|var/tmp|dev/shm)/''') AS TemporaryRootHome,
  (UserGid="0" AND UserUid!="0" AND UserUid!="") AS PrimaryRootGroup,
  (UserName =~ '''^(www-data|apache|nginx|mysql|mariadb|postgres|redis|memcached|nobody)$'''
   AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS ServiceInteractiveShell
FROM UserFields

LET AccountMatches <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_account_configuration" AS SignalId,
  if(condition=TemporaryShell,then="Account declares a shell under a temporary directory",
    else=if(condition=TemporaryRootHome,then="Root account declares a temporary home directory",
      else=if(condition=PrimaryRootGroup,then="Non-root UID has primary GID 0",
        else="Named service account has an interactive shell"))) AS Indicator,
  if(condition=TemporaryShell,then=4,else=if(condition=TemporaryRootHome,then=3,else=2)) AS FindingWeight,
  UserName AS Evidence1,dict(Uid=UserUid,Gid=UserGid) AS Evidence2,
  UserShell AS Evidence3,dict(Home=HomeDir,TemporaryShell=TemporaryShell,
    TemporaryRootHome=TemporaryRootHome,PrimaryRootGroup=PrimaryRootGroup,
    ServiceInteractiveShell=ServiceInteractiveShell) AS Evidence4,
  format(format="%v|account_config|%v|%v|%v|%v|%v",
    args=[ClientId,UserName,UserUid,UserGid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate account role and whether this shell, group or home was authorized" AS Hypothesis,
  "Configuration snapshot; does not establish a login or privilege use" AS ObservationLimit,
  "LTH - 02 - Users Groups and Privileges Dashboard" AS RecommendedNotebook
FROM AccountSignals
WHERE TemporaryShell OR TemporaryRootHome OR PrimaryRootGroup OR ServiceInteractiveShell

LET ProcessExtraFields <= SELECT *,
  format(format="%v|%v|%v",args=[ClientId,RowFlowId,ProcPid]) AS ProcessLookupKey,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS CleanExe,
  (ProcDeleted=TRUE OR ProcExe =~ '''\(deleted\)$''') AS IsDeleted,
  ProcExe =~ '''^/?memfd:''' AS IsMemfd
FROM ProcessFields

LET ProcessIndex <= memoize(query={SELECT * FROM ProcessExtraFields},key="ProcessLookupKey")
LET ProcessWithParent <= SELECT *,
  get(item=ProcessIndex,field=format(format="%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPpid])) AS ParentProcess
FROM ProcessExtraFields

LET NewProcessSignals <= SELECT *,
  (ParentProcess.ProcName =~ '''^(nginx|apache2|httpd|php-fpm[0-9.]*|uwsgi|gunicorn[0-9.: -]*)$'''
   AND CleanExe =~ '''/(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php[0-9.]*)$'''
   AND ProcPpid!="0" AND ProcPpid!="") AS WebServiceChild,
  (CleanExe =~ '''/ssh$'''
   AND ProcCommandLine =~ '''(^|\s)(-(R|D)(\s|[0-9*\[:/])|-o\s*(RemoteForward|DynamicForward)\s*=)''') AS SSHForwarding
FROM ProcessWithParent

LET ExtraProcessMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_context" AS SignalId,
  if(condition=IsMemfd,then="Process executable is backed by memfd",
    else=if(condition=WebServiceChild,then="Shell or interpreter has a web-service parent in this snapshot",
      else=if(condition=SSHForwarding,then="SSH process declares remote or dynamic forwarding",
        else="Process executable is marked deleted"))) AS Indicator,
  if(condition=IsMemfd,then=4,else=if(condition=WebServiceChild,then=3,else=2)) AS FindingWeight,
  dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername,CreatedTime=ProcCreatedTime) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Deleted=IsDeleted,Memfd=IsMemfd,SSHForwarding=SSHForwarding,
    WebServiceChild=WebServiceChild,ParentName=ParentProcess.ProcName,
    ParentExe=ParentProcess.ProcExe,ParentCommandLine=ParentProcess.ProcCommandLine,
    FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|process_context|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the executable, parent application behavior and authorized forwarding or updates" AS Hypothesis,
  "Snapshot correlation; not historical process-creation evidence. Deleted binaries can follow normal updates" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook
FROM NewProcessSignals
WHERE IsMemfd OR WebServiceChild OR SSHForwarding OR IsDeleted

LET CronScriptFiles <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=get(item=scope(),field="OSPath")) AS ScriptPath,
  TextOrEmpty(X=get(item=scope(),field="Content")) AS ScriptContent,
  get(item=scope(),field="Mtime") AS ScriptMtime,
  get(item=scope(),field="FileSize") AS ScriptFileSize,
  get(item=scope(),field="ContentLimit") AS ScriptContentLimit,
  get(item=scope(),field="PotentiallyTruncated") AS ScriptPotentiallyTruncated
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Crontab")
WHERE ScriptPath!="" AND ScriptContent!=""

LET ScriptResults <= SELECT * FROM foreach(row=CronScriptFiles,query={
  SELECT ClientId,Fqdn,ScriptPath,ScriptMtime,ScriptFileSize,ScriptContentLimit,ScriptPotentiallyTruncated,
    _value AS CronCommand,(_key + 1) AS ScriptLineNumber,"" AS CronEvent,"" AS Minute,"" AS Hour
  FROM items(item=split(string=ScriptContent,sep="\n"))
})
WHERE NOT CronCommand =~ '''^\s*(#|$)'''

LET ScriptSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM ScriptResults


LET ClassifiedScript <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM ScriptSignals


LET ScoredScript <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedScript



LET CronScriptMatches <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_script_content" AS SignalId,
  if(condition=CriticalCommand,then="Cron script line contains a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron script line declares temporary-path execution",
      else=if(condition=InlineInterpreter,then="Cron script line declares inline interpreter code",
        else="Cron script line declares remote fetch"))) AS Indicator,
  if(condition=CriticalCommand,then=5,else=if(condition=WritablePathExecution,then=4,
    else=if(condition=InlineInterpreter,then=3,else=2))) AS FindingWeight,
  ScriptPath AS Evidence1,ScriptLineNumber AS Evidence2,CronCommand AS Evidence3,
  dict(Mtime=ScriptMtime,FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated,CriticalCommand=CriticalCommand,
    WritablePathExecution=WritablePathExecution,InlineInterpreter=InlineInterpreter,
    ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  format(format="%v|cron_script|%v|%v|%v",args=[ClientId,ScriptPath,ScriptLineNumber,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script invoked by cron/run-parts, and is the declared behavior authorized?" AS Hypothesis,
  "Content prefix and line regex only; comments skipped, but strings/dead code may match. Existence does not prove execution" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook
FROM ScoredScript
WHERE CriticalCommand OR WritablePathExecution OR InlineInterpreter OR ScheduledRemoteFetch

LET MountFields <= SELECT ClientId,Fqdn,Device,Mount,FSType,Options,
  TextOrEmpty(X=(get(item=scope(),field="FlowId") || get(item=scope(),field="_FlowId"))) AS MountFlowId,
  regex_replace(source=TextOrEmpty(X=Mount),re="/+$",replace="") AS MountPrefix
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Mounts")

-- Resolve the longest matching mount, including normal nested mounts.
-- Encoded mount paths require decoding before they can be correlated safely.
LET MountFor(C,F,E) = SELECT *,len(list=MountPrefix) AS PrefixLength
FROM MountFields
WHERE ClientId=C AND MountFlowId=F AND TextOrEmpty(X=Mount)!=""
  AND NOT TextOrEmpty(X=Mount) =~ '''\\[0-7]{3}'''
  AND (E=MountPrefix OR split(string=E,sep_string=MountPrefix+"/")[0]="")
ORDER BY PrefixLength DESC LIMIT 1

LET MountProcessPaths <= SELECT *,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS ExecutablePath
FROM ProcessFields
WHERE ProcExe =~ '''^/(mnt|media|home|srv|opt|run/user)/'''

LET ExecutableMounts <= SELECT *,
  MountFor(C=ClientId,F=RowFlowId,E=ExecutablePath)[0] AS BackingMount
FROM MountProcessPaths
WHERE NOT ExecutablePath =~ '''[\s\\]'''

LET MountExecutionMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_network_mount_execution" AS SignalId,
  "Process executable path resolves to a network filesystem in this snapshot" AS Indicator,
  2 AS FindingWeight,dict(Pid=ProcPid,Ppid=ProcPpid) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Mount=BackingMount.Mount,Device=BackingMount.Device,FSType=BackingMount.FSType,
    Options=BackingMount.Options,SupportingArtifact="LTH.SystemBaseline/Mounts",FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|mounted_exe|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,BackingMount.Mount]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is executable code on this network share expected for this server role?" AS Hypothesis,
  "Path-based, non-atomic snapshot correlation; process mount namespaces and mounts may differ" AS ObservationLimit,
  "LTH - 01 / LTH - 04" AS RecommendedNotebook
FROM ExecutableMounts
WHERE BackingMount.FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountContext <= SELECT ClientId,Fqdn,"Mount Review" AS Category,
  "baseline_network_mount_inventory" AS SignalId,
  "Network filesystem available for hypothesis review" AS Indicator,
  0 AS FindingWeight,Mount AS Evidence1,Device AS Evidence2,FSType AS Evidence3,
  dict(Options=Options,FlowId=MountFlowId) AS Evidence4,
  format(format="%v|%v|mount_context|%v|%v",args=[ClientId,MountFlowId,Mount,Device]) AS EvidenceKey,
  "LTH.SystemBaseline/Mounts" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the share owner, purpose and which applications use it" AS Hypothesis,
  "Mount inventory alone has weight zero and does not establish malicious use" AS ObservationLimit,
  "LTH - 01 - System Baseline Dashboard" AS RecommendedNotebook
FROM MountFields WHERE FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountReview <= SELECT * FROM chain(execution=MountExecutionMatches,context=MountContext)

LET PackageRaw <= SELECT * FROM chain(
  debian={SELECT *,"Debian" AS PackageFamily,"LTH.SystemBaseline/DebianPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/DebianPackages")},
  rhel={SELECT *,"RHEL" AS PackageFamily,"LTH.SystemBaseline/RHELPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/RHELPackages")}
)
LET PackageFields <= SELECT ClientId,Fqdn,PackageFamily,PackageSource,
  TextOrEmpty(X=(get(item=scope(),field="Package") || get(item=scope(),field="Name"))) AS PackageName,
  TextOrEmpty(X=get(item=scope(),field="Version")) AS PackageVersion,
  TextOrEmpty(X=(get(item=scope(),field="State") || get(item=scope(),field="Status"))) AS PackageState,
  TextOrEmpty(X=get(item=scope(),field="Repository")) AS PackageRepository
FROM PackageRaw
LET InstalledPackages <= SELECT *,
  regex_replace(source=PackageName,
    re='''(\.(x86_64|i[3-6]86|noarch|aarch64|armv[0-9]+[a-z]*|ppc64le|s390x)|:[a-z0-9_-]+)$''',replace="") AS NormalizedPackage
FROM PackageFields
WHERE PackageName!="" AND (PackageFamily="RHEL" OR PackageState IN ("installed","active"))
LET PackageContext <= SELECT ClientId,Fqdn,"Package Review" AS Category,
  "baseline_dual_use_package_inventory" AS SignalId,
  "Installed network, proxy or remote-access tooling for role review" AS Indicator,
  0 AS FindingWeight,PackageName AS Evidence1,PackageVersion AS Evidence2,
  dict(Family=PackageFamily,State=PackageState,Repository=PackageRepository) AS Evidence3,
  "Installed software inventory does not establish execution, compromise, file ownership or vulnerability" AS Evidence4,
  format(format="%v|package_context|%v|%v|%v",args=[ClientId,PackageSource,PackageName,PackageVersion]) AS EvidenceKey,
  PackageSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this tool expected for the server role, and do process/network findings show relevant use?" AS Hypothesis,
  "RHEL package names include architecture; removed Debian entries are excluded. No version-to-CVE inference" AS ObservationLimit,
  "LTH - 01 / LTH - 04 / LTH - 05" AS RecommendedNotebook
FROM InstalledPackages
WHERE NormalizedPackage =~ '''^(nmap|nmap-ncat|ncat|netcat|netcat-openbsd|netcat-traditional|socat|masscan|proxychains|proxychains4|chisel|ngrok|frp|frpc|frps|rclone|openssh-clients|openssh-client)$'''

LET SecurityServiceMatches <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_security_service_state" AS SignalId,
  "A listed logging/audit service has an inactive or failed state" AS Indicator,
  2 AS FindingWeight,ServiceUnit AS Evidence1,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence2,
  ServiceDescription AS Evidence3,
  "Review maintenance, configured logging architecture and service diagnostics" AS Evidence4,
  format(format="%v|security_service_state|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this observed service state expected, or has logging continuity been affected?" AS Hypothesis,
  "Only an existing row is evaluated; absence does not mean disabled. State does not establish tampering" AS ObservationLimit,
  "LTH - 04 / LTH - 08" AS RecommendedNotebook
FROM ServiceFields
WHERE ServiceLoad="loaded" AND ServiceUnit =~ '''^(auditd|rsyslog|systemd-journald)\.service$'''
  AND (ServiceActive IN ("failed","inactive") OR ServiceSub="failed")
LET SourceCoverage <=
SELECT *
FROM chain(
  users={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Users source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM UserFields
    GROUP BY ClientId
  },
  processes={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Processes source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ProcessFields
    GROUP BY ClientId
  },
  services={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Services source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ServiceFields
    GROUP BY ClientId
  },
  network={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Network source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM NetworkFields
    GROUP BY ClientId
  },
  cron={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Cron source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM CronFields
    WHERE CommandValue!="" OR CronContent!=""
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
LET InventoryPlatform <= SELECT ClientId,Fqdn,TextOrEmpty(X=get(item=scope(),field="Platform")) AS Platform
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET PlatformFamilies <= SELECT *,
  if(condition=Platform =~ '''(?i)^(ubuntu|debian|linuxmint|kali|raspbian|pop)$''',then="Debian",
    else=if(condition=Platform =~ '''(?i)^(alma|almalinux|rocky|rhel|redhat|red hat.*|centos|ol|oracle|oraclelinux|fedora)$''',then="RHEL",else="Unknown")) AS ExpectedPackageFamily
FROM InventoryPlatform
LET PlatformIndex <= memoize(query={SELECT * FROM PlatformFamilies},key="ClientId")
LET ApplicablePackages <= SELECT *,get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily AS ExpectedFamily
FROM InstalledPackages
WHERE PackageFamily=ExpectedFamily

LET ExtraCoverage <= SELECT * FROM chain(
  mounts={SELECT ClientId,Fqdn,"Coverage" AS Category,"Mounts source returned rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM MountFields GROUP BY ClientId},
  packages={SELECT ClientId,Fqdn,"Coverage" AS Category,"Applicable package family returned installed rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM ApplicablePackages GROUP BY ClientId}
)

LET SelectedScope <= SELECT ClientId,Fqdn FROM chain(
  inventory=Fleet,users=UserFields,processes=ProcessFields,services=ServiceFields,
  network=NetworkFields,cron=CronFields,mounts=MountFields,packages=PackageFields
) GROUP BY ClientId

LET CronQuality <= SELECT ClientId,
  sum(item=if(condition=CommandValue!="" AND CronParserVersion!=2,then=1,else=0)) AS LegacyCronRows,
  sum(item=if(condition=CronParseStatus="Unparsed",then=1,else=0)) AS UnparsedCronRows,
  sum(item=if(condition=CronPotentiallyTruncated=TRUE,then=1,else=0)) AS TruncatedCronScripts
FROM CronFields GROUP BY ClientId
LET CronQualityIndex <= memoize(query={SELECT * FROM CronQuality},key="ClientId")

LET AllEvidenceCandidates <= SELECT * FROM chain(
  users=UserDetail,processes=ProcessDetail,services=ServiceDetail,network=NetworkDetail,cron=CronDetail,
  accounts=AccountMatches,process_context=ExtraProcessMatches,cron_scripts=CronScriptMatches,
  mounts=MountReview,packages=PackageContext,security_services=SecurityServiceMatches
)
LET AllEvidence <= SELECT * FROM AllEvidenceCandidates GROUP BY EvidenceKey
LET PositiveEvidence <= SELECT * FROM AllEvidence WHERE FindingWeight>0

-- Original five categories; cap each category at its highest matched weight.
LET RiskAreas <= SELECT ClientId,Fqdn,Category,
  "Highest matched weight in this existing area" AS Indicator,
  max(item=FindingWeight) AS Weight,count() AS EvidenceCount,0 AS SourceCollected,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM PositiveEvidence GROUP BY AreaKey
LET Findings <= SELECT * FROM chain(
  all_clients={SELECT ClientId,Fqdn,"Coverage" AS Category,"Client has selected baseline data" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,0 AS SourceCollected FROM SelectedScope},
  inventory=Fleet,source_coverage=SourceCoverage,added_coverage=ExtraCoverage,areas=RiskAreas
)

-- Edit to include your actual internal networks, including internally routed public ranges.
-- A peer outside this list is not automatically Internet traffic or malicious.
LET ReviewInternalCIDRs <= split(string="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",sep=",")

LET ReviewMinCohortHosts <= 4
LET ReviewMaxRareHosts <= 2
LET ReviewMaxRarePercent <= 25

LET AdminProcessSignals <= SELECT *,
  ProcName =~ '''(?i)^ssh$''' AS RemoteClient,
  ProcName =~ '''(?i)^(scp|sftp|rsync|rclone)$''' AS TransferTool,
  ProcName =~ '''(?i)^(curl|wget)$''' AS FetchTool,
  ProcName =~ '''(?i)^(nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS NetworkUtility,
  (ProcUsername="root" AND ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS RootShell,
  ProcName =~ '''(?i)^(sudo|su|doas)$''' AS PrivilegeUtility,
  ProcCommandLine =~ '''(?i)(^|\s|/)(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)''' AS InlineCode,
  (ProcName =~ '''(?i)^(screen|tmux|nohup)$'''
   OR ProcCommandLine =~ '''(?i)^\s*(sudo\s+)?nohup\s''') AS BackgroundSession,
  ProcExe =~ '''^/(usr/local|opt|srv|home|root|mnt|media)/''' AS ApplicationPathExe,
  (ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby)$'''
   AND ProcCommandLine =~ '''\s/(usr/local|opt|srv|home|root|mnt|media)/[^\s;&|]+''') AS InterpreterPathReference
FROM ProcessFields

LET AdministrativeProcessLeads <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "review_administrative_process" AS SignalId,
  "Administrative, application-path or interpreter process to validate" AS Indicator,
  0 AS FindingWeight,
  if(condition=RootShell OR PrivilegeUtility OR InlineCode OR TransferTool OR RemoteClient,then=2,else=1) AS ReviewPriority,
  dict(Pid=ProcPid,Ppid=ProcPpid,Name=ProcName,Username=ProcUsername,FlowId=RowFlowId) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(RemoteClient=RemoteClient,TransferTool=TransferTool,FetchTool=FetchTool,NetworkUtility=NetworkUtility,
    RootShell=RootShell,PrivilegeUtility=PrivilegeUtility,InlineCode=InlineCode,BackgroundSession=BackgroundSession,
    ApplicationPathExe=ApplicationPathExe,InterpreterPathReference=InterpreterPathReference) AS Evidence4,
  format(format="%v|%v|review_process|%v|%v|%v",args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this observed command, account, path and peer fit the approved administration or application workflow?" AS Hypothesis,
  "Identify the process owner and approved task; read parent and network context; validate the script or binary when needed" AS SuggestedChecks,
  "Current process snapshot only. Root shell is not proof of an interactive session; an interpreter argument may reference data rather than executed code" AS ObservationLimit,
  "LTH - 04 / LTH - 03 / LTH - 05" AS RecommendedNotebook
FROM AdminProcessSignals
WHERE RemoteClient OR TransferTool OR FetchTool OR NetworkUtility OR RootShell OR PrivilegeUtility
   OR InlineCode OR BackgroundSession OR ApplicationPathExe OR InterpreterPathReference

LET ReviewAccountSignals <= SELECT *,
  (UserUid!="0" AND UserUid!="" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS NonRootShellAccount,
  (UserUid!="0" AND UserUid!="" AND HomeDir =~ '''^/(root|opt|srv)(/|$)''') AS ApplicationHomeAccount
FROM UserFields
LET ReviewAccountLeads <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "review_account_role" AS SignalId,"Account shell or application home requires role confirmation" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,dict(Shell=UserShell,Home=HomeDir) AS Evidence3,
  dict(NonRootShellAccount=NonRootShellAccount,ApplicationHomeAccount=ApplicationHomeAccount) AS Evidence4,
  format(format="%v|review_account|%v|%v|%v|%v",args=[ClientId,UserName,UserUid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this account, shell and home required by a named person or application?" AS Hypothesis,
  "Identify the account owner and intended role; request authentication or group evidence only if the hypothesis requires it" AS SuggestedChecks,
  "Passwd snapshot: configured shell is not proof of login, and primary GID is not supplementary group membership" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook
FROM ReviewAccountSignals WHERE NonRootShellAccount OR ApplicationHomeAccount

LET ScheduledTaskLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_scheduled_command" AS SignalId,"Scheduled command for administrative-workflow review" AS Indicator,
  0 AS FindingWeight,
  if(condition=CronUser="root" OR CronEvent="@reboot" OR (Minute IN ("*","*/1") AND Hour="*"),then=2,else=1) AS ReviewPriority,
  CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParserVersion=CronParserVersion,ParseStatus=CronParseStatus) AS Evidence4,
  format(format="%v|review_cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,CronPath,CronUser,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this scheduled command, execution account and frequency belong to an approved job?" AS Hypothesis,
  "Identify the job owner; validate its script and destination; use execution logs if proof of a run is needed" AS SuggestedChecks,
  "Shows every nonempty parsed command, including legitimate maintenance. Legacy cron parsing may have lost the real command or user" AS ObservationLimit,
  "LTH - 06 / LTH - 04" AS RecommendedNotebook
FROM CronResults

LET ScheduledScriptLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_cron_script" AS SignalId,"Periodic cron script content for purpose and ownership review" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ScriptPath AS Evidence1,ScriptContent AS Evidence2,
  ScriptMtime AS Evidence3,dict(FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated) AS Evidence4,
  format(format="%v|review_cron_script|%v|%v",args=[ClientId,ScriptPath,ScriptContent]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script expected in a periodic cron directory, and is it actually invoked by the configured scheduler?" AS Hypothesis,
  "Review the collected content and owner; confirm run-parts eligibility and scheduler configuration if execution matters" AS SuggestedChecks,
  "Only a collected content prefix; placement and Mtime do not prove execution or identify the modifier" AS ObservationLimit,
  "LTH - 06" AS RecommendedNotebook
FROM CronScriptFiles

LET AccountScheduledLeads <= SELECT * FROM chain(accounts=ReviewAccountLeads,commands=ScheduledTaskLeads,scripts=ScheduledScriptLeads)

LET ReviewNetworkFields <= SELECT *,
  regex_replace(source=Laddr,re='''^\[|\]$''',replace="") AS ReviewLocalIP,
  regex_replace(source=Raddr,re='''^\[|\]$''',replace="") AS ReviewPeerIP,
  ConnStatus =~ '''(?i)^LISTEN(ING)?$''' AS ReviewListening,
  ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$''' AS ReviewEstablished,
  ProcName =~ '''(?i)^(ssh|scp|sftp|rsync|rclone|curl|wget|nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS ReviewAdministrativeTool
FROM NetworkResults
LET ReviewNetworkSignals <= SELECT *,
  (ReviewListening AND cidr_contains(ip=ReviewLocalIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewLocalIP,ranges=["127.0.0.0/8","::1/128"])) AS NonLoopbackListener,
  (ReviewEstablished AND ReviewAdministrativeTool
    AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["127.0.0.0/8","::1/128","0.0.0.0/8","::/128"])) AS AdministrativeConnection,
  (ReviewEstablished AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fe80::/10","ff00::/8"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=ReviewInternalCIDRs)) AS PeerOutsideConfiguredNetworks
FROM ReviewNetworkFields
LET NetworkReviewLeads <= SELECT ClientId,Fqdn,"Network" AS Category,
  "review_socket_role" AS SignalId,"Listener or established peer for role and administration review" AS Indicator,
  0 AS FindingWeight,
  if(condition=AdministrativeConnection OR PeerOutsideConfiguredNetworks,then=2,else=1) AS ReviewPriority,
  dict(Pid=Pid,Name=ProcName,Username=ProcUsername) AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,CallChain=CallChain,
    NonLoopbackListener=NonLoopbackListener,AdministrativeConnection=AdministrativeConnection,
    PeerOutsideConfiguredNetworks=PeerOutsideConfiguredNetworks) AS Evidence4,
  format(format="%v|review_socket|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,Pid,Laddr,Lport,Raddr,Rport,ConnStatus,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this process need this listening address or peer for its approved service or administrative task?" AS Hypothesis,
  "Identify service and destination owners; confirm intended exposure and peer; correlate with the process and approved task" AS SuggestedChecks,
  "Established sockets do not establish initiation direction. Wildcard listening does not prove Internet reachability; configured CIDRs are not a reputation check" AS ObservationLimit,
  "LTH - 05 / LTH - 04" AS RecommendedNotebook
FROM ReviewNetworkSignals
WHERE NonLoopbackListener OR AdministrativeConnection OR PeerOutsideConfiguredNetworks

LET ReviewServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(ssh|sshd|xrdp|xrdp-sesman|vncserver|tigervnc|telnet|rsh)([-.@][^ ]*)?\.service$''' AS RemoteAccessService,
  ServiceUnit =~ '''(?i)^(docker|containerd|crio|cri-o|podman|kubelet)([-.@][^ ]*)?\.service$''' AS ContainerService,
  ServiceUnit =~ '''(?i)^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|postgres|redis|redis-server|mongod|mongodb|elasticsearch)([-.@][^ ]*)?\.service$''' AS ApplicationDataService,
  ServiceUnit =~ '''(?i)^(nfs|nfs-server|rpcbind|smb|smbd|nmb|nmbd|vsftpd|proftpd|pure-ftpd)([-.@][^ ]*)?\.service$''' AS FileSharingService
FROM ServiceFields
LET ActiveServiceLeads <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "review_active_service_role" AS SignalId,"Active access, application, container or file-sharing service" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(RemoteAccessService=RemoteAccessService,ContainerService=ContainerService,
    ApplicationDataService=ApplicationDataService,FileSharingService=FileSharingService) AS Evidence4,
  format(format="%v|review_service|%v|%v|%v",args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this active service required for the host role and is its access or data exposure intended?" AS Hypothesis,
  "Confirm the service owner and purpose; inspect related listeners; collect unit configuration only for the selected hypothesis" AS SuggestedChecks,
  "Observed loaded service state and naming only; no ExecStart, enablement, installed-package ownership or exposure proof" AS ObservationLimit,
  "LTH - 04 / LTH - 05 / LTH - 12" AS RecommendedNotebook
FROM ReviewServiceSignals
WHERE ServiceLoad="loaded" AND ServiceActive="active"
  AND (RemoteAccessService OR ContainerService OR ApplicationDataService OR FileSharingService)

LET ReviewPlatforms <= SELECT ClientId,
  (TextOrEmpty(X=get(item=scope(),field="Platform")) || "Unknown") AS ReviewCohort
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET ReviewPlatformIndex <= memoize(query={SELECT * FROM ReviewPlatforms},key="ClientId")

-- Denominator is distinct clients that returned usable rows for this source,
-- not all 16 scoped clients when some source results are missing.
LET ReviewSourceClients <= SELECT * FROM chain(
  processes={SELECT ClientId,"Process executable" AS Family FROM ProcessFields WHERE ProcExe!="" GROUP BY ClientId},
  services={SELECT ClientId,"Service unit" AS Family FROM ServiceFields WHERE ServiceUnit!="" GROUP BY ClientId},
  users={SELECT ClientId,"Shell account" AS Family FROM UserFields WHERE UserName!="" GROUP BY ClientId},
  cron={SELECT ClientId,"Cron command" AS Family FROM CronResults GROUP BY ClientId}
)
LET ReviewSourceCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewSourceClients
LET ReviewCoverage <= SELECT Family,ReviewCohort,count() AS CoveredHosts,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewSourceCohorts GROUP BY CohortKey
LET ReviewCoverageIndex <= memoize(query={SELECT * FROM ReviewCoverage},key="CohortKey")

LET ReviewObservations <= SELECT * FROM chain(
  processes={SELECT ClientId,Fqdn,"Processes" AS Category,"Process executable" AS Family,
    regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS Entity,
    "LTH.SystemBaseline/Processes" AS ObservationSource FROM ProcessFields WHERE ProcExe!=""},
  services={SELECT ClientId,Fqdn,"Services and Persistence" AS Category,"Service unit" AS Family,
    ServiceUnit AS Entity,"LTH.SystemBaseline/Services" AS ObservationSource FROM ServiceFields WHERE ServiceUnit!=""},
  users={SELECT ClientId,Fqdn,"Users and Privileges" AS Category,"Shell account" AS Family,
    UserName+"|"+UserShell AS Entity,"LTH.SystemBaseline/Users" AS ObservationSource
    FROM UserFields WHERE UserUid!="0" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$'''},
  cron={SELECT ClientId,Fqdn,"Persistence" AS Category,"Cron command" AS Family,
    CronUser+"|"+CronCommand AS Entity,"LTH.SystemBaseline/Crontab" AS ObservationSource FROM CronResults}
)
LET ReviewObservedCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewObservations
LET ReviewUniqueHostEntities <= SELECT *,
  format(format="%v|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS HostEntityKey,
  format(format="%v|%v|%v",args=[ReviewCohort,Family,Entity]) AS PrevalenceKey,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewObservedCohorts GROUP BY HostEntityKey
LET ReviewPrevalence <= SELECT PrevalenceKey,count() AS HostsWithEntity
FROM ReviewUniqueHostEntities GROUP BY PrevalenceKey
LET ReviewPrevalenceIndex <= memoize(query={SELECT * FROM ReviewPrevalence},key="PrevalenceKey")
LET ReviewPrevalenceRows <= SELECT *,
  get(item=ReviewCoverageIndex,field=CohortKey).CoveredHosts AS CoveredHosts,
  get(item=ReviewPrevalenceIndex,field=PrevalenceKey).HostsWithEntity AS HostsWithEntity
FROM ReviewUniqueHostEntities
LET RareBaselineLeads <= SELECT ClientId,Fqdn,Category,
  "review_low_prevalence" AS SignalId,"Low-prevalence baseline entity in the observed platform cohort" AS Indicator,
  0 AS FindingWeight,2 AS ReviewPriority,Family AS Evidence1,Entity AS Evidence2,
  dict(PlatformCohort=ReviewCohort,HostsWithEntity=HostsWithEntity,CoveredHosts=CoveredHosts) AS Evidence3,
  "Compare approved roles before treating rarity as an anomaly; do not interpret as newly created" AS Evidence4,
  format(format="%v|review_prevalence|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS EvidenceKey,
  ObservationSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this uncommon executable, unit, account or scheduled command explained by this host's approved role?" AS Hypothesis,
  "Compare with hosts having the same business role; identify owner and deployment purpose; inspect related baseline evidence" AS SuggestedChecks,
  "One-Hunt prevalence among clients with source rows. Platform is not a business-role cohort; exact cron commands may contain host-specific values" AS ObservationLimit,
  "LTH - 01 / the notebook for the observed family" AS RecommendedNotebook
FROM ReviewPrevalenceRows
WHERE ReviewCohort!="Unknown" AND CoveredHosts>=ReviewMinCohortHosts
  AND HostsWithEntity<=ReviewMaxRareHosts
  AND (HostsWithEntity * 100)<= (CoveredHosts * ReviewMaxRarePercent)

LET AdditionalReviewCandidates <= SELECT * FROM chain(
  admin=AdministrativeProcessLeads,account_cron=AccountScheduledLeads,
  network=NetworkReviewLeads,services=ActiveServiceLeads,prevalence=RareBaselineLeads
)
LET EnhancedEvidenceCandidates <= SELECT * FROM chain(existing=AllEvidence,review=AdditionalReviewCandidates)
LET EnhancedEvidence <= SELECT *,
  if(condition=FindingWeight>0,then="Risk Indicator",else="Hunt Lead") AS EvidenceKind,
  "Unreviewed" AS ReviewState,
  if(condition=FindingWeight>=4,then=3,else=if(condition=FindingWeight>0,then=2,
    else=(get(item=scope(),field="ReviewPriority") || 1))) AS ReviewPriority,
  (get(item=scope(),field="SuggestedChecks") || Hypothesis) AS SuggestedChecks
FROM EnhancedEvidenceCandidates GROUP BY EvidenceKey

LET HuntLeadSummary <= SELECT ClientId,count() AS HuntLeadCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority
FROM EnhancedEvidence GROUP BY ClientId
LET HuntLeadIndex <= memoize(query={SELECT * FROM HuntLeadSummary},key="ClientId")
LET FirstHuntLead(C) = SELECT Hypothesis FROM EnhancedEvidence WHERE ClientId=C ORDER BY ReviewPriority DESC LIMIT 1

LET EvidenceAreas <= SELECT ClientId,Fqdn,Category,
  max(item=FindingWeight) AS Weight,
  sum(item=if(condition=FindingWeight>0,then=1,else=0)) AS EvidenceCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM EnhancedEvidence GROUP BY AreaKey
LET HostScores <=
SELECT ClientId,
       Fqdn,
       sum(
         item=if(
           condition=Weight > 0,
           then=1,
           else=0
         )
       ) AS TriggeredAreaCount,
       sum(item=Weight) AS RiskScore,
       sum(item=EvidenceCount) AS FindingEvidenceCount,
       sum(
         item=if(
           condition=Weight = 5,
           then=1,
           else=0
         )
       ) AS CriticalAreaCount,
       sum(item=SourceCollected) AS CollectedSourceCount
FROM Findings
GROUP BY ClientId

LET ExtendedHostScores <=
SELECT ClientId,
       Fqdn,
       TriggeredAreaCount,
       RiskScore,
       (get(item=HuntLeadIndex,field=ClientId).HuntLeadCount || 0) AS HuntLeadCount,
       (get(item=HuntLeadIndex,field=ClientId).ReviewLeadCount || 0) AS ReviewLeadCount,
       (get(item=HuntLeadIndex,field=ClientId).HighestReviewPriority || 0) AS HighestReviewPriority,
       if(condition=RiskScore>0,then="Risk Indicators Found",
         else=if(condition=get(item=HuntLeadIndex,field=ClientId).ReviewLeadCount>0,
           then="Review Leads Available",else="Planned Hunt Needed")) AS HuntStatus,
       (FirstHuntLead(C=ClientId)[0].Hypothesis || "Confirm host role and collection coverage; select a role-based hypothesis even when this snapshot has no lead") AS TopHuntHypothesis,
       FindingEvidenceCount,
       CriticalAreaCount,
       CollectedSourceCount,
       8 AS ExpectedSourceCount,
       get(item=PlatformIndex,field=ClientId).Platform AS Platform,
       (get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily || "Unknown") AS ExpectedPackageFamily,
       (get(item=CronQualityIndex,field=ClientId).LegacyCronRows || 0) AS LegacyCronRows,
       (get(item=CronQualityIndex,field=ClientId).UnparsedCronRows || 0) AS UnparsedCronRows,
       (get(item=CronQualityIndex,field=ClientId).TruncatedCronScripts || 0) AS TruncatedCronScripts,
       if(condition=get(item=CronQualityIndex,field=ClientId).LegacyCronRows>0
           OR get(item=CronQualityIndex,field=ClientId).UnparsedCronRows>0,
         then="Cron parser review required; read RawLine or recollect with parser v2",
         else="No detected parser warning; row presence does not establish complete collection") AS DataQualityStatus,
       if(
         condition=CollectedSourceCount = 8,
         then="Selected sources returned rows; inspect collection logs for errors",
         else=format(
           format="Validate empty sources - %v of 8 selected source groups returned rows",
           args=[CollectedSourceCount]
         )
       ) AS CollectionStatus,
       if(
         condition=RiskScore = 0
                   AND (CollectedSourceCount < 8
                     OR get(item=CronQualityIndex,field=ClientId).LegacyCronRows>0
                     OR get(item=CronQualityIndex,field=ClientId).UnparsedCronRows>0),
         then="Collection Review",
         else=if(
           condition=RiskScore = 0,
           then="No Matched Finding",
           else=if(
             condition=CriticalAreaCount > 0
                   OR RiskScore >= 10,
             then="High",
             else=if(
               condition=RiskScore >= 6,
               then="Suspicious",
               else=if(
                 condition=RiskScore >= 3,
                 then="Review",
                 else="Low"
               )
             )
           )
         )
       ) AS RiskLevel
FROM HostScores

SELECT * FROM ExtendedHostScores ORDER BY RiskScore DESC

```

## Cell 28 (markdown)

# Evidence Behind the Score

Shows how each hunting area contributes to the client risk score. Coverage rows confirm that a source returned data and have no effect on the score. Finding rows represent investigation candidates, not confirmed incidents.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))
-- Keep this FALSE on the production server, consistently in all cells.
LET EnableLabIndicators <= FALSE


LET Fleet <= SELECT ClientId,Fqdn,"Coverage" AS Category,"Basic information source returned rows" AS Indicator,
  0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)


LET UserMatches <=
SELECT *,
       format(
         format="%v|uid0|%v|%v",
         args=[ClientId, UserName, HomeDir]
       ) AS EvidenceKey,
       5 AS FindingWeight
FROM UserFields
WHERE UserUid = "0"
  AND NOT UserName =~ '''^root$'''
  AND NOT (
    UserName = ""
    AND HomeDir = "/root"
  )

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET ProcessSignals <=
SELECT *,
       ProcCommandLine =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       ProcCommandLine =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       ProcExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer,
       ProcExe =~ '''(?i)^/run/user/[0-9]+/''' AS UserRuntimeExecution,
       (ProcName =~ '''(?i)^(xmrig|minerd|kinsing|kdevtmpfsi)$'''
        OR ProcCommandLine =~ '''(?i)(xmrig|stratum\+tcp)''') AS MiningPattern
FROM ProcessFields


LET ProcessMatches <=
SELECT *,
       format(
         format="%v|process|%v|%v|%v",
         args=[ClientId, ProcPid, ProcExe, ProcCommandLine]
       ) AS EvidenceKey,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then=5,
         else=if(
           condition=WritablePathExe
                     OR WritablePathExecution
                     OR MiningPattern
                     OR (UserRuntimeExecution AND PythonHTTPServer),
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool
                       OR UserRuntimeExecution,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ProcessSignals
WHERE DownloadPipeShell
   OR DecodePipeShell
   OR NetcatExec
   OR SocatExec
   OR DevTcpShell
   OR WritablePathExe
   OR WritablePathExecution
   OR NetcatTool
   OR SocatTool
   OR PythonHTTPServer
   OR UserRuntimeExecution
   OR MiningPattern


LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")

LET ServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(kinsing|xmrig|kdevtmpfsi|watchbog)([-_.@][a-z0-9_.@-]+)?\.service$''' AS ThreatAssociatedName,
  ServiceDescription =~ '''(?i)(cryptocurrency[ -](miner|mining)|reverse[ -]shell|backdoor[ -]service|unauthorized[ -]remote[ -]access)''' AS HighRiskDescription,
  (EnableLabIndicators AND
   (ServiceUnit =~ '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
    OR ServiceDescription =~ '''(?i)(lab persistence|temporary update service|remote support lab)''')) AS KnownLabService
FROM ServiceFields

LET ServiceMatches <= SELECT *,
  format(format="%v|service|%v|%v|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceDescription,ServiceLoad,ServiceActive,ServiceSub]) AS EvidenceKey,
  if(condition=ThreatAssociatedName,then=5,else=4) AS FindingWeight
FROM ServiceSignals
WHERE ThreatAssociatedName OR HighRiskDescription OR KnownLabService

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="CallChain")) AS RawCallChain,
       TextOrEmpty(X=get(item=scope(), member="Laddr")) AS Laddr,
       TextOrEmpty(X=get(item=scope(), member="Lport")) AS Lport,
       TextOrEmpty(X=get(item=scope(), member="Raddr")) AS Raddr,
       TextOrEmpty(X=get(item=scope(), member="Rport")) AS Rport,
       TextOrEmpty(X=get(item=scope(), member="Pid")) AS Pid,
       TextOrEmpty(X=get(item=scope(), member="Status")) AS ConnStatus,
       get(item=scope(), member="ProcInfo") AS ProcInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET NetworkResults <=
SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus,
       RawCallChain AS CallChain,
       TextOrEmpty(X=get(item=ProcInfo,field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="CommandLine")
         ||
         get(item=ProcInfo, member="cmdline")
       )) AS ProcCommandLine
FROM NetworkFields


LET NetworkSignals <=
SELECT *,
       ConnStatus =~ '''(?i)^(LISTEN|LISTENING)$'''
         AS IsListening,

       ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$'''
         AS IsEstablished,

       Laddr =~ '''^(127\.|::1$|\[::1\]$)'''
         AS LoopbackBind,

       Lport =~ '''^(4444|5555)$'''
         AS HighRiskPort,

       ProcExe =~ '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer
FROM NetworkResults


LET ClassifiedNetwork <=
SELECT *,
       NetcatExec
       OR SocatExec
         AS CommandExecutionSocket,

       (
         (IsListening OR IsEstablished)
         AND
         (WritablePathExe OR WritablePathExecution)
       ) AS WritablePathSocket,

       (
         IsListening
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolListener,

       (
         IsEstablished
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolConnection,

       (
         IsListening
         AND
         PythonHTTPServer
       ) AS PythonListener,

       (
         IsListening
         AND
         HighRiskPort
         AND
         NOT LoopbackBind
       ) AS RiskyPortListener
FROM NetworkSignals


LET NetworkMatches <=
SELECT *,
       format(
         format="%v|network|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           Pid,
           Laddr,
           Lport,
           Raddr,
           Rport,
           ConnStatus
         ]
       ) AS EvidenceKey,

       if(
         condition=CommandExecutionSocket,
         then=5,
         else=if(
           condition=WritablePathSocket
                     OR (
                       PythonListener
                       AND RiskyPortListener
                     ),
           then=4,
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ClassifiedNetwork
WHERE CommandExecutionSocket
   OR WritablePathSocket
   OR NetworkToolListener
   OR NetworkToolConnection
   OR PythonListener
   OR RiskyPortListener

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"


LET CronSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM CronResults


LET ClassifiedCron <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM CronSignals


LET ScoredCron <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedCron


LET CronMatches <=
SELECT *,
       format(
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
           CronUser,
           CronEvent,
           Minute,
           Hour,
           DayOfMonth,
           Month,
           DayOfWeek,
           CronCommand
         ]
       ) AS EvidenceKey,

       if(
         condition=CriticalCommand,
         then=5,
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then=4,
           else=if(
             condition=InlineInterpreter,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ScoredCron
WHERE CriticalCommand
   OR WritablePathExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter
   OR ScheduledRemoteFetch


LET UserDetail <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_additional_uid0" AS SignalId,"Additional UID 0 account" AS Indicator,
  FindingWeight,EvidenceKey,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,HomeDir AS Evidence3,UserShell AS Evidence4,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this additional UID 0 identity authorized for this server?" AS Hypothesis,
  "Passwd configuration only; no proof of login or privilege use" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook,
  UserName AS User,UserDescription AS Description,UserUid AS Uid,UserGid AS Gid,
  HomeDir AS Homedir,UserShell AS Shell
FROM UserMatches

LET ProcessDetail <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_behavior" AS SignalId,
  if(condition=DownloadPipeShell,then="Downloaded content piped to a shell",
    else=if(condition=DecodePipeShell,then="Decoded content piped to a shell",
      else=if(condition=NetcatExec OR SocatExec OR DevTcpShell,then="Command contains a shell/socket execution pattern",
        else=if(condition=MiningPattern,then="Mining-related name or command pattern",
          else=if(condition=WritablePathExe OR WritablePathExecution,then="Execution from a temporary path",
            else=if(condition=UserRuntimeExecution,then="Execution from a user runtime path",
              else=if(condition=NetcatTool OR SocatTool,then="Network utility in process command",
                else="Python HTTP server command"))))))) AS Indicator,
  FindingWeight,EvidenceKey,dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Name=ProcName,Hash=ProcHash,FlowId=RowFlowId,DownloadPipeShell=DownloadPipeShell,DecodePipeShell=DecodePipeShell,
    NetcatExec=NetcatExec,SocatExec=SocatExec,DevTcpShell=DevTcpShell,MiningPattern=MiningPattern,
    WritablePathExe=WritablePathExe,WritablePathExecution=WritablePathExecution,
    UserRuntimeExecution=UserRuntimeExecution,NetcatTool=NetcatTool,SocatTool=SocatTool,
    PythonHTTPServer=PythonHTTPServer) AS Evidence4,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate executable origin, server role and whether this command was authorized" AS Hypothesis,
  "Command/name regex on a process snapshot; not a shell parser or confirmation of compromise" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook,
  ProcPid AS Pid,ProcPpid AS Ppid,ProcName AS Name,ProcExe AS Exe,ProcCommandLine AS CommandLine,
  ProcUsername AS Username,ProcHash AS Hash
FROM ProcessMatches

LET ServiceDetail <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_service_name_description" AS SignalId,
  if(condition=ThreatAssociatedName,then="Service name matches a threat-associated watchlist",
    else=if(condition=HighRiskDescription,then="Service description matches suspicious terminology",
      else="Explicitly enabled lab service indicator")) AS Indicator,
  FindingWeight,EvidenceKey,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(ThreatAssociatedName=ThreatAssociatedName,HighRiskDescription=HighRiskDescription,KnownLabService=KnownLabService) AS Evidence4,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this service name/description correspond to an unauthorized installed service?" AS Hypothesis,
  "Only name, description and state are available. Priority weight is not confidence; collect the unit and executable to validate" AS ObservationLimit,
  "LTH - 04 / LTH - 06" AS RecommendedNotebook,
  ServiceUnit AS Unit,ServiceDescription AS Description,ServiceLoad AS Load,
  ServiceActive AS Active,ServiceSub AS Sub
FROM ServiceMatches

LET NetworkDetail <= SELECT ClientId,Fqdn,"Network" AS Category,
  "baseline_process_socket" AS SignalId,
  if(condition=CommandExecutionSocket,then="Socket-owning process has a command execution pattern",
    else=if(condition=WritablePathSocket,then="Active socket with temporary-path execution context",
      else=if(condition=NetworkToolListener OR NetworkToolConnection,then="Network utility listener or connection",
        else=if(condition=PythonListener,then="Python HTTP listener",else="Non-loopback listener on a configured review port")))) AS Indicator,
  FindingWeight,EvidenceKey,Pid AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,
    Username=ProcUsername,CallChain=CallChain,
    CommandExecutionSocket=CommandExecutionSocket,WritablePathSocket=WritablePathSocket,
    NetworkToolListener=NetworkToolListener,NetworkToolConnection=NetworkToolConnection,
    PythonListener=PythonListener,RiskyPortListener=RiskyPortListener) AS Evidence4,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this socket, associated command and peer expected for this host role?" AS Hypothesis,
  "Socket snapshot; a port number does not identify a protocol or prove command-and-control" AS ObservationLimit,
  "LTH - 05 - Network Connections Dashboard" AS RecommendedNotebook,
  Laddr,Lport,Raddr,Rport,Pid,ConnStatus AS Status,ProcName,ProcExe,ProcCommandLine,ProcUsername,CallChain
FROM NetworkMatches

LET CronDetail <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_command" AS SignalId,
  if(condition=CriticalCommand,then="Cron declares a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron declares execution from a temporary path",
      else=if(condition=RepeatedRemoteFetch,then="Cron declares remote fetch at reboot or every minute",
        else=if(condition=InlineInterpreter,then="Cron declares inline interpreter code",else="Cron declares remote fetch")))) AS Indicator,
  FindingWeight,EvidenceKey,CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParseStatus=CronParseStatus,ParserVersion=CronParserVersion,
    CriticalCommand=CriticalCommand,WritablePathExecution=WritablePathExecution,
    RepeatedRemoteFetch=RepeatedRemoteFetch,InlineInterpreter=InlineInterpreter,ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this scheduled command authorized and is there separate evidence it executed?" AS Hypothesis,
  "Declared command only; legacy parser rows may be incomplete. No cron runtime or complete shell semantics" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook,
  CronUser,CronPath,CronCommand,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek
FROM CronMatches

LET AccountSignals <= SELECT *,
  UserShell =~ '''^/(tmp|var/tmp|dev/shm)/''' AS TemporaryShell,
  (UserName="root" AND HomeDir =~ '''^/(tmp|var/tmp|dev/shm)/''') AS TemporaryRootHome,
  (UserGid="0" AND UserUid!="0" AND UserUid!="") AS PrimaryRootGroup,
  (UserName =~ '''^(www-data|apache|nginx|mysql|mariadb|postgres|redis|memcached|nobody)$'''
   AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS ServiceInteractiveShell
FROM UserFields

LET AccountMatches <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_account_configuration" AS SignalId,
  if(condition=TemporaryShell,then="Account declares a shell under a temporary directory",
    else=if(condition=TemporaryRootHome,then="Root account declares a temporary home directory",
      else=if(condition=PrimaryRootGroup,then="Non-root UID has primary GID 0",
        else="Named service account has an interactive shell"))) AS Indicator,
  if(condition=TemporaryShell,then=4,else=if(condition=TemporaryRootHome,then=3,else=2)) AS FindingWeight,
  UserName AS Evidence1,dict(Uid=UserUid,Gid=UserGid) AS Evidence2,
  UserShell AS Evidence3,dict(Home=HomeDir,TemporaryShell=TemporaryShell,
    TemporaryRootHome=TemporaryRootHome,PrimaryRootGroup=PrimaryRootGroup,
    ServiceInteractiveShell=ServiceInteractiveShell) AS Evidence4,
  format(format="%v|account_config|%v|%v|%v|%v|%v",
    args=[ClientId,UserName,UserUid,UserGid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate account role and whether this shell, group or home was authorized" AS Hypothesis,
  "Configuration snapshot; does not establish a login or privilege use" AS ObservationLimit,
  "LTH - 02 - Users Groups and Privileges Dashboard" AS RecommendedNotebook
FROM AccountSignals
WHERE TemporaryShell OR TemporaryRootHome OR PrimaryRootGroup OR ServiceInteractiveShell

LET ProcessExtraFields <= SELECT *,
  format(format="%v|%v|%v",args=[ClientId,RowFlowId,ProcPid]) AS ProcessLookupKey,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS CleanExe,
  (ProcDeleted=TRUE OR ProcExe =~ '''\(deleted\)$''') AS IsDeleted,
  ProcExe =~ '''^/?memfd:''' AS IsMemfd
FROM ProcessFields

LET ProcessIndex <= memoize(query={SELECT * FROM ProcessExtraFields},key="ProcessLookupKey")
LET ProcessWithParent <= SELECT *,
  get(item=ProcessIndex,field=format(format="%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPpid])) AS ParentProcess
FROM ProcessExtraFields

LET NewProcessSignals <= SELECT *,
  (ParentProcess.ProcName =~ '''^(nginx|apache2|httpd|php-fpm[0-9.]*|uwsgi|gunicorn[0-9.: -]*)$'''
   AND CleanExe =~ '''/(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php[0-9.]*)$'''
   AND ProcPpid!="0" AND ProcPpid!="") AS WebServiceChild,
  (CleanExe =~ '''/ssh$'''
   AND ProcCommandLine =~ '''(^|\s)(-(R|D)(\s|[0-9*\[:/])|-o\s*(RemoteForward|DynamicForward)\s*=)''') AS SSHForwarding
FROM ProcessWithParent

LET ExtraProcessMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_context" AS SignalId,
  if(condition=IsMemfd,then="Process executable is backed by memfd",
    else=if(condition=WebServiceChild,then="Shell or interpreter has a web-service parent in this snapshot",
      else=if(condition=SSHForwarding,then="SSH process declares remote or dynamic forwarding",
        else="Process executable is marked deleted"))) AS Indicator,
  if(condition=IsMemfd,then=4,else=if(condition=WebServiceChild,then=3,else=2)) AS FindingWeight,
  dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername,CreatedTime=ProcCreatedTime) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Deleted=IsDeleted,Memfd=IsMemfd,SSHForwarding=SSHForwarding,
    WebServiceChild=WebServiceChild,ParentName=ParentProcess.ProcName,
    ParentExe=ParentProcess.ProcExe,ParentCommandLine=ParentProcess.ProcCommandLine,
    FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|process_context|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the executable, parent application behavior and authorized forwarding or updates" AS Hypothesis,
  "Snapshot correlation; not historical process-creation evidence. Deleted binaries can follow normal updates" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook
FROM NewProcessSignals
WHERE IsMemfd OR WebServiceChild OR SSHForwarding OR IsDeleted

LET CronScriptFiles <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=get(item=scope(),field="OSPath")) AS ScriptPath,
  TextOrEmpty(X=get(item=scope(),field="Content")) AS ScriptContent,
  get(item=scope(),field="Mtime") AS ScriptMtime,
  get(item=scope(),field="FileSize") AS ScriptFileSize,
  get(item=scope(),field="ContentLimit") AS ScriptContentLimit,
  get(item=scope(),field="PotentiallyTruncated") AS ScriptPotentiallyTruncated
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Crontab")
WHERE ScriptPath!="" AND ScriptContent!=""

LET ScriptResults <= SELECT * FROM foreach(row=CronScriptFiles,query={
  SELECT ClientId,Fqdn,ScriptPath,ScriptMtime,ScriptFileSize,ScriptContentLimit,ScriptPotentiallyTruncated,
    _value AS CronCommand,(_key + 1) AS ScriptLineNumber,"" AS CronEvent,"" AS Minute,"" AS Hour
  FROM items(item=split(string=ScriptContent,sep="\n"))
})
WHERE NOT CronCommand =~ '''^\s*(#|$)'''

LET ScriptSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM ScriptResults


LET ClassifiedScript <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM ScriptSignals


LET ScoredScript <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedScript



LET CronScriptMatches <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_script_content" AS SignalId,
  if(condition=CriticalCommand,then="Cron script line contains a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron script line declares temporary-path execution",
      else=if(condition=InlineInterpreter,then="Cron script line declares inline interpreter code",
        else="Cron script line declares remote fetch"))) AS Indicator,
  if(condition=CriticalCommand,then=5,else=if(condition=WritablePathExecution,then=4,
    else=if(condition=InlineInterpreter,then=3,else=2))) AS FindingWeight,
  ScriptPath AS Evidence1,ScriptLineNumber AS Evidence2,CronCommand AS Evidence3,
  dict(Mtime=ScriptMtime,FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated,CriticalCommand=CriticalCommand,
    WritablePathExecution=WritablePathExecution,InlineInterpreter=InlineInterpreter,
    ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  format(format="%v|cron_script|%v|%v|%v",args=[ClientId,ScriptPath,ScriptLineNumber,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script invoked by cron/run-parts, and is the declared behavior authorized?" AS Hypothesis,
  "Content prefix and line regex only; comments skipped, but strings/dead code may match. Existence does not prove execution" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook
FROM ScoredScript
WHERE CriticalCommand OR WritablePathExecution OR InlineInterpreter OR ScheduledRemoteFetch

LET MountFields <= SELECT ClientId,Fqdn,Device,Mount,FSType,Options,
  TextOrEmpty(X=(get(item=scope(),field="FlowId") || get(item=scope(),field="_FlowId"))) AS MountFlowId,
  regex_replace(source=TextOrEmpty(X=Mount),re="/+$",replace="") AS MountPrefix
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Mounts")

-- Resolve the longest matching mount, including normal nested mounts.
-- Encoded mount paths require decoding before they can be correlated safely.
LET MountFor(C,F,E) = SELECT *,len(list=MountPrefix) AS PrefixLength
FROM MountFields
WHERE ClientId=C AND MountFlowId=F AND TextOrEmpty(X=Mount)!=""
  AND NOT TextOrEmpty(X=Mount) =~ '''\\[0-7]{3}'''
  AND (E=MountPrefix OR split(string=E,sep_string=MountPrefix+"/")[0]="")
ORDER BY PrefixLength DESC LIMIT 1

LET MountProcessPaths <= SELECT *,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS ExecutablePath
FROM ProcessFields
WHERE ProcExe =~ '''^/(mnt|media|home|srv|opt|run/user)/'''

LET ExecutableMounts <= SELECT *,
  MountFor(C=ClientId,F=RowFlowId,E=ExecutablePath)[0] AS BackingMount
FROM MountProcessPaths
WHERE NOT ExecutablePath =~ '''[\s\\]'''

LET MountExecutionMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_network_mount_execution" AS SignalId,
  "Process executable path resolves to a network filesystem in this snapshot" AS Indicator,
  2 AS FindingWeight,dict(Pid=ProcPid,Ppid=ProcPpid) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Mount=BackingMount.Mount,Device=BackingMount.Device,FSType=BackingMount.FSType,
    Options=BackingMount.Options,SupportingArtifact="LTH.SystemBaseline/Mounts",FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|mounted_exe|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,BackingMount.Mount]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is executable code on this network share expected for this server role?" AS Hypothesis,
  "Path-based, non-atomic snapshot correlation; process mount namespaces and mounts may differ" AS ObservationLimit,
  "LTH - 01 / LTH - 04" AS RecommendedNotebook
FROM ExecutableMounts
WHERE BackingMount.FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountContext <= SELECT ClientId,Fqdn,"Mount Review" AS Category,
  "baseline_network_mount_inventory" AS SignalId,
  "Network filesystem available for hypothesis review" AS Indicator,
  0 AS FindingWeight,Mount AS Evidence1,Device AS Evidence2,FSType AS Evidence3,
  dict(Options=Options,FlowId=MountFlowId) AS Evidence4,
  format(format="%v|%v|mount_context|%v|%v",args=[ClientId,MountFlowId,Mount,Device]) AS EvidenceKey,
  "LTH.SystemBaseline/Mounts" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the share owner, purpose and which applications use it" AS Hypothesis,
  "Mount inventory alone has weight zero and does not establish malicious use" AS ObservationLimit,
  "LTH - 01 - System Baseline Dashboard" AS RecommendedNotebook
FROM MountFields WHERE FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountReview <= SELECT * FROM chain(execution=MountExecutionMatches,context=MountContext)

LET PackageRaw <= SELECT * FROM chain(
  debian={SELECT *,"Debian" AS PackageFamily,"LTH.SystemBaseline/DebianPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/DebianPackages")},
  rhel={SELECT *,"RHEL" AS PackageFamily,"LTH.SystemBaseline/RHELPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/RHELPackages")}
)
LET PackageFields <= SELECT ClientId,Fqdn,PackageFamily,PackageSource,
  TextOrEmpty(X=(get(item=scope(),field="Package") || get(item=scope(),field="Name"))) AS PackageName,
  TextOrEmpty(X=get(item=scope(),field="Version")) AS PackageVersion,
  TextOrEmpty(X=(get(item=scope(),field="State") || get(item=scope(),field="Status"))) AS PackageState,
  TextOrEmpty(X=get(item=scope(),field="Repository")) AS PackageRepository
FROM PackageRaw
LET InstalledPackages <= SELECT *,
  regex_replace(source=PackageName,
    re='''(\.(x86_64|i[3-6]86|noarch|aarch64|armv[0-9]+[a-z]*|ppc64le|s390x)|:[a-z0-9_-]+)$''',replace="") AS NormalizedPackage
FROM PackageFields
WHERE PackageName!="" AND (PackageFamily="RHEL" OR PackageState IN ("installed","active"))
LET PackageContext <= SELECT ClientId,Fqdn,"Package Review" AS Category,
  "baseline_dual_use_package_inventory" AS SignalId,
  "Installed network, proxy or remote-access tooling for role review" AS Indicator,
  0 AS FindingWeight,PackageName AS Evidence1,PackageVersion AS Evidence2,
  dict(Family=PackageFamily,State=PackageState,Repository=PackageRepository) AS Evidence3,
  "Installed software inventory does not establish execution, compromise, file ownership or vulnerability" AS Evidence4,
  format(format="%v|package_context|%v|%v|%v",args=[ClientId,PackageSource,PackageName,PackageVersion]) AS EvidenceKey,
  PackageSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this tool expected for the server role, and do process/network findings show relevant use?" AS Hypothesis,
  "RHEL package names include architecture; removed Debian entries are excluded. No version-to-CVE inference" AS ObservationLimit,
  "LTH - 01 / LTH - 04 / LTH - 05" AS RecommendedNotebook
FROM InstalledPackages
WHERE NormalizedPackage =~ '''^(nmap|nmap-ncat|ncat|netcat|netcat-openbsd|netcat-traditional|socat|masscan|proxychains|proxychains4|chisel|ngrok|frp|frpc|frps|rclone|openssh-clients|openssh-client)$'''

LET SecurityServiceMatches <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_security_service_state" AS SignalId,
  "A listed logging/audit service has an inactive or failed state" AS Indicator,
  2 AS FindingWeight,ServiceUnit AS Evidence1,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence2,
  ServiceDescription AS Evidence3,
  "Review maintenance, configured logging architecture and service diagnostics" AS Evidence4,
  format(format="%v|security_service_state|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this observed service state expected, or has logging continuity been affected?" AS Hypothesis,
  "Only an existing row is evaluated; absence does not mean disabled. State does not establish tampering" AS ObservationLimit,
  "LTH - 04 / LTH - 08" AS RecommendedNotebook
FROM ServiceFields
WHERE ServiceLoad="loaded" AND ServiceUnit =~ '''^(auditd|rsyslog|systemd-journald)\.service$'''
  AND (ServiceActive IN ("failed","inactive") OR ServiceSub="failed")
LET SourceCoverage <=
SELECT *
FROM chain(
  users={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Users source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM UserFields
    GROUP BY ClientId
  },
  processes={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Processes source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ProcessFields
    GROUP BY ClientId
  },
  services={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Services source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ServiceFields
    GROUP BY ClientId
  },
  network={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Network source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM NetworkFields
    GROUP BY ClientId
  },
  cron={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Cron source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM CronFields
    WHERE CommandValue!="" OR CronContent!=""
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
LET InventoryPlatform <= SELECT ClientId,Fqdn,TextOrEmpty(X=get(item=scope(),field="Platform")) AS Platform
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET PlatformFamilies <= SELECT *,
  if(condition=Platform =~ '''(?i)^(ubuntu|debian|linuxmint|kali|raspbian|pop)$''',then="Debian",
    else=if(condition=Platform =~ '''(?i)^(alma|almalinux|rocky|rhel|redhat|red hat.*|centos|ol|oracle|oraclelinux|fedora)$''',then="RHEL",else="Unknown")) AS ExpectedPackageFamily
FROM InventoryPlatform
LET PlatformIndex <= memoize(query={SELECT * FROM PlatformFamilies},key="ClientId")
LET ApplicablePackages <= SELECT *,get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily AS ExpectedFamily
FROM InstalledPackages
WHERE PackageFamily=ExpectedFamily

LET ExtraCoverage <= SELECT * FROM chain(
  mounts={SELECT ClientId,Fqdn,"Coverage" AS Category,"Mounts source returned rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM MountFields GROUP BY ClientId},
  packages={SELECT ClientId,Fqdn,"Coverage" AS Category,"Applicable package family returned installed rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM ApplicablePackages GROUP BY ClientId}
)

LET SelectedScope <= SELECT ClientId,Fqdn FROM chain(
  inventory=Fleet,users=UserFields,processes=ProcessFields,services=ServiceFields,
  network=NetworkFields,cron=CronFields,mounts=MountFields,packages=PackageFields
) GROUP BY ClientId

LET CronQuality <= SELECT ClientId,
  sum(item=if(condition=CommandValue!="" AND CronParserVersion!=2,then=1,else=0)) AS LegacyCronRows,
  sum(item=if(condition=CronParseStatus="Unparsed",then=1,else=0)) AS UnparsedCronRows,
  sum(item=if(condition=CronPotentiallyTruncated=TRUE,then=1,else=0)) AS TruncatedCronScripts
FROM CronFields GROUP BY ClientId
LET CronQualityIndex <= memoize(query={SELECT * FROM CronQuality},key="ClientId")

LET AllEvidenceCandidates <= SELECT * FROM chain(
  users=UserDetail,processes=ProcessDetail,services=ServiceDetail,network=NetworkDetail,cron=CronDetail,
  accounts=AccountMatches,process_context=ExtraProcessMatches,cron_scripts=CronScriptMatches,
  mounts=MountReview,packages=PackageContext,security_services=SecurityServiceMatches
)
LET AllEvidence <= SELECT * FROM AllEvidenceCandidates GROUP BY EvidenceKey
LET PositiveEvidence <= SELECT * FROM AllEvidence WHERE FindingWeight>0

-- Original five categories; cap each category at its highest matched weight.
LET RiskAreas <= SELECT ClientId,Fqdn,Category,
  "Highest matched weight in this existing area" AS Indicator,
  max(item=FindingWeight) AS Weight,count() AS EvidenceCount,0 AS SourceCollected,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM PositiveEvidence GROUP BY AreaKey
LET Findings <= SELECT * FROM chain(
  all_clients={SELECT ClientId,Fqdn,"Coverage" AS Category,"Client has selected baseline data" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,0 AS SourceCollected FROM SelectedScope},
  inventory=Fleet,source_coverage=SourceCoverage,added_coverage=ExtraCoverage,areas=RiskAreas
)

-- Edit to include your actual internal networks, including internally routed public ranges.
-- A peer outside this list is not automatically Internet traffic or malicious.
LET ReviewInternalCIDRs <= split(string="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",sep=",")

LET ReviewMinCohortHosts <= 4
LET ReviewMaxRareHosts <= 2
LET ReviewMaxRarePercent <= 25

LET AdminProcessSignals <= SELECT *,
  ProcName =~ '''(?i)^ssh$''' AS RemoteClient,
  ProcName =~ '''(?i)^(scp|sftp|rsync|rclone)$''' AS TransferTool,
  ProcName =~ '''(?i)^(curl|wget)$''' AS FetchTool,
  ProcName =~ '''(?i)^(nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS NetworkUtility,
  (ProcUsername="root" AND ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS RootShell,
  ProcName =~ '''(?i)^(sudo|su|doas)$''' AS PrivilegeUtility,
  ProcCommandLine =~ '''(?i)(^|\s|/)(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)''' AS InlineCode,
  (ProcName =~ '''(?i)^(screen|tmux|nohup)$'''
   OR ProcCommandLine =~ '''(?i)^\s*(sudo\s+)?nohup\s''') AS BackgroundSession,
  ProcExe =~ '''^/(usr/local|opt|srv|home|root|mnt|media)/''' AS ApplicationPathExe,
  (ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby)$'''
   AND ProcCommandLine =~ '''\s/(usr/local|opt|srv|home|root|mnt|media)/[^\s;&|]+''') AS InterpreterPathReference
FROM ProcessFields

LET AdministrativeProcessLeads <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "review_administrative_process" AS SignalId,
  "Administrative, application-path or interpreter process to validate" AS Indicator,
  0 AS FindingWeight,
  if(condition=RootShell OR PrivilegeUtility OR InlineCode OR TransferTool OR RemoteClient,then=2,else=1) AS ReviewPriority,
  dict(Pid=ProcPid,Ppid=ProcPpid,Name=ProcName,Username=ProcUsername,FlowId=RowFlowId) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(RemoteClient=RemoteClient,TransferTool=TransferTool,FetchTool=FetchTool,NetworkUtility=NetworkUtility,
    RootShell=RootShell,PrivilegeUtility=PrivilegeUtility,InlineCode=InlineCode,BackgroundSession=BackgroundSession,
    ApplicationPathExe=ApplicationPathExe,InterpreterPathReference=InterpreterPathReference) AS Evidence4,
  format(format="%v|%v|review_process|%v|%v|%v",args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this observed command, account, path and peer fit the approved administration or application workflow?" AS Hypothesis,
  "Identify the process owner and approved task; read parent and network context; validate the script or binary when needed" AS SuggestedChecks,
  "Current process snapshot only. Root shell is not proof of an interactive session; an interpreter argument may reference data rather than executed code" AS ObservationLimit,
  "LTH - 04 / LTH - 03 / LTH - 05" AS RecommendedNotebook
FROM AdminProcessSignals
WHERE RemoteClient OR TransferTool OR FetchTool OR NetworkUtility OR RootShell OR PrivilegeUtility
   OR InlineCode OR BackgroundSession OR ApplicationPathExe OR InterpreterPathReference

LET ReviewAccountSignals <= SELECT *,
  (UserUid!="0" AND UserUid!="" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS NonRootShellAccount,
  (UserUid!="0" AND UserUid!="" AND HomeDir =~ '''^/(root|opt|srv)(/|$)''') AS ApplicationHomeAccount
FROM UserFields
LET ReviewAccountLeads <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "review_account_role" AS SignalId,"Account shell or application home requires role confirmation" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,dict(Shell=UserShell,Home=HomeDir) AS Evidence3,
  dict(NonRootShellAccount=NonRootShellAccount,ApplicationHomeAccount=ApplicationHomeAccount) AS Evidence4,
  format(format="%v|review_account|%v|%v|%v|%v",args=[ClientId,UserName,UserUid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this account, shell and home required by a named person or application?" AS Hypothesis,
  "Identify the account owner and intended role; request authentication or group evidence only if the hypothesis requires it" AS SuggestedChecks,
  "Passwd snapshot: configured shell is not proof of login, and primary GID is not supplementary group membership" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook
FROM ReviewAccountSignals WHERE NonRootShellAccount OR ApplicationHomeAccount

LET ScheduledTaskLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_scheduled_command" AS SignalId,"Scheduled command for administrative-workflow review" AS Indicator,
  0 AS FindingWeight,
  if(condition=CronUser="root" OR CronEvent="@reboot" OR (Minute IN ("*","*/1") AND Hour="*"),then=2,else=1) AS ReviewPriority,
  CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParserVersion=CronParserVersion,ParseStatus=CronParseStatus) AS Evidence4,
  format(format="%v|review_cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,CronPath,CronUser,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this scheduled command, execution account and frequency belong to an approved job?" AS Hypothesis,
  "Identify the job owner; validate its script and destination; use execution logs if proof of a run is needed" AS SuggestedChecks,
  "Shows every nonempty parsed command, including legitimate maintenance. Legacy cron parsing may have lost the real command or user" AS ObservationLimit,
  "LTH - 06 / LTH - 04" AS RecommendedNotebook
FROM CronResults

LET ScheduledScriptLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_cron_script" AS SignalId,"Periodic cron script content for purpose and ownership review" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ScriptPath AS Evidence1,ScriptContent AS Evidence2,
  ScriptMtime AS Evidence3,dict(FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated) AS Evidence4,
  format(format="%v|review_cron_script|%v|%v",args=[ClientId,ScriptPath,ScriptContent]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script expected in a periodic cron directory, and is it actually invoked by the configured scheduler?" AS Hypothesis,
  "Review the collected content and owner; confirm run-parts eligibility and scheduler configuration if execution matters" AS SuggestedChecks,
  "Only a collected content prefix; placement and Mtime do not prove execution or identify the modifier" AS ObservationLimit,
  "LTH - 06" AS RecommendedNotebook
FROM CronScriptFiles

LET AccountScheduledLeads <= SELECT * FROM chain(accounts=ReviewAccountLeads,commands=ScheduledTaskLeads,scripts=ScheduledScriptLeads)

LET ReviewNetworkFields <= SELECT *,
  regex_replace(source=Laddr,re='''^\[|\]$''',replace="") AS ReviewLocalIP,
  regex_replace(source=Raddr,re='''^\[|\]$''',replace="") AS ReviewPeerIP,
  ConnStatus =~ '''(?i)^LISTEN(ING)?$''' AS ReviewListening,
  ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$''' AS ReviewEstablished,
  ProcName =~ '''(?i)^(ssh|scp|sftp|rsync|rclone|curl|wget|nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS ReviewAdministrativeTool
FROM NetworkResults
LET ReviewNetworkSignals <= SELECT *,
  (ReviewListening AND cidr_contains(ip=ReviewLocalIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewLocalIP,ranges=["127.0.0.0/8","::1/128"])) AS NonLoopbackListener,
  (ReviewEstablished AND ReviewAdministrativeTool
    AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["127.0.0.0/8","::1/128","0.0.0.0/8","::/128"])) AS AdministrativeConnection,
  (ReviewEstablished AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fe80::/10","ff00::/8"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=ReviewInternalCIDRs)) AS PeerOutsideConfiguredNetworks
FROM ReviewNetworkFields
LET NetworkReviewLeads <= SELECT ClientId,Fqdn,"Network" AS Category,
  "review_socket_role" AS SignalId,"Listener or established peer for role and administration review" AS Indicator,
  0 AS FindingWeight,
  if(condition=AdministrativeConnection OR PeerOutsideConfiguredNetworks,then=2,else=1) AS ReviewPriority,
  dict(Pid=Pid,Name=ProcName,Username=ProcUsername) AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,CallChain=CallChain,
    NonLoopbackListener=NonLoopbackListener,AdministrativeConnection=AdministrativeConnection,
    PeerOutsideConfiguredNetworks=PeerOutsideConfiguredNetworks) AS Evidence4,
  format(format="%v|review_socket|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,Pid,Laddr,Lport,Raddr,Rport,ConnStatus,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this process need this listening address or peer for its approved service or administrative task?" AS Hypothesis,
  "Identify service and destination owners; confirm intended exposure and peer; correlate with the process and approved task" AS SuggestedChecks,
  "Established sockets do not establish initiation direction. Wildcard listening does not prove Internet reachability; configured CIDRs are not a reputation check" AS ObservationLimit,
  "LTH - 05 / LTH - 04" AS RecommendedNotebook
FROM ReviewNetworkSignals
WHERE NonLoopbackListener OR AdministrativeConnection OR PeerOutsideConfiguredNetworks

LET ReviewServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(ssh|sshd|xrdp|xrdp-sesman|vncserver|tigervnc|telnet|rsh)([-.@][^ ]*)?\.service$''' AS RemoteAccessService,
  ServiceUnit =~ '''(?i)^(docker|containerd|crio|cri-o|podman|kubelet)([-.@][^ ]*)?\.service$''' AS ContainerService,
  ServiceUnit =~ '''(?i)^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|postgres|redis|redis-server|mongod|mongodb|elasticsearch)([-.@][^ ]*)?\.service$''' AS ApplicationDataService,
  ServiceUnit =~ '''(?i)^(nfs|nfs-server|rpcbind|smb|smbd|nmb|nmbd|vsftpd|proftpd|pure-ftpd)([-.@][^ ]*)?\.service$''' AS FileSharingService
FROM ServiceFields
LET ActiveServiceLeads <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "review_active_service_role" AS SignalId,"Active access, application, container or file-sharing service" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(RemoteAccessService=RemoteAccessService,ContainerService=ContainerService,
    ApplicationDataService=ApplicationDataService,FileSharingService=FileSharingService) AS Evidence4,
  format(format="%v|review_service|%v|%v|%v",args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this active service required for the host role and is its access or data exposure intended?" AS Hypothesis,
  "Confirm the service owner and purpose; inspect related listeners; collect unit configuration only for the selected hypothesis" AS SuggestedChecks,
  "Observed loaded service state and naming only; no ExecStart, enablement, installed-package ownership or exposure proof" AS ObservationLimit,
  "LTH - 04 / LTH - 05 / LTH - 12" AS RecommendedNotebook
FROM ReviewServiceSignals
WHERE ServiceLoad="loaded" AND ServiceActive="active"
  AND (RemoteAccessService OR ContainerService OR ApplicationDataService OR FileSharingService)

LET ReviewPlatforms <= SELECT ClientId,
  (TextOrEmpty(X=get(item=scope(),field="Platform")) || "Unknown") AS ReviewCohort
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET ReviewPlatformIndex <= memoize(query={SELECT * FROM ReviewPlatforms},key="ClientId")

-- Denominator is distinct clients that returned usable rows for this source,
-- not all 16 scoped clients when some source results are missing.
LET ReviewSourceClients <= SELECT * FROM chain(
  processes={SELECT ClientId,"Process executable" AS Family FROM ProcessFields WHERE ProcExe!="" GROUP BY ClientId},
  services={SELECT ClientId,"Service unit" AS Family FROM ServiceFields WHERE ServiceUnit!="" GROUP BY ClientId},
  users={SELECT ClientId,"Shell account" AS Family FROM UserFields WHERE UserName!="" GROUP BY ClientId},
  cron={SELECT ClientId,"Cron command" AS Family FROM CronResults GROUP BY ClientId}
)
LET ReviewSourceCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewSourceClients
LET ReviewCoverage <= SELECT Family,ReviewCohort,count() AS CoveredHosts,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewSourceCohorts GROUP BY CohortKey
LET ReviewCoverageIndex <= memoize(query={SELECT * FROM ReviewCoverage},key="CohortKey")

LET ReviewObservations <= SELECT * FROM chain(
  processes={SELECT ClientId,Fqdn,"Processes" AS Category,"Process executable" AS Family,
    regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS Entity,
    "LTH.SystemBaseline/Processes" AS ObservationSource FROM ProcessFields WHERE ProcExe!=""},
  services={SELECT ClientId,Fqdn,"Services and Persistence" AS Category,"Service unit" AS Family,
    ServiceUnit AS Entity,"LTH.SystemBaseline/Services" AS ObservationSource FROM ServiceFields WHERE ServiceUnit!=""},
  users={SELECT ClientId,Fqdn,"Users and Privileges" AS Category,"Shell account" AS Family,
    UserName+"|"+UserShell AS Entity,"LTH.SystemBaseline/Users" AS ObservationSource
    FROM UserFields WHERE UserUid!="0" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$'''},
  cron={SELECT ClientId,Fqdn,"Persistence" AS Category,"Cron command" AS Family,
    CronUser+"|"+CronCommand AS Entity,"LTH.SystemBaseline/Crontab" AS ObservationSource FROM CronResults}
)
LET ReviewObservedCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewObservations
LET ReviewUniqueHostEntities <= SELECT *,
  format(format="%v|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS HostEntityKey,
  format(format="%v|%v|%v",args=[ReviewCohort,Family,Entity]) AS PrevalenceKey,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewObservedCohorts GROUP BY HostEntityKey
LET ReviewPrevalence <= SELECT PrevalenceKey,count() AS HostsWithEntity
FROM ReviewUniqueHostEntities GROUP BY PrevalenceKey
LET ReviewPrevalenceIndex <= memoize(query={SELECT * FROM ReviewPrevalence},key="PrevalenceKey")
LET ReviewPrevalenceRows <= SELECT *,
  get(item=ReviewCoverageIndex,field=CohortKey).CoveredHosts AS CoveredHosts,
  get(item=ReviewPrevalenceIndex,field=PrevalenceKey).HostsWithEntity AS HostsWithEntity
FROM ReviewUniqueHostEntities
LET RareBaselineLeads <= SELECT ClientId,Fqdn,Category,
  "review_low_prevalence" AS SignalId,"Low-prevalence baseline entity in the observed platform cohort" AS Indicator,
  0 AS FindingWeight,2 AS ReviewPriority,Family AS Evidence1,Entity AS Evidence2,
  dict(PlatformCohort=ReviewCohort,HostsWithEntity=HostsWithEntity,CoveredHosts=CoveredHosts) AS Evidence3,
  "Compare approved roles before treating rarity as an anomaly; do not interpret as newly created" AS Evidence4,
  format(format="%v|review_prevalence|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS EvidenceKey,
  ObservationSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this uncommon executable, unit, account or scheduled command explained by this host's approved role?" AS Hypothesis,
  "Compare with hosts having the same business role; identify owner and deployment purpose; inspect related baseline evidence" AS SuggestedChecks,
  "One-Hunt prevalence among clients with source rows. Platform is not a business-role cohort; exact cron commands may contain host-specific values" AS ObservationLimit,
  "LTH - 01 / the notebook for the observed family" AS RecommendedNotebook
FROM ReviewPrevalenceRows
WHERE ReviewCohort!="Unknown" AND CoveredHosts>=ReviewMinCohortHosts
  AND HostsWithEntity<=ReviewMaxRareHosts
  AND (HostsWithEntity * 100)<= (CoveredHosts * ReviewMaxRarePercent)

LET AdditionalReviewCandidates <= SELECT * FROM chain(
  admin=AdministrativeProcessLeads,account_cron=AccountScheduledLeads,
  network=NetworkReviewLeads,services=ActiveServiceLeads,prevalence=RareBaselineLeads
)
LET EnhancedEvidenceCandidates <= SELECT * FROM chain(existing=AllEvidence,review=AdditionalReviewCandidates)
LET EnhancedEvidence <= SELECT *,
  if(condition=FindingWeight>0,then="Risk Indicator",else="Hunt Lead") AS EvidenceKind,
  "Unreviewed" AS ReviewState,
  if(condition=FindingWeight>=4,then=3,else=if(condition=FindingWeight>0,then=2,
    else=(get(item=scope(),field="ReviewPriority") || 1))) AS ReviewPriority,
  (get(item=scope(),field="SuggestedChecks") || Hypothesis) AS SuggestedChecks
FROM EnhancedEvidenceCandidates GROUP BY EvidenceKey

LET HuntLeadSummary <= SELECT ClientId,count() AS HuntLeadCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority
FROM EnhancedEvidence GROUP BY ClientId
LET HuntLeadIndex <= memoize(query={SELECT * FROM HuntLeadSummary},key="ClientId")
LET FirstHuntLead(C) = SELECT Hypothesis FROM EnhancedEvidence WHERE ClientId=C ORDER BY ReviewPriority DESC LIMIT 1

LET EvidenceAreas <= SELECT ClientId,Fqdn,Category,
  max(item=FindingWeight) AS Weight,
  sum(item=if(condition=FindingWeight>0,then=1,else=0)) AS EvidenceCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM EnhancedEvidence GROUP BY AreaKey

SELECT ClientId,Fqdn,Category AS HuntingArea,
  if(condition=Weight>0,then="Risk indicators and available review leads",else="Review leads available; no scored indicator in this area") AS Indicator,
  if(condition=Weight=5,then="Critical",else=if(condition=Weight=4,then="High",
    else=if(condition=Weight=3,then="Medium",else=if(condition=Weight>0,then="Low",else="Review")))) AS Severity,
  Weight AS ScoreContribution,EvidenceCount AS FindingCount,ReviewLeadCount,HighestReviewPriority
FROM EvidenceAreas ORDER BY Fqdn

```

## Cell 30 (markdown)

# Triage Findings Detail

Displays the raw evidence behind each investigation candidate. Analysts must validate the process, command, account, service, network endpoint, or Cron entry before classifying the result as malicious or benign.

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET TextOrEmpty(X) = if(condition=X=NULL,then="",else=str(str=X))
-- Keep this FALSE on the production server, consistently in all cells.
LET EnableLabIndicators <= FALSE


LET Fleet <= SELECT ClientId,Fqdn,"Coverage" AS Category,"Basic information source returned rows" AS Indicator,
  0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET UserFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="Description")) AS UserDescription,
       TextOrEmpty(X=get(item=scope(), member="Uid")) AS UserUid,
       TextOrEmpty(X=get(item=scope(), field="Gid")) AS UserGid,
       TextOrEmpty(X=get(item=scope(), field="Shell")) AS UserShell,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       TextOrEmpty(X=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)


LET UserMatches <=
SELECT *,
       format(
         format="%v|uid0|%v|%v",
         args=[ClientId, UserName, HomeDir]
       ) AS EvidenceKey,
       5 AS FindingWeight
FROM UserFields
WHERE UserUid = "0"
  AND NOT UserName =~ '''^root$'''
  AND NOT (
    UserName = ""
    AND HomeDir = "/root"
  )

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       get(item=scope(),field="Hash") AS ProcHash,
       TextOrEmpty(X=(get(item=scope(), field="FlowId") || get(item=scope(), field="_FlowId"))) AS RowFlowId,
       get(item=scope(), field="Deleted") AS ProcDeleted,
       get(item=scope(), field="CreatedTime") AS ProcCreatedTime,
       TextOrEmpty(X=get(item=scope(), field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       TextOrEmpty(X=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       TextOrEmpty(X=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=scope(), member="CommandLine")
         ||
         get(item=scope(), member="Cmdline")
         ||
         get(item=scope(), member="cmdline")
         ||
         get(item=scope(), member="Command")
       )) AS ProcCommandLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET ProcessSignals <=
SELECT *,
       ProcCommandLine =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       ProcCommandLine =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       ProcExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer,
       ProcExe =~ '''(?i)^/run/user/[0-9]+/''' AS UserRuntimeExecution,
       (ProcName =~ '''(?i)^(xmrig|minerd|kinsing|kdevtmpfsi)$'''
        OR ProcCommandLine =~ '''(?i)(xmrig|stratum\+tcp)''') AS MiningPattern
FROM ProcessFields


LET ProcessMatches <=
SELECT *,
       format(
         format="%v|process|%v|%v|%v",
         args=[ClientId, ProcPid, ProcExe, ProcCommandLine]
       ) AS EvidenceKey,

       if(
         condition=DownloadPipeShell
                   OR DecodePipeShell
                   OR NetcatExec
                   OR SocatExec
                   OR DevTcpShell,
         then=5,
         else=if(
           condition=WritablePathExe
                     OR WritablePathExecution
                     OR MiningPattern
                     OR (UserRuntimeExecution AND PythonHTTPServer),
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool
                       OR UserRuntimeExecution,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ProcessSignals
WHERE DownloadPipeShell
   OR DecodePipeShell
   OR NetcatExec
   OR SocatExec
   OR DevTcpShell
   OR WritablePathExe
   OR WritablePathExecution
   OR NetcatTool
   OR SocatTool
   OR PythonHTTPServer
   OR UserRuntimeExecution
   OR MiningPattern


LET ServiceFields <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=Unit) AS ServiceUnit,TextOrEmpty(X=Description) AS ServiceDescription,
  TextOrEmpty(X=Load) AS ServiceLoad,TextOrEmpty(X=Active) AS ServiceActive,TextOrEmpty(X=Sub) AS ServiceSub
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Services")

LET ServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(kinsing|xmrig|kdevtmpfsi|watchbog)([-_.@][a-z0-9_.@-]+)?\.service$''' AS ThreatAssociatedName,
  ServiceDescription =~ '''(?i)(cryptocurrency[ -](miner|mining)|reverse[ -]shell|backdoor[ -]service|unauthorized[ -]remote[ -]access)''' AS HighRiskDescription,
  (EnableLabIndicators AND
   (ServiceUnit =~ '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
    OR ServiceDescription =~ '''(?i)(lab persistence|temporary update service|remote support lab)''')) AS KnownLabService
FROM ServiceFields

LET ServiceMatches <= SELECT *,
  format(format="%v|service|%v|%v|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceDescription,ServiceLoad,ServiceActive,ServiceSub]) AS EvidenceKey,
  if(condition=ThreatAssociatedName,then=5,else=4) AS FindingWeight
FROM ServiceSignals
WHERE ThreatAssociatedName OR HighRiskDescription OR KnownLabService

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(),field="CallChain")) AS RawCallChain,
       TextOrEmpty(X=get(item=scope(), member="Laddr")) AS Laddr,
       TextOrEmpty(X=get(item=scope(), member="Lport")) AS Lport,
       TextOrEmpty(X=get(item=scope(), member="Raddr")) AS Raddr,
       TextOrEmpty(X=get(item=scope(), member="Rport")) AS Rport,
       TextOrEmpty(X=get(item=scope(), member="Pid")) AS Pid,
       TextOrEmpty(X=get(item=scope(), member="Status")) AS ConnStatus,
       get(item=scope(), member="ProcInfo") AS ProcInfo
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET NetworkResults <=
SELECT ClientId,
       Fqdn,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ConnStatus,
       RawCallChain AS CallChain,
       TextOrEmpty(X=get(item=ProcInfo,field="Username")) AS ProcUsername,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       TextOrEmpty(X=(
         get(item=ProcInfo, member="CommandLine")
         ||
         get(item=ProcInfo, member="cmdline")
       )) AS ProcCommandLine
FROM NetworkFields


LET NetworkSignals <=
SELECT *,
       ConnStatus =~ '''(?i)^(LISTEN|LISTENING)$'''
         AS IsListening,

       ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$'''
         AS IsEstablished,

       Laddr =~ '''^(127\.|::1$|\[::1\]$)'''
         AS LoopbackBind,

       Lport =~ '''^(4444|5555)$'''
         AS HighRiskPort,

       ProcExe =~ '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExe,

       (
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ProcCommandLine =~
           '''(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS WritablePathExecution,

       (
         ProcName =~ '''(?i)^(nc|ncat)$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)(nc|ncat)(\s|$)'''
       ) AS NetcatTool,

       (
         ProcName =~ '''(?i)^socat$'''
         OR
         ProcCommandLine =~
           '''(?i)(^|\s|/)socat(\s|$)'''
       ) AS SocatTool,

       ProcCommandLine =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       ProcCommandLine =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       ProcCommandLine =~
         '''(?i)python[0-9.]*\s+-m\s+(http\.server|SimpleHTTPServer)(\s|$)'''
         AS PythonHTTPServer
FROM NetworkResults


LET ClassifiedNetwork <=
SELECT *,
       NetcatExec
       OR SocatExec
         AS CommandExecutionSocket,

       (
         (IsListening OR IsEstablished)
         AND
         (WritablePathExe OR WritablePathExecution)
       ) AS WritablePathSocket,

       (
         IsListening
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolListener,

       (
         IsEstablished
         AND
         (NetcatTool OR SocatTool)
       ) AS NetworkToolConnection,

       (
         IsListening
         AND
         PythonHTTPServer
       ) AS PythonListener,

       (
         IsListening
         AND
         HighRiskPort
         AND
         NOT LoopbackBind
       ) AS RiskyPortListener
FROM NetworkSignals


LET NetworkMatches <=
SELECT *,
       format(
         format="%v|network|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           Pid,
           Laddr,
           Lport,
           Raddr,
           Rport,
           ConnStatus
         ]
       ) AS EvidenceKey,

       if(
         condition=CommandExecutionSocket,
         then=5,
         else=if(
           condition=WritablePathSocket
                     OR (
                       PythonListener
                       AND RiskyPortListener
                     ),
           then=4,
           else=if(
             condition=NetworkToolListener
                       OR NetworkToolConnection,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ClassifiedNetwork
WHERE CommandExecutionSocket
   OR WritablePathSocket
   OR NetworkToolListener
   OR NetworkToolConnection
   OR PythonListener
   OR RiskyPortListener

LET CronFields <=
SELECT ClientId,
       Fqdn,
       TextOrEmpty(X=get(item=scope(), member="User")) AS CronUser,
       TextOrEmpty(X=get(item=scope(), member="Event")) AS CronEvent,
       TextOrEmpty(X=get(item=scope(), member="Minute")) AS Minute,
       TextOrEmpty(X=get(item=scope(), member="Hour")) AS Hour,
       TextOrEmpty(X=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       TextOrEmpty(X=get(item=scope(), member="Month")) AS Month,
       TextOrEmpty(X=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       TextOrEmpty(X=get(item=scope(), member="Path")) AS CronPath,
       TextOrEmpty(X=get(item=scope(), field="Command")) AS CommandValue,
       TextOrEmpty(X=get(item=scope(), field="RawLine")) AS CronRawLine,
       TextOrEmpty(X=get(item=scope(), field="ParseStatus")) AS CronParseStatus,
       get(item=scope(), field="ParserVersion") AS CronParserVersion,
       TextOrEmpty(X=get(item=scope(), field="Content")) AS CronContent,
       get(item=scope(), field="PotentiallyTruncated") AS CronPotentiallyTruncated
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)


LET CronResults <=
SELECT ClientId,
       Fqdn,
       CronUser,
       CronEvent,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       CronPath,
       CronRawLine,CronParseStatus,CronParserVersion,
       CommandValue AS CronCommand
FROM CronFields
WHERE CommandValue != "" AND CronParseStatus != "Unparsed"


LET CronSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM CronResults


LET ClassifiedCron <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM CronSignals


LET ScoredCron <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedCron


LET CronMatches <=
SELECT *,
       format(
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
           CronUser,
           CronEvent,
           Minute,
           Hour,
           DayOfMonth,
           Month,
           DayOfWeek,
           CronCommand
         ]
       ) AS EvidenceKey,

       if(
         condition=CriticalCommand,
         then=5,
         else=if(
           condition=WritablePathExecution
                     OR RepeatedRemoteFetch,
           then=4,
           else=if(
             condition=InlineInterpreter,
             then=3,
             else=2
           )
         )
       ) AS FindingWeight
FROM ScoredCron
WHERE CriticalCommand
   OR WritablePathExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter
   OR ScheduledRemoteFetch


LET UserDetail <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_additional_uid0" AS SignalId,"Additional UID 0 account" AS Indicator,
  FindingWeight,EvidenceKey,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,HomeDir AS Evidence3,UserShell AS Evidence4,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this additional UID 0 identity authorized for this server?" AS Hypothesis,
  "Passwd configuration only; no proof of login or privilege use" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook,
  UserName AS User,UserDescription AS Description,UserUid AS Uid,UserGid AS Gid,
  HomeDir AS Homedir,UserShell AS Shell
FROM UserMatches

LET ProcessDetail <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_behavior" AS SignalId,
  if(condition=DownloadPipeShell,then="Downloaded content piped to a shell",
    else=if(condition=DecodePipeShell,then="Decoded content piped to a shell",
      else=if(condition=NetcatExec OR SocatExec OR DevTcpShell,then="Command contains a shell/socket execution pattern",
        else=if(condition=MiningPattern,then="Mining-related name or command pattern",
          else=if(condition=WritablePathExe OR WritablePathExecution,then="Execution from a temporary path",
            else=if(condition=UserRuntimeExecution,then="Execution from a user runtime path",
              else=if(condition=NetcatTool OR SocatTool,then="Network utility in process command",
                else="Python HTTP server command"))))))) AS Indicator,
  FindingWeight,EvidenceKey,dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Name=ProcName,Hash=ProcHash,FlowId=RowFlowId,DownloadPipeShell=DownloadPipeShell,DecodePipeShell=DecodePipeShell,
    NetcatExec=NetcatExec,SocatExec=SocatExec,DevTcpShell=DevTcpShell,MiningPattern=MiningPattern,
    WritablePathExe=WritablePathExe,WritablePathExecution=WritablePathExecution,
    UserRuntimeExecution=UserRuntimeExecution,NetcatTool=NetcatTool,SocatTool=SocatTool,
    PythonHTTPServer=PythonHTTPServer) AS Evidence4,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate executable origin, server role and whether this command was authorized" AS Hypothesis,
  "Command/name regex on a process snapshot; not a shell parser or confirmation of compromise" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook,
  ProcPid AS Pid,ProcPpid AS Ppid,ProcName AS Name,ProcExe AS Exe,ProcCommandLine AS CommandLine,
  ProcUsername AS Username,ProcHash AS Hash
FROM ProcessMatches

LET ServiceDetail <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_service_name_description" AS SignalId,
  if(condition=ThreatAssociatedName,then="Service name matches a threat-associated watchlist",
    else=if(condition=HighRiskDescription,then="Service description matches suspicious terminology",
      else="Explicitly enabled lab service indicator")) AS Indicator,
  FindingWeight,EvidenceKey,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(ThreatAssociatedName=ThreatAssociatedName,HighRiskDescription=HighRiskDescription,KnownLabService=KnownLabService) AS Evidence4,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this service name/description correspond to an unauthorized installed service?" AS Hypothesis,
  "Only name, description and state are available. Priority weight is not confidence; collect the unit and executable to validate" AS ObservationLimit,
  "LTH - 04 / LTH - 06" AS RecommendedNotebook,
  ServiceUnit AS Unit,ServiceDescription AS Description,ServiceLoad AS Load,
  ServiceActive AS Active,ServiceSub AS Sub
FROM ServiceMatches

LET NetworkDetail <= SELECT ClientId,Fqdn,"Network" AS Category,
  "baseline_process_socket" AS SignalId,
  if(condition=CommandExecutionSocket,then="Socket-owning process has a command execution pattern",
    else=if(condition=WritablePathSocket,then="Active socket with temporary-path execution context",
      else=if(condition=NetworkToolListener OR NetworkToolConnection,then="Network utility listener or connection",
        else=if(condition=PythonListener,then="Python HTTP listener",else="Non-loopback listener on a configured review port")))) AS Indicator,
  FindingWeight,EvidenceKey,Pid AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,
    Username=ProcUsername,CallChain=CallChain,
    CommandExecutionSocket=CommandExecutionSocket,WritablePathSocket=WritablePathSocket,
    NetworkToolListener=NetworkToolListener,NetworkToolConnection=NetworkToolConnection,
    PythonListener=PythonListener,RiskyPortListener=RiskyPortListener) AS Evidence4,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this socket, associated command and peer expected for this host role?" AS Hypothesis,
  "Socket snapshot; a port number does not identify a protocol or prove command-and-control" AS ObservationLimit,
  "LTH - 05 - Network Connections Dashboard" AS RecommendedNotebook,
  Laddr,Lport,Raddr,Rport,Pid,ConnStatus AS Status,ProcName,ProcExe,ProcCommandLine,ProcUsername,CallChain
FROM NetworkMatches

LET CronDetail <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_command" AS SignalId,
  if(condition=CriticalCommand,then="Cron declares a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron declares execution from a temporary path",
      else=if(condition=RepeatedRemoteFetch,then="Cron declares remote fetch at reboot or every minute",
        else=if(condition=InlineInterpreter,then="Cron declares inline interpreter code",else="Cron declares remote fetch")))) AS Indicator,
  FindingWeight,EvidenceKey,CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParseStatus=CronParseStatus,ParserVersion=CronParserVersion,
    CriticalCommand=CriticalCommand,WritablePathExecution=WritablePathExecution,
    RepeatedRemoteFetch=RepeatedRemoteFetch,InlineInterpreter=InlineInterpreter,ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this scheduled command authorized and is there separate evidence it executed?" AS Hypothesis,
  "Declared command only; legacy parser rows may be incomplete. No cron runtime or complete shell semantics" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook,
  CronUser,CronPath,CronCommand,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek
FROM CronMatches

LET AccountSignals <= SELECT *,
  UserShell =~ '''^/(tmp|var/tmp|dev/shm)/''' AS TemporaryShell,
  (UserName="root" AND HomeDir =~ '''^/(tmp|var/tmp|dev/shm)/''') AS TemporaryRootHome,
  (UserGid="0" AND UserUid!="0" AND UserUid!="") AS PrimaryRootGroup,
  (UserName =~ '''^(www-data|apache|nginx|mysql|mariadb|postgres|redis|memcached|nobody)$'''
   AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS ServiceInteractiveShell
FROM UserFields

LET AccountMatches <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "baseline_account_configuration" AS SignalId,
  if(condition=TemporaryShell,then="Account declares a shell under a temporary directory",
    else=if(condition=TemporaryRootHome,then="Root account declares a temporary home directory",
      else=if(condition=PrimaryRootGroup,then="Non-root UID has primary GID 0",
        else="Named service account has an interactive shell"))) AS Indicator,
  if(condition=TemporaryShell,then=4,else=if(condition=TemporaryRootHome,then=3,else=2)) AS FindingWeight,
  UserName AS Evidence1,dict(Uid=UserUid,Gid=UserGid) AS Evidence2,
  UserShell AS Evidence3,dict(Home=HomeDir,TemporaryShell=TemporaryShell,
    TemporaryRootHome=TemporaryRootHome,PrimaryRootGroup=PrimaryRootGroup,
    ServiceInteractiveShell=ServiceInteractiveShell) AS Evidence4,
  format(format="%v|account_config|%v|%v|%v|%v|%v",
    args=[ClientId,UserName,UserUid,UserGid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate account role and whether this shell, group or home was authorized" AS Hypothesis,
  "Configuration snapshot; does not establish a login or privilege use" AS ObservationLimit,
  "LTH - 02 - Users Groups and Privileges Dashboard" AS RecommendedNotebook
FROM AccountSignals
WHERE TemporaryShell OR TemporaryRootHome OR PrimaryRootGroup OR ServiceInteractiveShell

LET ProcessExtraFields <= SELECT *,
  format(format="%v|%v|%v",args=[ClientId,RowFlowId,ProcPid]) AS ProcessLookupKey,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS CleanExe,
  (ProcDeleted=TRUE OR ProcExe =~ '''\(deleted\)$''') AS IsDeleted,
  ProcExe =~ '''^/?memfd:''' AS IsMemfd
FROM ProcessFields

LET ProcessIndex <= memoize(query={SELECT * FROM ProcessExtraFields},key="ProcessLookupKey")
LET ProcessWithParent <= SELECT *,
  get(item=ProcessIndex,field=format(format="%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPpid])) AS ParentProcess
FROM ProcessExtraFields

LET NewProcessSignals <= SELECT *,
  (ParentProcess.ProcName =~ '''^(nginx|apache2|httpd|php-fpm[0-9.]*|uwsgi|gunicorn[0-9.: -]*)$'''
   AND CleanExe =~ '''/(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php[0-9.]*)$'''
   AND ProcPpid!="0" AND ProcPpid!="") AS WebServiceChild,
  (CleanExe =~ '''/ssh$'''
   AND ProcCommandLine =~ '''(^|\s)(-(R|D)(\s|[0-9*\[:/])|-o\s*(RemoteForward|DynamicForward)\s*=)''') AS SSHForwarding
FROM ProcessWithParent

LET ExtraProcessMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_process_context" AS SignalId,
  if(condition=IsMemfd,then="Process executable is backed by memfd",
    else=if(condition=WebServiceChild,then="Shell or interpreter has a web-service parent in this snapshot",
      else=if(condition=SSHForwarding,then="SSH process declares remote or dynamic forwarding",
        else="Process executable is marked deleted"))) AS Indicator,
  if(condition=IsMemfd,then=4,else=if(condition=WebServiceChild,then=3,else=2)) AS FindingWeight,
  dict(Pid=ProcPid,Ppid=ProcPpid,Username=ProcUsername,CreatedTime=ProcCreatedTime) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Deleted=IsDeleted,Memfd=IsMemfd,SSHForwarding=SSHForwarding,
    WebServiceChild=WebServiceChild,ParentName=ParentProcess.ProcName,
    ParentExe=ParentProcess.ProcExe,ParentCommandLine=ParentProcess.ProcCommandLine,
    FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|process_context|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the executable, parent application behavior and authorized forwarding or updates" AS Hypothesis,
  "Snapshot correlation; not historical process-creation evidence. Deleted binaries can follow normal updates" AS ObservationLimit,
  "LTH - 04 - Processes and Services Dashboard" AS RecommendedNotebook
FROM NewProcessSignals
WHERE IsMemfd OR WebServiceChild OR SSHForwarding OR IsDeleted

LET CronScriptFiles <= SELECT ClientId,Fqdn,
  TextOrEmpty(X=get(item=scope(),field="OSPath")) AS ScriptPath,
  TextOrEmpty(X=get(item=scope(),field="Content")) AS ScriptContent,
  get(item=scope(),field="Mtime") AS ScriptMtime,
  get(item=scope(),field="FileSize") AS ScriptFileSize,
  get(item=scope(),field="ContentLimit") AS ScriptContentLimit,
  get(item=scope(),field="PotentiallyTruncated") AS ScriptPotentiallyTruncated
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Crontab")
WHERE ScriptPath!="" AND ScriptContent!=""

LET ScriptResults <= SELECT * FROM foreach(row=CronScriptFiles,query={
  SELECT ClientId,Fqdn,ScriptPath,ScriptMtime,ScriptFileSize,ScriptContentLimit,ScriptPotentiallyTruncated,
    _value AS CronCommand,(_key + 1) AS ScriptLineNumber,"" AS CronEvent,"" AS Minute,"" AS Hour
  FROM items(item=split(string=ScriptContent,sep="\n"))
})
WHERE NOT CronCommand =~ '''^\s*(#|$)'''

LET ScriptSignals <=
SELECT *,
       CronCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExec,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExec,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
       ) AS InlineInterpreter,

       CronCommand =~
         '''(?i)(^|[;&|]\s*|\s)(/usr/bin/|/bin/)?(curl|wget)(\s|$)[^\r\n]{0,1000}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       CronEvent =~ '''(?i)^@reboot$'''
         AS AtReboot,

       (
         Minute =~ '''^(\*|\*/1)$'''
         AND
         Hour = "*"
       ) AS EveryMinute
FROM ScriptResults


LET ClassifiedScript <=
SELECT *,
       DirectWritableExecution
       OR InterpretedWritableExecution
         AS WritablePathExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           DirectWritableExecution
           OR InterpretedWritableExecution
         )
       ) AS DownloadThenWritableExecution,

       (
         ScheduledRemoteFetch
         AND
         (
           AtReboot
           OR EveryMinute
         )
       ) AS RepeatedRemoteFetch
FROM ScriptSignals


LET ScoredScript <=
SELECT *,
       DownloadPipeShell
       OR DecodePipeShell
       OR NetcatExec
       OR SocatExec
       OR DevTcpShell
       OR DownloadThenWritableExecution
         AS CriticalCommand
FROM ClassifiedScript



LET CronScriptMatches <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "baseline_cron_script_content" AS SignalId,
  if(condition=CriticalCommand,then="Cron script line contains a shell/socket or download-execution pattern",
    else=if(condition=WritablePathExecution,then="Cron script line declares temporary-path execution",
      else=if(condition=InlineInterpreter,then="Cron script line declares inline interpreter code",
        else="Cron script line declares remote fetch"))) AS Indicator,
  if(condition=CriticalCommand,then=5,else=if(condition=WritablePathExecution,then=4,
    else=if(condition=InlineInterpreter,then=3,else=2))) AS FindingWeight,
  ScriptPath AS Evidence1,ScriptLineNumber AS Evidence2,CronCommand AS Evidence3,
  dict(Mtime=ScriptMtime,FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated,CriticalCommand=CriticalCommand,
    WritablePathExecution=WritablePathExecution,InlineInterpreter=InlineInterpreter,
    ScheduledRemoteFetch=ScheduledRemoteFetch) AS Evidence4,
  format(format="%v|cron_script|%v|%v|%v",args=[ClientId,ScriptPath,ScriptLineNumber,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script invoked by cron/run-parts, and is the declared behavior authorized?" AS Hypothesis,
  "Content prefix and line regex only; comments skipped, but strings/dead code may match. Existence does not prove execution" AS ObservationLimit,
  "LTH - 06 - Persistence Mechanisms Dashboard" AS RecommendedNotebook
FROM ScoredScript
WHERE CriticalCommand OR WritablePathExecution OR InlineInterpreter OR ScheduledRemoteFetch

LET MountFields <= SELECT ClientId,Fqdn,Device,Mount,FSType,Options,
  TextOrEmpty(X=(get(item=scope(),field="FlowId") || get(item=scope(),field="_FlowId"))) AS MountFlowId,
  regex_replace(source=TextOrEmpty(X=Mount),re="/+$",replace="") AS MountPrefix
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Mounts")

-- Resolve the longest matching mount, including normal nested mounts.
-- Encoded mount paths require decoding before they can be correlated safely.
LET MountFor(C,F,E) = SELECT *,len(list=MountPrefix) AS PrefixLength
FROM MountFields
WHERE ClientId=C AND MountFlowId=F AND TextOrEmpty(X=Mount)!=""
  AND NOT TextOrEmpty(X=Mount) =~ '''\\[0-7]{3}'''
  AND (E=MountPrefix OR split(string=E,sep_string=MountPrefix+"/")[0]="")
ORDER BY PrefixLength DESC LIMIT 1

LET MountProcessPaths <= SELECT *,
  regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS ExecutablePath
FROM ProcessFields
WHERE ProcExe =~ '''^/(mnt|media|home|srv|opt|run/user)/'''

LET ExecutableMounts <= SELECT *,
  MountFor(C=ClientId,F=RowFlowId,E=ExecutablePath)[0] AS BackingMount
FROM MountProcessPaths
WHERE NOT ExecutablePath =~ '''[\s\\]'''

LET MountExecutionMatches <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "baseline_network_mount_execution" AS SignalId,
  "Process executable path resolves to a network filesystem in this snapshot" AS Indicator,
  2 AS FindingWeight,dict(Pid=ProcPid,Ppid=ProcPpid) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(Mount=BackingMount.Mount,Device=BackingMount.Device,FSType=BackingMount.FSType,
    Options=BackingMount.Options,SupportingArtifact="LTH.SystemBaseline/Mounts",FlowId=RowFlowId) AS Evidence4,
  format(format="%v|%v|mounted_exe|%v|%v|%v",
    args=[ClientId,RowFlowId,ProcPid,ProcExe,BackingMount.Mount]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is executable code on this network share expected for this server role?" AS Hypothesis,
  "Path-based, non-atomic snapshot correlation; process mount namespaces and mounts may differ" AS ObservationLimit,
  "LTH - 01 / LTH - 04" AS RecommendedNotebook
FROM ExecutableMounts
WHERE BackingMount.FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountContext <= SELECT ClientId,Fqdn,"Mount Review" AS Category,
  "baseline_network_mount_inventory" AS SignalId,
  "Network filesystem available for hypothesis review" AS Indicator,
  0 AS FindingWeight,Mount AS Evidence1,Device AS Evidence2,FSType AS Evidence3,
  dict(Options=Options,FlowId=MountFlowId) AS Evidence4,
  format(format="%v|%v|mount_context|%v|%v",args=[ClientId,MountFlowId,Mount,Device]) AS EvidenceKey,
  "LTH.SystemBaseline/Mounts" AS SourceArtifact,HuntId AS SourceHuntId,
  "Validate the share owner, purpose and which applications use it" AS Hypothesis,
  "Mount inventory alone has weight zero and does not establish malicious use" AS ObservationLimit,
  "LTH - 01 - System Baseline Dashboard" AS RecommendedNotebook
FROM MountFields WHERE FSType =~ '''^(nfs|nfs4|cifs|smb3|fuse\.sshfs)$'''

LET MountReview <= SELECT * FROM chain(execution=MountExecutionMatches,context=MountContext)

LET PackageRaw <= SELECT * FROM chain(
  debian={SELECT *,"Debian" AS PackageFamily,"LTH.SystemBaseline/DebianPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/DebianPackages")},
  rhel={SELECT *,"RHEL" AS PackageFamily,"LTH.SystemBaseline/RHELPackages" AS PackageSource
    FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/RHELPackages")}
)
LET PackageFields <= SELECT ClientId,Fqdn,PackageFamily,PackageSource,
  TextOrEmpty(X=(get(item=scope(),field="Package") || get(item=scope(),field="Name"))) AS PackageName,
  TextOrEmpty(X=get(item=scope(),field="Version")) AS PackageVersion,
  TextOrEmpty(X=(get(item=scope(),field="State") || get(item=scope(),field="Status"))) AS PackageState,
  TextOrEmpty(X=get(item=scope(),field="Repository")) AS PackageRepository
FROM PackageRaw
LET InstalledPackages <= SELECT *,
  regex_replace(source=PackageName,
    re='''(\.(x86_64|i[3-6]86|noarch|aarch64|armv[0-9]+[a-z]*|ppc64le|s390x)|:[a-z0-9_-]+)$''',replace="") AS NormalizedPackage
FROM PackageFields
WHERE PackageName!="" AND (PackageFamily="RHEL" OR PackageState IN ("installed","active"))
LET PackageContext <= SELECT ClientId,Fqdn,"Package Review" AS Category,
  "baseline_dual_use_package_inventory" AS SignalId,
  "Installed network, proxy or remote-access tooling for role review" AS Indicator,
  0 AS FindingWeight,PackageName AS Evidence1,PackageVersion AS Evidence2,
  dict(Family=PackageFamily,State=PackageState,Repository=PackageRepository) AS Evidence3,
  "Installed software inventory does not establish execution, compromise, file ownership or vulnerability" AS Evidence4,
  format(format="%v|package_context|%v|%v|%v",args=[ClientId,PackageSource,PackageName,PackageVersion]) AS EvidenceKey,
  PackageSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this tool expected for the server role, and do process/network findings show relevant use?" AS Hypothesis,
  "RHEL package names include architecture; removed Debian entries are excluded. No version-to-CVE inference" AS ObservationLimit,
  "LTH - 01 / LTH - 04 / LTH - 05" AS RecommendedNotebook
FROM InstalledPackages
WHERE NormalizedPackage =~ '''^(nmap|nmap-ncat|ncat|netcat|netcat-openbsd|netcat-traditional|socat|masscan|proxychains|proxychains4|chisel|ngrok|frp|frpc|frps|rclone|openssh-clients|openssh-client)$'''

LET SecurityServiceMatches <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "baseline_security_service_state" AS SignalId,
  "A listed logging/audit service has an inactive or failed state" AS Indicator,
  2 AS FindingWeight,ServiceUnit AS Evidence1,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence2,
  ServiceDescription AS Evidence3,
  "Review maintenance, configured logging architecture and service diagnostics" AS Evidence4,
  format(format="%v|security_service_state|%v|%v|%v",
    args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this observed service state expected, or has logging continuity been affected?" AS Hypothesis,
  "Only an existing row is evaluated; absence does not mean disabled. State does not establish tampering" AS ObservationLimit,
  "LTH - 04 / LTH - 08" AS RecommendedNotebook
FROM ServiceFields
WHERE ServiceLoad="loaded" AND ServiceUnit =~ '''^(auditd|rsyslog|systemd-journald)\.service$'''
  AND (ServiceActive IN ("failed","inactive") OR ServiceSub="failed")
LET SourceCoverage <=
SELECT *
FROM chain(
  users={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Users source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM UserFields
    GROUP BY ClientId
  },
  processes={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Processes source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ProcessFields
    GROUP BY ClientId
  },
  services={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Services source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM ServiceFields
    GROUP BY ClientId
  },
  network={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Network source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM NetworkFields
    GROUP BY ClientId
  },
  cron={
    SELECT ClientId,
           Fqdn,
           "Coverage" AS Category,
           "Cron source returned rows" AS Indicator,
           0 AS Weight,
           0 AS EvidenceCount,
           1 AS SourceCollected
    FROM CronFields
    WHERE CommandValue!="" OR CronContent!=""
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
LET InventoryPlatform <= SELECT ClientId,Fqdn,TextOrEmpty(X=get(item=scope(),field="Platform")) AS Platform
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET PlatformFamilies <= SELECT *,
  if(condition=Platform =~ '''(?i)^(ubuntu|debian|linuxmint|kali|raspbian|pop)$''',then="Debian",
    else=if(condition=Platform =~ '''(?i)^(alma|almalinux|rocky|rhel|redhat|red hat.*|centos|ol|oracle|oraclelinux|fedora)$''',then="RHEL",else="Unknown")) AS ExpectedPackageFamily
FROM InventoryPlatform
LET PlatformIndex <= memoize(query={SELECT * FROM PlatformFamilies},key="ClientId")
LET ApplicablePackages <= SELECT *,get(item=PlatformIndex,field=ClientId).ExpectedPackageFamily AS ExpectedFamily
FROM InstalledPackages
WHERE PackageFamily=ExpectedFamily

LET ExtraCoverage <= SELECT * FROM chain(
  mounts={SELECT ClientId,Fqdn,"Coverage" AS Category,"Mounts source returned rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM MountFields GROUP BY ClientId},
  packages={SELECT ClientId,Fqdn,"Coverage" AS Category,"Applicable package family returned installed rows" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,1 AS SourceCollected FROM ApplicablePackages GROUP BY ClientId}
)

LET SelectedScope <= SELECT ClientId,Fqdn FROM chain(
  inventory=Fleet,users=UserFields,processes=ProcessFields,services=ServiceFields,
  network=NetworkFields,cron=CronFields,mounts=MountFields,packages=PackageFields
) GROUP BY ClientId

LET CronQuality <= SELECT ClientId,
  sum(item=if(condition=CommandValue!="" AND CronParserVersion!=2,then=1,else=0)) AS LegacyCronRows,
  sum(item=if(condition=CronParseStatus="Unparsed",then=1,else=0)) AS UnparsedCronRows,
  sum(item=if(condition=CronPotentiallyTruncated=TRUE,then=1,else=0)) AS TruncatedCronScripts
FROM CronFields GROUP BY ClientId
LET CronQualityIndex <= memoize(query={SELECT * FROM CronQuality},key="ClientId")

LET AllEvidenceCandidates <= SELECT * FROM chain(
  users=UserDetail,processes=ProcessDetail,services=ServiceDetail,network=NetworkDetail,cron=CronDetail,
  accounts=AccountMatches,process_context=ExtraProcessMatches,cron_scripts=CronScriptMatches,
  mounts=MountReview,packages=PackageContext,security_services=SecurityServiceMatches
)
LET AllEvidence <= SELECT * FROM AllEvidenceCandidates GROUP BY EvidenceKey
LET PositiveEvidence <= SELECT * FROM AllEvidence WHERE FindingWeight>0

-- Original five categories; cap each category at its highest matched weight.
LET RiskAreas <= SELECT ClientId,Fqdn,Category,
  "Highest matched weight in this existing area" AS Indicator,
  max(item=FindingWeight) AS Weight,count() AS EvidenceCount,0 AS SourceCollected,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM PositiveEvidence GROUP BY AreaKey
LET Findings <= SELECT * FROM chain(
  all_clients={SELECT ClientId,Fqdn,"Coverage" AS Category,"Client has selected baseline data" AS Indicator,
    0 AS Weight,0 AS EvidenceCount,0 AS SourceCollected FROM SelectedScope},
  inventory=Fleet,source_coverage=SourceCoverage,added_coverage=ExtraCoverage,areas=RiskAreas
)

-- Edit to include your actual internal networks, including internally routed public ranges.
-- A peer outside this list is not automatically Internet traffic or malicious.
LET ReviewInternalCIDRs <= split(string="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",sep=",")

LET ReviewMinCohortHosts <= 4
LET ReviewMaxRareHosts <= 2
LET ReviewMaxRarePercent <= 25

LET AdminProcessSignals <= SELECT *,
  ProcName =~ '''(?i)^ssh$''' AS RemoteClient,
  ProcName =~ '''(?i)^(scp|sftp|rsync|rclone)$''' AS TransferTool,
  ProcName =~ '''(?i)^(curl|wget)$''' AS FetchTool,
  ProcName =~ '''(?i)^(nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS NetworkUtility,
  (ProcUsername="root" AND ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS RootShell,
  ProcName =~ '''(?i)^(sudo|su|doas)$''' AS PrivilegeUtility,
  ProcCommandLine =~ '''(?i)(^|\s|/)(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)''' AS InlineCode,
  (ProcName =~ '''(?i)^(screen|tmux|nohup)$'''
   OR ProcCommandLine =~ '''(?i)^\s*(sudo\s+)?nohup\s''') AS BackgroundSession,
  ProcExe =~ '''^/(usr/local|opt|srv|home|root|mnt|media)/''' AS ApplicationPathExe,
  (ProcName =~ '''(?i)^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby)$'''
   AND ProcCommandLine =~ '''\s/(usr/local|opt|srv|home|root|mnt|media)/[^\s;&|]+''') AS InterpreterPathReference
FROM ProcessFields

LET AdministrativeProcessLeads <= SELECT ClientId,Fqdn,"Processes" AS Category,
  "review_administrative_process" AS SignalId,
  "Administrative, application-path or interpreter process to validate" AS Indicator,
  0 AS FindingWeight,
  if(condition=RootShell OR PrivilegeUtility OR InlineCode OR TransferTool OR RemoteClient,then=2,else=1) AS ReviewPriority,
  dict(Pid=ProcPid,Ppid=ProcPpid,Name=ProcName,Username=ProcUsername,FlowId=RowFlowId) AS Evidence1,
  ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(RemoteClient=RemoteClient,TransferTool=TransferTool,FetchTool=FetchTool,NetworkUtility=NetworkUtility,
    RootShell=RootShell,PrivilegeUtility=PrivilegeUtility,InlineCode=InlineCode,BackgroundSession=BackgroundSession,
    ApplicationPathExe=ApplicationPathExe,InterpreterPathReference=InterpreterPathReference) AS Evidence4,
  format(format="%v|%v|review_process|%v|%v|%v",args=[ClientId,RowFlowId,ProcPid,ProcExe,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/Processes" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this observed command, account, path and peer fit the approved administration or application workflow?" AS Hypothesis,
  "Identify the process owner and approved task; read parent and network context; validate the script or binary when needed" AS SuggestedChecks,
  "Current process snapshot only. Root shell is not proof of an interactive session; an interpreter argument may reference data rather than executed code" AS ObservationLimit,
  "LTH - 04 / LTH - 03 / LTH - 05" AS RecommendedNotebook
FROM AdminProcessSignals
WHERE RemoteClient OR TransferTool OR FetchTool OR NetworkUtility OR RootShell OR PrivilegeUtility
   OR InlineCode OR BackgroundSession OR ApplicationPathExe OR InterpreterPathReference

LET ReviewAccountSignals <= SELECT *,
  (UserUid!="0" AND UserUid!="" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$''') AS NonRootShellAccount,
  (UserUid!="0" AND UserUid!="" AND HomeDir =~ '''^/(root|opt|srv)(/|$)''') AS ApplicationHomeAccount
FROM UserFields
LET ReviewAccountLeads <= SELECT ClientId,Fqdn,"Users and Privileges" AS Category,
  "review_account_role" AS SignalId,"Account shell or application home requires role confirmation" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,UserName AS Evidence1,
  dict(Uid=UserUid,Gid=UserGid) AS Evidence2,dict(Shell=UserShell,Home=HomeDir) AS Evidence3,
  dict(NonRootShellAccount=NonRootShellAccount,ApplicationHomeAccount=ApplicationHomeAccount) AS Evidence4,
  format(format="%v|review_account|%v|%v|%v|%v",args=[ClientId,UserName,UserUid,UserShell,HomeDir]) AS EvidenceKey,
  "LTH.SystemBaseline/Users" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this account, shell and home required by a named person or application?" AS Hypothesis,
  "Identify the account owner and intended role; request authentication or group evidence only if the hypothesis requires it" AS SuggestedChecks,
  "Passwd snapshot: configured shell is not proof of login, and primary GID is not supplementary group membership" AS ObservationLimit,
  "LTH - 02 / LTH - 03" AS RecommendedNotebook
FROM ReviewAccountSignals WHERE NonRootShellAccount OR ApplicationHomeAccount

LET ScheduledTaskLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_scheduled_command" AS SignalId,"Scheduled command for administrative-workflow review" AS Indicator,
  0 AS FindingWeight,
  if(condition=CronUser="root" OR CronEvent="@reboot" OR (Minute IN ("*","*/1") AND Hour="*"),then=2,else=1) AS ReviewPriority,
  CronUser AS Evidence1,CronPath AS Evidence2,CronCommand AS Evidence3,
  dict(Event=CronEvent,Minute=Minute,Hour=Hour,DayOfMonth=DayOfMonth,Month=Month,DayOfWeek=DayOfWeek,
    RawLine=CronRawLine,ParserVersion=CronParserVersion,ParseStatus=CronParseStatus) AS Evidence4,
  format(format="%v|review_cron|%v|%v|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,CronPath,CronUser,CronEvent,Minute,Hour,DayOfMonth,Month,DayOfWeek,CronCommand]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this scheduled command, execution account and frequency belong to an approved job?" AS Hypothesis,
  "Identify the job owner; validate its script and destination; use execution logs if proof of a run is needed" AS SuggestedChecks,
  "Shows every nonempty parsed command, including legitimate maintenance. Legacy cron parsing may have lost the real command or user" AS ObservationLimit,
  "LTH - 06 / LTH - 04" AS RecommendedNotebook
FROM CronResults

LET ScheduledScriptLeads <= SELECT ClientId,Fqdn,"Persistence" AS Category,
  "review_cron_script" AS SignalId,"Periodic cron script content for purpose and ownership review" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ScriptPath AS Evidence1,ScriptContent AS Evidence2,
  ScriptMtime AS Evidence3,dict(FileSize=ScriptFileSize,ContentLimit=ScriptContentLimit,
    PotentiallyTruncated=ScriptPotentiallyTruncated) AS Evidence4,
  format(format="%v|review_cron_script|%v|%v",args=[ClientId,ScriptPath,ScriptContent]) AS EvidenceKey,
  "LTH.SystemBaseline/Crontab" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this script expected in a periodic cron directory, and is it actually invoked by the configured scheduler?" AS Hypothesis,
  "Review the collected content and owner; confirm run-parts eligibility and scheduler configuration if execution matters" AS SuggestedChecks,
  "Only a collected content prefix; placement and Mtime do not prove execution or identify the modifier" AS ObservationLimit,
  "LTH - 06" AS RecommendedNotebook
FROM CronScriptFiles

LET AccountScheduledLeads <= SELECT * FROM chain(accounts=ReviewAccountLeads,commands=ScheduledTaskLeads,scripts=ScheduledScriptLeads)

LET ReviewNetworkFields <= SELECT *,
  regex_replace(source=Laddr,re='''^\[|\]$''',replace="") AS ReviewLocalIP,
  regex_replace(source=Raddr,re='''^\[|\]$''',replace="") AS ReviewPeerIP,
  ConnStatus =~ '''(?i)^LISTEN(ING)?$''' AS ReviewListening,
  ConnStatus =~ '''(?i)^(ESTABLISHED|ESTAB)$''' AS ReviewEstablished,
  ProcName =~ '''(?i)^(ssh|scp|sftp|rsync|rclone|curl|wget|nc|ncat|socat|nmap|masscan|tcpdump|tshark)$''' AS ReviewAdministrativeTool
FROM NetworkResults
LET ReviewNetworkSignals <= SELECT *,
  (ReviewListening AND cidr_contains(ip=ReviewLocalIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewLocalIP,ranges=["127.0.0.0/8","::1/128"])) AS NonLoopbackListener,
  (ReviewEstablished AND ReviewAdministrativeTool
    AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["127.0.0.0/8","::1/128","0.0.0.0/8","::/128"])) AS AdministrativeConnection,
  (ReviewEstablished AND cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/0","::/0"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fe80::/10","ff00::/8"])
    AND NOT cidr_contains(ip=ReviewPeerIP,ranges=ReviewInternalCIDRs)) AS PeerOutsideConfiguredNetworks
FROM ReviewNetworkFields
LET NetworkReviewLeads <= SELECT ClientId,Fqdn,"Network" AS Category,
  "review_socket_role" AS SignalId,"Listener or established peer for role and administration review" AS Indicator,
  0 AS FindingWeight,
  if(condition=AdministrativeConnection OR PeerOutsideConfiguredNetworks,then=2,else=1) AS ReviewPriority,
  dict(Pid=Pid,Name=ProcName,Username=ProcUsername) AS Evidence1,ProcExe AS Evidence2,ProcCommandLine AS Evidence3,
  dict(LocalAddress=Laddr,LocalPort=Lport,RemoteAddress=Raddr,RemotePort=Rport,Status=ConnStatus,CallChain=CallChain,
    NonLoopbackListener=NonLoopbackListener,AdministrativeConnection=AdministrativeConnection,
    PeerOutsideConfiguredNetworks=PeerOutsideConfiguredNetworks) AS Evidence4,
  format(format="%v|review_socket|%v|%v|%v|%v|%v|%v|%v",
    args=[ClientId,Pid,Laddr,Lport,Raddr,Rport,ConnStatus,ProcCommandLine]) AS EvidenceKey,
  "LTH.SystemBaseline/NetworkConnections" AS SourceArtifact,HuntId AS SourceHuntId,
  "Does this process need this listening address or peer for its approved service or administrative task?" AS Hypothesis,
  "Identify service and destination owners; confirm intended exposure and peer; correlate with the process and approved task" AS SuggestedChecks,
  "Established sockets do not establish initiation direction. Wildcard listening does not prove Internet reachability; configured CIDRs are not a reputation check" AS ObservationLimit,
  "LTH - 05 / LTH - 04" AS RecommendedNotebook
FROM ReviewNetworkSignals
WHERE NonLoopbackListener OR AdministrativeConnection OR PeerOutsideConfiguredNetworks

LET ReviewServiceSignals <= SELECT *,
  ServiceUnit =~ '''(?i)^(ssh|sshd|xrdp|xrdp-sesman|vncserver|tigervnc|telnet|rsh)([-.@][^ ]*)?\.service$''' AS RemoteAccessService,
  ServiceUnit =~ '''(?i)^(docker|containerd|crio|cri-o|podman|kubelet)([-.@][^ ]*)?\.service$''' AS ContainerService,
  ServiceUnit =~ '''(?i)^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|postgres|redis|redis-server|mongod|mongodb|elasticsearch)([-.@][^ ]*)?\.service$''' AS ApplicationDataService,
  ServiceUnit =~ '''(?i)^(nfs|nfs-server|rpcbind|smb|smbd|nmb|nmbd|vsftpd|proftpd|pure-ftpd)([-.@][^ ]*)?\.service$''' AS FileSharingService
FROM ServiceFields
LET ActiveServiceLeads <= SELECT ClientId,Fqdn,"Services and Persistence" AS Category,
  "review_active_service_role" AS SignalId,"Active access, application, container or file-sharing service" AS Indicator,
  0 AS FindingWeight,1 AS ReviewPriority,ServiceUnit AS Evidence1,ServiceDescription AS Evidence2,
  dict(Load=ServiceLoad,Active=ServiceActive,Sub=ServiceSub) AS Evidence3,
  dict(RemoteAccessService=RemoteAccessService,ContainerService=ContainerService,
    ApplicationDataService=ApplicationDataService,FileSharingService=FileSharingService) AS Evidence4,
  format(format="%v|review_service|%v|%v|%v",args=[ClientId,ServiceUnit,ServiceActive,ServiceSub]) AS EvidenceKey,
  "LTH.SystemBaseline/Services" AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this active service required for the host role and is its access or data exposure intended?" AS Hypothesis,
  "Confirm the service owner and purpose; inspect related listeners; collect unit configuration only for the selected hypothesis" AS SuggestedChecks,
  "Observed loaded service state and naming only; no ExecStart, enablement, installed-package ownership or exposure proof" AS ObservationLimit,
  "LTH - 04 / LTH - 05 / LTH - 12" AS RecommendedNotebook
FROM ReviewServiceSignals
WHERE ServiceLoad="loaded" AND ServiceActive="active"
  AND (RemoteAccessService OR ContainerService OR ApplicationDataService OR FileSharingService)

LET ReviewPlatforms <= SELECT ClientId,
  (TextOrEmpty(X=get(item=scope(),field="Platform")) || "Unknown") AS ReviewCohort
FROM hunt_results(hunt_id=HuntId,artifact="LTH.SystemBaseline/Client_BasicInformation")
GROUP BY ClientId
LET ReviewPlatformIndex <= memoize(query={SELECT * FROM ReviewPlatforms},key="ClientId")

-- Denominator is distinct clients that returned usable rows for this source,
-- not all 16 scoped clients when some source results are missing.
LET ReviewSourceClients <= SELECT * FROM chain(
  processes={SELECT ClientId,"Process executable" AS Family FROM ProcessFields WHERE ProcExe!="" GROUP BY ClientId},
  services={SELECT ClientId,"Service unit" AS Family FROM ServiceFields WHERE ServiceUnit!="" GROUP BY ClientId},
  users={SELECT ClientId,"Shell account" AS Family FROM UserFields WHERE UserName!="" GROUP BY ClientId},
  cron={SELECT ClientId,"Cron command" AS Family FROM CronResults GROUP BY ClientId}
)
LET ReviewSourceCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewSourceClients
LET ReviewCoverage <= SELECT Family,ReviewCohort,count() AS CoveredHosts,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewSourceCohorts GROUP BY CohortKey
LET ReviewCoverageIndex <= memoize(query={SELECT * FROM ReviewCoverage},key="CohortKey")

LET ReviewObservations <= SELECT * FROM chain(
  processes={SELECT ClientId,Fqdn,"Processes" AS Category,"Process executable" AS Family,
    regex_replace(source=ProcExe,re='''\s+\(deleted\)$''',replace="") AS Entity,
    "LTH.SystemBaseline/Processes" AS ObservationSource FROM ProcessFields WHERE ProcExe!=""},
  services={SELECT ClientId,Fqdn,"Services and Persistence" AS Category,"Service unit" AS Family,
    ServiceUnit AS Entity,"LTH.SystemBaseline/Services" AS ObservationSource FROM ServiceFields WHERE ServiceUnit!=""},
  users={SELECT ClientId,Fqdn,"Users and Privileges" AS Category,"Shell account" AS Family,
    UserName+"|"+UserShell AS Entity,"LTH.SystemBaseline/Users" AS ObservationSource
    FROM UserFields WHERE UserUid!="0" AND UserShell =~ '''/(sh|bash|dash|zsh|ksh|fish|csh|tcsh)$'''},
  cron={SELECT ClientId,Fqdn,"Persistence" AS Category,"Cron command" AS Family,
    CronUser+"|"+CronCommand AS Entity,"LTH.SystemBaseline/Crontab" AS ObservationSource FROM CronResults}
)
LET ReviewObservedCohorts <= SELECT *,
  (get(item=ReviewPlatformIndex,field=ClientId).ReviewCohort || "Unknown") AS ReviewCohort
FROM ReviewObservations
LET ReviewUniqueHostEntities <= SELECT *,
  format(format="%v|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS HostEntityKey,
  format(format="%v|%v|%v",args=[ReviewCohort,Family,Entity]) AS PrevalenceKey,
  format(format="%v|%v",args=[ReviewCohort,Family]) AS CohortKey
FROM ReviewObservedCohorts GROUP BY HostEntityKey
LET ReviewPrevalence <= SELECT PrevalenceKey,count() AS HostsWithEntity
FROM ReviewUniqueHostEntities GROUP BY PrevalenceKey
LET ReviewPrevalenceIndex <= memoize(query={SELECT * FROM ReviewPrevalence},key="PrevalenceKey")
LET ReviewPrevalenceRows <= SELECT *,
  get(item=ReviewCoverageIndex,field=CohortKey).CoveredHosts AS CoveredHosts,
  get(item=ReviewPrevalenceIndex,field=PrevalenceKey).HostsWithEntity AS HostsWithEntity
FROM ReviewUniqueHostEntities
LET RareBaselineLeads <= SELECT ClientId,Fqdn,Category,
  "review_low_prevalence" AS SignalId,"Low-prevalence baseline entity in the observed platform cohort" AS Indicator,
  0 AS FindingWeight,2 AS ReviewPriority,Family AS Evidence1,Entity AS Evidence2,
  dict(PlatformCohort=ReviewCohort,HostsWithEntity=HostsWithEntity,CoveredHosts=CoveredHosts) AS Evidence3,
  "Compare approved roles before treating rarity as an anomaly; do not interpret as newly created" AS Evidence4,
  format(format="%v|review_prevalence|%v|%v|%v",args=[ClientId,ReviewCohort,Family,Entity]) AS EvidenceKey,
  ObservationSource AS SourceArtifact,HuntId AS SourceHuntId,
  "Is this uncommon executable, unit, account or scheduled command explained by this host's approved role?" AS Hypothesis,
  "Compare with hosts having the same business role; identify owner and deployment purpose; inspect related baseline evidence" AS SuggestedChecks,
  "One-Hunt prevalence among clients with source rows. Platform is not a business-role cohort; exact cron commands may contain host-specific values" AS ObservationLimit,
  "LTH - 01 / the notebook for the observed family" AS RecommendedNotebook
FROM ReviewPrevalenceRows
WHERE ReviewCohort!="Unknown" AND CoveredHosts>=ReviewMinCohortHosts
  AND HostsWithEntity<=ReviewMaxRareHosts
  AND (HostsWithEntity * 100)<= (CoveredHosts * ReviewMaxRarePercent)

LET AdditionalReviewCandidates <= SELECT * FROM chain(
  admin=AdministrativeProcessLeads,account_cron=AccountScheduledLeads,
  network=NetworkReviewLeads,services=ActiveServiceLeads,prevalence=RareBaselineLeads
)
LET EnhancedEvidenceCandidates <= SELECT * FROM chain(existing=AllEvidence,review=AdditionalReviewCandidates)
LET EnhancedEvidence <= SELECT *,
  if(condition=FindingWeight>0,then="Risk Indicator",else="Hunt Lead") AS EvidenceKind,
  "Unreviewed" AS ReviewState,
  if(condition=FindingWeight>=4,then=3,else=if(condition=FindingWeight>0,then=2,
    else=(get(item=scope(),field="ReviewPriority") || 1))) AS ReviewPriority,
  (get(item=scope(),field="SuggestedChecks") || Hypothesis) AS SuggestedChecks
FROM EnhancedEvidenceCandidates GROUP BY EvidenceKey

LET HuntLeadSummary <= SELECT ClientId,count() AS HuntLeadCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority
FROM EnhancedEvidence GROUP BY ClientId
LET HuntLeadIndex <= memoize(query={SELECT * FROM HuntLeadSummary},key="ClientId")
LET FirstHuntLead(C) = SELECT Hypothesis FROM EnhancedEvidence WHERE ClientId=C ORDER BY ReviewPriority DESC LIMIT 1

LET EvidenceAreas <= SELECT ClientId,Fqdn,Category,
  max(item=FindingWeight) AS Weight,
  sum(item=if(condition=FindingWeight>0,then=1,else=0)) AS EvidenceCount,
  sum(item=if(condition=FindingWeight=0,then=1,else=0)) AS ReviewLeadCount,
  max(item=ReviewPriority) AS HighestReviewPriority,
  format(format="%v|%v",args=[ClientId,Category]) AS AreaKey
FROM EnhancedEvidence GROUP BY AreaKey

SELECT ClientId,Fqdn,Category AS HuntingArea,EvidenceKind,ReviewState,ReviewPriority,
  if(condition=FindingWeight=5,then="Critical",else=if(condition=FindingWeight=4,then="High",
    else=if(condition=FindingWeight=3,then="Medium",else=if(condition=FindingWeight>0,then="Low",else="Review")))) AS Severity,
  Indicator,FindingWeight AS Weight,(FindingWeight>0) AS ContributesToRisk,
  Evidence1,Evidence2,Evidence3,Evidence4,Hypothesis,SuggestedChecks,ObservationLimit,
  EvidenceKey AS FindingKey,SignalId,SourceArtifact,SourceHuntId,RecommendedNotebook
FROM EnhancedEvidence ORDER BY ReviewPriority DESC

```

## Cell 32 (markdown)

# Investigation Pivot Guide

Provides evidence-driven routing from Master Triage to specialized investigation notebooks.
Select a route based on the actual indicator—not the Risk Score alone—define a constrained scope and testable hypothesis, validate the evidence in the primary notebook, and open secondary notebooks only when correlation is required.

## Cell 33 (vql)

```vql
LET PivotRoutes =
SELECT *
FROM chain(

  route01={
    SELECT
      1 AS RouteOrder,
      "Collection Gate" AS EntryMode,
      "System Baseline and Collection Health" AS HuntingArea,

      "Expected client or source is missing, a source unexpectedly returns no rows, an artifact reports errors, or the artifact does not match the client operating system"
        AS Trigger,

      "Resolve collection reliability before interpreting an empty or incomplete result"
        AS PriorityRule,

      "LTH - 01 - System Baseline Dashboard"
        AS PrimaryNotebook,

      "LTH - 00 - Master Triage / Hunt and Collection Health"
        AS SecondaryNotebook,

      "ClientId, FQDN, operating system, Hunt ID, artifact source, collection time and expected client count"
        AS ScopeKeys,

      "The apparent clean result may be caused by a collection gap, incompatible artifact source, incorrect scope or unavailable telemetry"
        AS TestableHypothesis,

      "Confirm the client is in scope; compare expected and completed clients; review source row counts; inspect collection errors; validate operating-system compatibility; confirm the collection time and artifact parameters"
        AS MinimumChecks,

      "Do not pivot to threat conclusions until the required source has returned valid data or the source has been classified as Not Applicable"
        AS EscalateWhen,

      "Validated, Collected - No Finding, Not Applicable, Collection Failed or Needs Tuning"
        AS DecisionGoal

    FROM scope()
  },

  route02={
    SELECT
      2 AS RouteOrder,
      "Direct User Signal / Secondary Privilege Pivot"
        AS EntryMode,

      "Users, Groups and Privileges"
        AS HuntingArea,

      "Unexpected UID 0 account, unusual interactive shell, suspicious home directory, service account with interactive access, unexpected group membership or unauthorized sudo assignment"
        AS Trigger,

      "Prioritize immediately when UID 0 is assigned to a non-root account or suspicious privilege evidence is correlated with authentication activity"
        AS PriorityRule,

      "LTH - 02 - Users Groups and Privileges Dashboard"
        AS PrimaryNotebook,

      "LTH - 09 - Privilege Escalation Indicators Dashboard; then LTH - 03 - Authentication and SSH Activity Dashboard"
        AS SecondaryNotebook,

      "ClientId, username, UID, GID, groups, shell, home directory, sudoers entry and relevant time range"
        AS ScopeKeys,

      "An unauthorized account was created or an existing account received privileges that exceed its expected business role"
        AS TestableHypothesis,

      "Validate account ownership and purpose; compare UID and GID; review group membership; inspect shell and home directory; inspect sudoers and sudoers.d; determine when the account or privilege was added; review recent login activity"
        AS MinimumChecks,

      "Escalate when the account is unauthorized, UID 0 is unexpected, sudo access has no approved purpose, or privilege changes correlate with suspicious login or process activity"
        AS EscalateWhen,

      "Authorized administrative account, misconfiguration, unauthorized account creation or privilege-escalation candidate"
        AS DecisionGoal

    FROM scope()
  },

  route03={
    SELECT
      3 AS RouteOrder,
      "Secondary Pivot from User, Logs or SSH Evidence"
        AS EntryMode,

      "Authentication and SSH"
        AS HuntingArea,

      "Unexpected successful login, unusual source address, failed-login burst followed by success, new authorized key, suspicious private key, unusual SSH configuration or login using a suspicious account"
        AS Trigger,

      "Prioritize when a new identity, new key or unusual source address is followed by privileged or suspicious activity"
        AS PriorityRule,

      "LTH - 03 - Authentication and SSH Activity Dashboard"
        AS PrimaryNotebook,

      "LTH - 02 - Users Groups and Privileges Dashboard; then LTH - 08 - Logs and Security Events Dashboard"
        AS SecondaryNotebook,

      "ClientId, username, source address, login time, authentication result, authentication method, key path and key fingerprint"
        AS ScopeKeys,

      "Credentials or SSH keys were used to obtain unauthorized remote access to the client"
        AS TestableHypothesis,

      "Validate successful and failed login events; identify source address and username; determine authentication method; inspect authorized_keys ownership and permissions; review key creation or modification time; inspect sshd configuration; identify processes started after the session"
        AS MinimumChecks,

      "Escalate when an unknown address or key successfully authenticates, the account is unexpected, or post-login activity includes privilege changes, persistence, suspicious execution or outbound communication"
        AS EscalateWhen,

      "Expected administrative login, credential misuse, unauthorized key persistence or compromised SSH account"
        AS DecisionGoal

    FROM scope()
  },

  route04={
    SELECT
      4 AS RouteOrder,
      "Direct Process or Service Signal"
        AS EntryMode,

      "Processes and Services"
        AS HuntingArea,

      "Deleted executable still running, executable launched from a writable temporary path, suspicious command chain, unusual parent-child relationship or suspicious active service"
        AS Trigger,

      "Prioritize when two related signals exist, such as writable-path execution plus network activity, persistence or an unknown executable"
        AS PriorityRule,

      "LTH - 04 - Processes and Services Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; then LTH - 11 - Malware and Suspicious Tools Dashboard"
        AS SecondaryNotebook,

      "ClientId, PID, PPID, process name, executable path, command line, user, start time and service unit"
        AS ScopeKeys,

      "An unauthorized executable or service is running and may provide execution, persistence, remote access, tunnelling or cryptocurrency mining"
        AS TestableHypothesis,

      "Validate process owner and start time; inspect process tree; review executable and command line; check deleted status; calculate hash; identify package ownership; inspect file metadata; correlate network sockets, service configuration and persistence references"
        AS MinimumChecks,

      "Escalate when an unknown or deleted executable is running, execution originates from a writable path, or the same process has suspicious network or persistence evidence"
        AS EscalateWhen,

      "Approved software, administrative activity, unauthorized execution, malware or service-based persistence"
        AS DecisionGoal

    FROM scope()
  },

  route05={
    SELECT
      5 AS RouteOrder,
      "Direct Network Signal"
        AS EntryMode,

      "Network Connections"
        AS HuntingArea,

      "Active connection from a suspicious process, reverse-shell command pattern, external listener, uncommon destination or suspicious network tool communicating over an unusual port"
        AS Trigger,

      "Prioritize when the socket is owned by a writable-path, deleted or otherwise suspicious process"
        AS PriorityRule,

      "LTH - 05 - Network Connections Dashboard"
        AS PrimaryNotebook,

      "LTH - 04 - Processes and Services Dashboard; then LTH - 13 - Data Access and Exfiltration Dashboard"
        AS SecondaryNotebook,

      "ClientId, PID, process path, user, local address and port, remote address and port, connection state and observation time"
        AS ScopeKeys,

      "A suspicious process is communicating with an unauthorized remote system for command-and-control, tunnelling, remote shell activity or data transfer"
        AS TestableHypothesis,

      "Validate socket ownership; determine connection direction; inspect process path and command line; classify destination and port; compare with the host role; identify DNS or proxy context if available; review connection frequency, duration and associated transferred files"
        AS MinimumChecks,

      "Escalate when a suspicious process communicates externally, a reverse-shell chain is visible, or the destination has no authorized business purpose and correlates with execution, persistence or staged data"
        AS EscalateWhen,

      "Authorized application traffic, administrative connection, command-and-control, tunnelling or exfiltration candidate"
        AS DecisionGoal

    FROM scope()
  },

  route06={
    SELECT
      6 AS RouteOrder,
      "Direct Cron or Service Signal"
        AS EntryMode,

      "Persistence Mechanisms"
        AS HuntingArea,

      "Cron or systemd entry executes from a writable path, downloads remote content, decodes and executes data, runs inline code, launches at startup or repeatedly invokes a suspicious command"
        AS Trigger,

      "Prioritize immediately for download-and-execute, reverse-shell, decode-and-execute or writable-path persistence chains"
        AS PriorityRule,

      "LTH - 06 - Persistence Mechanisms Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; then LTH - 08 - Logs and Security Events Dashboard"
        AS SecondaryNotebook,

      "ClientId, persistence type, source file, user, schedule, command, referenced executable, remote URL and relevant timestamps"
        AS ScopeKeys,

      "An unauthorized Cron, systemd or startup mechanism was created to repeatedly execute attacker-controlled content"
        AS TestableHypothesis,

      "Inspect the original crontab, unit or startup file; validate owner and permissions; review schedule and execution user; inspect ExecStart and environment values; locate referenced files; calculate hashes; review creation and modification times; identify remote URLs; correlate process and log activity"
        AS MinimumChecks,

      "Escalate when persistence references an unknown or writable-path executable, downloads remote content, executes encoded data, or correlates with suspicious process or network evidence"
        AS EscalateWhen,

      "Approved automation, configuration issue or unauthorized persistence"
        AS DecisionGoal

    FROM scope()
  },

  route07={
    SELECT
      7 AS RouteOrder,
      "Secondary Pivot from Process, Persistence or Exfiltration"
        AS EntryMode,

      "File System and Timeline"
        AS HuntingArea,

      "Suspicious process or persistence entry references a file; a recent executable, archive, hidden file, anomalous timestamp or writable-path payload is identified"
        AS Trigger,

      "Prioritize files directly referenced by a suspicious process, Cron entry, service or data-transfer activity"
        AS PriorityRule,

      "LTH - 07 - File System and Timeline Analysis Dashboard"
        AS PrimaryNotebook,

      "LTH - 11 - Malware and Suspicious Tools Dashboard; then LTH - 08 - Logs and Security Events Dashboard"
        AS SecondaryNotebook,

      "ClientId, full path, filename, owner, permissions, size, hash, timestamps and referring process or persistence entry"
        AS ScopeKeys,

      "A malicious or unauthorized file was created, modified, executed, staged or deleted during the suspected activity window"
        AS TestableHypothesis,

      "Validate file type and full path; inspect owner and permissions; calculate hash; identify package ownership; compare creation, modification and change times; examine nearby files; build a focused timeline; correlate the file with its process, user, persistence mechanism and network activity"
        AS MinimumChecks,

      "Escalate when a recent executable or archive is located in a writable path, has no legitimate package ownership, or correlates with execution, persistence or transfer evidence"
        AS EscalateWhen,

      "Legitimate file, administrative artifact, suspicious payload, staging archive or evidence of cleanup"
        AS DecisionGoal

    FROM scope()
  },

  route08={
    SELECT
      8 AS RouteOrder,
      "Correlation Pivot"
        AS EntryMode,

      "Logs and Security Events"
        AS HuntingArea,

      "Two or more related indicators exist, an exact sequence must be reconstructed, or authentication, sudo, service, Cron and system events must be confirmed"
        AS Trigger,

      "Prioritize when independent data sources can confirm or refute the same user, process or event sequence"
        AS PriorityRule,

      "LTH - 08 - Logs and Security Events Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; plus the notebook associated with the original finding"
        AS SecondaryNotebook,

      "ClientId, time window, username, process, file path, service, source address and the original finding identifier"
        AS ScopeKeys,

      "System and security logs contain a timeline that confirms or refutes the suspected authentication, execution, privilege, persistence or network behavior"
        AS TestableHypothesis,

      "Confirm time synchronization; inspect authentication and system logs; review sudo and service events; correlate Cron execution; identify errors or restarts; align events by timestamp, user, PID, file path and remote address; record missing telemetry explicitly"
        AS MinimumChecks,

      "Escalate when two independent sources support the same behavior or when logs confirm an unauthorized change, login, privilege action or persistence execution"
        AS EscalateWhen,

      "Confirmed sequence, contradicted hypothesis, insufficient telemetry or collection gap"
        AS DecisionGoal

    FROM scope()
  },

  route09={
    SELECT
      9 AS RouteOrder,
      "Secondary Pivot from User or File Evidence"
        AS EntryMode,

      "Privilege Escalation Indicators"
        AS HuntingArea,

      "Unexpected UID 0 account, unauthorized sudo rule, suspicious SUID or SGID file, world-writable privileged path or privilege change associated with suspicious activity"
        AS Trigger,

      "Prioritize UID 0 anomalies and recently created or modified privileged files"
        AS PriorityRule,

      "LTH - 09 - Privilege Escalation Indicators Dashboard"
        AS PrimaryNotebook,

      "LTH - 02 - Users Groups and Privileges Dashboard; then LTH - 08 - Logs and Security Events Dashboard"
        AS SecondaryNotebook,

      "ClientId, username, UID and GID, sudo rule, file path, owner, mode, package ownership and modification time"
        AS ScopeKeys,

      "An account or executable gained elevated privileges through an unauthorized identity, sudo configuration or privileged file"
        AS TestableHypothesis,

      "Validate UID and group membership; inspect sudoers changes; review SUID and SGID ownership and permissions; determine package ownership; compare against baseline; review timestamps; inspect execution and authentication evidence"
        AS MinimumChecks,

      "Escalate when the privilege path is newly introduced, unauthorized, not owned by an expected package, or has evidence of execution by a suspicious user or process"
        AS EscalateWhen,

      "Expected privileged component, insecure configuration or confirmed privilege-escalation candidate"
        AS DecisionGoal

    FROM scope()
  },

  route10={
    SELECT
      10 AS RouteOrder,
      "Secondary Pivot from Process, File or Kernel Evidence"
        AS EntryMode,

      "Rootkit and Kernel Analysis"
        AS HuntingArea,

      "Unexpected kernel module, module-loading persistence, hidden-process discrepancy, kernel integrity anomaly or rootkit-tool alert supported by other suspicious behavior"
        AS Trigger,

      "Treat scanner output as supporting evidence; prioritize only when kernel evidence correlates with integrity, process or persistence anomalies"
        AS PriorityRule,

      "LTH - 10 - Rootkit and Kernel Analysis Dashboard"
        AS PrimaryNotebook,

      "LTH - 11 - Malware and Suspicious Tools Dashboard; then LTH - 08 - Logs and Security Events Dashboard"
        AS SecondaryNotebook,

      "ClientId, kernel version, module name, module path, load time, configuration file, process discrepancy and related file hashes"
        AS ScopeKeys,

      "A malicious or unauthorized kernel component is hiding activity, intercepting system behavior or providing persistent privileged access"
        AS TestableHypothesis,

      "Review loaded modules and module-loading configuration; validate module path and package ownership; inspect hashes and metadata; review kernel and boot logs; check kernel taint or errors; correlate hidden-process, network and persistence evidence; do not conclude compromise from a rootkit scanner alert alone"
        AS MinimumChecks,

      "Escalate when an unexplained module or kernel modification correlates with integrity mismatch, hidden activity, suspicious persistence or malicious process and network behavior"
        AS EscalateWhen,

      "Expected kernel component, scanner false positive, kernel integrity concern or rootkit candidate"
        AS DecisionGoal

    FROM scope()
  },

  route11={
    SELECT
      11 AS RouteOrder,
      "Secondary Pivot from Process or File Evidence"
        AS EntryMode,

      "Malware and Suspicious Tools"
        AS HuntingArea,

      "Unknown executable, writable-path payload, miner, tunnelling utility, reverse-shell tool, suspicious hash, YARA match or unauthorized dual-use tool"
        AS Trigger,

      "Prioritize when file reputation or content evidence is combined with execution, persistence or network behavior"
        AS PriorityRule,

      "LTH - 11 - Malware and Suspicious Tools Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; then LTH - 04 - Processes and Services Dashboard"
        AS SecondaryNotebook,

      "ClientId, file path, hash, file type, owner, permissions, process, command line, persistence reference and network endpoint"
        AS ScopeKeys,

      "An unauthorized binary or script is providing malware execution, tunnelling, remote access, credential access or cryptocurrency mining"
        AS TestableHypothesis,

      "Calculate hash; validate file type and package ownership; inspect metadata and permissions; run targeted content or YARA analysis when appropriate; review process tree, command line, network activity and persistence references; upload only targeted files when deeper analysis is necessary"
        AS MinimumChecks,

      "Escalate when an unknown or suspicious file has behavioral evidence such as execution, persistence, credential access, mining or external communication"
        AS EscalateWhen,

      "Authorized administrative tool, policy violation, suspicious dual-use tool or malware candidate"
        AS DecisionGoal

    FROM scope()
  },

  route12={
    SELECT
      12 AS RouteOrder,
      "Secondary Pivot from Container, Process or Network Context"
        AS EntryMode,

      "Containers and Cloud Workloads"
        AS HuntingArea,

      "Container runtime is present and evidence involves a privileged container, host filesystem mount, dangerous capability, suspicious container execution, unusual network communication or cloud metadata access"
        AS Trigger,

      "Mark Not Applicable when the client has no container or cloud workload; prioritize privileged containers with host access"
        AS PriorityRule,

      "LTH - 12 - Containers and Cloud Workloads Dashboard"
        AS PrimaryNotebook,

      "LTH - 04 - Processes and Services Dashboard; then LTH - 05 - Network Connections Dashboard"
        AS SecondaryNotebook,

      "ClientId, runtime, container ID, image, image digest, namespace, entrypoint, privileges, capabilities, mounts and network endpoints"
        AS ScopeKeys,

      "A compromised or misconfigured container is executing suspicious activity or providing access to the host or cloud environment"
        AS TestableHypothesis,

      "Identify runtime and container; validate image and digest; inspect entrypoint and executed commands; review privileged mode, capabilities and host mounts; inspect namespaces and container processes; review container logs and network activity; check access to host secrets or cloud metadata"
        AS MinimumChecks,

      "Escalate when a privileged container has host access, an unknown image executes suspicious commands, or container activity correlates with host-level persistence, secret access or external communication"
        AS EscalateWhen,

      "Not Applicable, expected workload, insecure deployment, compromised container or host-escape candidate"
        AS DecisionGoal

    FROM scope()
  },

  route13={
    SELECT
      13 AS RouteOrder,
      "Secondary Pivot from Network and File Evidence"
        AS EntryMode,

      "Data Access and Exfiltration"
        AS HuntingArea,

      "Large recent file or archive, suspicious data-staging path, transfer utility, unusual outbound connection, repeated upload activity or access to sensitive data followed by communication"
        AS Trigger,

      "Prioritize when staging and outbound-transfer evidence occur on the same client and within the same time window"
        AS PriorityRule,

      "LTH - 13 - Data Access and Exfiltration Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; then LTH - 05 - Network Connections Dashboard"
        AS SecondaryNotebook,

      "ClientId, file path, size, owner, timestamps, archive type, process, command line, remote destination, port and time window"
        AS ScopeKeys,

      "Sensitive data was collected or staged locally and then transferred to an unauthorized destination"
        AS TestableHypothesis,

      "Validate file size, type, owner and timestamps; identify archive or staging behavior; inspect the creating process and command line; correlate the remote destination and connection time; estimate transfer volume when available; determine business purpose; inspect whether secrets or sensitive configuration were included"
        AS MinimumChecks,

      "Escalate when data staging, archive creation or sensitive-file access correlates with an unauthorized outbound connection or transfer utility"
        AS EscalateWhen,

      "Expected backup or transfer, suspicious staging, attempted exfiltration or confirmed exfiltration candidate"
        AS DecisionGoal

    FROM scope()
  },

  route14={
    SELECT
      14 AS RouteOrder,
      "Secondary Pivot from File, Authentication or Exfiltration Evidence"
        AS EntryMode,

      "Configuration and Secrets Review"
        AS HuntingArea,

      "Private key, token, credential file, secret-bearing configuration, insecure permissions, suspicious copying or access to secrets by an unexpected user or process"
        AS Trigger,

      "Prioritize when secret access correlates with an untrusted process, new login, staging activity or external communication"
        AS PriorityRule,

      "LTH - 14 - Configuration and Secrets Review Dashboard"
        AS PrimaryNotebook,

      "LTH - 07 - File System and Timeline Analysis Dashboard; then LTH - 13 - Data Access and Exfiltration Dashboard"
        AS SecondaryNotebook,

      "ClientId, file path, secret type, owner, permissions, modification time, accessing user or process and related destination"
        AS ScopeKeys,

      "Credentials, keys or sensitive configuration were exposed, copied, modified or used by an unauthorized identity or process"
        AS TestableHypothesis,

      "Validate file purpose, owner and permissions; identify modification and reliable access evidence; determine the user and process involved; check copies in temporary or staging locations; review authentication and outbound activity; determine whether credential rotation is required; do not rely on access time alone because atime may be disabled or modified by mount options"
        AS MinimumChecks,

      "Escalate when secrets are read or copied by an unexpected process or user, permissions expose sensitive material, or secret access correlates with staging, authentication or outbound communication"
        AS EscalateWhen,

      "Expected configuration, insecure secret handling, credential exposure or confirmed secret-access candidate"
        AS DecisionGoal

    FROM scope()
  }
)

SELECT RouteOrder,
       EntryMode,
       HuntingArea,
       Trigger,
       PriorityRule,
       PrimaryNotebook,
       SecondaryNotebook,
       ScopeKeys,
       TestableHypothesis,
       MinimumChecks,
       EscalateWhen,
       DecisionGoal
FROM PivotRoutes
ORDER BY RouteOrder
```
