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

## Public-template usage

1. Run the broad `LTH.SystemBaseline` hunt before using this notebook.
2. Replace every `HUNT_ID` placeholder with the secured hunt identifier inside Velociraptor.
3. Keep the real Hunt ID, Client IDs, hostnames, usernames, and IP addresses out of public commits.
4. `EnableLabIndicators` is set to `TRUE` to reproduce the presentation lab. Set it to `FALSE` before production use.
5. Treat the score as an investigation priority, not as proof of compromise.

## Cell 1 — Baseline Hunt Client Inventory

Confirms that expected endpoints returned baseline identity data before analysts interpret empty findings.

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

## Cell 2 — Suspicious Users

Identifies additional UID 0 accounts that require immediate ownership and authorization validation.

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

## Cell 3 — Suspicious Processes

Classifies suspicious execution patterns, writable-path activity, reverse-shell behavior, temporary web servers, and mining indicators.

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

## Cell 4 — Suspicious Services

Identifies suspicious systemd services using threat-associated names, high-risk descriptions, and controlled lab indicators.

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

## Cell 5 — Suspicious Network Activity

Correlates sockets with process context to identify command-execution utilities, writable-path processes, unusual listeners, and suspicious connections.

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

## Cell 6 — Suspicious Cron Jobs

Classifies scheduled tasks that fetch remote content, execute from writable locations, use inline interpreters, or contain shell-execution patterns.

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

## Cell 7 — Master Risk Score

Calculates one explainable, coverage-aware risk score per client while keeping collection health separate from suspicious findings.

```vql
LET HuntId <= "HUNT_ID"

-- TRUE for the presentation lab. Set to FALSE in production.
LET EnableLabIndicators <= TRUE


-- ============================================================
-- 1. Fleet coverage
-- ============================================================

LET Fleet <=
SELECT ClientId,
       Fqdn,
       "Coverage" AS Category,
       "Baseline successfully collected" AS Indicator,
       0 AS Weight,
       0 AS EvidenceCount,
       1 AS SourceCollected
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)
GROUP BY ClientId


-- ============================================================
-- 2. Additional UID 0 accounts
-- ============================================================

LET UserFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="Uid")) AS UserUid,
       str(str=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       str(str=(
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


LET UniqueUsers <=
SELECT ClientId,
       Fqdn,
       UserName,
       HomeDir,
       FindingWeight
FROM UserMatches
GROUP BY EvidenceKey


LET UsersByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount
FROM UniqueUsers
GROUP BY ClientId


LET SuspiciousUsers <=
SELECT ClientId,
       Fqdn,
       "Users and Privileges" AS Category,
       "Additional UID 0 account" AS Indicator,
       5 AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM UsersByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 3. Suspicious processes
-- ============================================================

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       str(str=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       str(str=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       str(str=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       str(str=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       str(str=(
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
         AS PythonHTTPServer
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
                     OR WritablePathExecution,
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool,
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


LET UniqueProcesses <=
SELECT ClientId,
       Fqdn,
       ProcPid,
       ProcName,
       ProcExe,
       ProcCommandLine,
       FindingWeight
FROM ProcessMatches
GROUP BY EvidenceKey


LET ProcessesByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount,
       sum(
         item=if(
           condition=FindingWeight = 2,
           then=1,
           else=0
         )
       ) AS LowCount
FROM UniqueProcesses
GROUP BY ClientId


LET SuspiciousProcesses <=
SELECT ClientId,
       Fqdn,
       "Processes" AS Category,
       "Suspicious process behavior" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM ProcessesByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 4. Suspicious systemd services
-- ============================================================

LET ServiceFields <=
SELECT ClientId,
       Fqdn,
       str(str=(
         get(item=scope(), member="Unit")
         ||
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="Service")
       )) AS ServiceUnit,
       str(str=get(item=scope(), member="Description"))
         AS ServiceDescription,
       str(str=(
         get(item=scope(), member="ExecStart")
         ||
         get(item=scope(), member="Command")
         ||
         get(item=scope(), member="CommandLine")
       )) AS ServiceCommand,
       str(str=(
         get(item=scope(), member="FragmentPath")
         ||
         get(item=scope(), member="SourcePath")
         ||
         get(item=scope(), member="Path")
       )) AS ServicePath
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)


LET ServiceSignals <=
SELECT *,
       ServiceCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       (
         ServiceCommand =~
           '''(?i)(^|\s)/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ServicePath =~
           '''(?i)^/(tmp|var/tmp|dev/shm)/'''
       ) AS WritableServiceExecution,

       (
         EnableLabIndicators
         AND
         (
           ServiceUnit =~
             '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
           OR
           ServiceDescription =~
             '''(?i)(lab persistence|temporary update service|remote support lab)'''
         )
       ) AS KnownLabService
FROM ServiceFields


LET ServiceMatches <=
SELECT *,
       format(
         format="%v|service|%v|%v|%v",
         args=[ClientId, ServiceUnit, ServicePath, ServiceCommand]
       ) AS EvidenceKey,
       if(
         condition=DownloadPipeShell,
         then=5,
         else=4
       ) AS FindingWeight
FROM ServiceSignals
WHERE DownloadPipeShell
   OR WritableServiceExecution
   OR KnownLabService


LET UniqueServices <=
SELECT ClientId,
       Fqdn,
       ServiceUnit,
       ServicePath,
       ServiceCommand,
       FindingWeight
FROM ServiceMatches
GROUP BY EvidenceKey


LET ServicesByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount
FROM UniqueServices
GROUP BY ClientId


LET SuspiciousServices <=
SELECT ClientId,
       Fqdn,
       "Services and Persistence" AS Category,
       "Suspicious systemd service" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=4
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM ServicesByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 5. Suspicious network activity
-- ============================================================

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="Laddr")) AS Laddr,
       str(str=get(item=scope(), member="Lport")) AS Lport,
       str(str=get(item=scope(), member="Raddr")) AS Raddr,
       str(str=get(item=scope(), member="Rport")) AS Rport,
       str(str=get(item=scope(), member="Pid")) AS Pid,
       str(str=get(item=scope(), member="Status")) AS ConnStatus,
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
       str(str=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       str(str=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       str(str=(
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


LET UniqueNetwork <=
SELECT ClientId,
       Fqdn,
       Pid,
       Laddr,
       Lport,
       Raddr,
       Rport,
       ConnStatus,
       FindingWeight
FROM NetworkMatches
GROUP BY EvidenceKey


LET NetworkByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount
FROM UniqueNetwork
GROUP BY ClientId


LET SuspiciousNetwork <=
SELECT ClientId,
       Fqdn,
       "Network" AS Category,
       "Suspicious process and socket behavior" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM NetworkByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 6. Suspicious Cron jobs
-- ============================================================

LET CronFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="User")) AS CronUser,
       str(str=get(item=scope(), member="Event")) AS CronEvent,
       str(str=get(item=scope(), member="Minute")) AS Minute,
       str(str=get(item=scope(), member="Hour")) AS Hour,
       str(str=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       str(str=get(item=scope(), member="Month")) AS Month,
       str(str=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       str(str=get(item=scope(), member="Path")) AS CronPath,
       str(str=get(item=scope(), member="Command")) AS CommandValue,
       str(str=get(item=scope(), member="$Query")) AS QueryValue
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
       if(
         condition=CommandValue,
         then=CommandValue,
         else=QueryValue
       ) AS CronCommand
FROM CronFields


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
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         )
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         )
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
         )
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
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
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


LET UniqueCron <=
SELECT ClientId,
       Fqdn,
       CronPath,
       CronCommand,
       FindingWeight
FROM CronMatches
GROUP BY EvidenceKey


LET CronByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount
FROM UniqueCron
GROUP BY ClientId


LET SuspiciousCron <=
SELECT ClientId,
       Fqdn,
       "Persistence" AS Category,
       "Suspicious scheduled task" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM CronByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 7. Source data coverage
--
-- A source is counted only when it returned at least one row.
-- Missing source rows require validation; they are not treated as
-- proof that the endpoint is clean or that collection failed.
-- ============================================================

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
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
-- ============================================================

LET Findings <=
SELECT *
FROM chain(
  coverage={
    SELECT *
    FROM Fleet
  },
  source_coverage={
    SELECT *
    FROM SourceCoverage
  },
  users={
    SELECT *
    FROM SuspiciousUsers
  },
  processes={
    SELECT *
    FROM SuspiciousProcesses
  },
  services={
    SELECT *
    FROM SuspiciousServices
  },
  network={
    SELECT *
    FROM SuspiciousNetwork
  },
  cron={
    SELECT *
    FROM SuspiciousCron
  }
)


-- ============================================================
-- 9. Calculate one score per host
-- ============================================================

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


SELECT ClientId,
       Fqdn,
       TriggeredAreaCount,
       RiskScore,
       FindingEvidenceCount,
       CriticalAreaCount,
       CollectedSourceCount,
       6 AS ExpectedSourceCount,
       if(
         condition=CollectedSourceCount = 6,
         then="Complete - all expected sources returned rows",
         else=format(
           format="Validate empty sources - %v of 6 returned rows",
           args=[CollectedSourceCount]
         )
       ) AS CollectionStatus,
       if(
         condition=RiskScore = 0
                   AND CollectedSourceCount < 6,
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
ORDER BY RiskScore DESC
```

## Cell 8 — Evidence Behind the Score

Shows the exact contribution of each triggered hunting area to the client RiskScore.

Each area contributes its highest applicable weight once. FindingCount shows the number of underlying matched findings, while ScoreContribution shows the value added to the Master Risk Score.

The sum of ScoreContribution for each client must equal its RiskScore.

```vql
LET HuntId <= "HUNT_ID"

-- TRUE for the presentation lab. Set to FALSE in production.
LET EnableLabIndicators <= TRUE


-- ============================================================
-- 1. Fleet coverage
-- ============================================================

LET Fleet <=
SELECT ClientId,
       Fqdn,
       "Coverage" AS Category,
       "Baseline successfully collected" AS Indicator,
       0 AS Weight,
       0 AS EvidenceCount,
       1 AS SourceCollected
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)
GROUP BY ClientId


-- ============================================================
-- 2. Additional UID 0 accounts
-- ============================================================

LET UserFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="Uid")) AS UserUid,
       str(str=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,
       str(str=(
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


LET UniqueUsers <=
SELECT ClientId,
       Fqdn,
       UserName,
       HomeDir,
       FindingWeight
FROM UserMatches
GROUP BY EvidenceKey


LET UsersByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount
FROM UniqueUsers
GROUP BY ClientId


LET SuspiciousUsers <=
SELECT ClientId,
       Fqdn,
       "Users and Privileges" AS Category,
       "Additional UID 0 account" AS Indicator,
       5 AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM UsersByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 3. Suspicious processes
-- ============================================================

LET ProcessFields <=
SELECT ClientId,
       Fqdn,
       str(str=(
         get(item=scope(), member="Pid")
         ||
         get(item=scope(), member="PID")
       )) AS ProcPid,
       str(str=(
         get(item=scope(), member="Ppid")
         ||
         get(item=scope(), member="PPid")
         ||
         get(item=scope(), member="PPID")
       )) AS ProcPpid,
       str(str=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="ProcessName")
       )) AS ProcName,
       str(str=(
         get(item=scope(), member="Exe")
         ||
         get(item=scope(), member="Executable")
         ||
         get(item=scope(), member="Path")
       )) AS ProcExe,
       str(str=(
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
         AS PythonHTTPServer
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
                     OR WritablePathExecution,
           then=4,
           else=if(
             condition=NetcatTool
                       OR SocatTool,
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


LET UniqueProcesses <=
SELECT ClientId,
       Fqdn,
       ProcPid,
       ProcName,
       ProcExe,
       ProcCommandLine,
       FindingWeight
FROM ProcessMatches
GROUP BY EvidenceKey


LET ProcessesByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount,
       sum(
         item=if(
           condition=FindingWeight = 2,
           then=1,
           else=0
         )
       ) AS LowCount
FROM UniqueProcesses
GROUP BY ClientId


LET SuspiciousProcesses <=
SELECT ClientId,
       Fqdn,
       "Processes" AS Category,
       "Suspicious process behavior" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM ProcessesByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 4. Suspicious systemd services
-- ============================================================

LET ServiceFields <=
SELECT ClientId,
       Fqdn,
       str(str=(
         get(item=scope(), member="Unit")
         ||
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="Service")
       )) AS ServiceUnit,
       str(str=get(item=scope(), member="Description"))
         AS ServiceDescription,
       str(str=(
         get(item=scope(), member="ExecStart")
         ||
         get(item=scope(), member="Command")
         ||
         get(item=scope(), member="CommandLine")
       )) AS ServiceCommand,
       str(str=(
         get(item=scope(), member="FragmentPath")
         ||
         get(item=scope(), member="SourcePath")
         ||
         get(item=scope(), member="Path")
       )) AS ServicePath
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)


LET ServiceSignals <=
SELECT *,
       ServiceCommand =~
         '''(?i)(/usr/bin/|/bin/)?(curl|wget)[^|]{0,1000}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       (
         ServiceCommand =~
           '''(?i)(^|\s)/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         ServicePath =~
           '''(?i)^/(tmp|var/tmp|dev/shm)/'''
       ) AS WritableServiceExecution,

       (
         EnableLabIndicators
         AND
         (
           ServiceUnit =~
             '''(?i)^(system-update-lab|backup-sync-lab|remote-support-lab)\.service$'''
           OR
           ServiceDescription =~
             '''(?i)(lab persistence|temporary update service|remote support lab)'''
         )
       ) AS KnownLabService
FROM ServiceFields


LET ServiceMatches <=
SELECT *,
       format(
         format="%v|service|%v|%v|%v",
         args=[ClientId, ServiceUnit, ServicePath, ServiceCommand]
       ) AS EvidenceKey,
       if(
         condition=DownloadPipeShell,
         then=5,
         else=4
       ) AS FindingWeight
FROM ServiceSignals
WHERE DownloadPipeShell
   OR WritableServiceExecution
   OR KnownLabService


LET UniqueServices <=
SELECT ClientId,
       Fqdn,
       ServiceUnit,
       ServicePath,
       ServiceCommand,
       FindingWeight
FROM ServiceMatches
GROUP BY EvidenceKey


LET ServicesByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount
FROM UniqueServices
GROUP BY ClientId


LET SuspiciousServices <=
SELECT ClientId,
       Fqdn,
       "Services and Persistence" AS Category,
       "Suspicious systemd service" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=4
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM ServicesByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 5. Suspicious network activity
-- ============================================================

LET NetworkFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="Laddr")) AS Laddr,
       str(str=get(item=scope(), member="Lport")) AS Lport,
       str(str=get(item=scope(), member="Raddr")) AS Raddr,
       str(str=get(item=scope(), member="Rport")) AS Rport,
       str(str=get(item=scope(), member="Pid")) AS Pid,
       str(str=get(item=scope(), member="Status")) AS ConnStatus,
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
       str(str=(
         get(item=ProcInfo, member="Name")
         ||
         get(item=ProcInfo, member="name")
       )) AS ProcName,
       str(str=(
         get(item=ProcInfo, member="Exe")
         ||
         get(item=ProcInfo, member="exe")
       )) AS ProcExe,
       str(str=(
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


LET UniqueNetwork <=
SELECT ClientId,
       Fqdn,
       Pid,
       Laddr,
       Lport,
       Raddr,
       Rport,
       ConnStatus,
       FindingWeight
FROM NetworkMatches
GROUP BY EvidenceKey


LET NetworkByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount
FROM UniqueNetwork
GROUP BY ClientId


LET SuspiciousNetwork <=
SELECT ClientId,
       Fqdn,
       "Network" AS Category,
       "Suspicious process and socket behavior" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM NetworkByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 6. Suspicious Cron jobs
-- ============================================================

LET CronFields <=
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="User")) AS CronUser,
       str(str=get(item=scope(), member="Event")) AS CronEvent,
       str(str=get(item=scope(), member="Minute")) AS Minute,
       str(str=get(item=scope(), member="Hour")) AS Hour,
       str(str=get(item=scope(), member="DayOfMonth")) AS DayOfMonth,
       str(str=get(item=scope(), member="Month")) AS Month,
       str(str=get(item=scope(), member="DayOfWeek")) AS DayOfWeek,
       str(str=get(item=scope(), member="Path")) AS CronPath,
       str(str=get(item=scope(), member="Command")) AS CommandValue,
       str(str=get(item=scope(), member="$Query")) AS QueryValue
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
       if(
         condition=CommandValue,
         then=CommandValue,
         else=QueryValue
       ) AS CronCommand
FROM CronFields


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
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(nohup\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         )
       ) AS DirectWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         )
       ) AS InterpretedWritableExecution,

       (
         CronCommand =~
           '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
         OR
         (
           CronEvent =~ '''(?i)^@reboot$'''
           AND
           CronCommand =~
             '''(?i)^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
         )
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
         format="%v|cron|%v|%v|%v|%v|%v|%v|%v",
         args=[
           ClientId,
           CronPath,
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


LET UniqueCron <=
SELECT ClientId,
       Fqdn,
       CronPath,
       CronCommand,
       FindingWeight
FROM CronMatches
GROUP BY EvidenceKey


LET CronByHost <=
SELECT ClientId,
       Fqdn,
       count() AS EvidenceCount,
       sum(
         item=if(
           condition=FindingWeight = 5,
           then=1,
           else=0
         )
       ) AS CriticalCount,
       sum(
         item=if(
           condition=FindingWeight = 4,
           then=1,
           else=0
         )
       ) AS HighCount,
       sum(
         item=if(
           condition=FindingWeight = 3,
           then=1,
           else=0
         )
       ) AS MediumCount
FROM UniqueCron
GROUP BY ClientId


LET SuspiciousCron <=
SELECT ClientId,
       Fqdn,
       "Persistence" AS Category,
       "Suspicious scheduled task" AS Indicator,
       if(
         condition=CriticalCount > 0,
         then=5,
         else=if(
           condition=HighCount > 0,
           then=4,
           else=if(
             condition=MediumCount > 0,
             then=3,
             else=2
           )
         )
       ) AS Weight,
       EvidenceCount,
       0 AS SourceCollected
FROM CronByHost
WHERE EvidenceCount > 0


-- ============================================================
-- 7. Source data coverage
--
-- A source is counted only when it returned at least one row.
-- Missing source rows require validation; they are not treated as
-- proof that the endpoint is clean or that collection failed.
-- ============================================================

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
    GROUP BY ClientId
  }
)


-- ============================================================
-- 8. Merge category-level findings
-- ============================================================

LET Findings <=
SELECT *
FROM chain(
  coverage={
    SELECT *
    FROM Fleet
  },
  source_coverage={
    SELECT *
    FROM SourceCoverage
  },
  users={
    SELECT *
    FROM SuspiciousUsers
  },
  processes={
    SELECT *
    FROM SuspiciousProcesses
  },
  services={
    SELECT *
    FROM SuspiciousServices
  },
  network={
    SELECT *
    FROM SuspiciousNetwork
  },
  cron={
    SELECT *
    FROM SuspiciousCron
  }
)


-- ============================================================
-- 9. Explain the exact score contribution of each area
--
-- Each triggered area contributes one value: its highest matched
-- weight. Therefore, the sum of ScoreContribution for a client
-- equals RiskScore in the Master Risk Score cell.
-- ============================================================

SELECT ClientId,
       Fqdn,
       Category AS HuntingArea,
       Indicator,
       if(
         condition=Weight = 5,
         then="Critical",
         else=if(
           condition=Weight = 4,
           then="High",
           else=if(
             condition=Weight = 3,
             then="Medium",
             else="Low"
           )
         )
       ) AS Severity,
       Weight AS ScoreContribution,
       EvidenceCount AS FindingCount,
       if(
         condition=Category = "Users and Privileges",
         then="LTH - 02 - Users Groups and Privileges Dashboard",
         else=if(
           condition=Category = "Processes",
           then="LTH - 04 - Processes and Services Dashboard",
           else=if(
             condition=Category = "Services and Persistence",
             then="LTH - 04 - Processes and Services Dashboard; then LTH - 06 - Persistence Mechanisms Dashboard",
             else=if(
               condition=Category = "Network",
               then="LTH - 05 - Network Connections Dashboard",
               else="LTH - 06 - Persistence Mechanisms Dashboard"
             )
           )
         )
       ) AS RecommendedNotebook
FROM Findings
WHERE Weight > 0
ORDER BY Fqdn
```

## Cell 9 — Triage Findings Detail

Provides an additional raw-evidence view for analyst validation.

Analysts must validate the process, command, account, service, network endpoint, or Cron entry before classifying the result as malicious or benign.

This table is not used directly to calculate RiskScore. Use Evidence Behind the Score for the exact contribution of each hunting area.

```vql
LET HuntId <= "HUNT_ID"

-- ============================================================
-- 1. Raw source rows
-- ============================================================

LET UserRows =
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="User")) AS UserName,
       get(item=scope(), member="Uid") AS UserUid,
       str(str=get(item=scope(), member="Shell")) AS UserShell,
       str(str=get(item=scope(), member="Homedir")) AS UserHome
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Users"
)


LET ProcessRows =
SELECT ClientId,
       Fqdn,
       get(item=scope(), member="Pid") AS ProcessPid,
       str(str=get(item=scope(), member="Name")) AS ProcessName,
       str(str=get(item=scope(), member="Exe")) AS ProcessExe,
       str(str=get(item=scope(), member="CommandLine")) AS ProcessCommand,
       get(item=scope(), member="Deleted") AS DeletedValue
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Processes"
)


LET ServiceRows =
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="Unit")) AS ServiceUnit,
       str(str=get(item=scope(), member="Active")) AS ServiceActive,
       str(str=get(item=scope(), member="Sub")) AS ServiceSub,
       str(str=get(item=scope(), member="Description")) AS ServiceDescription
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Services"
)


LET NetworkRows =
SELECT ClientId,
       Fqdn,
       get(item=scope(), member="Pid") AS NetworkPid,
       str(str=get(item=scope(), member="Status")) AS NetworkStatus,
       str(str=get(item=scope(), member="Laddr")) AS LocalAddress,
       get(item=scope(), member="Lport") AS LocalPort,
       str(str=get(item=scope(), member="Raddr")) AS RemoteAddress,
       get(item=scope(), member="Rport") AS RemotePort,

       str(str=get(
         item=get(item=scope(), member="ProcInfo"),
         member="Exe"
       )) AS NetworkProcessExe,

       str(str=get(
         item=get(item=scope(), member="ProcInfo"),
         member="CommandLine"
       )) AS NetworkProcessCommand

FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/NetworkConnections"
)


LET CronRows =
SELECT ClientId,
       Fqdn,
       str(str=get(item=scope(), member="User")) AS CronUser,
       str(str=get(item=scope(), member="Path")) AS CronPath,
       str(str=get(item=scope(), member="Event")) AS CronEvent,
       str(str=get(item=scope(), member="Minute")) AS CronMinute,
       str(str=get(item=scope(), member="Hour")) AS CronHour,

       str(str=(
         get(item=scope(), member="Command")
         ||
         get(item=scope(), member="$Query")
       )) AS CronCommand

FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline/Crontab"
)

-- ============================================================
-- 2. Process signals
-- ============================================================

LET ProcessSignals =
SELECT *,
       (
         DeletedValue = TRUE
         OR
         str(str=DeletedValue) =~ '''(?i)^(1|true|yes|y)$'''
       ) AS DeletedExecutable,

       ProcessExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritablePathExecution,

       ProcessCommand =~
         '''(?i)(bash\s+-i|/dev/(tcp|udp)/|(nc|ncat|netcat)\s+[^\r\n]{0,500}\s(-e|-c)(\s|$)|socat\s+[^\r\n]{0,500}(EXEC|SYSTEM):|base64\s+(-d|--decode)[^|]{0,500}[|]\s*(ba|da|z|k)?sh)'''
         AS SuspiciousCommandChain

FROM ProcessRows

-- ============================================================
-- 3. Network signals
-- ============================================================


LET NetworkSignals =
SELECT *,
       NetworkStatus =~
         '''(?i)^(ESTAB|ESTABLISHED|LISTEN)$'''
         AS ActiveSocket,

       NetworkProcessExe =~
         '''(?i)^/(tmp|var/tmp|dev/shm)/'''
         AS WritableProcess,

       RemotePort =~
         '''^(4444|1337|31337|9001|9002)$'''
         AS UncommonRemotePort,

       NetworkProcessCommand =~
         '''(?i)(bash\s+-i|/dev/(tcp|udp)/|(nc|ncat|netcat)\s+[^\r\n]{0,500}\s(-e|-c)(\s|$)|socat\s+[^\r\n]{0,500}(EXEC|SYSTEM):)'''
         AS ReverseShellCommand,

       NetworkProcessCommand =~
         '''(?i)(^|[\s/])(nc|ncat|netcat|socat|bash|sh|python[0-9.]*|perl|ruby)(\s|$)'''
         AS SuspiciousNetworkTool

FROM NetworkRows
-- ============================================================
-- 4. Cron signals
-- ============================================================

LET CronSignals =
SELECT *,
       CronCommand =~
         '''(?i)(curl|wget)[^|]{0,500}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DownloadPipeShell,

       CronCommand =~
         '''(?i)(base64\s+(-d|--decode)|openssl\s+enc\s+-d)[^|]{0,500}[|]\s*(sudo\s+)?(/usr/bin/|/bin/)?(ba|da|z|k)?sh(\s|$)'''
         AS DecodePipeShell,

       CronCommand =~
         '''(?i)(^|\s|/)(nc|ncat|netcat)(\s|$).*(\s-e(\s|$)|\s-c(\s|$)|--exec(=|\s)|--sh-exec(=|\s))'''
         AS NetcatExecution,

       CronCommand =~
         '''(?i)(^|\s|/)socat(\s|$).*(EXEC|SYSTEM):'''
         AS SocatExecution,

       CronCommand =~
         '''(?i)/dev/(tcp|udp)/[A-Za-z0-9._:-]+'''
         AS DevTcpShell,

       CronCommand =~
         '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(nohup\s+)?((/usr/bin/|/bin/)?((ba|da|z|k)?sh|python[0-9.]*|perl|php|ruby)\s+)?/(tmp|var/tmp|dev/shm)/[^\s;&|]+'''
         AS WritableCronExecution,

       CronCommand =~
         '''(?i)(^\s*|[;&|]\s*)(sudo\s+)?(/usr/bin/|/bin/)?(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)(\s|$)'''
         AS InlineInterpreter,

       CronCommand =~
         '''(?i)(curl|wget)[^\r\n]{0,500}(https?|ftp)://'''
         AS ScheduledRemoteFetch,

       (
         CronEvent =~ '''(?i)^@reboot$'''
         OR
         (
           CronMinute =~ '''^(\*|\*/1)$'''
           AND CronHour = "*"
         )
       ) AS StartupOrFrequent

FROM CronRows


LET CronCorrelated =
SELECT *,
       (
         DownloadPipeShell
         OR DecodePipeShell
         OR NetcatExecution
         OR SocatExecution
         OR DevTcpShell
       ) AS CriticalCronChain,

       (
         ScheduledRemoteFetch
         AND StartupOrFrequent
       ) AS RepeatedRemoteFetch

FROM CronSignals
-- ============================================================
-- 5. Finding rows
-- ============================================================


LET UserFindings =
SELECT ClientId,
       Fqdn,
       "Users & Privileges" AS HuntingArea,
       "Unexpected UID 0 account" AS Indicator,
       "High" AS Severity,
       5 AS Weight,
       UserName AS Evidence1,
       UserUid AS Evidence2,
       UserShell AS Evidence3,
       UserHome AS Evidence4,
       "LTH - 02 - Users Groups and Privileges Dashboard"
         AS RecommendedNotebook
FROM UserRows
WHERE UserUid = 0
  AND UserName != "root"


LET ProcessFindings =
SELECT ClientId,
       Fqdn,
       "Processes & Services" AS HuntingArea,

       if(
         condition=DeletedExecutable,
         then="Deleted executable is still running",
         else=if(
           condition=WritablePathExecution,
           then="Process executing from a writable temporary path",
           else="Suspicious process command chain"
         )
       ) AS Indicator,

       "High" AS Severity,
       5 AS Weight,
       ProcessPid AS Evidence1,
       ProcessExe AS Evidence2,
       ProcessCommand AS Evidence3,
       ProcessName AS Evidence4,
       "LTH - 04 - Processes and Services Dashboard"
         AS RecommendedNotebook

FROM ProcessSignals
WHERE DeletedExecutable
   OR WritablePathExecution
   OR SuspiciousCommandChain


LET ServiceFindings =
SELECT ClientId,
       Fqdn,
       "Processes & Services" AS HuntingArea,
       "Suspicious active service" AS Indicator,
       "Medium" AS Severity,
       3 AS Weight,
       ServiceUnit AS Evidence1,
       ServiceActive AS Evidence2,
       ServiceDescription AS Evidence3,
       ServiceSub AS Evidence4,
       "LTH - 04 - Processes and Services Dashboard"
         AS RecommendedNotebook

FROM ServiceRows
WHERE ServiceActive =~ '''(?i)^active$'''
  AND (
       ServiceUnit =~
         '''(?i)(ngrok|chisel|xmrig|miner|backdoor|reverse.?shell|netcat|ncat|socat|frpc|frps)'''
       OR
       ServiceDescription =~
         '''(?i)(ngrok|chisel|xmrig|miner|backdoor|reverse.?shell|netcat|ncat|socat|frpc|frps)'''
  )


LET NetworkFindings =
SELECT ClientId,
       Fqdn,
       "Network Connections" AS HuntingArea,

       if(
         condition=WritableProcess,
         then="Network activity from a writable-path executable",
         else=if(
           condition=ReverseShellCommand,
           then="Possible reverse-shell network activity",
           else="Suspicious tool communicating over an uncommon port"
         )
       ) AS Indicator,

       if(
         condition=WritableProcess OR ReverseShellCommand,
         then="High",
         else="Medium"
       ) AS Severity,

       if(
         condition=WritableProcess OR ReverseShellCommand,
         then=5,
         else=3
       ) AS Weight,

       NetworkPid AS Evidence1,
       NetworkProcessExe AS Evidence2,
       NetworkProcessCommand AS Evidence3,

       dict(
         RemoteAddress=RemoteAddress,
         RemotePort=RemotePort,
         Status=NetworkStatus
       ) AS Evidence4,

       "LTH - 05 - Network Connections Dashboard"
         AS RecommendedNotebook

FROM NetworkSignals
WHERE ActiveSocket
  AND (
       WritableProcess
       OR ReverseShellCommand
       OR (
            UncommonRemotePort
            AND SuspiciousNetworkTool
          )
  )


LET CronFindings =
SELECT ClientId,
       Fqdn,
       "Persistence - Cron" AS HuntingArea,

       if(
         condition=CriticalCronChain,
         then="High-confidence malicious Cron command chain",
         else=if(
           condition=WritableCronExecution,
           then="Cron execution from a writable temporary path",
           else=if(
             condition=RepeatedRemoteFetch,
             then="Remote content retrieved at startup or every minute",
             else="Inline interpreter execution from Cron"
           )
         )
       ) AS Indicator,

       if(
         condition=CriticalCronChain,
         then="High",
         else="Medium"
       ) AS Severity,

       if(
         condition=CriticalCronChain,
         then=5,
         else=3
       ) AS Weight,

       CronUser AS Evidence1,
       CronPath AS Evidence2,
       CronCommand AS Evidence3,

       dict(
         Event=CronEvent,
         Minute=CronMinute,
         Hour=CronHour
       ) AS Evidence4,

       "LTH - 06 - Persistence Mechanisms Dashboard"
         AS RecommendedNotebook

FROM CronCorrelated
WHERE CriticalCronChain
   OR WritableCronExecution
   OR RepeatedRemoteFetch
   OR InlineInterpreter


LET Findings =
SELECT *
FROM chain(
  users=UserFindings,
  processes=ProcessFindings,
  services=ServiceFindings,
  network=NetworkFindings,
  cron=CronFindings
)


SELECT ClientId,
       Fqdn,
       HuntingArea,
       Severity,
       Indicator,
       Evidence1,
       Evidence2,
       Evidence3,
       Evidence4,
       RecommendedNotebook
FROM Findings
ORDER BY Fqdn
```

## Cell 10 — Investigation Pivot Guide

Provides evidence-driven routing from Master Triage to specialized investigation notebooks.
Select a route based on the actual indicator—not the Risk Score alone—define a constrained scope and testable hypothesis, validate the evidence in the primary notebook, and open secondary notebooks only when correlation is required.

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

## Scoring reference

The Master Risk Score assigns the highest applicable weight once per triggered hunting area. Multiple underlying matches are retained in `FindingCount`, but they do not multiply the area contribution.

| Weight | Severity |
| ---: | --- |
| 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 0 | Coverage only; no score contribution |

The client `RiskScore` is the sum of the triggered-area contributions.

| Condition | RiskLevel |
| --- | --- |
| `RiskScore = 0` and fewer than 6 expected sources returned rows | Collection Review |
| `RiskScore = 0` and all 6 expected sources returned rows | No Matched Finding |
| At least one critical area, or `RiskScore >= 10` | High |
| `RiskScore >= 6` | Suspicious |
| `RiskScore >= 3` | Review |
| Otherwise | Low |

The six expected coverage sources are basic client information, users, processes, services, network connections, and Cron. An empty source requires validation; it is not proof that an endpoint is clean or that collection failed.

## Interpretation rules

- `RiskScore` ranks analyst attention; it does not provide a final verdict.
- The sum of `ScoreContribution` in **Evidence Behind the Score** must equal the client's `RiskScore`.
- **Triage Findings Detail** provides supporting raw evidence and is not added directly to `RiskScore`.
- Select investigation routes from the actual indicator and evidence, not from the score alone.
- Confirm findings through the relevant domain notebook, evidence correlation, and timeline analysis.
