# Master Triage Notebook

Use this notebook after the baseline hunt completes. Replace `HUNT_ID` with the secured hunt identifier inside Velociraptor. Do not commit the real identifier.

## Cell 1 — Baseline client inventory

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Hostname,
       Fqdn,
       OS,
       Architecture,
       Platform,
       PlatformVersion,
       KernelVersion,
       Labels
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.SystemBaseline.ClientInfo",
  source="BasicInformation"
)
ORDER BY ClientId
```

Purpose: confirm that the expected clients returned baseline identity data before interpreting empty findings.

## Cell 2 — Suspicious process evidence

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Severity,
       Reason,
       Pid,
       Ppid,
       Name,
       Username,
       Exe,
       CommandLine,
       CreatedTime,
       Deleted
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ProcessServices.SuspiciousProcesses",
  source="SuspiciousProcesses"
)
ORDER BY ClientId, Severity
```

Purpose: identify deleted executables, execution from writable paths, reverse-shell patterns, downloaders, and suspicious interpreters.

## Cell 3 — Suspicious network evidence

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Severity,
       Reason,
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
       CallChain
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.SuspiciousConnections",
  source="SuspiciousConnections"
)
ORDER BY ClientId, Severity
```

Purpose: correlate suspicious ports, shells, network tools, and processes running from writable locations.

## Cell 4 — Suspicious cron evidence

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Event,
       User,
       Minute,
       Hour,
       DayOfMonth,
       Month,
       DayOfWeek,
       Command,
       Path,
       if(
         condition=Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|curl|wget|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/|xmrig|miner|chisel|ngrok|frp)",
         then="HIGH",
         else="MEDIUM"
       ) AS Severity,
       "Suspicious command or path in cron" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence.Crontab",
  source="CronTabs"
)
WHERE Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|curl|wget|python -c|python3 -c|perl -e|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/|xmrig|miner|chisel|ngrok|frp)"
ORDER BY ClientId
```

Purpose: reduce the full cron inventory to commands that justify a persistence pivot.

## Cell 5 — Master risk score

```vql
LET HuntId <= "HUNT_ID"

LET ProcessEvidence = SELECT ClientId,
       "Process" AS Category,
       Severity,
       Reason,
       format(
         format="%v pid=%v path=%v command=%v",
         args=[Name, Pid, Exe, CommandLine]
       ) AS Evidence,
       if(condition=Severity = "HIGH", then=3, else=1) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ProcessServices.SuspiciousProcesses",
  source="SuspiciousProcesses"
)

LET NetworkEvidence = SELECT ClientId,
       "Network" AS Category,
       Severity,
       Reason,
       format(
         format="%v:%v -> %v:%v process=%v pid=%v",
         args=[Laddr, Lport, Raddr, Rport, ProcessName, Pid]
       ) AS Evidence,
       if(condition=Severity = "HIGH", then=3, else=1) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.SuspiciousConnections",
  source="SuspiciousConnections"
)

LET CronEvidence = SELECT ClientId,
       "Persistence" AS Category,
       if(
         condition=Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|/tmp/|/var/tmp/|/dev/shm/)",
         then="HIGH",
         else="MEDIUM"
       ) AS Severity,
       "Suspicious command or path in cron" AS Reason,
       format(
         format="%v user=%v command=%v",
         args=[Path, User, Command]
       ) AS Evidence,
       if(
         condition=Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|/tmp/|/var/tmp/|/dev/shm/)",
         then=3,
         else=1
       ) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence.Crontab",
  source="CronTabs"
)
WHERE Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|curl|wget|python -c|python3 -c|perl -e|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/|xmrig|miner|chisel|ngrok|frp)"

SELECT ClientId,
       count() AS EvidenceCount,
       sum(item=RiskWeight) AS RiskScore,
       if(
         condition=sum(item=RiskWeight) >= 8,
         then="HIGH",
         else=if(
           condition=sum(item=RiskWeight) >= 4,
           then="MEDIUM",
           else="LOW"
         )
       ) AS Priority
FROM chain(
  process=ProcessEvidence,
  network=NetworkEvidence,
  persistence=CronEvidence
)
GROUP BY ClientId
ORDER BY RiskScore DESC
```

Scoring:

- `HIGH` evidence = 3 points;
- other selected evidence = 1 point;
- client priority is `HIGH` at 8+, `MEDIUM` at 4–7, and `LOW` below 4.

The score ranks analyst attention. It does not confirm malicious activity.

## Cell 6 — Evidence behind the score

```vql
LET HuntId <= "HUNT_ID"

LET ProcessEvidence = SELECT ClientId,
       "Process" AS Category,
       Severity,
       Reason,
       format(
         format="%v pid=%v path=%v command=%v",
         args=[Name, Pid, Exe, CommandLine]
       ) AS Evidence,
       if(condition=Severity = "HIGH", then=3, else=1) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ProcessServices.SuspiciousProcesses",
  source="SuspiciousProcesses"
)

LET NetworkEvidence = SELECT ClientId,
       "Network" AS Category,
       Severity,
       Reason,
       format(
         format="%v:%v -> %v:%v process=%v pid=%v",
         args=[Laddr, Lport, Raddr, Rport, ProcessName, Pid]
       ) AS Evidence,
       if(condition=Severity = "HIGH", then=3, else=1) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.SuspiciousConnections",
  source="SuspiciousConnections"
)

LET CronEvidence = SELECT ClientId,
       "Persistence" AS Category,
       if(
         condition=Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|/tmp/|/var/tmp/|/dev/shm/)",
         then="HIGH",
         else="MEDIUM"
       ) AS Severity,
       "Suspicious command or path in cron" AS Reason,
       format(
         format="%v user=%v command=%v",
         args=[Path, User, Command]
       ) AS Evidence,
       if(
         condition=Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|/tmp/|/var/tmp/|/dev/shm/)",
         then=3,
         else=1
       ) AS RiskWeight
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.Persistence.Crontab",
  source="CronTabs"
)
WHERE Command =~ "(?i)(/dev/tcp|bash -i|nc |ncat|netcat|socat|curl|wget|python -c|python3 -c|perl -e|base64 -d|chmod \\+x|/tmp/|/var/tmp/|/dev/shm/|xmrig|miner|chisel|ngrok|frp)"

SELECT ClientId,
       Category,
       Severity,
       RiskWeight,
       Reason,
       Evidence
FROM chain(
  process=ProcessEvidence,
  network=NetworkEvidence,
  persistence=CronEvidence
)
ORDER BY ClientId, RiskWeight DESC, Category
```

Use this table to explain every score and decide the next domain pivot.

## Analyst pivot

| Evidence category | Recommended next notebook |
| --- | --- |
| Process | Processes & Services, File Timeline, Malware Tools |
| Network | Network Connections, Processes & Services |
| Persistence | Persistence, File Timeline, Logs |
| Privilege | Privilege Escalation, Users & Privileges |
| Kernel | Rootkit & Kernel |
| Exfiltration | Data Access & Exfiltration, Network Connections |

