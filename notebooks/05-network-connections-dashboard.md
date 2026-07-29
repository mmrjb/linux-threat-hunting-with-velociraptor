# Network Connections Dashboard

Replace `HUNT_ID` inside Velociraptor. Keep real Hunt and Client identifiers out of the public repository.

## Cell 1 — Listening ports inventory

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
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
  artifact="LTH.NetworkConnections.NetstatEnriched"
)
WHERE Status =~ "LISTEN"
ORDER BY ClientId
```

Purpose: build the complete listening-service inventory with process context.

## Cell 2 — Listening port exposure summary per client

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS ListeningPortCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.NetstatEnriched"
)
WHERE Status =~ "LISTEN"
GROUP BY ClientId
ORDER BY ListeningPortCount DESC
```

Purpose: identify clients with unusually broad listening exposure.

## Cell 3 — Established connections inventory

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Status,
       Laddr,
       Lport,
       Raddr,
       Rport,
       Pid,
       ProcInfo.Name AS ProcessName,
       ProcInfo.Exe AS ProcessPath,
       ProcInfo.Username AS Username,
       ProcInfo.CommandLine AS CommandLine,
       CallChain
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.NetstatEnriched"
)
WHERE Status =~ "ESTAB"
ORDER BY ClientId
```

Purpose: review active network sessions and the process lineage responsible for them.

## Cell 4 — Established connection count per client

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS EstablishedConnectionCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.NetstatEnriched"
)
WHERE Status =~ "ESTAB"
GROUP BY ClientId
ORDER BY EstablishedConnectionCount DESC
```

Purpose: locate outliers before inspecting individual connections.

## Cell 5 — Suspicious connection evidence

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

Purpose: show connections already enriched with the artifact's suspicious-port, process, path, and command-line logic.

## Cell 6 — Network risk summary per client

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS SuspiciousConnectionCount,
       sum(
         item=if(
           condition=Severity = "HIGH",
           then=3,
           else=1
         )
       ) AS NetworkRiskScore
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.SuspiciousConnections",
  source="SuspiciousConnections"
)
GROUP BY ClientId
ORDER BY NetworkRiskScore DESC
```

Purpose: prioritize clients while keeping the detailed evidence in Cell 5.

## Cell 7 — High-risk listening ports

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Laddr,
       Lport,
       Pid,
       ProcInfo.Name AS ProcessName,
       ProcInfo.Exe AS ProcessPath,
       ProcInfo.Username AS Username,
       ProcInfo.CommandLine AS CommandLine,
       CallChain
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.NetworkConnections.NetstatEnriched"
)
WHERE Status =~ "LISTEN"
  AND (
    Lport =~ "^(4444|1337|31337|9001|9002)$"
    OR ProcInfo.Exe =~ "^/(tmp|var/tmp|dev/shm|home)/"
    OR ProcInfo.CommandLine =~ "(?i)(bash|sh|python|python3|perl|ruby|nc|ncat|netcat|socat|chisel|ngrok|frp)"
  )
ORDER BY ClientId
```

Purpose: focus on unusual ports and listeners associated with shells, tunneling tools, or writable execution paths.

## Investigation guidance

For every suspicious connection:

1. Confirm whether the local or remote address is expected.
2. Validate the process path, user, parent chain, and command line.
3. Pivot to Processes & Services for deleted or writable-path execution.
4. Pivot to Persistence when the process should not survive reboot.
5. Pivot to Malware Tools for suspicious binaries, hashes, or utilities.
6. Record the benign owner or the evidence that supports escalation.

