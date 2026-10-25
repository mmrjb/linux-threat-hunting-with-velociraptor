# LTH - 08 - Logs and Security Events Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 08 - Logs and Security Events Dashboard

This notebook analyzes Linux log and security event data collected by:

`LTH.LogSecurityEvents`

Main objectives:

- Review SSH login activity
- Review authentication and session events
- Review sudo and su activity
- Identify user and group management events
- Review service start/stop/reload events
- Review audit and kernel security messages
- Review suspicious command history
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# SSH Login Attempts

This section reviews SSH login attempts parsed from authentication logs.

It helps identify successful logins, failed attempts, invalid users, root login attempts, and suspicious source IPs.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Time,
       IP,
       Result,
       Method,
       AttemptedUser,
       OSPath
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SSHLogin"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Failed SSH Login Count per Client

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS FailedSSHCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SSHLogin"
)
WHERE Result =~ "(?i)(Failed|Invalid|failure)"
GROUP BY ClientId
ORDER BY FailedSSHCount DESC
```

## Cell 6 (markdown)

# Failed SSH Login Count by Source IP

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT IP,
       count() AS FailedCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SSHLogin"
)
WHERE Result =~ "(?i)(Failed|Invalid|failure)"
GROUP BY IP
ORDER BY FailedCount DESC
```

## Cell 8 (markdown)

# Last User Login Inventory

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       login_User,
       login_Host,
       login_IpAddr,
       login_Terminal,
       login_time,
       logout_time
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/LastUserLogin"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# Authentication Log Events

This section reviews authentication-related events from Linux auth logs.

It includes SSH activity, PAM events, session open/close events, failed authentication, and successful authentication.

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/AuthLogEvents"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Sudo and SU Events

This section reviews privilege-related activity from sudo and su logs.

Commands executed with elevated privileges should be reviewed carefully, especially when they involve downloaders, shells, scripting engines, or temporary paths.

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SudoSuEvents"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# User Management Events

This section reviews user and group management events.

Account creation, deletion, password changes, group membership changes, or unexpected administrative changes may indicate persistence or privilege abuse.

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/UserManagementEvents"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Service Events

This section reviews Linux service start, stop, reload, enable, and disable events.

Unexpected service changes may indicate persistence, attacker-controlled services, or operational changes that require validation.

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/ServiceEvents"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# Audit Events

This section reviews Linux audit log events when auditd is available.

Audit events can provide important evidence about authentication, command execution, policy violations, denied actions, and suspicious security activity.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/AuditEvents"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Kernel Security Events

This section reviews kernel security related messages.

Kernel messages can show AppArmor or SELinux denials, module warnings, segmentation faults, firewall blocks, and other low-level security indicators.

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/KernelSecurityEvents"
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Command History Inventory

This section reviews Linux shell command history files.

Command history can help identify suspicious administrative activity, attacker tooling, downloaders, staging commands, reverse shell attempts, and cleanup commands.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/CommandHistoryLines"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Suspicious Command History

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
  artifact="LTH.LogSecurityEvents/SuspiciousCommandHistory"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# Suspicious Security Events

This section combines high-value suspicious events across Linux security logs.

It includes failed authentication, root login activity, user management changes, suspicious sudo commands, audit alerts, denied actions, and kernel security warnings.

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       EventCategory,
       Severity,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SuspiciousSecurityEvents"
)
ORDER BY ClientId
```

## Cell 28 (markdown)

# Security Event Count per Client

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       count() AS SuspiciousEventCount
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.LogSecurityEvents/SuspiciousSecurityEvents"
)
GROUP BY ClientId
ORDER BY SuspiciousEventCount DESC
```

## Cell 30 (markdown)

# Final Findings Detail

This section combines suspicious log and security event indicators into one findings table.

It includes failed SSH login activity, suspicious security events, user management changes, suspicious command history, audit events, and kernel security messages.

Use this table as the main evidence view for log and security event hunting.

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSH <=
  SELECT ClientId,
         "MEDIUM" AS Severity,
         "Failed SSH Login" AS Finding,
         AttemptedUser AS Evidence1,
         IP AS Evidence2,
         Result AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SSHLogin"
  )
  WHERE Result =~ "(?i)(Failed|Invalid|failure)"

LET RootSSH <=
  SELECT ClientId,
         "HIGH" AS Severity,
         "Root SSH Login Attempt" AS Finding,
         AttemptedUser AS Evidence1,
         IP AS Evidence2,
         Result AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SSHLogin"
  )
  WHERE AttemptedUser = "root"

LET UserManagement <=
  SELECT ClientId,
         Severity,
         "User Management Event" AS Finding,
         Path AS Evidence1,
         EventCategory AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/UserManagementEvents"
  )

LET SuspiciousSecurity <=
  SELECT ClientId,
         Severity,
         "Suspicious Security Event" AS Finding,
         Path AS Evidence1,
         EventCategory AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SuspiciousSecurityEvents"
  )

LET SuspiciousHistory <=
  SELECT ClientId,
         Severity,
         "Suspicious Command History" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SuspiciousCommandHistory"
  )

LET AuditHigh <=
  SELECT ClientId,
         Severity,
         "Audit Security Event" AS Finding,
         Path AS Evidence1,
         EventCategory AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/AuditEvents"
  )
  WHERE Severity =~ "HIGH|MEDIUM"

LET KernelHigh <=
  SELECT ClientId,
         Severity,
         "Kernel Security Event" AS Finding,
         Path AS Evidence1,
         EventCategory AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/KernelSecurityEvents"
  )
  WHERE Severity =~ "HIGH|MEDIUM"

SELECT *
FROM chain(
  a=FailedSSH,
  b=RootSSH,
  c=UserManagement,
  d=SuspiciousSecurity,
  e=SuspiciousHistory,
  f=AuditHigh,
  g=KernelHigh
)
ORDER BY ClientId
```

## Cell 32 (markdown)

# Clients Needing Investigation

This section summarizes log and security event findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when failed logins, root access, account changes, suspicious commands, audit alerts, or kernel security events are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSH <=
  SELECT ClientId,
         "Failed SSH Login" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SSHLogin"
  )
  WHERE Result =~ "(?i)(Failed|Invalid|failure)"

LET RootSSH <=
  SELECT ClientId,
         "Root SSH Login Attempt" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SSHLogin"
  )
  WHERE AttemptedUser = "root"

LET UserManagement <=
  SELECT ClientId,
         "User Management Event" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/UserManagementEvents"
  )

LET SuspiciousSecurity <=
  SELECT ClientId,
         "Suspicious Security Event" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SuspiciousSecurityEvents"
  )

LET SuspiciousHistory <=
  SELECT ClientId,
         "Suspicious Command History" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/SuspiciousCommandHistory"
  )

LET AuditHigh <=
  SELECT ClientId,
         "Audit Security Event" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/AuditEvents"
  )
  WHERE Severity =~ "HIGH|MEDIUM"

LET KernelHigh <=
  SELECT ClientId,
         "Kernel Security Event" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.LogSecurityEvents/KernelSecurityEvents"
  )
  WHERE Severity =~ "HIGH|MEDIUM"

LET Findings <=
  SELECT *
  FROM chain(
    a=FailedSSH,
    b=RootSSH,
    c=UserManagement,
    d=SuspiciousSecurity,
    e=SuspiciousHistory,
    f=AuditHigh,
    g=KernelHigh
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 34 (markdown)

# Recommended Next Actions

Clients with log or security event findings should be reviewed in deeper hunting phases.

Recommended follow-up actions:

1. Review failed SSH login attempts and source IPs.
2. Validate root login attempts and successful privileged access.
3. Investigate user and group management events.
4. Review suspicious sudo/su commands and command history.
5. Correlate audit and kernel events with process, network, persistence, and privilege escalation hunts.
6. Run deeper investigation on clients with high finding counts.
