# LTH - 09 - Privilege Escalation Indicators Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 09 - Privilege Escalation Indicators Dashboard

This notebook analyzes Linux privilege escalation indicators collected by:

`LTH.PrivEsc`

Main objectives:

- Identify UID 0 users
- Review privileged group memberships
- Review risky sudoers rules
- Identify SUID and SGID files
- Review Linux file capabilities
- Identify world-writable sensitive paths
- Review anomalous files
- Identify suspicious root-owned processes
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# UID 0 Users

This section identifies non-root users with UID 0.

Any account other than `root` with UID 0 should be treated as high risk because it has root-equivalent privileges.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       User,
       Description,
       Uid,
       Gid,
       Homedir,
       Shell,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/UID0Users"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Privileged Group Memberships

This section reviews sensitive Linux group memberships.

Groups such as sudo, wheel, docker, lxd, disk, and shadow may provide administrative access or privilege escalation opportunities.

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Group,
       GID,
       Members,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/PrivilegedGroups"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Sudoers Rules Inventory

This section reviews active sudoers rules from `/etc/sudoers` and `/etc/sudoers.d`.

Broad permissions, NOPASSWD rules, and risky command delegation should be reviewed carefully.

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       RuleType,
       HasNOPASSWD,
       HasALL,
       HasRiskyCommand,
       ReferencesWritablePath,
       Severity,
       Reason,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/SudoersRules"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# Risky Sudoers Rules

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       RuleType,
       HasNOPASSWD,
       HasALL,
       HasRiskyCommand,
       ReferencesWritablePath,
       Severity,
       Reason,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/RiskySudoersRules"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# SUID and SGID Files

This section reviews files with SUID or SGID permissions.

Unexpected SUID/SGID files, especially in writable paths or on powerful binaries, may create privilege escalation opportunities.

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       OctalMode AS Mode,
       Owner,
       Group,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/SUIDSGIDFiles"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Suspicious SUID / SGID Files

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       OctalMode AS Mode,
       Owner,
       Group,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/SuspiciousSUIDSGIDFiles"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# Linux File Capabilities

This section reviews Linux file capabilities collected with `getcap`.

Dangerous capabilities such as `cap_setuid`, `cap_setgid`, `cap_dac_override`, and `cap_sys_admin` may enable privilege escalation.

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Tool,
       Stdout,
       Stderr,
       ReturnCode,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/FileCapabilities"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Suspicious File Capabilities

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Tool,
       Stdout,
       Stderr,
       ReturnCode,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/SuspiciousFileCapabilities"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# World-Writable Files

This section reviews world-writable files and directories in monitored paths.

World-writable objects in sensitive directories may allow privilege escalation through file replacement, path hijacking, or service abuse.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       OctalMode AS Mode,
       Owner,
       Group,
       FileType AS ObjectType,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/WorldWritableFiles"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Suspicious World-Writable Sensitive Paths

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       Size,
       OctalMode AS Mode,
       Owner,
       Group,
       FileType AS ObjectType,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/SuspiciousWorldWritableFiles"
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Anomalous Files

This section reviews anomalous files such as hidden files, large files, or files with privilege-related indicators.

These files should be reviewed based on path, ownership, permissions, and server role.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT *
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/AnomalousFiles"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Root Process Indicators

This section identifies suspicious root-owned processes.

Root processes running from writable paths, deleted executables, or suspicious command lines may indicate successful privilege escalation or post-exploitation activity.

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       Ppid,
       Name,
       Username,
       Exe,
       CommandLine,
       CreatedTime,
       Deleted,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.PrivEsc/RootProcessIndicators"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# Final Findings Detail

This section combines privilege escalation indicators into one findings table.

It includes UID 0 users, privileged group memberships, risky sudoers rules, suspicious SUID/SGID files, dangerous file capabilities, world-writable sensitive paths, and suspicious root processes.

Use this table as the main evidence view for privilege escalation hunting.

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET UID0Users <=
  SELECT ClientId,
         Severity,
         "Non-root UID 0 User" AS Finding,
         User AS Evidence1,
         Uid AS Evidence2,
         Shell AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/UID0Users"
  )

LET PrivilegedGroups <=
  SELECT ClientId,
         Severity,
         "Privileged Group Membership" AS Finding,
         Group AS Evidence1,
         GID AS Evidence2,
         Members AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/PrivilegedGroups"
  )

LET RiskySudoers <=
  SELECT ClientId,
         Severity,
         "Risky Sudoers Rule" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         Line AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/RiskySudoersRules"
  )

LET SuspiciousSUID <=
  SELECT ClientId,
         Severity,
         "Suspicious SUID/SGID File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousSUIDSGIDFiles"
  )

LET SuspiciousCaps <=
  SELECT ClientId,
         Severity,
         "Dangerous File Capability" AS Finding,
         Tool AS Evidence1,
         Reason AS Evidence2,
         Stdout AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousFileCapabilities"
  )

LET WorldWritable <=
  SELECT ClientId,
         Severity,
         "World-Writable Sensitive Path" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousWorldWritableFiles"
  )

LET RootProcesses <=
  SELECT ClientId,
         Severity,
         "Suspicious Root Process" AS Finding,
         Pid AS Evidence1,
         Exe AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/RootProcessIndicators"
  )

SELECT *
FROM chain(
  a=UID0Users,
  b=PrivilegedGroups,
  c=RiskySudoers,
  d=SuspiciousSUID,
  e=SuspiciousCaps,
  f=WorldWritable,
  g=RootProcesses
)
ORDER BY ClientId
```

## Cell 28 (markdown)

# Clients Needing Investigation

This section summarizes privilege escalation findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when UID 0 users, risky sudoers rules, suspicious SUID/SGID files, dangerous capabilities, or suspicious root processes are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET UID0Users <=
  SELECT ClientId,
         "Non-root UID 0 User" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/UID0Users"
  )

LET PrivilegedGroups <=
  SELECT ClientId,
         "Privileged Group Membership" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/PrivilegedGroups"
  )

LET RiskySudoers <=
  SELECT ClientId,
         "Risky Sudoers Rule" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/RiskySudoersRules"
  )

LET SuspiciousSUID <=
  SELECT ClientId,
         "Suspicious SUID/SGID File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousSUIDSGIDFiles"
  )

LET SuspiciousCaps <=
  SELECT ClientId,
         "Dangerous File Capability" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousFileCapabilities"
  )

LET WorldWritable <=
  SELECT ClientId,
         "World-Writable Sensitive Path" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/SuspiciousWorldWritableFiles"
  )

LET RootProcesses <=
  SELECT ClientId,
         "Suspicious Root Process" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.PrivEsc/RootProcessIndicators"
  )

LET Findings <=
  SELECT *
  FROM chain(
    a=UID0Users,
    b=PrivilegedGroups,
    c=RiskySudoers,
    d=SuspiciousSUID,
    e=SuspiciousCaps,
    f=WorldWritable,
    g=RootProcesses
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 30 (markdown)

# Recommended Next Actions

Clients with privilege escalation indicators should be reviewed in deeper hunting phases.

Recommended follow-up actions:

1. Validate UID 0 users and remove unauthorized root-equivalent accounts.
2. Review privileged group memberships such as sudo, wheel, docker, lxd, disk, and shadow.
3. Review sudoers rules, especially NOPASSWD and broad ALL permissions.
4. Investigate suspicious SUID/SGID binaries and dangerous Linux file capabilities.
5. Review world-writable sensitive paths for path hijacking or file replacement risk.
6. Correlate findings with authentication, process, persistence, filesystem, and log hunts.
