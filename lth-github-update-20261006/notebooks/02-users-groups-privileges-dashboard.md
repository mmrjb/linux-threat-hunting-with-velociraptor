# LTH - 02 - Users Groups and Privileges Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 02 - Users, Groups, and Privileges Dashboard

This notebook analyzes Linux user, group, and privilege data collected by:

`LTH.UsersPrivileges`

Main objectives:

- Review local Linux users
- Review local groups and memberships
- Identify interactive users
- Identify UID 0 accounts
- Identify users with sudo/root-level access
- Review sudoers rules
- Detect suspicious accounts and privilege configurations
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Identity Collection and Coverage Summary

## Cell 3 (vql)

```vql
-- ============================================================
-- LTH - 02 - Users, Groups and Privileges Dashboard
-- Cell: Identity Collection and Coverage Summary
--
-- Purpose:
--   * Collection/coverage visibility only
--   * No alert, severity or risk decision is produced here
--   * Interactive, UID 0 and privileged membership values are
--     inventory counters, not suspicious findings
-- ============================================================

LET HuntId <= "HUNT_ID"
LET BaselineHuntId <= "BASELINE_HUNT_ID"

-- Identity sources belong to LTH.UsersPrivileges. BaselineHuntId
-- supplies the independent fleet anchor from LTH.SystemBaseline.
LET UsersSource <= "LTH.UsersPrivileges/Users"
LET GroupsSource <= "LTH.UsersPrivileges/Groups"
LET SudoersSource <= "LTH.UsersPrivileges/SudoersRules"

LET ExpectedSources <= 3
LET CoreExpectedSources <= 2


-- ============================================================
-- 1. Fleet anchor
-- ============================================================

LET FleetRaw <=
SELECT ClientId,
       Fqdn
FROM hunt_results(
  hunt_id=BaselineHuntId,
  artifact="LTH.SystemBaseline/Client_BasicInformation"
)

LET Fleet <=
SELECT ClientId AS FleetClientId,
       Fqdn AS FleetFqdn
FROM FleetRaw
GROUP BY ClientId


-- ============================================================
-- 2. Users: normalize field-name differences and deduplicate
-- ============================================================

LET UserRows <=
SELECT ClientId AS UserClientId,
       Fqdn AS UserFqdn,

       str(str=(
         get(item=scope(), member="Name")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS UserName,

       (
         str(str=get(item=scope(), member="Uid"))
         ||
         str(str=get(item=scope(), member="UID"))
       ) AS UserUid,

       (
         str(str=get(item=scope(), member="Gid"))
         ||
         str(str=get(item=scope(), member="GID"))
       ) AS UserGid,

       str(str=(
         get(item=scope(), member="Homedir")
         ||
         get(item=scope(), member="HomeDir")
         ||
         get(item=scope(), member="Home")
       )) AS HomeDir,

       str(str=(
         get(item=scope(), member="Shell")
         ||
         get(item=scope(), member="LoginShell")
       )) AS UserShell

FROM hunt_results(
  hunt_id=HuntId,
  artifact=UsersSource
)

LET UserRowsKeyed <=
SELECT *,
       format(
         format="%v|%v|%v|%v|%v",
         args=[UserClientId, UserName, UserUid, HomeDir, UserShell]
       ) AS UserKey
FROM UserRows
WHERE UserName

LET UniqueUsers <=
SELECT UserClientId,
       UserFqdn,
       UserName,
       UserUid,
       UserGid,
       HomeDir,
       UserShell
FROM UserRowsKeyed
GROUP BY UserKey


-- ============================================================
-- 3. Groups: normalize field-name differences and deduplicate
-- ============================================================

LET GroupRows <=
SELECT ClientId AS GroupClientId,
       Fqdn AS GroupFqdn,

       str(str=(
         get(item=scope(), member="GroupName")
         ||
         get(item=scope(), member="Group")
         ||
         get(item=scope(), member="Name")
       )) AS GroupName,

       (
         str(str=get(item=scope(), member="Gid"))
         ||
         str(str=get(item=scope(), member="GID"))
       ) AS GroupGid,

       (
         get(item=scope(), member="Members")
         ||
         get(item=scope(), member="Users")
         ||
         get(item=scope(), member="MemberList")
       ) AS GroupMembers,

       str(str=(
         get(item=scope(), member="Member")
         ||
         get(item=scope(), member="User")
         ||
         get(item=scope(), member="Username")
       )) AS DirectMember

FROM hunt_results(
  hunt_id=HuntId,
  artifact=GroupsSource
)

LET GroupRowsKeyed <=
SELECT *,
       format(
         format="%v|%v|%v|%v|%v",
         args=[
           GroupClientId,
           GroupName,
           GroupGid,
           str(str=GroupMembers),
           DirectMember
         ]
       ) AS GroupKey
FROM GroupRows
WHERE GroupName

LET UniqueGroups <=
SELECT GroupClientId,
       GroupFqdn,
       GroupName,
       GroupGid,
       GroupMembers,
       DirectMember
FROM GroupRowsKeyed
GROUP BY GroupKey


-- ============================================================
-- 4. Privileged group memberships
--
-- The source may expose either:
--   * one row per member (Member/User/Username), or
--   * an array/comma-separated Members field.
-- This block supports both layouts.
-- ============================================================

LET PrivilegedGroups <=
SELECT *,
       if(
         condition=DirectMember,
         then=(DirectMember, ),
         else=split(
           string=regex_replace(
             source=str(str=GroupMembers),
             re='''[\[\]"]|\s+''',
             replace=""
           ),
           sep=","
         )
       ) AS NormalizedMemberList
FROM UniqueGroups
WHERE GroupName =~ '''(?i)^(sudo|wheel|admin|root|adm|operator)$'''

LET PrivilegedMembershipRows <=
SELECT *
FROM foreach(
  row=PrivilegedGroups,
  query={
    SELECT GroupClientId,
           GroupFqdn,
           GroupName,
           str(str=_value) AS Member
    FROM foreach(row=NormalizedMemberList)
    WHERE _value
      AND NOT _value =~ '''(?i)^(null|<null>)$'''
  }
)

LET PrivilegedMembershipRowsKeyed <=
SELECT *,
       format(
         format="%v|%v|%v",
         args=[GroupClientId, GroupName, Member]
       ) AS MembershipKey
FROM PrivilegedMembershipRows

LET UniquePrivilegedMemberships <=
SELECT GroupClientId,
       GroupFqdn,
       GroupName,
       Member
FROM PrivilegedMembershipRowsKeyed
GROUP BY MembershipKey


-- ============================================================
-- 5. Sudoers rules
-- ============================================================

LET SudoersRows <=
SELECT ClientId AS SudoClientId,
       Fqdn AS SudoFqdn,
       *
FROM hunt_results(
  hunt_id=HuntId,
  artifact=SudoersSource
)


-- ============================================================
-- 6. Per-client metrics
-- ============================================================

LET CoverageBase <=
SELECT FleetClientId AS ClientId,
       FleetFqdn AS Fqdn,

       len(list={
         SELECT UserName
         FROM UniqueUsers
         WHERE UserClientId = FleetClientId
       }) AS TotalUsers,

       len(list={
         SELECT UserName
         FROM UniqueUsers
         WHERE UserClientId = FleetClientId
           AND UserShell
           AND NOT UserShell =~
             '''(?i)/(nologin|false|sync|shutdown|halt)$'''
       }) AS InteractiveUsers,

       len(list={
         SELECT UserName
         FROM UniqueUsers
         WHERE UserClientId = FleetClientId
           AND UserUid =~ '''^0$'''
       }) AS UID0Accounts,

       len(list={
         SELECT GroupName
         FROM UniqueGroups
         WHERE GroupClientId = FleetClientId
       }) AS TotalGroups,

       len(list={
         SELECT Member
         FROM UniquePrivilegedMemberships
         WHERE GroupClientId = FleetClientId
       }) AS PrivilegedGroupMembers,

       len(list={
         SELECT *
         FROM SudoersRows
         WHERE SudoClientId = FleetClientId
       }) AS SudoersRuleCount

FROM Fleet


-- ============================================================
-- 7. Source presence and collection status
-- ============================================================

LET CoverageWithPresence <=
SELECT *,
       TotalUsers > 0 AS UsersCollected,
       TotalGroups > 0 AS GroupsCollected,
       SudoersRuleCount > 0 AS SudoersCollected
FROM CoverageBase

LET CoverageWithCounts <=
SELECT *,
       (
         if(condition=UsersCollected, then=1, else=0)
         +
         if(condition=GroupsCollected, then=1, else=0)
         +
         if(condition=SudoersCollected, then=1, else=0)
       ) AS CollectedSources
FROM CoverageWithPresence


-- ============================================================
-- 8. Final output
-- ============================================================

SELECT ClientId,
       Fqdn,
       TotalUsers,
       InteractiveUsers,
       UID0Accounts,
       TotalGroups,
       PrivilegedGroupMembers,
       SudoersRuleCount,
       UsersCollected,
       GroupsCollected,
       SudoersCollected,
       CollectedSources,
       ExpectedSources,
       CoreExpectedSources,

       if(
         condition=UsersCollected AND GroupsCollected AND SudoersCollected,
         then="Complete",
         else=if(
           condition=NOT UsersCollected AND NOT GroupsCollected,
           then="Collection Gap - Users and Groups missing",
           else=if(
             condition=NOT UsersCollected,
             then="Collection Review - Users missing",
             else=if(
               condition=NOT GroupsCollected,
               then="Collection Review - Groups missing",
               else="Core Complete - Sudoers empty or not collected"
             )
           )
         )
       ) AS CollectionStatus

FROM CoverageWithCounts
ORDER BY Fqdn

```

## Cell 4 (markdown)

# Users Inventory

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       User,
       Description,
       Uid,
       Gid,
       Homedir,
       Shell
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/Users"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Interactive Users Inventory

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       User,
       Description,
       Uid,
       Gid,
       Homedir,
       Shell
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/InteractiveUsers"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# UID 0 Account Review

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       User,
       Description,
       int(int=Uid) AS Uid,
       int(int=Gid) AS Gid,
       Homedir,
       Shell,
       "HIGH" AS Severity,
       "Unexpected non-root account has UID 0" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/Users"
)
WHERE int(int=Uid) = 0
  AND User != "root"
ORDER BY ClientId
```

## Cell 10 (markdown)

# Groups Inventory and Explicit Memberships

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Group,
       GID,
       Members
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/Groups"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Privileged Group Membership Review

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Group,
       GID,
       Members,
       if(
         condition=Group =~ "^(docker|lxd)$",
         then="ROOT-EQUIVALENT",
         else=if(
           condition=Group =~ "^(sudo|wheel|admin)$",
           then="ADMINISTRATIVE",
           else="SENSITIVE-ACCESS"
         )
       ) AS PrivilegeClass,
       if(
         condition=Group =~ "^(docker|lxd)$",
         then="Container management access may provide root-equivalent control",
         else=if(
           condition=Group =~ "^(sudo|wheel|admin)$",
           then="Administrative group membership",
           else="Access to sensitive logs or root-owned resources"
         )
       ) AS AccessContext,
       "Validate membership against the approved identity baseline"
         AS ReviewAction
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/Groups"
)
WHERE Group =~ "^(sudo|wheel|root|admin|docker|lxd|adm)$"
  AND Members
ORDER BY ClientId
```

## Cell 14 (markdown)

# Sudoers Rules Inventory

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       if(
         condition=Line =~ "(?i)^[[:space:]]*Defaults([[:space:]]|$)",
         then="Defaults",
         else=if(
           condition=Line =~ "(?i)^[[:space:]]*(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)([[:space:]]|$)",
           then="Alias",
           else=if(
             condition=Line =~ "(?i)^[[:space:]]*(#include|#includedir|@include|@includedir)([[:space:]]|$)",
             then="Include",
             else="PrivilegeRule"
           )
         )
       ) AS EntryType,
       HasNOPASSWD,
       HasALL,
       HasRiskyCommand,
       Line
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/SudoersRules"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# High-Risk Sudoers Review

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       RuleType,
       HasNOPASSWD,
       HasALL,
       HasRiskyCommand,
       Line,
       if(
         condition=HasRiskyCommand = "Yes",
         then="HIGH",
         else=if(
           condition=HasNOPASSWD = "Yes"
                     AND Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$",
           then="HIGH",
           else="REVIEW"
         )
       ) AS RiskLevel,
       if(
         condition=HasRiskyCommand = "Yes"
                   AND HasNOPASSWD = "Yes",
         then="Dangerous sudo command allowed without password",
         else=if(
           condition=HasRiskyCommand = "Yes",
           then="Dangerous command may provide privileged execution",
           else=if(
             condition=HasNOPASSWD = "Yes"
                       AND Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$",
             then="Unrestricted NOPASSWD sudo access",
             else="Non-baseline unrestricted sudo rule"
           )
         )
       ) AS Reason,
       "Validate authorization, business purpose, permitted command, file writability and related sudo usage"
         AS ReviewAction
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/SudoersRules"
)
WHERE NOT Line =~ "(?i)^[[:space:]]*root[[:space:]]+"
  AND (
       HasRiskyCommand = "Yes"

       OR (
         HasNOPASSWD = "Yes"
         AND Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$"
       )

       OR (
         Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$"
         AND NOT Line =~ "(?i)^[[:space:]]*%(sudo|wheel|admin)[[:space:]]+ALL[[:space:]]*=[[:space:]]*[(]ALL(:ALL)?[)][[:space:]]+ALL[[:space:]]*$"
       )
  )
ORDER BY ClientId
```

## Cell 18 (markdown)

# Suspicious Users Summary

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       User,
       Description,
       int(int=Uid) AS Uid,
       int(int=Gid) AS Gid,
       Homedir,
       Shell,

       if(
         condition=int(int=Uid) = 0
                   AND User != "root",
         then="HIGH",
         else=if(
           condition=Homedir =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
                     AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$",
           then="MEDIUM",
           else="REVIEW"
         )
       ) AS Severity,

       if(
         condition=int(int=Uid) = 0
                   AND User != "root",
         then="Unexpected non-root account has UID 0",
         else=if(
           condition=(
                       (
                         int(int=Uid) > 0
                         AND int(int=Uid) < 1000
                       )
                       OR User =~ "(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$"
                     )
                     AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$",
           then="System or service account has a login-capable shell",
           else=if(
             condition=Homedir =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
                       AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$",
             then="Login-capable account uses a temporary home directory",
             else="Account uses an unusual temporary home directory"
           )
         )
       ) AS Reason,

       "Validate account authorization, expected shell, home directory, authentication activity and related process execution"
         AS ReviewAction

FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.UsersPrivileges/Users"
)

WHERE (
        int(int=Uid) = 0
        AND User != "root"
      )

   OR (
        (
          (
            int(int=Uid) > 0
            AND int(int=Uid) < 1000
          )
          OR User =~ "(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$"
        )
        AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$"
      )

   OR Homedir =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"

ORDER BY ClientId
```

## Cell 20 (markdown)

# Final Findings Detail

This section combines suspicious indicators from users, groups, and sudoers rules into one findings table.

Each row represents a privilege-related issue that should be reviewed by the analyst, including UID 0 users, risky sudoers rules, sensitive group memberships, and suspicious interactive accounts.

Use this table as the main evidence view for user and privilege hunting.

## Cell 21 (vql)

```vql
-- ============================================================
-- Final Findings Detail
-- Users, Groups and Privileges
--
-- Risk Score Owner:
--   Each unique FindingKey may be counted once in this cell.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Account evidence
-- ============================================================

LET AccountSignals <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    User,
    Uid,
    Gid,
    Homedir,
    Shell,

    (
      int(int=Uid) = 0
      AND User != "root"
    ) AS UnexpectedUID0,

    (
      Homedir =~ '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''
      AND Shell =~ '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    ) AS TemporaryInteractiveAccount,

    (
      (
        (
          int(int=Uid) > 0
          AND int(int=Uid) < 1000
        )

        OR User =~
          '''(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$'''
      )

      AND Shell =~
        '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    ) AS ServiceAccountLoginShell,

    Homedir =~
      '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''
      AS TemporaryHomeDirectory

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/Users"
  )

  WHERE
    (
      int(int=Uid) = 0
      AND User != "root"
    )

    OR

    (
      (
        (
          int(int=Uid) > 0
          AND int(int=Uid) < 1000
        )

        OR User =~
          '''(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$'''
      )

      AND Shell =~
        '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    )

    OR Homedir =~
      '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''


LET AccountClassified <=
  SELECT
    *,

    if(
      condition=UnexpectedUID0,

      then="UNEXPECTED_UID0_ACCOUNT",

      else=if(
        condition=TemporaryInteractiveAccount,

        then="TEMP_HOME_INTERACTIVE_ACCOUNT",

        else=if(
          condition=ServiceAccountLoginShell,

          then="SERVICE_ACCOUNT_LOGIN_SHELL",
          else="TEMP_HOME_ACCOUNT_CONFIGURATION"
        )
      )
    ) AS DetectionClass,

    if(
      condition=UnexpectedUID0,

      then="HIGH",

      else=if(
        condition=TemporaryInteractiveAccount,

        then="MEDIUM",
        else="REVIEW"
      )
    ) AS Severity,

    if(
      condition=UnexpectedUID0,

      then="Unexpected non-root account has UID 0",

      else=if(
        condition=TemporaryInteractiveAccount,

        then="Login-capable account uses a temporary home directory",

        else=if(
          condition=ServiceAccountLoginShell,

          then="System or service account has a login-capable shell",
          else="Account uses an unusual temporary home directory"
        )
      )
    ) AS Finding

  FROM AccountSignals


LET AccountFindings <=
  SELECT
    ClientId,
    Fqdn,
    Severity,
    DetectionClass,
    Finding,

    User AS Subject,

    format(
      format="user=%v | uid=%v | gid=%v | home=%v | shell=%v",
      args=[
        User,
        Uid,
        Gid,
        Homedir,
        Shell
      ]
    ) AS PrimaryEvidence,

    User AS Evidence1,
    Homedir AS Evidence2,
    Shell AS Evidence3,

    format(
      format="IDENTITY|%v|%v|%v|%v|%v|%v",
      args=[
        ClientId,
        DetectionClass,
        User,
        Uid,
        Homedir,
        Shell
      ]
    ) AS FindingKey,

    "Final Findings Detail - count each FindingKey once"
      AS RiskScoreOwner

  FROM AccountClassified


-- ============================================================
-- 2. Sudoers evidence
-- ============================================================

LET SudoersSignals <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    Path,
    RuleType,
    Line,
    HasRiskyCommand,
    HasNOPASSWD

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/SudoersRules"
  )

  WHERE NOT Line =~
    '''(?i)^[[:space:]]*root[[:space:]]+'''

    AND
    (
      HasRiskyCommand = "Yes"

      OR

      (
        HasNOPASSWD = "Yes"

        AND Line =~
          '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''
      )

      OR

      (
        Line =~
          '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''

        AND NOT Line =~
          '''(?i)^[[:space:]]*%(sudo|wheel|admin)[[:space:]]+ALL[[:space:]]*=[[:space:]]*[(]ALL(:ALL)?[)][[:space:]]+ALL[[:space:]]*$'''
      )
    )


LET SudoersClassified <=
  SELECT
    *,

    if(
      condition=
        HasRiskyCommand = "Yes"
        AND HasNOPASSWD = "Yes",

      then="DANGEROUS_NOPASSWD_SUDO_COMMAND",

      else=if(
        condition=HasRiskyCommand = "Yes",

        then="DANGEROUS_SUDO_COMMAND",

        else=if(
          condition=
            HasNOPASSWD = "Yes"

            AND Line =~
              '''(?i)([[:space:]]|:)ALL[[:space:]]*$''',

          then="UNRESTRICTED_NOPASSWD_ALL",
          else="BROAD_NON_BASELINE_SUDO_RULE"
        )
      )
    ) AS DetectionClass,

    if(
      condition=
        HasRiskyCommand = "Yes"

        OR
        (
          HasNOPASSWD = "Yes"

          AND Line =~
            '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''
        ),

      then="HIGH",
      else="REVIEW"
    ) AS Severity,

    if(
      condition=
        HasRiskyCommand = "Yes"
        AND HasNOPASSWD = "Yes",

      then="Dangerous sudo command allowed without password",

      else=if(
        condition=HasRiskyCommand = "Yes",

        then="Dangerous command may provide privileged execution",

        else=if(
          condition=
            HasNOPASSWD = "Yes"

            AND Line =~
              '''(?i)([[:space:]]|:)ALL[[:space:]]*$''',

          then="Unrestricted NOPASSWD sudo access",
          else="Broad sudo access requires authorization review"
        )
      )
    ) AS Finding

  FROM SudoersSignals


LET RiskySudoers <=
  SELECT
    ClientId,
    Fqdn,
    Severity,
    DetectionClass,
    Finding,

    format(
      format="%v | %v",
      args=[
        Path,
        RuleType
      ]
    ) AS Subject,

    Line AS PrimaryEvidence,

    Path AS Evidence1,
    RuleType AS Evidence2,
    Line AS Evidence3,

    format(
      format="SUDOERS|%v|%v|%v|%v",
      args=[
        ClientId,
        DetectionClass,
        Path,
        Line
      ]
    ) AS FindingKey,

    "Final Findings Detail - count each FindingKey once"
      AS RiskScoreOwner

  FROM SudoersClassified


-- ============================================================
-- 3. Combine and deduplicate findings
-- ============================================================

LET AllFindings <=
  SELECT *
  FROM chain(
    a=AccountFindings,
    b=RiskySudoers
  )


LET PrioritizedFindings <=
  SELECT
    *,

    if(
      condition=Severity = "HIGH",

      then=100,

      else=if(
        condition=Severity = "MEDIUM",

        then=70,
        else=40
      )
    ) AS FindingRank

  FROM AllFindings

  ORDER BY FindingRank DESC


LET UniqueFindings <=
  SELECT *
  FROM PrioritizedFindings
  GROUP BY FindingKey


SELECT
  ClientId,
  Fqdn,
  Severity,
  DetectionClass,
  Finding,
  Subject,
  PrimaryEvidence,
  Evidence1,
  Evidence2,
  Evidence3,
  FindingKey,
  RiskScoreOwner

FROM UniqueFindings

ORDER BY FindingRank DESC
```

## Cell 22 (markdown)

# Clients Needing Investigation

This section summarizes the number of privilege-related findings per client.

Clients with a higher finding count should be prioritized for deeper investigation, especially if they contain UID 0 users, NOPASSWD sudo rules, or sensitive group memberships.

This view helps analysts quickly identify which Linux endpoints require follow-up hunting.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET AccountFindings <=
  SELECT ClientId,

         if(
           condition=int(int=Uid) = 0
                     AND User != "root",
           then="Unexpected non-root account has UID 0",
           else=if(
             condition=Homedir =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"
                       AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$",
             then="Login-capable account uses a temporary home directory",
             else=if(
               condition=(
                           (
                             int(int=Uid) > 0
                             AND int(int=Uid) < 1000
                           )
                           OR User =~ "(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$"
                         )
                         AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$",
               then="System or service account has a login-capable shell",
               else="Account uses an unusual temporary home directory"
             )
           )
         ) AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/Users"
  )

  WHERE (
          int(int=Uid) = 0
          AND User != "root"
        )

     OR (
          (
            (
              int(int=Uid) > 0
              AND int(int=Uid) < 1000
            )
            OR User =~ "(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$"
          )
          AND Shell =~ "(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$"
        )

     OR Homedir =~ "(?i)^/(tmp|var/tmp|dev/shm)(/|$)"


LET RiskySudoers <=
  SELECT ClientId,

         if(
           condition=HasRiskyCommand = "Yes"
                     AND HasNOPASSWD = "Yes",
           then="Dangerous sudo command allowed without password",
           else=if(
             condition=HasRiskyCommand = "Yes",
             then="Dangerous command may provide privileged execution",
             else=if(
               condition=HasNOPASSWD = "Yes"
                         AND Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$",
               then="Unrestricted NOPASSWD sudo access",
               else="Broad sudo access requires authorization review"
             )
           )
         ) AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/SudoersRules"
  )

  WHERE NOT Line =~ "(?i)^[[:space:]]*root[[:space:]]+"

    AND (
         HasRiskyCommand = "Yes"

         OR (
           HasNOPASSWD = "Yes"
           AND Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$"
         )

         OR (
           Line =~ "(?i)([[:space:]]|:)ALL[[:space:]]*$"
           AND NOT Line =~ "(?i)^[[:space:]]*%(sudo|wheel|admin)[[:space:]]+ALL[[:space:]]*=[[:space:]]*[(]ALL(:ALL)?[)][[:space:]]+ALL[[:space:]]*$"
         )
    )


LET Findings <=
  SELECT *
  FROM chain(
    a=AccountFindings,
    b=RiskySudoers
  )


SELECT ClientId,
       count() AS ActionableFindingCount
FROM Findings
GROUP BY ClientId
ORDER BY ActionableFindingCount DESC
```

## Cell 24 (markdown)

# Investigation Pivot Queue — Dynamic Identity and Privilege Routes

## Cell 25 (vql)

```vql
-- ============================================================
-- Investigation Pivot Queue
-- Users, Groups and Privileges
--
-- Standalone version:
--   * No NotebookId
--   * No FinalFindingsCellId
--   * No PivotGuideCellId
--   * Reads directly from Hunt results
--   * Recreates the Final Findings classifications
--   * Applies all 8 investigation routes in this cell
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Account evidence
-- ============================================================

LET AccountSignals <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    User,
    Uid,
    Gid,
    Homedir,
    Shell,

    (
      int(int=Uid) = 0
      AND User != "root"
    ) AS UnexpectedUID0,

    (
      Homedir =~ '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''
      AND Shell =~ '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    ) AS TemporaryInteractiveAccount,

    (
      (
        (
          int(int=Uid) > 0
          AND int(int=Uid) < 1000
        )

        OR User =~
          '''(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$'''
      )

      AND Shell =~
        '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    ) AS ServiceAccountLoginShell,

    Homedir =~
      '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''
      AS TemporaryHomeDirectory

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/Users"
  )

  WHERE
    (
      int(int=Uid) = 0
      AND User != "root"
    )

    OR

    (
      (
        (
          int(int=Uid) > 0
          AND int(int=Uid) < 1000
        )

        OR User =~
          '''(?i)^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|nobody|postgres|mysql|nginx|apache|sshd|ftp|backup)$'''
      )

      AND Shell =~
        '''(?i)/(bash|dash|ash|sh|zsh|ksh|csh|tcsh|fish)$'''
    )

    OR Homedir =~
      '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''


LET AccountClassified <=
  SELECT
    *,

    if(
      condition=UnexpectedUID0,
      then="UNEXPECTED_UID0_ACCOUNT",
      else=if(
        condition=TemporaryInteractiveAccount,
        then="TEMP_HOME_INTERACTIVE_ACCOUNT",
        else=if(
          condition=ServiceAccountLoginShell,
          then="SERVICE_ACCOUNT_LOGIN_SHELL",
          else="TEMP_HOME_ACCOUNT_CONFIGURATION"
        )
      )
    ) AS DetectionClass,

    if(
      condition=UnexpectedUID0,
      then="HIGH",
      else=if(
        condition=TemporaryInteractiveAccount,
        then="MEDIUM",
        else="REVIEW"
      )
    ) AS Severity,

    if(
      condition=UnexpectedUID0,
      then="Unexpected non-root account has UID 0",
      else=if(
        condition=TemporaryInteractiveAccount,
        then="Login-capable account uses a temporary home directory",
        else=if(
          condition=ServiceAccountLoginShell,
          then="System or service account has a login-capable shell",
          else="Account uses an unusual temporary home directory"
        )
      )
    ) AS Finding

  FROM AccountSignals


LET AccountFindings <=
  SELECT
    ClientId,
    Fqdn,
    Severity,
    DetectionClass,
    Finding,
    User AS Subject,

    format(
      format="user=%v | uid=%v | gid=%v | home=%v | shell=%v",
      args=[User, Uid, Gid, Homedir, Shell]
    ) AS PrimaryEvidence,

    User AS Evidence1,
    Homedir AS Evidence2,
    Shell AS Evidence3,

    format(
      format="IDENTITY|%v|%v|%v|%v|%v|%v",
      args=[ClientId, DetectionClass, User, Uid, Homedir, Shell]
    ) AS FindingKey,

    "Final Findings Detail - count each FindingKey once"
      AS RiskScoreOwner

  FROM AccountClassified


-- ============================================================
-- 2. Sudoers evidence
-- ============================================================

LET SudoersSignals <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.fqdn AS Fqdn,

    Path,
    RuleType,
    Line,
    HasRiskyCommand,
    HasNOPASSWD

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.UsersPrivileges/SudoersRules"
  )

  WHERE NOT Line =~
    '''(?i)^[[:space:]]*root[[:space:]]+'''

    AND
    (
      HasRiskyCommand = "Yes"

      OR

      (
        HasNOPASSWD = "Yes"
        AND Line =~
          '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''
      )

      OR

      (
        Line =~
          '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''

        AND NOT Line =~
          '''(?i)^[[:space:]]*%(sudo|wheel|admin)[[:space:]]+ALL[[:space:]]*=[[:space:]]*[(]ALL(:ALL)?[)][[:space:]]+ALL[[:space:]]*$'''
      )
    )


LET SudoersClassified <=
  SELECT
    *,

    if(
      condition=
        HasRiskyCommand = "Yes"
        AND HasNOPASSWD = "Yes",
      then="DANGEROUS_NOPASSWD_SUDO_COMMAND",
      else=if(
        condition=HasRiskyCommand = "Yes",
        then="DANGEROUS_SUDO_COMMAND",
        else=if(
          condition=
            HasNOPASSWD = "Yes"
            AND Line =~
              '''(?i)([[:space:]]|:)ALL[[:space:]]*$''',
          then="UNRESTRICTED_NOPASSWD_ALL",
          else="BROAD_NON_BASELINE_SUDO_RULE"
        )
      )
    ) AS DetectionClass,

    if(
      condition=
        HasRiskyCommand = "Yes"
        OR
        (
          HasNOPASSWD = "Yes"
          AND Line =~
            '''(?i)([[:space:]]|:)ALL[[:space:]]*$'''
        ),
      then="HIGH",
      else="REVIEW"
    ) AS Severity,

    if(
      condition=
        HasRiskyCommand = "Yes"
        AND HasNOPASSWD = "Yes",
      then="Dangerous sudo command allowed without password",
      else=if(
        condition=HasRiskyCommand = "Yes",
        then="Dangerous command may provide privileged execution",
        else=if(
          condition=
            HasNOPASSWD = "Yes"
            AND Line =~
              '''(?i)([[:space:]]|:)ALL[[:space:]]*$''',
          then="Unrestricted NOPASSWD sudo access",
          else="Broad sudo access requires authorization review"
        )
      )
    ) AS Finding

  FROM SudoersSignals


LET RiskySudoers <=
  SELECT
    ClientId,
    Fqdn,
    Severity,
    DetectionClass,
    Finding,

    format(
      format="%v | %v",
      args=[Path, RuleType]
    ) AS Subject,

    Line AS PrimaryEvidence,
    Path AS Evidence1,
    RuleType AS Evidence2,
    Line AS Evidence3,

    format(
      format="SUDOERS|%v|%v|%v|%v",
      args=[ClientId, DetectionClass, Path, Line]
    ) AS FindingKey,

    "Final Findings Detail - count each FindingKey once"
      AS RiskScoreOwner

  FROM SudoersClassified


-- ============================================================
-- 3. Combine, rank and deduplicate findings
-- ============================================================

LET AllFindings <=
  SELECT *
  FROM chain(
    accounts=AccountFindings,
    sudoers=RiskySudoers
  )


LET PrioritizedFindings <=
  SELECT
    *,

    if(
      condition=Severity = "HIGH",
      then=100,
      else=if(
        condition=Severity = "MEDIUM",
        then=70,
        else=40
      )
    ) AS FindingRank

  FROM AllFindings

  ORDER BY FindingRank DESC


LET UniqueFindings <=
  SELECT *
  FROM PrioritizedFindings
  GROUP BY FindingKey


-- ============================================================
-- 4. Static route catalog inside this standalone cell
-- ============================================================

LET IdentityPrivilegeRoutes <=
  SELECT *

  FROM chain(

    unexpected_uid0={
      SELECT
        100 AS RouteRank,
        "UNEXPECTED_UID0_ACCOUNT" AS RouteDetectionClass,
        "ROOT_EQUIVALENT_IDENTITY_REVIEW" AS RouteClass,
        "DIRECT_ACCOUNT_CONFIGURATION" AS EvidenceRole,
        "LTH - 03 - Authentication and SSH Dashboard" AS PrimaryNotebook,
        "Validate authentication sources, activity and authorization for the UID 0 account." AS PrimaryChecks,
        "LTH - 04 - Processes and Services Dashboard -> LTH - 08 - Logs and Security Events Dashboard" AS SecondaryNotebook,
        "Correlate processes, services, sudo or su activity, account changes and persistence." AS SecondaryChecks,
        "Confirm the account against /etc/passwd and the approved identity baseline." AS ValidationBeforePivot,
        "Escalate when unauthorized, newly introduced or correlated with suspicious activity." AS EscalateWhen,
        "OBSERVED_CONFIGURATION_REQUIRES_AUTHORIZATION_CHECK" AS VerificationStatus,
        "Count each FindingKey once as HIGH in Final Findings Detail." AS RiskScoreImpact
      FROM scope()
    },

    dangerous_nopasswd={
      SELECT
        95 AS RouteRank,
        "DANGEROUS_NOPASSWD_SUDO_COMMAND" AS RouteDetectionClass,
        "PASSWORDLESS_PRIVILEGE_ESCAPE_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,
        "LTH - 08 - Logs and Security Events Dashboard" AS PrimaryNotebook,
        "Identify the principal and correlate the rule with sudo execution and command history." AS PrimaryChecks,
        "LTH - 04 - Processes and Services Dashboard -> LTH - 09 - Privilege Escalation Indicators Dashboard" AS SecondaryNotebook,
        "Review privileged child processes, command arguments and resulting system changes." AS SecondaryChecks,
        "Validate the effective rule with visudo and sudo -l for the affected identity." AS ValidationBeforePivot,
        "Escalate when unauthorized, escape-capable or used suspiciously." AS EscalateWhen,
        "EFFECTIVE_RULE_AND_AUTHORIZATION_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as HIGH in Final Findings Detail." AS RiskScoreImpact
      FROM scope()
    },

    unrestricted_nopasswd={
      SELECT
        90 AS RouteRank,
        "UNRESTRICTED_NOPASSWD_ALL" AS RouteDetectionClass,
        "UNRESTRICTED_PASSWORDLESS_SUDO_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,
        "LTH - 08 - Logs and Security Events Dashboard" AS PrimaryNotebook,
        "Review the affected principal, sudo activity and passwordless privileged commands." AS PrimaryChecks,
        "LTH - 04 - Processes and Services Dashboard -> LTH - 09 - Privilege Escalation Indicators Dashboard" AS SecondaryNotebook,
        "Correlate the rule with privileged shells, processes, services and persistence." AS SecondaryChecks,
        "Confirm RunAs and command scope with visudo and sudo -l and compare with baseline." AS ValidationBeforePivot,
        "Escalate when unauthorized, newly added or correlated with suspicious execution." AS EscalateWhen,
        "EFFECTIVE_RULE_AND_AUTHORIZATION_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as HIGH in Final Findings Detail." AS RiskScoreImpact
      FROM scope()
    },

    dangerous_sudo={
      SELECT
        85 AS RouteRank,
        "DANGEROUS_SUDO_COMMAND" AS RouteDetectionClass,
        "PRIVILEGED_COMMAND_ESCAPE_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,
        "LTH - 08 - Logs and Security Events Dashboard" AS PrimaryNotebook,
        "Determine whether the permitted command was executed with sudo and by which identity." AS PrimaryChecks,
        "LTH - 04 - Processes and Services Dashboard -> LTH - 07 - File System and Timeline Analysis Dashboard" AS SecondaryNotebook,
        "Review child processes, shell escapes and privileged file changes." AS SecondaryChecks,
        "Confirm effective command, arguments and RunAs restrictions with visudo and sudo -l." AS ValidationBeforePivot,
        "Escalate when unauthorized, escape-capable or correlated with suspicious changes." AS EscalateWhen,
        "EFFECTIVE_RULE_AND_COMMAND_BEHAVIOR_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as HIGH in Final Findings Detail." AS RiskScoreImpact
      FROM scope()
    },

    temp_interactive={
      SELECT
        75 AS RouteRank,
        "TEMP_HOME_INTERACTIVE_ACCOUNT" AS RouteDetectionClass,
        "TEMPORARY_INTERACTIVE_IDENTITY_REVIEW" AS RouteClass,
        "ACCOUNT_CONFIGURATION_WITH_LOGIN_CAPABILITY" AS EvidenceRole,
        "LTH - 03 - Authentication and SSH Dashboard" AS PrimaryNotebook,
        "Check whether the account authenticated and whether its shell is approved." AS PrimaryChecks,
        "LTH - 07 - File System and Timeline Analysis Dashboard -> LTH - 04 - Processes and Services Dashboard" AS SecondaryNotebook,
        "Inspect the temporary home, SSH material, scripts, timestamps and executed processes." AS SecondaryChecks,
        "Confirm account purpose, owner, shell, home ownership and approved baseline." AS ValidationBeforePivot,
        "Escalate when unauthorized, recently created, active or associated with suspicious files or execution." AS EscalateWhen,
        "ACCOUNT_PURPOSE_AND_ACTIVITY_VALIDATION_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as MEDIUM in Final Findings Detail." AS RiskScoreImpact
      FROM scope()
    },

    service_login_shell={
      SELECT
        60 AS RouteRank,
        "SERVICE_ACCOUNT_LOGIN_SHELL" AS RouteDetectionClass,
        "SERVICE_IDENTITY_LOGIN_REVIEW" AS RouteClass,
        "ACCOUNT_CONFIGURATION_CONTEXT" AS EvidenceRole,
        "LTH - 03 - Authentication and SSH Dashboard" AS PrimaryNotebook,
        "Determine whether the service account authenticated interactively and whether the shell is required." AS PrimaryChecks,
        "LTH - 04 - Processes and Services Dashboard -> LTH - 08 - Logs and Security Events Dashboard" AS SecondaryNotebook,
        "Review processes, services, sudo or su activity and account-change history." AS SecondaryChecks,
        "Confirm package or business owner, UID policy, shell and approved baseline." AS ValidationBeforePivot,
        "Escalate when interactive access is unauthorized, newly enabled or suspiciously used." AS EscalateWhen,
        "BASELINE_AND_ACTIVITY_VALIDATION_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as REVIEW; promote only after validation." AS RiskScoreImpact
      FROM scope()
    },

    temp_home_configuration={
      SELECT
        50 AS RouteRank,
        "TEMP_HOME_ACCOUNT_CONFIGURATION" AS RouteDetectionClass,
        "TEMPORARY_ACCOUNT_PATH_REVIEW" AS RouteClass,
        "ACCOUNT_PATH_CONFIGURATION_CONTEXT" AS EvidenceRole,
        "LTH - 07 - File System and Timeline Analysis Dashboard" AS PrimaryNotebook,
        "Inspect directory ownership, permissions, timestamps, scripts, keys and other artifacts." AS PrimaryChecks,
        "LTH - 08 - Logs and Security Events Dashboard -> LTH - 04 - Processes and Services Dashboard" AS SecondaryNotebook,
        "Review account changes, logins and processes or services associated with the identity." AS SecondaryChecks,
        "Confirm directory existence, account purpose, shell behavior and approved use." AS ValidationBeforePivot,
        "Escalate when unauthorized or associated with suspicious files, credentials, execution or persistence." AS EscalateWhen,
        "FILESYSTEM_AND_ACCOUNT_PURPOSE_VALIDATION_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as REVIEW; promote only after validation." AS RiskScoreImpact
      FROM scope()
    },

    broad_sudo={
      SELECT
        40 AS RouteRank,
        "BROAD_NON_BASELINE_SUDO_RULE" AS RouteDetectionClass,
        "BROAD_SUDO_AUTHORIZATION_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION_CONTEXT" AS EvidenceRole,
        "LTH - 08 - Logs and Security Events Dashboard" AS PrimaryNotebook,
        "Identify the affected principal and determine whether the broad rule has been used." AS PrimaryChecks,
        "LTH - 09 - Privilege Escalation Indicators Dashboard -> LTH - 04 - Processes and Services Dashboard" AS SecondaryNotebook,
        "Review effective privilege scope, privileged processes and resulting system changes." AS SecondaryChecks,
        "Validate the effective configuration with visudo and sudo -l and compare with baseline." AS ValidationBeforePivot,
        "Escalate when unauthorized, newly introduced, unnecessarily broad or suspiciously used." AS EscalateWhen,
        "AUTHORIZATION_AND_EFFECTIVE_SCOPE_REQUIRED" AS VerificationStatus,
        "Count each FindingKey once as REVIEW; promote only after validation." AS RiskScoreImpact
      FROM scope()
    }
  )


-- ============================================================
-- 5. Route each unique finding by DetectionClass
-- ============================================================

LET RoutedFindings <=
  SELECT *

  FROM foreach(
    row=UniqueFindings,

    query={
      SELECT
        FindingRank,
        ClientId,
        Fqdn,
        Severity,
        DetectionClass,
        Finding,
        Subject,
        PrimaryEvidence,
        Evidence1,
        Evidence2,
        Evidence3,
        FindingKey,
        RiskScoreOwner,

        RouteRank,
        RouteClass,
        EvidenceRole,
        PrimaryNotebook,
        PrimaryChecks,
        SecondaryNotebook,
        SecondaryChecks,
        ValidationBeforePivot,
        EscalateWhen,
        VerificationStatus,
        RiskScoreImpact

      FROM IdentityPrivilegeRoutes

      WHERE RouteDetectionClass = DetectionClass
    }
  )


-- ============================================================
-- 6. Final analyst-facing queue
-- ============================================================

SELECT
  Severity AS InvestigationPriority,
  RouteRank,
  ClientId,
  Fqdn AS EndpointHostname,
  DetectionClass,
  Finding,
  Subject,
  PrimaryEvidence,
  Evidence1,
  Evidence2,
  Evidence3,
  VerificationStatus,
  RouteClass,
  EvidenceRole,
  PrimaryNotebook,
  PrimaryChecks,
  SecondaryNotebook,
  SecondaryChecks,
  ValidationBeforePivot,
  EscalateWhen,
  "Open" AS InvestigationState,
  FindingKey,
  RiskScoreOwner,
  RiskScoreImpact

FROM RoutedFindings

ORDER BY
  RouteRank DESC
```

## Cell 26 (markdown)

# Investigation Pivot Guide — Identity and Privilege Routes

## Cell 27 (vql)

```vql
-- ============================================================
-- Investigation Pivot Guide
-- Identity and Privilege Routes
--
-- Expected output: exactly 8 static route rows.
-- This cell does not read Hunt results.
-- ============================================================

LET IdentityPrivilegeRoutes <=
  SELECT *

  FROM chain(

    unexpected_uid0={
      SELECT
        100 AS RouteRank,
        "UNEXPECTED_UID0_ACCOUNT" AS DetectionClass,
        "ROOT_EQUIVALENT_IDENTITY_REVIEW" AS RouteClass,
        "DIRECT_ACCOUNT_CONFIGURATION" AS EvidenceRole,

        "LTH - 03 - Authentication and SSH Dashboard"
          AS PrimaryNotebook,

        "Validate whether the account has authenticated, from which source, and whether its use is authorized."
          AS PrimaryChecks,

        "LTH - 04 - Processes and Services Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Correlate the account with processes, services, sudo or su activity, account changes and persistence."
          AS SecondaryChecks,

        "Confirm the UID, username, shell and home directory against /etc/passwd and the approved identity baseline."
          AS ValidationBeforePivot,

        "Escalate when the UID 0 account is unauthorized, newly introduced, login-capable or correlated with suspicious execution or persistence."
          AS EscalateWhen,

        "OBSERVED_CONFIGURATION_REQUIRES_AUTHORIZATION_CHECK"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as HIGH."
          AS RiskScoreImpact

      FROM scope()
    },


    dangerous_nopasswd={
      SELECT
        95 AS RouteRank,
        "DANGEROUS_NOPASSWD_SUDO_COMMAND" AS DetectionClass,
        "PASSWORDLESS_PRIVILEGE_ESCAPE_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Identify the affected principal and correlate the rule with sudo execution, command history and privilege-use events."
          AS PrimaryChecks,

        "LTH - 04 - Processes and Services Dashboard -> LTH - 09 - Privilege Escalation Indicators Dashboard"
          AS SecondaryNotebook,

        "Review privileged child processes, shell escape capability, command arguments and resulting system changes."
          AS SecondaryChecks,

        "Validate the exact effective rule with visudo and sudo -l for the affected identity; do not rely only on the parsed line."
          AS ValidationBeforePivot,

        "Escalate when the passwordless command is unauthorized, enables arbitrary command execution or has been used suspiciously."
          AS EscalateWhen,

        "EFFECTIVE_RULE_AND_AUTHORIZATION_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as HIGH."
          AS RiskScoreImpact

      FROM scope()
    },


    unrestricted_nopasswd={
      SELECT
        90 AS RouteRank,
        "UNRESTRICTED_NOPASSWD_ALL" AS DetectionClass,
        "UNRESTRICTED_PASSWORDLESS_SUDO_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Identify the granted principal and review sudo activity, timestamps and privileged commands executed without a password."
          AS PrimaryChecks,

        "LTH - 04 - Processes and Services Dashboard -> LTH - 09 - Privilege Escalation Indicators Dashboard"
          AS SecondaryNotebook,

        "Correlate the rule with privileged shells, processes, services and persistence changes."
          AS SecondaryChecks,

        "Confirm the effective RunAs and command scope with visudo and sudo -l, then compare it with the approved privilege baseline."
          AS ValidationBeforePivot,

        "Escalate when unrestricted NOPASSWD access is unauthorized, newly added or correlated with suspicious privileged execution."
          AS EscalateWhen,

        "EFFECTIVE_RULE_AND_AUTHORIZATION_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as HIGH."
          AS RiskScoreImpact

      FROM scope()
    },


    dangerous_sudo={
      SELECT
        85 AS RouteRank,
        "DANGEROUS_SUDO_COMMAND" AS DetectionClass,
        "PRIVILEGED_COMMAND_ESCAPE_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION" AS EvidenceRole,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Determine whether the permitted command was executed with sudo and by which identity."
          AS PrimaryChecks,

        "LTH - 04 - Processes and Services Dashboard -> LTH - 07 - File System and Timeline Analysis Dashboard"
          AS SecondaryNotebook,

        "Review child processes, command arguments, shell escapes and privileged file changes caused by the command."
          AS SecondaryChecks,

        "Confirm the effective command, argument and RunAs restrictions with visudo and sudo -l for the affected identity."
          AS ValidationBeforePivot,

        "Escalate when the command is unauthorized, permits a privileged shell or arbitrary execution, or correlates with suspicious changes."
          AS EscalateWhen,

        "EFFECTIVE_RULE_AND_COMMAND_BEHAVIOR_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as HIGH."
          AS RiskScoreImpact

      FROM scope()
    },


    temp_interactive={
      SELECT
        75 AS RouteRank,
        "TEMP_HOME_INTERACTIVE_ACCOUNT" AS DetectionClass,
        "TEMPORARY_INTERACTIVE_IDENTITY_REVIEW" AS RouteClass,
        "ACCOUNT_CONFIGURATION_WITH_LOGIN_CAPABILITY" AS EvidenceRole,

        "LTH - 03 - Authentication and SSH Dashboard"
          AS PrimaryNotebook,

        "Check whether the account authenticated, how it was created and whether its interactive shell is approved."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Inspect the temporary home directory, SSH material, scripts, timestamps and processes executed by the account."
          AS SecondaryChecks,

        "Confirm the account purpose, owner, UID, shell, home path, directory ownership and approved baseline."
          AS ValidationBeforePivot,

        "Escalate when the account is unauthorized, recently created, used for login or associated with suspicious files or execution."
          AS EscalateWhen,

        "ACCOUNT_PURPOSE_AND_ACTIVITY_VALIDATION_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as MEDIUM."
          AS RiskScoreImpact

      FROM scope()
    },


    service_login_shell={
      SELECT
        60 AS RouteRank,
        "SERVICE_ACCOUNT_LOGIN_SHELL" AS DetectionClass,
        "SERVICE_IDENTITY_LOGIN_REVIEW" AS RouteClass,
        "ACCOUNT_CONFIGURATION_CONTEXT" AS EvidenceRole,

        "LTH - 03 - Authentication and SSH Dashboard"
          AS PrimaryNotebook,

        "Determine whether the service account has authenticated interactively and whether the configured shell is required."
          AS PrimaryChecks,

        "LTH - 04 - Processes and Services Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Review the account's processes, services, sudo or su activity and account-change history."
          AS SecondaryChecks,

        "Confirm the package or business owner, expected UID policy, approved shell and service-account baseline."
          AS ValidationBeforePivot,

        "Escalate when interactive access is unauthorized, newly enabled or correlated with suspicious authentication or execution."
          AS EscalateWhen,

        "BASELINE_AND_ACTIVITY_VALIDATION_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as REVIEW and promote only after validation."
          AS RiskScoreImpact

      FROM scope()
    },


    temp_home_configuration={
      SELECT
        50 AS RouteRank,
        "TEMP_HOME_ACCOUNT_CONFIGURATION" AS DetectionClass,
        "TEMPORARY_ACCOUNT_PATH_REVIEW" AS RouteClass,
        "ACCOUNT_PATH_CONFIGURATION_CONTEXT" AS EvidenceRole,

        "LTH - 07 - File System and Timeline Analysis Dashboard"
          AS PrimaryNotebook,

        "Inspect the temporary home directory, ownership, permissions, timestamps, scripts, keys and other account artifacts."
          AS PrimaryChecks,

        "LTH - 08 - Logs and Security Events Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review account changes, logins and any processes or services associated with the identity."
          AS SecondaryChecks,

        "Confirm directory existence, account purpose, shell behavior and whether the path is approved for this identity."
          AS ValidationBeforePivot,

        "Escalate when the configuration is unauthorized or the path contains suspicious files, credentials, execution evidence or persistence."
          AS EscalateWhen,

        "FILESYSTEM_AND_ACCOUNT_PURPOSE_VALIDATION_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as REVIEW and promote only after validation."
          AS RiskScoreImpact

      FROM scope()
    },


    broad_sudo={
      SELECT
        40 AS RouteRank,
        "BROAD_NON_BASELINE_SUDO_RULE" AS DetectionClass,
        "BROAD_SUDO_AUTHORIZATION_REVIEW" AS RouteClass,
        "DECLARED_SUDO_CONFIGURATION_CONTEXT" AS EvidenceRole,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Identify the affected principal and determine whether the broad rule has been used."
          AS PrimaryChecks,

        "LTH - 09 - Privilege Escalation Indicators Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review the effective privilege scope, privileged processes and resulting system changes."
          AS SecondaryChecks,

        "Validate the complete effective configuration with visudo and sudo -l and compare it with the approved privilege baseline."
          AS ValidationBeforePivot,

        "Escalate when the rule is unauthorized, newly introduced, unnecessarily broad or correlated with suspicious privileged activity."
          AS EscalateWhen,

        "AUTHORIZATION_AND_EFFECTIVE_SCOPE_REQUIRED"
          AS VerificationStatus,

        "Final Findings Detail owns scoring; count each FindingKey once as REVIEW and promote only after validation."
          AS RiskScoreImpact

      FROM scope()
    }
  )


SELECT
  RouteRank,
  DetectionClass,
  RouteClass,
  EvidenceRole,
  PrimaryNotebook,
  PrimaryChecks,
  SecondaryNotebook,
  SecondaryChecks,
  ValidationBeforePivot,
  EscalateWhen,
  VerificationStatus,
  RiskScoreImpact

FROM IdentityPrivilegeRoutes

ORDER BY RouteRank DESC
```
