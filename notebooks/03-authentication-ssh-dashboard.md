# LTH - 03 - Authentication and SSH Activity Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 03 - Authentication and SSH Activity Dashboard

This notebook analyzes Linux authentication and SSH activity collected by:

`LTH.AuthSSH`

Main objectives:

- Review successful and failed SSH logins
- Identify invalid users and brute-force attempts
- Detect root SSH access
- Review authorized SSH keys
- Identify unencrypted private keys
- Review known_hosts relationships
- Detect risky SSH configuration
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Last User Login Inventory

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET LoginInventory <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS Hostname,

    OSPath,
    login_User,
    login_Type,
    login_Host,
    login_IpAddr,
    login_Terminal,
    login_PID,
    login_time,
    logout_time,

    if(
      condition=logout_time,
      then="Closed",
      else="No logout record"
    ) AS SessionStatus

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/LastUserLogin"
  )

SELECT ClientId,
       Hostname,
       OSPath,
       login_User,
       login_Type,
       login_Host,
       login_IpAddr,
       login_Terminal,
       login_PID,
       login_time,
       logout_time,
       SessionStatus
FROM LoginInventory
ORDER BY login_time DESC
```

## Cell 4 (markdown)

# SSH Login Activity

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SSHActivity <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS Hostname,

    /*
     * Original parsed timestamp.
     * Keep for sorting, but do not display because its year may be zero.
     */
    Time AS ParsedTime,

    if(
      condition=Time.Year = 0,
      then=format(
        format="%02d-%02d %02d:%02d:%02d",
        args=[
          Time.Month,
          Time.Day,
          Time.Hour,
          Time.Minute,
          Time.Second
        ]
      ),
      else=Time.String
    ) AS DisplayTime,

    if(
      condition=Time.Year = 0,
      then="SOURCE_YEAR_MISSING",
      else="COMPLETE_TIMESTAMP"
    ) AS TimeQuality,

    IP,
    Result,
    Method,
    AttemptedUser,

    if(
      condition=Result =~ "(?i)^accepted$"
        AND AttemptedUser =~ "(?i)^root$",
      then="SUCCESS_ROOT_REVIEW",
      else=if(
        condition=Result =~ "(?i)^accepted$",
        then="SUCCESS",
        else=if(
          condition=Result =~ "(?i)^failed$",
          then="FAILURE",
          else="OTHER"
        )
      )
    ) AS ActivityClass,

    OSPath

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

SELECT ClientId,
       Hostname,
       DisplayTime,
       TimeQuality,
       IP,
       Result,
       Method,
       AttemptedUser,
       ActivityClass,
       OSPath
FROM SSHActivity
ORDER BY DisplayTime DESC
```

## Cell 6 (markdown)

# Failed SSH Login Count per Client

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSHCounts <=
  SELECT
    ClientId,
    count() AS FailedSSHCount

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)^failed$"

  GROUP BY ClientId

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS Hostname,

  FailedSSHCount

FROM FailedSSHCounts
ORDER BY FailedSSHCount DESC
```

## Cell 8 (markdown)

# Failed SSH Login Count by Source IP

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSHBySource <=
  SELECT
    IP,
    count() AS FailedCount

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)^failed$"
    AND IP

  GROUP BY IP

SELECT
  IP AS SourceIP,
  FailedCount

FROM FailedSSHBySource
ORDER BY FailedCount DESC
```

## Cell 10 (markdown)

# Failed SSH Login Attempts

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSHDetails <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS Hostname,

    /*
     * Keep the parsed value internally for sorting.
     * Do not display it because the source timestamp has no year.
     */
    Time AS ParsedTime,

    if(
      condition=Time.Year = 0,
      then=format(
        format="%02d-%02d %02d:%02d:%02d",
        args=[
          Time.Month,
          Time.Day,
          Time.Hour,
          Time.Minute,
          Time.Second
        ]
      ),
      else=Time.String
    ) AS DisplayTime,

    if(
      condition=Time.Year = 0,
      then="SOURCE_YEAR_MISSING",
      else="COMPLETE_TIMESTAMP"
    ) AS TimeQuality,

    IP AS SourceIP,
    Result,
    Method AS AuthenticationMethod,
    AttemptedUser,
    OSPath

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)^failed$"

SELECT
  ClientId,
  Hostname,
  DisplayTime,
  TimeQuality,
  SourceIP,
  Result,
  AuthenticationMethod,
  AttemptedUser,
  OSPath,
  "SSH_LOGIN_FAILURE" AS ActivityClass

FROM FailedSSHDetails
ORDER BY DisplayTime DESC
```

## Cell 12 (markdown)

# Successful Root SSH Logins

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SuccessfulRootSSH <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS Hostname,

    /*
     * Keep internally for sorting.
     * The source Syslog timestamp may not contain a year.
     */
    Time AS ParsedTime,

    if(
      condition=Time.Year = 0,
      then=format(
        format="%02d-%02d %02d:%02d:%02d",
        args=[
          Time.Month,
          Time.Day,
          Time.Hour,
          Time.Minute,
          Time.Second
        ]
      ),
      else=Time.String
    ) AS DisplayTime,

    if(
      condition=Time.Year = 0,
      then="SOURCE_YEAR_MISSING",
      else="COMPLETE_TIMESTAMP"
    ) AS TimeQuality,

    IP AS SourceIP,
    Result,
    Method AS AuthenticationMethod,
    AttemptedUser,
    OSPath

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE AttemptedUser =~ "(?i)^root$"
    AND Result =~ "(?i)^accepted$"

SELECT
  ClientId,
  Hostname,
  DisplayTime,
  TimeQuality,
  SourceIP,
  Result,
  AuthenticationMethod,
  AttemptedUser,
  OSPath,

  "HIGH" AS ReviewPriority,
  "SUCCESSFUL_ROOT_SSH_LOGIN" AS ActivityClass,
  "Successful SSH login to root account" AS Reason

FROM SuccessfulRootSSH
ORDER BY DisplayTime DESC
```

## Cell 14 (markdown)

# Authorized SSH Keys Inventory

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET AuthorizedSSHKeys <=
  SELECT
    ClientId,
    Fqdn AS Hostname,
    OSPath,

    keytype AS KeyType,
    options AS Options,
    comment AS Comment,

    if(
      condition=OSPath =~ "(?i)^/root/",
      then="ROOT_ACCOUNT_KEY",
      else="USER_ACCOUNT_KEY"
    ) AS AccountScope,

    if(
      condition=options,
      then="KEY_OPTIONS_PRESENT",
      else="NO_PER_KEY_OPTIONS"
    ) AS OptionsStatus

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthorizedKeys"
  )

SELECT
  ClientId,
  Hostname,
  OSPath,
  AccountScope,
  KeyType,
  Options,
  OptionsStatus,
  Comment,

  if(
    condition=AccountScope = "ROOT_ACCOUNT_KEY",
    then="ELEVATED_REVIEW",
    else="STANDARD_REVIEW"
  ) AS ReviewPriority,

  if(
    condition=AccountScope = "ROOT_ACCOUNT_KEY",
    then="Authorized SSH key present for root account",
    else="Authorized SSH key present for user account"
  ) AS Reason

FROM AuthorizedSSHKeys
ORDER BY ClientId
```

## Cell 16 (markdown)

# Authorized Keys with Sensitive Options

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SensitiveAuthorizedKeys <=
  SELECT
    ClientId,
    Fqdn AS Hostname,
    OSPath,

    keytype AS KeyType,
    options AS Options,
    comment AS Comment,

    if(
      condition=OSPath =~ "(?i)^/root/",
      then="ROOT_ACCOUNT_KEY",
      else="USER_ACCOUNT_KEY"
    ) AS AccountScope,

    if(
      condition=options =~ "(?i)(^|,)cert-authority(,|$)",
      then="AUTHORIZED_KEY_CA_TRUST",
      else=if(
        condition=options =~ "(?i)(^|,)tunnel=",
        then="SSH_TUNNEL_OPTION",
        else=if(
          condition=options =~ "(?i)(^|,)environment=",
          then="SSH_ENVIRONMENT_OPTION",
          else="SSH_FORCED_COMMAND_OPTION"
        )
      )
    ) AS OptionClass

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthorizedKeys"
  )

  WHERE options =~ "(?i)(command=|environment=|tunnel=|(^|,)cert-authority(,|$))"

SELECT
  ClientId,
  Hostname,
  OSPath,
  AccountScope,
  KeyType,
  Options,
  OptionClass,
  Comment,

  if(
    condition=OptionClass =~
      "AUTHORIZED_KEY_CA_TRUST|SSH_TUNNEL_OPTION|SSH_ENVIRONMENT_OPTION",
    then="HIGH_REVIEW",
    else=if(
      condition=AccountScope = "ROOT_ACCOUNT_KEY",
      then="HIGH_REVIEW",
      else="ELEVATED_REVIEW"
    )
  ) AS ReviewPriority,

  if(
    condition=OptionClass = "AUTHORIZED_KEY_CA_TRUST",
    then="Authorized key trusts an SSH certificate authority",
    else=if(
      condition=OptionClass = "SSH_TUNNEL_OPTION",
      then="Authorized key contains SSH tunnel configuration",
      else=if(
        condition=OptionClass = "SSH_ENVIRONMENT_OPTION",
        then="Authorized key can provide environment variables",
        else="Authorized key executes a forced command"
      )
    )
  ) AS Reason

FROM SensitiveAuthorizedKeys
ORDER BY ClientId
```

## Cell 18 (markdown)

# SSH Private Keys Inventory

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SSHPrivateKeys <=
  SELECT
    ClientId,
    Fqdn AS Hostname,
    OSPath,
    KeyType,
    Cipher,
    Header,

    if(
      condition=OSPath =~ "(?i)^/root/",
      then="ROOT_ACCOUNT_KEY",
      else=if(
        condition=OSPath =~ "(?i)^/home/",
        then="USER_ACCOUNT_KEY",
        else="SERVICE_OR_SYSTEM_KEY"
      )
    ) AS AccountScope,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="UNENCRYPTED",
      else=if(
        condition=Cipher,
        then="ENCRYPTED",
        else="UNKNOWN_OR_LEGACY_FORMAT"
      )
    ) AS ProtectionStatus

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/PrivateKeys"
  )

SELECT
  ClientId,
  Hostname,
  OSPath,
  AccountScope,
  KeyType,
  Cipher,
  ProtectionStatus,
  Header,

  if(
    condition=ProtectionStatus = "UNENCRYPTED",
    then="HIGH_REVIEW",
    else=if(
      condition=AccountScope = "ROOT_ACCOUNT_KEY",
      then="ELEVATED_REVIEW",
      else="STANDARD_REVIEW"
    )
  ) AS ReviewPriority,

  if(
    condition=ProtectionStatus = "UNENCRYPTED",
    then="SSH private key is not protected by file encryption",
    else=if(
      condition=ProtectionStatus = "ENCRYPTED",
      then="Encrypted SSH private key requires authorization review",
      else="Private key protection status could not be confirmed"
    )
  ) AS Reason

FROM SSHPrivateKeys
ORDER BY ClientId
```

## Cell 20 (markdown)

# Unencrypted SSH Private Keys

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET UnencryptedSSHPrivateKeys <=
  SELECT
    ClientId,
    Fqdn AS Hostname,
    OSPath,
    KeyType,
    Cipher,
    Header,

    if(
      condition=OSPath =~ "(?i)^/root/",
      then="ROOT_ACCOUNT_KEY",
      else=if(
        condition=OSPath =~ "(?i)^/home/",
        then="USER_ACCOUNT_KEY",
        else="SERVICE_OR_NONSTANDARD_KEY"
      )
    ) AS AccountScope

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/PrivateKeys"
  )

  /*
   * Only Cipher=none confirms that the key file
   * is stored without passphrase encryption.
   */
  WHERE Cipher =~ "(?i)^none$"

SELECT
  ClientId,
  Hostname,
  OSPath,
  AccountScope,
  KeyType,
  Cipher,
  "CONFIRMED_UNENCRYPTED" AS ProtectionStatus,
  Header,

  "HIGH_REVIEW" AS ReviewPriority,
  "UNENCRYPTED_SSH_PRIVATE_KEY" AS FindingClass,

  if(
    condition=AccountScope = "ROOT_ACCOUNT_KEY",
    then="Unencrypted SSH private key associated with root account",
    else="SSH private key stored without passphrase encryption"
  ) AS Reason

FROM UnencryptedSSHPrivateKeys
ORDER BY ClientId
```

## Cell 22 (markdown)

# Known Hosts Inventory

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET KnownHostsInventory <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS EndpointHostname,

    User AS LocalUser,
    Uid AS LocalUid,
    OSPath,

    Hostname AS RemoteHostIdentifier,
    Type AS RemoteHostKeyType,

    if(
      condition=Hostname =~ "^[|]1[|]",
      then="HASHED_IDENTIFIER",
      else=if(
        condition=Hostname,
        then="PLAINTEXT_IDENTIFIER",
        else="UNKNOWN_IDENTIFIER"
      )
    ) AS IdentifierStatus,

    if(
      condition=Uid = 0 OR User =~ "(?i)^root$",
      then="PRIVILEGED_ACCOUNT",
      else="STANDARD_USER_ACCOUNT"
    ) AS AccountScope

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/KnownHosts"
  )

SELECT
  ClientId,
  EndpointHostname,
  LocalUser,
  LocalUid,
  AccountScope,
  OSPath,
  RemoteHostIdentifier,
  IdentifierStatus,
  RemoteHostKeyType,

  if(
    condition=AccountScope = "PRIVILEGED_ACCOUNT",
    then="ELEVATED_REVIEW",
    else="STANDARD_REVIEW"
  ) AS ReviewPriority,

  if(
    condition=AccountScope = "PRIVILEGED_ACCOUNT",
    then="Known SSH host entry associated with a privileged local account",
    else="Known SSH host entry associated with a standard local account"
  ) AS Reason

FROM KnownHostsInventory
ORDER BY ClientId
```

## Cell 24 (markdown)

# SSH Host Public Keys Inventory

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SSHHostPublicKeys <=
  SELECT
    ClientId,
    Fqdn AS EndpointHostname,
    OSPath,

    Type AS HostKeyType,
    KeyName AS KeyComment,
    PublicKey AS PublicKeyMaterial,

    if(
      condition=OSPath =~ "(?i)^/etc/ssh/ssh_host_.+_key[.]pub$",
      then="STANDARD_HOST_KEY_PATH",
      else="NONSTANDARD_HOST_KEY_PATH"
    ) AS PathStatus,

    if(
      condition=Type =~ "(?i)^ssh-dss$",
      then="LEGACY_DSA_HOST_KEY",
      else=if(
        condition=Type =~ "(?i)^ssh-rsa$",
        then="RSA_HOST_KEY",
        else=if(
          condition=Type =~ "(?i)^ssh-ed25519$",
          then="ED25519_HOST_KEY",
          else=if(
            condition=Type =~ "(?i)^ecdsa-sha2-",
            then="ECDSA_HOST_KEY",
            else="OTHER_OR_UNKNOWN_HOST_KEY"
          )
        )
      )
    ) AS AlgorithmClass

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/HostPublicKeys"
  )

SELECT
  ClientId,
  EndpointHostname,
  OSPath,
  PathStatus,
  HostKeyType,
  AlgorithmClass,
  KeyComment,
  PublicKeyMaterial,

  if(
    condition=PathStatus = "NONSTANDARD_HOST_KEY_PATH",
    then="ELEVATED_REVIEW",
    else=if(
      condition=AlgorithmClass =~
        "LEGACY_DSA_HOST_KEY|OTHER_OR_UNKNOWN_HOST_KEY",
      then="ELEVATED_REVIEW",
      else="STANDARD_REVIEW"
    )
  ) AS ReviewPriority,

  if(
    condition=PathStatus = "NONSTANDARD_HOST_KEY_PATH",
    then="SSH host public key found in a nonstandard path",
    else=if(
      condition=AlgorithmClass = "LEGACY_DSA_HOST_KEY",
      then="Legacy DSA SSH host key requires configuration review",
      else=if(
        condition=AlgorithmClass = "OTHER_OR_UNKNOWN_HOST_KEY",
        then="Unrecognized SSH host key type requires review",
        else="SSH server public host identity key"
      )
    )
  ) AS Reason

FROM SSHHostPublicKeys
ORDER BY ClientId
```

## Cell 26 (markdown)

# SSH Configuration Review

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET SSHConfigInventory <=
  SELECT
    ClientId,
    Path,
    Severity,
    Reason,
    Line,
    count() AS SourceRowCount

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHConfigReview"
  )

  GROUP BY
    ClientId,
    Path,
    Severity,
    Reason,
    Line

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  if(
    condition=Path =~ "(?i)/sshd_config",
    then="SSH_SERVER_CONFIG",
    else=if(
      condition=Path =~ "(?i)/ssh_config",
      then="SSH_CLIENT_CONFIG",
      else="UNKNOWN_CONFIG"
    )
  ) AS ConfigScope,

  Path,
  Line,

  if(
    condition=Severity =~ "(?i)^HIGH$",
    then="HIGH_REVIEW",
    else=if(
      condition=Severity =~ "(?i)^MEDIUM$",
      then="ELEVATED_REVIEW",
      else="INFORMATIONAL"
    )
  ) AS ReviewPriority,

  Severity AS ArtifactSeverity,
  Reason,
  SourceRowCount,
  "DECLARED_CONFIGURATION" AS EvidenceType

FROM SSHConfigInventory
ORDER BY ClientId
```

## Cell 28 (markdown)

# Risky SSH Configuration

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET DeduplicatedRiskySSHConfig <=
  SELECT
    ClientId,
    Path,
    Severity,
    Reason,
    Line,
    count() AS SourceRowCount

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHConfigReview"
  )

  WHERE Severity =~ "(?i)^(HIGH|MEDIUM)$"

  GROUP BY
    ClientId,
    Path,
    Severity,
    Reason,
    Line

SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  if(
    condition=Path =~ "(?i)/sshd_config",
    then="SSH_SERVER_CONFIG",
    else=if(
      condition=Path =~ "(?i)/ssh_config",
      then="SSH_CLIENT_CONFIG",
      else="UNKNOWN_CONFIG"
    )
  ) AS ConfigScope,

  Path,

  if(
    condition=Severity =~ "(?i)^HIGH$",
    then="HIGH_REVIEW",
    else="ELEVATED_REVIEW"
  ) AS ReviewPriority,

  Severity AS ArtifactSeverity,
  Reason,
  Line,
  SourceRowCount,

  "SSH_ROOT_LOGIN_POLICY" AS FindingClass,
  "DECLARED_CONFIGURATION" AS EvidenceType,
  "EFFECTIVE_VALUE_NOT_VERIFIED" AS VerificationStatus

FROM DeduplicatedRiskySSHConfig
ORDER BY ClientId
```

## Cell 30 (markdown)

# Suspicious Authentication Log Events

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET ParsedAuthEvents <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS EndpointHostname,

    Path,
    EventCategory,
    Severity AS ArtifactSeverity,

    parse_string_with_regex(
      string=Line,
      regex=[
        '''^(?P<LogTimeText>[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})''',

        '''sshd\[(?P<SshdPid>[0-9]+)\]''',

        '''Accepted (?P<AuthMethod>[^ ]+) for (?P<Account>[^ ]+) from (?P<SourceAddress>[^ ]+) port (?P<SourcePort>[0-9]+)''',

        '''Failed (?P<AuthMethod>[^ ]+) for (?:invalid user )?(?P<Account>[^ ]+) from (?P<SourceAddress>[^ ]+) port (?P<SourcePort>[0-9]+)''',

        '''Invalid user (?P<Account>[^ ]+) from (?P<SourceAddress>[^ ]+) port (?P<SourcePort>[0-9]+)''',

        '''rhost=(?P<SourceAddress>[^ ]+)''',

        '''(?:^|[ ;])user=(?P<Account>[^ ]+)'''
      ]
    ) AS Parsed,

    Line

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthLogReview"
  )

  WHERE ArtifactSeverity =~ "(?i)^(HIGH|MEDIUM)$"

SELECT
  ClientId,
  EndpointHostname,
  Parsed.LogTimeText AS LogTimeText,
  Path,
  EventCategory,

  Parsed.Account AS Account,
  Parsed.AuthMethod AS AuthMethod,
  Parsed.SourceAddress AS SourceAddress,
  Parsed.SourcePort AS SourcePort,
  Parsed.SshdPid AS SshdPid,

  if(
    condition=
      EventCategory =~ "(?i)^Successful SSH Login$"
      AND Parsed.Account =~ "(?i)^root$",
    then="HIGH_REVIEW",
    else=if(
      condition=EventCategory =~ "(?i)^Successful SSH Login$",
      then="ELEVATED_REVIEW",
      else="AUTH_FAILURE_REVIEW"
    )
  ) AS ReviewPriority,

  if(
    condition=
      EventCategory =~ "(?i)^Successful SSH Login$"
      AND Parsed.Account =~ "(?i)^root$"
      AND Parsed.AuthMethod =~ "(?i)^password$",
    then="ROOT_PASSWORD_SSH_SUCCESS",
    else=if(
      condition=
        EventCategory =~ "(?i)^Successful SSH Login$"
        AND Parsed.Account =~ "(?i)^root$",
      then="ROOT_SSH_SUCCESS",
      else=if(
        condition=EventCategory =~ "(?i)^Successful SSH Login$",
        then="SSH_LOGIN_SUCCESS",
        else=if(
          condition=EventCategory =~ "(?i)^Invalid SSH User$",
          then="SSH_INVALID_USER_ATTEMPT",
          else="SSH_AUTHENTICATION_FAILURE"
        )
      )
    )
  ) AS FindingClass,

  ArtifactSeverity,
  "AUTHENTICATION_LOG_EVENT" AS EvidenceType,
  Line

FROM ParsedAuthEvents
ORDER BY
  ClientId
```

## Cell 32 (markdown)

# Raw Authentication Log Events

## Cell 33 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RawAuthEvents <=
  SELECT
    ClientId,

    client_info(
      client_id=ClientId
    ).os_info.hostname AS EndpointHostname,

    Path,
    EventCategory,
    Severity AS ArtifactSeverity,
    Line

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthLogReview"
  )

SELECT
  ClientId,
  EndpointHostname,
  Path,

  if(
    condition=Line =~ '''(?i)sshd\[[0-9]+\]''',
    then="SSH_EVENT",
    else=if(
      condition=Line =~
        '''(?i)(sudo:|sudo\[[0-9]+\]|pam_unix\(sudo:)''',
      then="SUDO_EVENT",
      else=if(
        condition=Line =~
          '''(?i)(su:|su\[[0-9]+\]|pam_unix\(su:)''',
        then="SU_EVENT",
        else=if(
          condition=Line =~
            '''(?i)(useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd)\[[0-9]+\]''',
          then="IDENTITY_CHANGE",
          else=if(
            condition=EventCategory =~ "(?i)^Session Event$",
            then="OTHER_SESSION_EVENT",
            else="OTHER_AUTH_EVENT"
          )
        )
      )
    )
  ) AS EventClass,

  if(
    condition=ArtifactSeverity =~ "(?i)^HIGH$",
    then="HIGH_REVIEW",
    else=if(
      condition=ArtifactSeverity =~ "(?i)^MEDIUM$",
      then="ELEVATED_REVIEW",
      else="CONTEXT_ONLY"
    )
  ) AS ReviewScope,

  EventCategory,
  ArtifactSeverity,
  Line

FROM RawAuthEvents

WHERE
  ArtifactSeverity =~ "(?i)^(HIGH|MEDIUM)$"
  OR NOT (
    EventCategory =~ "(?i)^Session Event$"
    AND Line =~
      '''(?i)CRON\[[0-9]+\]: pam_unix\(cron:session\): session (opened|closed)'''
  )

ORDER BY
  ClientId
```

## Cell 34 (markdown)

## Clients Needing Investigation

This section summarizes authentication and SSH-related findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when root SSH access, unencrypted private keys, or risky SSH configuration is detected.

## Cell 35 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET FailedSSH <=
  SELECT
    ClientId,
    "FAILED_SSH_ACTIVITY" AS FindingClass,
    "Failed SSH authentication activity observed" AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)(Failed|Invalid|failure)"


LET SuccessfulRootSSH <=
  SELECT
    ClientId,
    "ROOT_SSH_SUCCESS" AS FindingClass,
    "Successful direct root SSH login observed" AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthLogReview"
  )

  WHERE
    EventCategory =~ "(?i)^Successful SSH Login$"
    AND Line =~
      '''(?i)Accepted (password|publickey|keyboard-interactive) for root from '''


LET RiskyAuthorizedKeys <=
  SELECT
    ClientId,
    "RISKY_AUTHORIZED_KEY_OPTION" AS FindingClass,
    "Risky option found in authorized_keys" AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthorizedKeys"
  )

  WHERE options =~
    "(?i)(command=|permitopen|tunnel|environment)"


LET UnencryptedPrivateKeys <=
  SELECT
    ClientId,
    "UNENCRYPTED_PRIVATE_KEY" AS FindingClass,
    "Unencrypted SSH private key discovered" AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/PrivateKeys"
  )

  WHERE
    Cipher =~ "(?i)^none$"
    OR Cipher = ""


LET RiskySSHConfig <=
  SELECT
    ClientId,
    "RISKY_SSH_CONFIGURATION" AS FindingClass,
    "Risky SSH server configuration detected" AS Finding

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHConfigReview"
  )

  WHERE Severity =~ "(?i)^(HIGH|MEDIUM)$"


LET RawFindings <=
  SELECT *
  FROM chain(
    a=FailedSSH,
    b=SuccessfulRootSSH,
    c=RiskyAuthorizedKeys,
    d=UnencryptedPrivateKeys,
    e=RiskySSHConfig
  )


LET UniqueFindings <=
  SELECT
    ClientId,
    FindingClass,
    Finding,
    count() AS SourceRowCount

  FROM RawFindings

  GROUP BY
    ClientId,
    FindingClass,
    Finding


LET ClientSummary <=
  SELECT
    ClientId,
    count() AS DistinctFindingTypeCount,
    sum(item=SourceRowCount) AS RawMatchedRowCount,
    enumerate(items=FindingClass) AS FindingClasses,
    enumerate(items=Finding) AS Findings

  FROM UniqueFindings

  GROUP BY ClientId


LET PrioritizedClients <=
  SELECT
    ClientId,
    DistinctFindingTypeCount,
    RawMatchedRowCount,
    FindingClasses,
    Findings,

    if(
      condition=FindingClasses =~
        "(?i)(ROOT_SSH_SUCCESS|UNENCRYPTED_PRIVATE_KEY)",
      then="HIGH_PRIORITY",
      else=if(
        condition=FindingClasses =~
          "(?i)(RISKY_AUTHORIZED_KEY_OPTION|RISKY_SSH_CONFIGURATION)",
        then="ELEVATED_PRIORITY",
        else="REVIEW_PRIORITY"
      )
    ) AS InvestigationPriority,

    if(
      condition=FindingClasses =~
        "(?i)(ROOT_SSH_SUCCESS|UNENCRYPTED_PRIVATE_KEY)",
      then=3,
      else=if(
        condition=FindingClasses =~
          "(?i)(RISKY_AUTHORIZED_KEY_OPTION|RISKY_SSH_CONFIGURATION)",
        then=2,
        else=1
      )
    ) AS PriorityRank

  FROM ClientSummary


SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  InvestigationPriority,
  DistinctFindingTypeCount,
  RawMatchedRowCount,
  FindingClasses,
  Findings

FROM PrioritizedClients

ORDER BY
  PriorityRank DESC
```

## Cell 36 (markdown)

## Final Findings Detail — Consolidated Evidence

This section combines SSH and authentication-related suspicious indicators into one findings table.

It includes failed SSH attempts, root SSH access, risky authorized keys, unencrypted private keys, and risky SSH configuration.

## Cell 37 (vql)

```vql
-- ============================================================
-- Final Findings Detail - Consolidated Evidence
-- Authentication and SSH Activity
--
-- Detection and deduplication owner for this notebook.
-- Count only rows where RiskScoreEligible = "YES" and count
-- each FindingKey no more than once.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Failed SSH evidence
--
-- Raw artifact row count is not treated as a validated attempt
-- count. This route requires session/time-window aggregation.
-- ============================================================

LET FailedSSHFindings <=
  SELECT
    ClientId,
    "MEDIUM" AS Severity,
    "FAILED_SSH_ACTIVITY" AS DetectionClass,

    "Failed SSH evidence requires aggregation and threshold validation"
      AS Finding,

    AttemptedUser AS Subject,

    format(
      format="user=%v | source=%v | result=%v",
      args=[
        AttemptedUser,
        IP,
        Result
      ]
    ) AS PrimaryEvidence,

    AttemptedUser AS Evidence1,
    IP AS Evidence2,
    Result AS Evidence3,

    count() AS SourceRowCount,
    "DIRECT_AUTH_EVENT" AS EvidenceType,
    "AGGREGATION_REQUIRED" AS VerificationStatus,
    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|FAILED_SSH_ACTIVITY|%v|%v|%v",
      args=[
        ClientId,
        AttemptedUser,
        IP,
        Result
      ]
    ) AS FindingKey,

    "NONE - use tuned aggregation after unique-event validation"
      AS RiskScoreOwner

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)(Failed|Invalid|failure)"

  GROUP BY
    ClientId,
    AttemptedUser,
    IP,
    Result


-- ============================================================
-- 2. Successful direct root SSH authentication
-- ============================================================

LET SuccessfulRootSSHFindings <=
  SELECT
    ClientId,
    "HIGH" AS Severity,
    "ROOT_SSH_SUCCESS" AS DetectionClass,
    "Successful direct root SSH login observed" AS Finding,

    AttemptedUser AS Subject,

    format(
      format="user=%v | source=%v | result=%v",
      args=[
        AttemptedUser,
        IP,
        Result
      ]
    ) AS PrimaryEvidence,

    AttemptedUser AS Evidence1,
    IP AS Evidence2,
    Result AS Evidence3,

    count() AS SourceRowCount,
    "DIRECT_AUTH_EVENT" AS EvidenceType,
    "OBSERVED" AS VerificationStatus,
    "YES" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|ROOT_SSH_SUCCESS|%v|%v|%v",
      args=[
        ClientId,
        AttemptedUser,
        IP,
        Result
      ]
    ) AS FindingKey,

    "Final Findings Detail - count each FindingKey once"
      AS RiskScoreOwner

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE
    AttemptedUser =~ "(?i)^root$"
    AND Result =~ "(?i)(Accepted|Success|Succeeded)"

  GROUP BY
    ClientId,
    AttemptedUser,
    IP,
    Result


-- ============================================================
-- 3. Authorized-key options requiring baseline review
--
-- The presence of command= or permitopen= is not automatically
-- malicious. These options may intentionally restrict a key.
-- ============================================================

LET AuthorizedKeyOptionFindings <=
  SELECT
    ClientId,
    "REVIEW" AS Severity,
    "RISKY_AUTHORIZED_KEY_OPTION" AS DetectionClass,

    "Authorized-key option requires authorization and baseline review"
      AS Finding,

    OSPath AS Subject,

    format(
      format="path=%v | options=%v | comment=%v",
      args=[
        OSPath,
        options,
        comment
      ]
    ) AS PrimaryEvidence,

    OSPath AS Evidence1,
    options AS Evidence2,
    comment AS Evidence3,

    count() AS SourceRowCount,
    "AUTHORIZED_KEY_CONFIGURATION" AS EvidenceType,
    "BASELINE_AND_EFFECTIVE_BEHAVIOR_REQUIRED" AS VerificationStatus,
    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|RISKY_AUTHORIZED_KEY_OPTION|%v|%v|%v",
      args=[
        ClientId,
        OSPath,
        options,
        comment
      ]
    ) AS FindingKey,

    "NONE - context until the key or option is confirmed unauthorized"
      AS RiskScoreOwner

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthorizedKeys"
  )

  WHERE options =~
    "(?i)(command=|environment=|tunnel=|permitopen=|permitlisten=|cert-authority|principals=|no-touch-required)"

  GROUP BY
    ClientId,
    OSPath,
    options,
    comment


-- ============================================================
-- 4. Private-key protection review
--
-- Cipher=none is reported as unencrypted by the Artifact.
-- An empty Cipher value is unverified, not proof of encryption
-- or lack of encryption.
-- ============================================================

LET PrivateKeyFindings <=
  SELECT
    ClientId,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="HIGH",
      else="REVIEW"
    ) AS Severity,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="UNENCRYPTED_PRIVATE_KEY",
      else="PRIVATE_KEY_CIPHER_UNVERIFIED"
    ) AS DetectionClass,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="Unencrypted SSH private key reported by the Artifact",
      else="SSH private-key cipher status requires verification"
    ) AS Finding,

    OSPath AS Subject,

    format(
      format="path=%v | key_type=%v | cipher=%v",
      args=[
        OSPath,
        KeyType,
        Cipher
      ]
    ) AS PrimaryEvidence,

    OSPath AS Evidence1,
    KeyType AS Evidence2,
    Cipher AS Evidence3,

    count() AS SourceRowCount,
    "PRIVATE_KEY_FILE" AS EvidenceType,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="UNENCRYPTED_REPORTED",
      else="CIPHER_VALUE_MISSING"
    ) AS VerificationStatus,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="YES",
      else="NO"
    ) AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|%v|%v|%v|%v",
      args=[
        ClientId,
        if(
          condition=Cipher =~ "(?i)^none$",
          then="UNENCRYPTED_PRIVATE_KEY",
          else="PRIVATE_KEY_CIPHER_UNVERIFIED"
        ),
        OSPath,
        KeyType,
        Cipher
      ]
    ) AS FindingKey,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="Final Findings Detail - count each FindingKey once",
      else="NONE - verify key protection before scoring"
    ) AS RiskScoreOwner

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/PrivateKeys"
  )

  WHERE
    Cipher =~ "(?i)^none$"
    OR NOT Cipher

  GROUP BY
    ClientId,
    OSPath,
    KeyType,
    Cipher


-- ============================================================
-- 5. Declared SSH configuration review
--
-- Artifact output identifies declared configuration text.
-- The effective value must be verified separately with sshd -T.
-- ============================================================

LET SSHConfigurationFindings <=
  SELECT
    ClientId,
    Severity,
    "RISKY_SSH_CONFIGURATION" AS DetectionClass,

    "Declared SSH configuration requires effective-value validation"
      AS Finding,

    Path AS Subject,

    format(
      format="path=%v | reason=%v | line=%v",
      args=[
        Path,
        Reason,
        Line
      ]
    ) AS PrimaryEvidence,

    Path AS Evidence1,
    Reason AS Evidence2,
    Line AS Evidence3,

    count() AS SourceRowCount,
    "DECLARED_SSH_CONFIGURATION" AS EvidenceType,
    "EFFECTIVE_VALUE_NOT_VERIFIED" AS VerificationStatus,
    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|RISKY_SSH_CONFIGURATION|%v|%v|%v",
      args=[
        ClientId,
        Path,
        Reason,
        Line
      ]
    ) AS FindingKey,

    "NONE - validate effective and authorized configuration before scoring"
      AS RiskScoreOwner

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHConfigReview"
  )

  WHERE Severity =~ "(?i)^(HIGH|MEDIUM)$"

  GROUP BY
    ClientId,
    Path,
    Severity,
    Reason,
    Line


-- ============================================================
-- 6. Combine, prioritize and deduplicate
-- ============================================================

LET AllAuthenticationSSHFindings <=
  SELECT *

  FROM chain(
    a=FailedSSHFindings,
    b=SuccessfulRootSSHFindings,
    c=AuthorizedKeyOptionFindings,
    d=PrivateKeyFindings,
    e=SSHConfigurationFindings
  )


LET RankedAuthenticationSSHFindings <=
  SELECT
    *,

    if(
      condition=Severity =~ "(?i)^HIGH$",
      then=100,
      else=if(
        condition=Severity =~ "(?i)^MEDIUM$",
        then=70,
        else=40
      )
    ) AS FindingRank

  FROM AllAuthenticationSSHFindings

  ORDER BY FindingRank DESC


LET UniqueAuthenticationSSHFindings <=
  SELECT *

  FROM RankedAuthenticationSSHFindings

  GROUP BY FindingKey


SELECT
  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  Severity,
  DetectionClass,
  Finding,
  Subject,
  PrimaryEvidence,

  Evidence1,
  Evidence2,
  Evidence3,

  SourceRowCount,
  EvidenceType,
  VerificationStatus,
  RiskScoreEligible,
  FindingKey,
  RiskScoreOwner

FROM UniqueAuthenticationSSHFindings

ORDER BY FindingRank DESC
```

## Cell 38 (markdown)

# Investigation Pivot Queue — Dynamic Authentication and SSH Routes

## Cell 39 (vql)

```vql
-- ============================================================
-- Investigation Pivot Queue
-- Authentication and SSH
--
-- Standalone version:
-- - No NotebookId
-- - No FinalFindingsCellId
-- - No PivotGuideCellId
-- - Reads directly from Hunt results
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Failed SSH activity
-- ============================================================

LET FailedSSHFindings <=
  SELECT
    ClientId,
    "MEDIUM" AS FindingSeverity,
    "FAILED_SSH_ACTIVITY" AS FindingDetectionClass,

    "Failed SSH evidence requires aggregation and threshold validation"
      AS Finding,

    AttemptedUser AS Subject,
    AttemptedUser AS Evidence1,
    IP AS Evidence2,
    Result AS Evidence3,

    count() AS SourceRowCount,

    "AGGREGATION_REQUIRED"
      AS VerificationStatus,

    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|FAILED_SSH_ACTIVITY|%v|%v|%v",
      args=[
        ClientId,
        AttemptedUser,
        IP,
        Result
      ]
    ) AS FindingKey

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE Result =~ "(?i)(Failed|Invalid|failure)"

  GROUP BY
    ClientId,
    AttemptedUser,
    IP,
    Result


-- ============================================================
-- 2. Successful direct root SSH login
-- ============================================================

LET RootSSHSuccessFindings <=
  SELECT
    ClientId,
    "HIGH" AS FindingSeverity,
    "ROOT_SSH_SUCCESS" AS FindingDetectionClass,

    "Successful direct root SSH login observed"
      AS Finding,

    AttemptedUser AS Subject,
    AttemptedUser AS Evidence1,
    IP AS Evidence2,
    Result AS Evidence3,

    count() AS SourceRowCount,

    "OBSERVED"
      AS VerificationStatus,

    "YES" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|ROOT_SSH_SUCCESS|%v|%v|%v",
      args=[
        ClientId,
        AttemptedUser,
        IP,
        Result
      ]
    ) AS FindingKey

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHLogin"
  )

  WHERE
    AttemptedUser =~ "(?i)^root$"
    AND Result =~ "(?i)(Accepted|Success|Succeeded)"

  GROUP BY
    ClientId,
    AttemptedUser,
    IP,
    Result


-- ============================================================
-- 3. Authorized-key options requiring review
-- ============================================================

LET AuthorizedKeyFindings <=
  SELECT
    ClientId,
    "REVIEW" AS FindingSeverity,
    "RISKY_AUTHORIZED_KEY_OPTION" AS FindingDetectionClass,

    "Authorized-key option requires authorization and baseline review"
      AS Finding,

    OSPath AS Subject,
    OSPath AS Evidence1,
    options AS Evidence2,
    comment AS Evidence3,

    count() AS SourceRowCount,

    "BASELINE_AND_EFFECTIVE_BEHAVIOR_REQUIRED"
      AS VerificationStatus,

    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|RISKY_AUTHORIZED_KEY_OPTION|%v|%v|%v",
      args=[
        ClientId,
        OSPath,
        options,
        comment
      ]
    ) AS FindingKey

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/AuthorizedKeys"
  )

  WHERE options =~
    "(?i)(command=|environment=|tunnel=|permitopen=|permitlisten=|cert-authority|principals=|no-touch-required)"

  GROUP BY
    ClientId,
    OSPath,
    options,
    comment


-- ============================================================
-- 4. Private-key review
-- ============================================================

LET PrivateKeyFindings <=
  SELECT
    ClientId,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="HIGH",
      else="REVIEW"
    ) AS FindingSeverity,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="UNENCRYPTED_PRIVATE_KEY",
      else="PRIVATE_KEY_CIPHER_UNVERIFIED"
    ) AS FindingDetectionClass,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="Unencrypted SSH private key reported by the Artifact",
      else="SSH private-key cipher status requires verification"
    ) AS Finding,

    OSPath AS Subject,
    OSPath AS Evidence1,
    KeyType AS Evidence2,
    Cipher AS Evidence3,

    count() AS SourceRowCount,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="UNENCRYPTED_REPORTED",
      else="CIPHER_VALUE_MISSING"
    ) AS VerificationStatus,

    if(
      condition=Cipher =~ "(?i)^none$",
      then="YES",
      else="NO"
    ) AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|%v|%v|%v|%v",
      args=[
        ClientId,

        if(
          condition=Cipher =~ "(?i)^none$",
          then="UNENCRYPTED_PRIVATE_KEY",
          else="PRIVATE_KEY_CIPHER_UNVERIFIED"
        ),

        OSPath,
        KeyType,
        Cipher
      ]
    ) AS FindingKey

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/PrivateKeys"
  )

  WHERE
    Cipher =~ "(?i)^none$"
    OR Cipher = ""

  GROUP BY
    ClientId,
    OSPath,
    KeyType,
    Cipher


-- ============================================================
-- 5. Risky SSH configuration
-- ============================================================

LET SSHConfigurationFindings <=
  SELECT
    ClientId,
    Severity AS FindingSeverity,
    "RISKY_SSH_CONFIGURATION" AS FindingDetectionClass,

    "Declared SSH configuration requires effective-value validation"
      AS Finding,

    Path AS Subject,
    Path AS Evidence1,
    Reason AS Evidence2,
    Line AS Evidence3,

    count() AS SourceRowCount,

    "EFFECTIVE_VALUE_NOT_VERIFIED"
      AS VerificationStatus,

    "NO" AS RiskScoreEligible,

    format(
      format="AUTHSSH|%v|RISKY_SSH_CONFIGURATION|%v|%v|%v",
      args=[
        ClientId,
        Path,
        Reason,
        Line
      ]
    ) AS FindingKey

  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.AuthSSH/SSHConfigReview"
  )

  WHERE Severity =~ "(?i)^(HIGH|MEDIUM)$"

  GROUP BY
    ClientId,
    Path,
    Severity,
    Reason,
    Line


-- ============================================================
-- 6. Combine and deduplicate findings
-- ============================================================

LET AllAuthenticationSSHFindings <=
  SELECT *

  FROM chain(
    failed_ssh=FailedSSHFindings,
    root_ssh=RootSSHSuccessFindings,
    authorized_keys=AuthorizedKeyFindings,
    private_keys=PrivateKeyFindings,
    ssh_config=SSHConfigurationFindings
  )


LET RankedAuthenticationSSHFindings <=
  SELECT
    *,

    if(
      condition=FindingSeverity =~ "(?i)^HIGH$",
      then=100,
      else=if(
        condition=FindingSeverity =~ "(?i)^MEDIUM$",
        then=70,
        else=40
      )
    ) AS FindingRank

  FROM AllAuthenticationSSHFindings

  ORDER BY FindingRank DESC


LET ActualAuthenticationSSHFindings <=
  SELECT *

  FROM RankedAuthenticationSSHFindings

  GROUP BY FindingKey


-- ============================================================
-- 7. Apply investigation routes
--
-- Each branch handles one DetectionClass. This avoids joins,
-- Cell IDs and cross-cell source() dependencies.
-- ============================================================

LET RoutedAuthenticationSSHFindings <=
  SELECT *

  FROM chain(

    failed_ssh={
      SELECT
        *,
        70 AS RouteRank,

        "AUTHENTICATION_ATTACK_REVIEW"
          AS RouteClass,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Validate the time window, unique events, source IP, targeted users and whether a successful login followed."
          AS PrimaryChecks,

        "LTH - 05 - Network Connections Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review the source address and identify unexpected shells, commands, processes or services after authentication."
          AS SecondaryChecks,

        "Escalate when validated failures exceed the approved threshold, target multiple identities or are followed by successful authentication."
          AS EscalateWhen,

        "NONE until aggregation and threshold validation"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "FAILED_SSH_ACTIVITY"
    },


    root_ssh={
      SELECT
        *,
        100 AS RouteRank,

        "ACCOUNT_COMPROMISE_REVIEW"
          AS RouteClass,

        "LTH - 04 - Processes and Services Dashboard"
          AS PrimaryNotebook,

        "Identify commands, shells, child processes, services and binaries executed by root after the login."
          AS PrimaryChecks,

        "LTH - 08 - Logs and Security Events Dashboard -> LTH - 05 - Network Connections Dashboard"
          AS SecondaryNotebook,

        "Correlate the root login with previous failures, sudo activity, account changes and network connections."
          AS SecondaryChecks,

        "Escalate when the login is unauthorized, originates from a non-baseline source or correlates with suspicious execution."
          AS EscalateWhen,

        "Count each eligible FindingKey once"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "ROOT_SSH_SUCCESS"
    },


    authorized_key={
      SELECT
        *,
        55 AS RouteRank,

        "SSH_PERSISTENCE_REVIEW"
          AS RouteClass,

        "LTH - 07 - File System and Timeline Analysis Dashboard"
          AS PrimaryNotebook,

        "Review the key path, account, options, ownership, permissions and file modification time."
          AS PrimaryChecks,

        "LTH - 06 - Persistence Mechanisms Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Check whether the key is authorized and whether it correlates with successful SSH authentication."
          AS SecondaryChecks,

        "Escalate when the key or option is unauthorized, unexpectedly modified or correlated with suspicious authentication."
          AS EscalateWhen,

        "NONE until authorization and baseline validation"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "RISKY_AUTHORIZED_KEY_OPTION"
    },


    unencrypted_key={
      SELECT
        *,
        90 AS RouteRank,

        "CREDENTIAL_EXPOSURE_REVIEW"
          AS RouteClass,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Confirm the key owner, purpose, path, permissions and exposure without displaying or uploading its content."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review timestamps and determine which users, scripts, processes or services may have accessed the key."
          AS SecondaryChecks,

        "Escalate when the key is unauthorized, broadly readable, unexpectedly stored or correlated with suspicious activity."
          AS EscalateWhen,

        "Count each eligible FindingKey once"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "UNENCRYPTED_PRIVATE_KEY"
    },


    unverified_key={
      SELECT
        *,
        40 AS RouteRank,

        "CREDENTIAL_FILE_VALIDATION"
          AS RouteClass,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Verify the private-key format, encryption status, owner, permissions and business purpose."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard"
          AS SecondaryNotebook,

        "Review file timestamps, location and unexpected duplicate copies."
          AS SecondaryChecks,

        "Escalate only after the key is confirmed unencrypted, unauthorized or exposed."
          AS EscalateWhen,

        "NONE until key protection is verified"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "PRIVATE_KEY_CIPHER_UNVERIFIED"
    },


    ssh_configuration={
      SELECT
        *,
        60 AS RouteRank,

        "CONFIGURATION_RISK_REVIEW"
          AS RouteClass,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Validate the effective SSH configuration with sshd -T and compare it with the approved hardening baseline."
          AS PrimaryChecks,

        "LTH - 05 - Network Connections Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Determine whether SSH is reachable and whether authentication evidence confirms use of the risky setting."
          AS SecondaryChecks,

        "Escalate when the risky setting is effective and unauthorized, especially when authentication evidence confirms use."
          AS EscalateWhen,

        "NONE until effective-value and authorization validation"
          AS RiskScoreImpact

      FROM ActualAuthenticationSSHFindings

      WHERE FindingDetectionClass =
        "RISKY_SSH_CONFIGURATION"
    }
  )


-- ============================================================
-- 8. Final analyst-facing queue
-- ============================================================

SELECT
  FindingSeverity AS InvestigationPriority,

  ClientId,

  client_info(
    client_id=ClientId
  ).os_info.hostname AS EndpointHostname,

  FindingDetectionClass AS DetectionClass,
  Finding,
  Subject,

  Evidence1,
  Evidence2,
  Evidence3,

  SourceRowCount,
  VerificationStatus,
  RiskScoreEligible,

  RouteClass,
  PrimaryNotebook,
  PrimaryChecks,
  SecondaryNotebook,
  SecondaryChecks,
  EscalateWhen,

  "Open" AS InvestigationState,
  FindingKey,
  RiskScoreImpact

FROM RoutedAuthenticationSSHFindings

ORDER BY
  RouteRank DESC
```

## Cell 40 (markdown)

# Investigation Pivot Guide — Authentication and SSH Evidence Routes

## Cell 41 (vql)

```vql
-- ============================================================
-- Investigation Pivot Guide
-- Authentication and SSH Evidence Routes
--
-- Fixed route catalog. This cell does not create findings and
-- does not contribute to Risk Score.
-- ============================================================

LET AuthenticationSSHPivotGuide <=
  SELECT *

  FROM chain(

    failed_authentication={
      SELECT
        1 AS RouteOrder,
        70 AS RouteRank,
        "FAILED_SSH_ACTIVITY" AS DetectionClass,
        "MEDIUM" AS DefaultPriority,
        "AUTHENTICATION_ATTACK_REVIEW" AS RouteClass,
        "DIRECT_AUTH_EVENTS_REQUIRING_AGGREGATION" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> Failed SSH aggregation cells"
          AS StartPoint,

        "Failed SSH Login Attempts; Failed SSH Login Count per Client; Failed SSH Login Count by Source IP; Final Findings Detail"
          AS SourceCells,

        "Repeated failures, one source targeting multiple usernames, failures distributed across clients, or success following failures"
          AS Trigger,

        "Confirm the time window, unique sessions, source IP, targeted users, targeted clients and whether a successful login followed. Do not treat raw log-row count as attempt count."
          AS ValidationBeforePivot,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Build the authentication timeline and review invalid-user events, PAM failures, SSH daemon events and successful authentication following the failures."
          AS PrimaryChecks,

        "LTH - 05 - Network Connections Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review activity involving the source address and identify unexpected processes, shells, services or commands after authentication."
          AS SecondaryChecks,

        "Escalate when validated activity exceeds the approved threshold, targets multiple accounts or clients, originates from an unauthorized source, or is followed by successful authentication."
          AS EscalateWhen,

        "NONE until unique-event and threshold validation"
          AS RiskScoreImpact

      FROM scope()
    },


    successful_root_login={
      SELECT
        2 AS RouteOrder,
        100 AS RouteRank,
        "ROOT_SSH_SUCCESS" AS DetectionClass,
        "HIGH" AS DefaultPriority,
        "ACCOUNT_COMPROMISE_REVIEW" AS RouteClass,
        "DIRECT_SUCCESSFUL_AUTHENTICATION" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> successful root authentication evidence"
          AS StartPoint,

        "Last User Login Inventory; Suspicious Authentication Log Events; Final Findings Detail"
          AS SourceCells,

        "Successful direct SSH login by root"
          AS Trigger,

        "Confirm the successful status, source IP, authentication method, time, session or PID and the approved administrative baseline."
          AS ValidationBeforePivot,

        "LTH - 04 - Processes and Services Dashboard"
          AS PrimaryNotebook,

        "Identify shells, commands, child processes, services and binaries executed by root after the login time."
          AS PrimaryChecks,

        "LTH - 08 - Logs and Security Events Dashboard -> LTH - 05 - Network Connections Dashboard"
          AS SecondaryNotebook,

        "Correlate the login with sudo or su activity, account changes, outbound connections and preceding authentication failures."
          AS SecondaryChecks,

        "Escalate when the login is unauthorized, originates from a non-baseline source, follows repeated failures or correlates with suspicious execution."
          AS EscalateWhen,

        "Count each eligible FindingKey once"
          AS RiskScoreImpact

      FROM scope()
    },


    authorized_key_option={
      SELECT
        3 AS RouteOrder,
        55 AS RouteRank,
        "RISKY_AUTHORIZED_KEY_OPTION" AS DetectionClass,
        "REVIEW" AS DefaultPriority,
        "SSH_PERSISTENCE_REVIEW" AS RouteClass,
        "SUPPORTING_CONFIGURATION_EVIDENCE" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> Authorized SSH Keys Inventory"
          AS StartPoint,

        "Authorized SSH Keys Inventory; Risky Authorized Keys; Final Findings Detail"
          AS SourceCells,

        "Unexpected or non-baseline key or option such as command, environment, tunnel, permitopen, permitlisten or certificate-authority behavior"
          AS Trigger,

        "Record the account, path, fingerprint when available, options, owner and permissions. Confirm whether the key and each option belong to the approved access baseline."
          AS ValidationBeforePivot,

        "LTH - 07 - File System and Timeline Analysis Dashboard"
          AS PrimaryNotebook,

        "Review creation and modification times, ownership, permissions, nearby SSH files and related account-file changes."
          AS PrimaryChecks,

        "LTH - 06 - Persistence Mechanisms Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Search for successful SSH authentication and other persistence involving the account, key or related source address."
          AS SecondaryChecks,

        "Escalate when the key or option is unauthorized, newly introduced without an approved change, or correlated with successful authentication or suspicious activity."
          AS EscalateWhen,

        "NONE until the key or option is confirmed unauthorized"
          AS RiskScoreImpact

      FROM scope()
    },


    unencrypted_private_key={
      SELECT
        4 AS RouteOrder,
        90 AS RouteRank,
        "UNENCRYPTED_PRIVATE_KEY" AS DetectionClass,
        "HIGH" AS DefaultPriority,
        "CREDENTIAL_EXPOSURE_REVIEW" AS RouteClass,
        "VERIFIED_PRIVATE_KEY_PROTECTION_EVIDENCE" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> SSH Private Keys Inventory"
          AS StartPoint,

        "SSH Private Keys Inventory; Final Findings Detail"
          AS SourceCells,

        "Artifact reports Cipher=none for an SSH private key"
          AS Trigger,

        "Confirm owner, purpose, path, permissions, accessibility and approved service or automation use without exposing or uploading the private-key content."
          AS ValidationBeforePivot,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Review credential exposure, permissions, secret-management controls, duplicate copies and sensitive material belonging to the same identity."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard -> LTH - 04 - Processes and Services Dashboard"
          AS SecondaryNotebook,

        "Review creation and modification time and determine which users, scripts, processes or services may have accessed the key."
          AS SecondaryChecks,

        "Escalate when the unencrypted key is unauthorized, broadly readable, stored unexpectedly, exposed to another identity or correlated with suspicious authentication."
          AS EscalateWhen,

        "Count each eligible FindingKey once"
          AS RiskScoreImpact

      FROM scope()
    },


    private_key_cipher_unverified={
      SELECT
        5 AS RouteOrder,
        40 AS RouteRank,
        "PRIVATE_KEY_CIPHER_UNVERIFIED" AS DetectionClass,
        "REVIEW" AS DefaultPriority,
        "CREDENTIAL_FILE_VALIDATION" AS RouteClass,
        "INCOMPLETE_PRIVATE_KEY_METADATA" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> SSH Private Keys Inventory"
          AS StartPoint,

        "SSH Private Keys Inventory; Final Findings Detail"
          AS SourceCells,

        "Private-key file was identified but Cipher is empty or unavailable"
          AS Trigger,

        "Do not classify an empty Cipher as unencrypted. Verify the file format, parser support and protection status, then confirm owner, permissions and business purpose."
          AS ValidationBeforePivot,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Verify whether the key is protected and review access controls and secret-management requirements."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard"
          AS SecondaryNotebook,

        "Review path, timestamps, owner, permissions and unexpected duplicate copies."
          AS SecondaryChecks,

        "Escalate only after the key is confirmed unencrypted, unauthorized, exposed or correlated with suspicious authentication or execution."
          AS EscalateWhen,

        "NONE until key protection is verified"
          AS RiskScoreImpact

      FROM scope()
    },


    risky_ssh_configuration={
      SELECT
        6 AS RouteOrder,
        60 AS RouteRank,
        "RISKY_SSH_CONFIGURATION" AS DetectionClass,
        "REVIEW" AS DefaultPriority,
        "CONFIGURATION_RISK_REVIEW" AS RouteClass,
        "DECLARED_CONFIGURATION_SUPPORTING_EVIDENCE" AS EvidenceRole,
        "Final Findings Detail" AS SourceCell,

        "Final Findings Detail -> SSH Configuration Review"
          AS StartPoint,

        "SSH Configuration Review; Risky SSH Configuration; Final Findings Detail"
          AS SourceCells,

        "Declared SSH configuration contains a potentially high-risk setting, but the effective runtime value is not verified"
          AS Trigger,

        "Validate syntax and keys with sshd -t and verify the effective configuration with sshd -T. Apply connection parameters with -C when Match blocks are relevant."
          AS ValidationBeforePivot,

        "LTH - 14 - Configuration and Secrets Review Dashboard"
          AS PrimaryNotebook,

        "Compare the effective value with the approved hardening baseline and review related credentials, keys, permissions and configuration exposure."
          AS PrimaryChecks,

        "LTH - 05 - Network Connections Dashboard -> LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Determine whether SSH is reachable and whether authentication activity confirms use of the risky setting."
          AS SecondaryChecks,

        "Escalate as a configuration finding only when the setting is effective and unauthorized; increase incident priority when authentication evidence confirms use."
          AS EscalateWhen,

        "NONE until the effective value and authorization status are verified"
          AS RiskScoreImpact

      FROM scope()
    },


    suspicious_authentication_context={
      SELECT
        7 AS RouteOrder,
        35 AS RouteRank,
        "CONTEXT_SUSPICIOUS_AUTH_EVENT" AS DetectionClass,
        "CONTEXT" AS DefaultPriority,
        "AUTH_EVENT_CORRELATION" AS RouteClass,
        "DIRECT_LOG_EVENT_OR_SUPPORTING_CONTEXT" AS EvidenceRole,
        "Suspicious Authentication Log Events" AS SourceCell,

        "Suspicious Authentication Log Events -> Authentication Log Events Review"
          AS StartPoint,

        "Suspicious Authentication Log Events; Authentication Log Events Review"
          AS SourceCells,

        "SSH, PAM, sudo, su, identity-change or authentication event requires timeline correlation"
          AS Trigger,

        "Inspect the original event and confirm time, hostname, account, source address, process, PID, result and parser interpretation."
          AS ValidationBeforePivot,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS PrimaryNotebook,

        "Build the surrounding timeline and review authentication, privilege use, account changes, service activity and possible log gaps."
          AS PrimaryChecks,

        "LTH - 02 - Users, Groups and Privileges Dashboard -> LTH - 09 - Privilege Escalation Indicators Dashboard"
          AS SecondaryNotebook,

        "Validate the identity baseline, Sudoers access, privileged execution paths and other evidence related to the account."
          AS SecondaryChecks,

        "Escalate when the event is unauthorized, repeated, successful, followed by privilege activity or correlated with suspicious account, process, network or persistence evidence."
          AS EscalateWhen,

        "NONE - context route only"
          AS RiskScoreImpact

      FROM scope()
    },


    ssh_trust_context={
      SELECT
        8 AS RouteOrder,
        25 AS RouteRank,
        "CONTEXT_SSH_TRUST_RELATIONSHIP" AS DetectionClass,
        "CONTEXT" AS DefaultPriority,
        "SSH_TRUST_CONTEXT_REVIEW" AS RouteClass,
        "CONTEXT_ONLY_UNTIL_VALIDATED" AS EvidenceRole,
        "Known Hosts and Host Keys Inventory" AS SourceCell,

        "Known Hosts Inventory -> SSH Host Public Keys Inventory"
          AS StartPoint,

        "Known Hosts Inventory; SSH Host Public Keys Inventory"
          AS SourceCells,

        "Unexpected Known Hosts relationship, unexplained host-key change or non-baseline host fingerprint"
          AS Trigger,

        "Inventory presence alone is not a finding. Confirm user or server, hostname, address, fingerprint, first-seen context and approved infrastructure baseline."
          AS ValidationBeforePivot,

        "LTH - 05 - Network Connections Dashboard"
          AS PrimaryNotebook,

        "Review communication with the destination, address, port, timing and associated network relationships."
          AS PrimaryChecks,

        "LTH - 07 - File System and Timeline Analysis Dashboard -> LTH - 14 - Configuration and Secrets Review Dashboard"
          AS SecondaryNotebook,

        "Review Known Hosts or host-key modification time, ownership, permissions and related SSH-file changes."
          AS SecondaryChecks,

        "Escalate only when the relationship or fingerprint change is unauthorized and correlates with network, authentication or file-modification evidence."
          AS EscalateWhen,

        "NONE - context route only"
          AS RiskScoreImpact

      FROM scope()
    },


    collection_gap={
      SELECT
        9 AS RouteOrder,
        10 AS RouteRank,
        "COLLECTION_GAP" AS DetectionClass,
        "HEALTH" AS DefaultPriority,
        "COLLECTION_VALIDATION" AS RouteClass,
        "TELEMETRY_HEALTH_NOT_SECURITY_FINDING" AS EvidenceRole,
        "Collection Coverage Review" AS SourceCell,

        "Collection coverage review"
          AS StartPoint,

        "SSH Login Attempts; Authentication Log Events; SSH Configuration Review; SSH Host Public Keys Inventory"
          AS SourceCells,

        "SSH is installed or active but expected authentication or configuration cells contain no data or show errors"
          AS Trigger,

        "Determine whether empty results represent no activity, unsupported log paths, journald-only logging, missing permissions, an incorrect hunt period or Artifact failure."
          AS ValidationBeforePivot,

        "LTH - 01 - System Baseline Dashboard"
          AS PrimaryNotebook,

        "Confirm operating system, SSH service state, listening port, package, client collection status and expected log locations."
          AS PrimaryChecks,

        "LTH - 08 - Logs and Security Events Dashboard"
          AS SecondaryNotebook,

        "Validate auth.log, secure, journal or audit coverage and confirm that the hunt period contains relevant events."
          AS SecondaryChecks,

        "Do not classify a collection gap as malicious activity; repair collection or document the accepted telemetry limitation before closing the hunt."
          AS EscalateWhen,

        "NONE - collection health only"
          AS RiskScoreImpact

      FROM scope()
    }
  )


SELECT
  RouteOrder,
  RouteRank,
  DetectionClass,
  DefaultPriority,
  RouteClass,
  EvidenceRole,
  SourceCell,
  StartPoint,
  SourceCells,
  Trigger,
  ValidationBeforePivot,
  PrimaryNotebook,
  PrimaryChecks,
  SecondaryNotebook,
  SecondaryChecks,
  EscalateWhen,
  RiskScoreImpact

FROM AuthenticationSSHPivotGuide

ORDER BY RouteOrder
```
