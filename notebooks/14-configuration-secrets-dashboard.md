# LTH - 14 - Configuration and Secrets Review Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 14 - Configuration and Secrets Review Dashboard

This notebook analyzes Linux configuration and secrets review data collected by:

`LTH.ConfigSecrets`

Main objectives:

- Review configuration file inventory
- Identify recently modified configuration files
- Inventory private keys and secret-like files
- Identify weak permissions on secret-like files
- Identify world-writable configuration files
- Detect secret indicators without exposing values
- Review process environment variable secret indicators
- Review application and web configuration indicators
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Configuration Files Inventory

This section inventories common Linux system, application, web, user, cloud, and container configuration files.

Use this view to understand where important configuration files exist across Linux endpoints.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/ConfigFiles"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Recently Modified Configuration Files

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/RecentlyModifiedConfigFiles"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Private Key Files

This section inventories private keys, certificate material, and key-like files.

Private keys with world-readable permissions should be treated as high risk and reviewed immediately.

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/PrivateKeyFiles"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# Secret-Like Files

This section identifies files with secret-like names or paths.

Examples include token files, credential files, environment files, cloud CLI configs, Kubernetes configs, and application secret files.

## Cell 9 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/SecretLikeFiles"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# Secret Indicator Matches

This section detects secret and credential indicators inside small configuration files.

The actual secret value is not displayed. Only the file path, line number, and indicator type are shown.

## Cell 11 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       Indicator,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/SecretIndicatorMatches"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Weak Secret Permissions

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/WeakSecretPermissions"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# World-Writable Configuration Files

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/WorldWritableConfigFiles"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Process Environment Secret Indicators

This section reviews process environment variables for secret-like variable names.

The actual variable value is not returned. Only the variable name is shown to avoid exposing secrets in the notebook.

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Pid,
       ProcessName,
       VariableName,
       Indicator,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/ProcessEnvironmentSecretIndicators"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# Application Configuration Files

This section reviews web and application configuration files.

Files such as `.env`, `wp-config.php`, `database.php`, `settings.php`, and `docker-compose.yml` often contain database credentials, API keys, or application secrets.

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/ApplicationConfigFiles"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Application Secret Indicators

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       Indicator,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/ApplicationSecretIndicators"
)
ORDER BY ClientId
```

## Cell 22 (markdown)

# Cloud and Kubernetes Secret Files

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       "Cloud, container, or Kubernetes secret-like file" AS Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/SecretLikeFiles"
)
WHERE OSPath =~ "(?i)(\\.aws|\\.azure|gcloud|rclone|kubernetes|kubelet|kubeconfig|docker|containerd)"
ORDER BY ClientId
```

## Cell 24 (markdown)

# FileFinder Results

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT *
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ConfigSecrets/FileFinder"
)
LIMIT 500
```

## Cell 26 (markdown)

# Finding Count by Category

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RecentConfigs <=
  SELECT ClientId,
         "Recently Modified Config File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/RecentlyModifiedConfigFiles"
  )
  GROUP BY ClientId

LET PrivateKeys <=
  SELECT ClientId,
         "Private Key File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/PrivateKeyFiles"
  )
  GROUP BY ClientId

LET SecretFiles <=
  SELECT ClientId,
         "Secret-Like File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretLikeFiles"
  )
  GROUP BY ClientId

LET SecretIndicators <=
  SELECT ClientId,
         "Secret Indicator Match" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretIndicatorMatches"
  )
  GROUP BY ClientId

LET WeakPermissions <=
  SELECT ClientId,
         "Weak Secret Permission" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WeakSecretPermissions"
  )
  GROUP BY ClientId

LET WorldWritableConfigs <=
  SELECT ClientId,
         "World-Writable Config File" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WorldWritableConfigFiles"
  )
  GROUP BY ClientId

LET EnvIndicators <=
  SELECT ClientId,
         "Process Environment Secret Indicator" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ProcessEnvironmentSecretIndicators"
  )
  GROUP BY ClientId

LET AppIndicators <=
  SELECT ClientId,
         "Application Secret Indicator" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ApplicationSecretIndicators"
  )
  GROUP BY ClientId

SELECT *
FROM chain(
  a=RecentConfigs,
  b=PrivateKeys,
  c=SecretFiles,
  d=SecretIndicators,
  e=WeakPermissions,
  f=WorldWritableConfigs,
  g=EnvIndicators,
  h=AppIndicators
)
ORDER BY ClientId
```

## Cell 28 (markdown)

# Final Findings Detail

This section combines configuration and secrets review indicators into one findings table.

It includes recently modified configs, private keys, secret-like files, secret indicators, weak permissions, world-writable configs, process environment indicators, and application secret indicators.

Use this table as the main evidence view for configuration and secrets hunting.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RecentConfigs <=
  SELECT ClientId,
         Severity,
         "Recently Modified Config File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         MTime AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/RecentlyModifiedConfigFiles"
  )

LET PrivateKeys <=
  SELECT ClientId,
         Severity,
         "Private Key File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/PrivateKeyFiles"
  )

LET SecretFiles <=
  SELECT ClientId,
         Severity,
         "Secret-Like File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretLikeFiles"
  )

LET SecretIndicators <=
  SELECT ClientId,
         Severity,
         "Secret Indicator Match" AS Finding,
         Path AS Evidence1,
         LineNumber AS Evidence2,
         Indicator AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretIndicatorMatches"
  )

LET WeakPermissions <=
  SELECT ClientId,
         Severity,
         "Weak Secret Permission" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WeakSecretPermissions"
  )

LET WorldWritableConfigs <=
  SELECT ClientId,
         Severity,
         "World-Writable Config File" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WorldWritableConfigFiles"
  )

LET EnvIndicators <=
  SELECT ClientId,
         Severity,
         "Process Environment Secret Indicator" AS Finding,
         Pid AS Evidence1,
         ProcessName AS Evidence2,
         VariableName AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ProcessEnvironmentSecretIndicators"
  )

LET AppIndicators <=
  SELECT ClientId,
         Severity,
         "Application Secret Indicator" AS Finding,
         Path AS Evidence1,
         LineNumber AS Evidence2,
         Indicator AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ApplicationSecretIndicators"
  )

SELECT *
FROM chain(
  a=RecentConfigs,
  b=PrivateKeys,
  c=SecretFiles,
  d=SecretIndicators,
  e=WeakPermissions,
  f=WorldWritableConfigs,
  g=EnvIndicators,
  h=AppIndicators
)
ORDER BY ClientId
```

## Cell 30 (markdown)

# Clients Needing Investigation

This section summarizes configuration and secrets findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when private keys, weak permissions, world-writable configs, secret indicators, or application secrets are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET PrivateKeys <=
  SELECT ClientId,
         "Private Key File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/PrivateKeyFiles"
  )

LET SecretFiles <=
  SELECT ClientId,
         "Secret-Like File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretLikeFiles"
  )

LET SecretIndicators <=
  SELECT ClientId,
         "Secret Indicator Match" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/SecretIndicatorMatches"
  )

LET WeakPermissions <=
  SELECT ClientId,
         "Weak Secret Permission" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WeakSecretPermissions"
  )

LET WorldWritableConfigs <=
  SELECT ClientId,
         "World-Writable Config File" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/WorldWritableConfigFiles"
  )

LET EnvIndicators <=
  SELECT ClientId,
         "Process Environment Secret Indicator" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ProcessEnvironmentSecretIndicators"
  )

LET AppIndicators <=
  SELECT ClientId,
         "Application Secret Indicator" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ConfigSecrets/ApplicationSecretIndicators"
  )

LET Findings <=
  SELECT *
  FROM chain(
    a=PrivateKeys,
    b=SecretFiles,
    c=SecretIndicators,
    d=WeakPermissions,
    e=WorldWritableConfigs,
    f=EnvIndicators,
    g=AppIndicators
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 32 (markdown)

# Recommended Next Actions

Clients with configuration or secrets findings should be reviewed in deeper investigation.

Recommended follow-up actions:

1. Review private keys and secret-like files based on owner, path, and permission.
2. Fix weak permissions on private keys, `.env` files, cloud credentials, and application configs.
3. Investigate world-writable configuration files immediately.
4. Review recently modified configuration files for unauthorized changes.
5. Rotate exposed credentials when secret indicators are confirmed.
6. Avoid uploading sensitive files during general hunts; collect files only from prioritized clients.
7. Correlate findings with authentication, process, persistence, data exfiltration, and malware/tool hunts.
