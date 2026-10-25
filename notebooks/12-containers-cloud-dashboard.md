# LTH - 12 - Containers and Cloud Workloads Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 12 - Containers and Cloud Workloads Dashboard

This notebook analyzes Linux container and cloud workload data collected by:

`LTH.ContainerCloud`

Main objectives:

- Discover container runtime tools and sockets
- Review Docker and Podman containers
- Identify privileged containers and host namespace usage
- Review Kubernetes configuration indicators
- Review container runtime configuration
- Review cloud agents and cloud workload indicators
- Identify suspicious metadata access or cloud config indicators
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Runtime Tools Inventory

This section shows which container runtime and orchestration tools are installed.

Installed tools such as Docker, Podman, containerd, crictl, kubectl, and kubelet help identify endpoints that host container or Kubernetes workloads.

## Cell 3 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Tool,
       Status,
       Path,
       Version,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/RuntimeTools"
)
ORDER BY ClientId
```

## Cell 4 (markdown)

# Runtime Sockets and Sensitive Runtime Files

## Cell 5 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       FileType,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/RuntimeSockets"
)
ORDER BY ClientId
```

## Cell 6 (markdown)

# Suspicious Runtime Sockets

## Cell 7 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       OSPath,
       FileType,
       OctalMode,
       Owner,
       Group,
       Size,
       MTime,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/SuspiciousRuntimeSockets"
)
ORDER BY ClientId
```

## Cell 8 (markdown)

# Container Runtime Processes

This section reviews running processes related to container runtimes, Kubernetes, and cloud workload agents.

It helps identify active Docker, Podman, containerd, CRI-O, kubelet, and cloud agent activity on Linux endpoints.

## Cell 9 (vql)

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
  artifact="LTH.ContainerCloud/ContainerRuntimeProcesses"
)
ORDER BY ClientId
```

## Cell 10 (markdown)

# Suspicious Container Processes

## Cell 11 (vql)

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
  artifact="LTH.ContainerCloud/SuspiciousContainerProcesses"
)
ORDER BY ClientId
```

## Cell 12 (markdown)

# Docker Containers Inventory

This section reviews Docker containers when Docker is available.

Container privilege level, host namespaces, user context, and bind mounts are important for identifying container escape or host exposure risks.

## Cell 13 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       ContainerId,
       Name,
       Image,
       Status,
       ContainerUser,
       Privileged,
       PidMode,
       NetworkMode,
       Binds,
       Mounts,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/DockerContainers"
)
ORDER BY ClientId
```

## Cell 14 (markdown)

# Suspicious Docker Containers

## Cell 15 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       ContainerId,
       Name,
       Image,
       Status,
       ContainerUser,
       Privileged,
       PidMode,
       NetworkMode,
       Binds,
       Mounts,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/SuspiciousDockerContainers"
)
ORDER BY ClientId
```

## Cell 16 (markdown)

# Docker Images Inventory

## Cell 17 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Repository,
       Tag,
       ImageId,
       CreatedSince,
       Size
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/DockerImages"
)
ORDER BY ClientId
```

## Cell 18 (markdown)

# Podman Containers Inventory

## Cell 19 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       ContainerId,
       Name,
       Image,
       Status,
       ContainerUser,
       Privileged,
       PidMode,
       NetworkMode,
       Binds,
       Mounts,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/PodmanContainers"
)
ORDER BY ClientId
```

## Cell 20 (markdown)

# Suspicious Podman Containers

## Cell 21 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       ContainerId,
       Name,
       Image,
       Status,
       ContainerUser,
       Privileged,
       PidMode,
       NetworkMode,
       Binds,
       Mounts,
       Severity,
       Reason
FROM hunt_results(hunt_id=HuntId,
                  artifact="LTH.ContainerCloud/SuspiciousPodmanContainers")
ORDER BY ClientId


```

## Cell 22 (markdown)

# Kubernetes Configuration Lines

This section reviews Kubernetes and kubelet configuration files.

Kubernetes configuration can reveal privileged workloads, hostPath mounts, host namespaces, root containers, and other workload hardening issues.

## Cell 23 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       ConfigLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/KubernetesConfigLines"
)
ORDER BY ClientId
```

## Cell 24 (markdown)

# Suspicious Kubernetes Configuration

## Cell 25 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       ConfigLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/SuspiciousKubernetesConfig"
)
ORDER BY ClientId
```

## Cell 26 (markdown)

# CRI Containers

## Cell 27 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       RawLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/CRIContainers"
)
ORDER BY ClientId
```

## Cell 28 (markdown)

# Container Runtime Configuration

This section reviews Docker, containerd, Podman, CRI-O, and CNI configuration files.

Insecure registries, disabled TLS verification, sensitive mounts, and risky runtime options should be reviewed carefully.

## Cell 29 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       ConfigLine
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/ContainerConfigLines"
)
ORDER BY ClientId
```

## Cell 30 (markdown)

# Suspicious Container Runtime Configuration

## Cell 31 (vql)

```vql
LET HuntId <= "HUNT_ID"

SELECT ClientId,
       Path,
       LineNumber,
       ConfigLine,
       Severity,
       Reason
FROM hunt_results(
  hunt_id=HuntId,
  artifact="LTH.ContainerCloud/SuspiciousContainerConfig"
)
ORDER BY ClientId
```

## Cell 32 (markdown)

# Cloud Agent Processes

This section reviews cloud workload and cloud agent processes.

Cloud agents such as AWS SSM Agent, Azure Linux Agent, Google Guest Agent, and cloud-init may indicate cloud-hosted Linux workloads.

## Cell 33 (vql)

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
  artifact="LTH.ContainerCloud/CloudAgentProcesses"
)
ORDER BY ClientId
```

## Cell 34 (markdown)

# Cloud Config File Inventory

## Cell 35 (vql)

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
  artifact="LTH.ContainerCloud/CloudConfigFileInventory"
)
ORDER BY ClientId
```

## Cell 36 (markdown)

# Suspicious Cloud Config Indicators

## Cell 37 (vql)

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
  artifact="LTH.ContainerCloud/SuspiciousCloudConfigIndicators"
)
ORDER BY ClientId
```

## Cell 38 (markdown)

# Metadata Access Processes

## Cell 39 (vql)

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
  artifact="LTH.ContainerCloud/MetadataAccessProcesses"
)
ORDER BY ClientId
```

## Cell 40 (markdown)

# Finding Count by Category

## Cell 41 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RuntimeSockets <=
  SELECT ClientId,
         "Suspicious Runtime Socket" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousRuntimeSockets"
  )
  GROUP BY ClientId

LET ContainerProcesses <=
  SELECT ClientId,
         "Suspicious Container Process" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerProcesses"
  )
  GROUP BY ClientId

LET DockerContainers <=
  SELECT ClientId,
         "Suspicious Docker Container" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousDockerContainers"
  )
  GROUP BY ClientId

LET PodmanContainers <=
  SELECT ClientId,
         "Suspicious Podman Container" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousPodmanContainers"
  )
  GROUP BY ClientId

LET KubernetesConfig <=
  SELECT ClientId,
         "Suspicious Kubernetes Configuration" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousKubernetesConfig"
  )
  GROUP BY ClientId

LET ContainerConfig <=
  SELECT ClientId,
         "Suspicious Container Runtime Configuration" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerConfig"
  )
  GROUP BY ClientId

LET CloudConfig <=
  SELECT ClientId,
         "Suspicious Cloud Config Indicator" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousCloudConfigIndicators"
  )
  GROUP BY ClientId

LET MetadataProcesses <=
  SELECT ClientId,
         "Cloud Metadata Access Process" AS Finding,
         count() AS EventCount
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/MetadataAccessProcesses"
  )
  GROUP BY ClientId

SELECT *
FROM chain(
  a=RuntimeSockets,
  b=ContainerProcesses,
  c=DockerContainers,
  d=PodmanContainers,
  e=KubernetesConfig,
  f=ContainerConfig,
  g=CloudConfig,
  h=MetadataProcesses
)
ORDER BY ClientId
```

## Cell 42 (markdown)

# Final Findings Detail

This section combines container and cloud workload indicators into one findings table.

It includes suspicious runtime sockets, suspicious container processes, privileged containers, risky Kubernetes configuration, suspicious container runtime configuration, cloud config indicators, and metadata access processes.

Use this table as the main evidence view for container and cloud workload hunting.

## Cell 43 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RuntimeSockets <=
  SELECT ClientId,
         Severity,
         "Suspicious Runtime Socket" AS Finding,
         OSPath AS Evidence1,
         OctalMode AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousRuntimeSockets"
  )

LET ContainerProcesses <=
  SELECT ClientId,
         Severity,
         "Suspicious Container Process" AS Finding,
         Pid AS Evidence1,
         Exe AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerProcesses"
  )

LET DockerContainers <=
  SELECT ClientId,
         Severity,
         "Suspicious Docker Container" AS Finding,
         Name AS Evidence1,
         Image AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousDockerContainers"
  )

LET PodmanContainers <=
  SELECT ClientId,
         Severity,
         "Suspicious Podman Container" AS Finding,
         Name AS Evidence1,
         Image AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousPodmanContainers"
  )

LET KubernetesConfig <=
  SELECT ClientId,
         Severity,
         "Suspicious Kubernetes Configuration" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         ConfigLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousKubernetesConfig"
  )

LET ContainerConfig <=
  SELECT ClientId,
         Severity,
         "Suspicious Container Runtime Configuration" AS Finding,
         Path AS Evidence1,
         Reason AS Evidence2,
         ConfigLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerConfig"
  )

LET CloudConfig <=
  SELECT ClientId,
         Severity,
         "Suspicious Cloud Config Indicator" AS Finding,
         Path AS Evidence1,
         Indicator AS Evidence2,
         Reason AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousCloudConfigIndicators"
  )

LET MetadataProcesses <=
  SELECT ClientId,
         Severity,
         "Cloud Metadata Access Process" AS Finding,
         Pid AS Evidence1,
         Exe AS Evidence2,
         CommandLine AS Evidence3
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/MetadataAccessProcesses"
  )

SELECT *
FROM chain(
  a=RuntimeSockets,
  b=ContainerProcesses,
  c=DockerContainers,
  d=PodmanContainers,
  e=KubernetesConfig,
  f=ContainerConfig,
  g=CloudConfig,
  h=MetadataProcesses
)
ORDER BY ClientId
```

## Cell 44 (markdown)

# Clients Needing Investigation

This section summarizes container and cloud workload findings per client.

Clients with higher finding counts should be prioritized for deeper investigation, especially when privileged containers, runtime socket exposure, host namespace usage, risky Kubernetes configuration, or cloud metadata access indicators are detected.

This view helps analysts quickly identify Linux endpoints that require follow-up hunts.

## Cell 45 (vql)

```vql
LET HuntId <= "HUNT_ID"

LET RuntimeSockets <=
  SELECT ClientId,
         "Suspicious Runtime Socket" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousRuntimeSockets"
  )

LET ContainerProcesses <=
  SELECT ClientId,
         "Suspicious Container Process" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerProcesses"
  )

LET DockerContainers <=
  SELECT ClientId,
         "Suspicious Docker Container" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousDockerContainers"
  )

LET PodmanContainers <=
  SELECT ClientId,
         "Suspicious Podman Container" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousPodmanContainers"
  )

LET KubernetesConfig <=
  SELECT ClientId,
         "Suspicious Kubernetes Configuration" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousKubernetesConfig"
  )

LET ContainerConfig <=
  SELECT ClientId,
         "Suspicious Container Runtime Configuration" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousContainerConfig"
  )

LET CloudConfig <=
  SELECT ClientId,
         "Suspicious Cloud Config Indicator" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/SuspiciousCloudConfigIndicators"
  )

LET MetadataProcesses <=
  SELECT ClientId,
         "Cloud Metadata Access Process" AS Finding
  FROM hunt_results(
    hunt_id=HuntId,
    artifact="LTH.ContainerCloud/MetadataAccessProcesses"
  )

LET Findings <=
  SELECT *
  FROM chain(
    a=RuntimeSockets,
    b=ContainerProcesses,
    c=DockerContainers,
    d=PodmanContainers,
    e=KubernetesConfig,
    f=ContainerConfig,
    g=CloudConfig,
    h=MetadataProcesses
  )

SELECT ClientId,
       count() AS FindingCount
FROM Findings
GROUP BY ClientId
ORDER BY FindingCount DESC
```

## Cell 46 (markdown)

# Recommended Next Actions

Clients with container or cloud workload findings should be reviewed in deeper investigation.

Recommended follow-up actions:

1. Review exposed or weakly protected container runtime sockets.
2. Investigate privileged containers and host namespace usage.
3. Validate Docker, Podman, and Kubernetes hostPath or sensitive bind mounts.
4. Review Kubernetes configurations for privileged, hostNetwork, hostPID, and runAsUser 0 settings.
5. Review container runtime configuration for insecure registries or disabled TLS verification.
6. Investigate cloud metadata access and suspicious cloud configuration indicators.
7. Correlate findings with process, network, persistence, filesystem, malware, and privilege escalation hunts.
