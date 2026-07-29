# Investigation Workflow

## 1. Baseline and hunt health

Confirm collection coverage before analyzing findings:

- intended clients versus responding clients;
- completed, in-progress, and failed flows;
- artifact and source availability;
- result volume anomalies;
- collection duration and resource impact;
- hosts with missing or incomplete baseline data.

A missing result may mean a clean endpoint, an inapplicable precondition, an unavailable data source, or a failed collection. Do not interpret empty output without checking hunt health.

## 2. Master Triage

Correlate high-signal evidence across clients:

- suspicious processes;
- unusual listening or established network connections;
- suspicious cron and persistence commands;
- privilege-escalation indicators;
- malware or tool indicators;
- secret and configuration exposure.

Rank clients by evidence count and weighted risk, then review the evidence rows behind each score.

## 3. Scope and hypothesis

Convert the triage observation into a testable hypothesis.

Example:

> A process executing from `/tmp` opened an established outbound connection and may have created persistence through cron.

Define:

- affected client or client group;
- relevant time window;
- user and privilege context;
- expected benign explanation;
- evidence required to confirm or reject the hypothesis.

## 4. Targeted investigation

| Triage signal | Primary pivot | Supporting pivots |
| --- | --- | --- |
| Unknown listener or external connection | Network Connections | Processes & Services, Malware Tools |
| Deleted executable or execution from writable path | Processes & Services | File Timeline, Malware Tools |
| Suspicious cron, systemd, shell profile, or PAM entry | Persistence | File Timeline, Logs |
| UID 0, risky sudoers, SUID/SGID, or capabilities | Privilege Escalation | Users & Privileges, Logs |
| Kernel module, preload hook, or `/proc` mismatch | Rootkit & Kernel | Processes, File Timeline |
| Archive, transfer tool, cloud CLI, or large recent files | Data Access & Exfiltration | Network, Logs, Config & Secrets |
| Container runtime or cloud-agent anomaly | Containers & Cloud | Processes, Network, Config & Secrets |
| Exposed credential pattern or risky config permission | Configuration & Secrets | Authentication & SSH, Logs |

Collect only the additional evidence needed to answer the hypothesis. Avoid broad file upload until the endpoint and target paths are justified.

## 5. Evidence correlation

Correlate at least two independent evidence types where possible:

- process plus network;
- process plus file timeline;
- authentication plus account or privilege change;
- persistence entry plus executable metadata;
- archive creation plus transfer activity;
- configuration exposure plus access evidence.

Preserve original timestamps and identifiers in the secured case record. Public documentation should use synthetic or redacted examples.

## 6. Disposition

Classify each finding:

- `Benign`: expected administrative or application behavior;
- `Suspicious`: requires more evidence or owner confirmation;
- `Confirmed`: malicious, unauthorized, or policy-violating activity;
- `Collection gap`: evidence was unavailable or insufficient.

Record the rationale, not only the label.

## 7. Report and detection improvement

The final output should include:

- executive summary;
- scope and hypothesis;
- affected systems;
- evidence timeline;
- findings and confidence;
- limitations;
- containment or hardening actions;
- detection-engineering improvements;
- artifact or notebook tuning actions.

Feed recurring benign patterns into narrowly scoped tuning. Feed confirmed behavior into detection content, telemetry requirements, and future hunt hypotheses.

