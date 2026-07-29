# Security Policy

## Supported version

The current public release line is `0.1.x`. Security fixes are applied to the latest repository state.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, endpoint data, unsafe command execution, or an artifact bypass.

Use GitHub's private vulnerability reporting feature when it is enabled for the repository. Include:

- the affected artifact and source name;
- the tested Velociraptor version;
- the unsafe input or execution path;
- impact and reproduction steps;
- a suggested mitigation, if available.

Remove organization names, credentials, endpoint identifiers, and collected evidence from the report.

## Data-handling warning

Several artifacts inspect sensitive paths, configuration files, command history, SSH material, process environment, and cloud CLI configuration. Eight definitions also contain conditional or source-specific `upload()` logic.

Before a production collection:

1. Review the selected artifact sources and parameters.
2. Disable uploads unless evidence acquisition is explicitly authorized.
3. Test on a canary endpoint.
4. Apply least privilege and retention controls.
5. Confirm that collected data may legally leave the endpoint.

## Execution warning

Some definitions use `execve()` for local discovery commands such as `systemctl`, package tools, container CLIs, and operating-system utilities. Treat all command execution as privileged collection logic:

- review the exact command and arguments;
- verify binary resolution and environment behavior;
- use conservative fleet concurrency;
- enforce collection timeouts and resource limits;
- avoid running unreviewed changes in production.

## Public-repository hygiene

Never commit:

- `server.config.yaml`, `client.config.yaml`, or API configuration;
- tokens, passwords, nonces, certificates, or private keys;
- real Hunt IDs, Client IDs, hostnames, usernames, or internal addresses;
- raw collections, uploaded endpoint files, or customer evidence.

Run `python3 scripts/validate_repository.py` before every release, then perform a manual review. Automated scanning cannot prove that content is safe to publish.
