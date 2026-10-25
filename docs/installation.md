# Installation and Import

## Prerequisites

- A Velociraptor server with authorized administrative access.
- A tested Linux client group.
- A backup of current custom artifact definitions.
- Change approval appropriate to the target environment.

The source export was produced from Velociraptor `0.76.5`. Validate against the version used in your environment before import.

## 1. Local structural validation

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
```

This validates repository structure and internal references. It does not compile or execute VQL.

## 2. Server-side verification

On the Velociraptor server:

```bash
VR_BIN=/usr/local/bin/velociraptor
SERVER_CFG=/etc/velociraptor/server.config.yaml
REPO_DIR=/path/to/linux-threat-hunting-with-velociraptor
```

Verify all artifact files:

```bash
find "$REPO_DIR/artifacts" \
  -type f \
  -name '*.yaml' \
  -print0 |
xargs -0 sudo "$VR_BIN" \
  --config "$SERVER_CFG" \
  artifacts verify
```

Stop if verification reports an error.

For builds that expose the verifier as a top-level command, use `verify` in
place of `artifacts verify`. The following helper selects the supported command
and verifies all collectors, notebook cells, hunt templates and extracted
report queries with temporary configuration:

```bash
python3 scripts/validate_vql.py --binary "$VR_BIN"
python3 scripts/test_baseline.py --binary "$VR_BIN"
```

These commands do not connect to the deployed server. The tests use temporary
cron fixtures, local test sockets and synthetic Master Triage rows. Complete
the endpoint canary test below separately.

## 3. Import options

### Option A: GUI artifact-pack import

Create a ZIP containing the contents of `artifacts/`:

```bash
cd "$REPO_DIR/artifacts"
zip -r /tmp/lth-artifacts-0.1.0.zip .
```

In the Velociraptor artifact screen, use the artifact-pack import action and upload the ZIP. Review the displayed definitions before confirming.

### Option B: Additional definitions directory

Velociraptor can recursively load `.yaml` and `.yml` definitions from an additional directory. Point the supported definitions-directory setting or CLI `--definitions` option at:

```text
/path/to/linux-threat-hunting-with-velociraptor/artifacts
```

Artifacts loaded through external definition directories are treated as built-in for that runtime and require a service restart after file changes.

Do not copy files directly into the live datastore unless you fully understand the ownership, organization, and service-account implications.

## 4. Confirm visibility

List the loaded definitions and filter outside the Velociraptor CLI:

```bash
sudo "$VR_BIN" \
  --config "$SERVER_CFG" \
  artifacts list |
grep -E '^LTH[.]'
```

Confirm the expected count:

```bash
sudo "$VR_BIN" \
  --config "$SERVER_CFG" \
  artifacts list |
grep -E '^LTH[.]' |
wc -l
```

Expected result:

```text
114
```

Display a wrapper and a child artifact:

```bash
sudo "$VR_BIN" \
  --config "$SERVER_CFG" \
  artifacts show "LTH.NetworkConnections"
```

```bash
sudo "$VR_BIN" \
  --config "$SERVER_CFG" \
  artifacts show "LTH.NetworkConnections.NetstatEnriched"
```

## 5. Canary test

Start with one non-production Linux endpoint:

1. Collect `LTH.SystemBaseline`.
2. Confirm each expected source table.
3. Collect one focused artifact, such as `LTH.NetworkConnections.SuspiciousConnections`.
4. Review client CPU, memory, execution time, and result volume.
5. Test wrapper dependencies.
6. Confirm that no unexpected file upload occurred.

Expand to a small lab group only after the canary result is understood.

## Operational considerations

### Command execution

Thirty-nine definitions contain `execve()` calls. These commands are intended for discovery, but they still execute local binaries. Review executable paths, parameters, output limits, and platform behavior.

### File upload

Eight definitions contain `upload()` logic. Cron upload now requires
`UploadFiles=TRUE`, and the baseline/persistence wrappers explicitly pass
`UploadFiles=FALSE`. To acquire original cron files deliberately, collect the
child artifact with that parameter enabled and select its `Uploaded` source.
Other collectors retain their existing upload controls.

### Sensitive content

The following areas can return confidential material:

- SSH keys and configuration;
- command history;
- cloud CLI configuration;
- application configuration;
- process environment;
- secret indicator matches;
- sudoers and authentication logs.

Apply access control, retention, case scoping, and evidence-handling requirements.

### Fleet rollout

- use labels or a small client group;
- set concurrency and timeouts conservatively;
- schedule expensive collections outside peak hours;
- avoid simultaneous use of every wrapper;
- monitor client and server resource use;
- document expected empty-result behavior per platform.

## Rollback

Before import, export the current custom definitions. If rollback is required:

1. Stop new hunts using `LTH.*`.
2. Remove only the imported `LTH.*` definitions through the supported GUI or API workflow.
3. Restore the previous custom-definition export if needed.
4. Confirm that `artifacts list` no longer shows unintended definitions.
5. Retain collected evidence according to case and retention policy.

