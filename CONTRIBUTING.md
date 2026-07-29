# Contributing

Contributions should improve detection value without weakening operational safety.

## Artifact requirements

Every new or changed artifact should:

- use a unique `LTH.<Domain>.<Name>` identifier;
- keep the filename identical to the artifact name;
- include a clear description and explicit Linux precondition where applicable;
- use unique source names when multiple result tables exist;
- expose safe, documented parameters instead of environment-specific values;
- declare required permissions;
- avoid uploads by default;
- avoid real endpoint, customer, Hunt, or Client data;
- document false positives and expected clean-host behavior.

## Development workflow

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_repository.py
python3 scripts/generate_artifact_catalog.py
```

Then validate the definitions with the same Velociraptor version used in the target environment.

## Pull-request checklist

- [ ] YAML parses successfully.
- [ ] Artifact name matches the filename.
- [ ] Internal artifact and named-source references resolve.
- [ ] Resource and permission impact is documented.
- [ ] Upload behavior is disabled by default or explicitly justified.
- [ ] Tests were performed on a non-production endpoint.
- [ ] No sensitive identifiers or evidence are included.
- [ ] The artifact catalog was regenerated.

