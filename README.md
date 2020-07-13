# elastic-migrate
Migrate elastic indices from 5.0 to 7.0

1. Reindex asynchronously to allow migrating large indices.
2. Validate by index counts after migrating to elastic 7.
3. Skip indices that are already migrated during re-run.
4. Provision to add aliases and index templates.
