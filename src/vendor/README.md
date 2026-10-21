# Vendored integrity modules

These files are vendored from the Provantix engine at release time:

- `collector.mjs`, `spool.mjs`, `batch.mjs`, `handles.mjs`, `gate.mjs`, `redact.mjs`
  come from `ledger/packages/collector-core/src/`
- `canonical.mjs`, `ulid.mjs`, `integrity.mjs`, `aar.mjs` come from
  `ledger/packages/aar-schema/src/`

They are copied (not depended on) so the published package stays self-contained:
no runtime dependencies, installable without the rest of the monorepo. Keep the
copies in sync when the engine modules change.
