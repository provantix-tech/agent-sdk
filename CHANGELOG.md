# Changelog

## 0.3.0

- **Location.** `new AgentEmitter({ location })` says where the emitter runs and what it acts on, as short codes: `{ runtime: { provider, region, zone, country }, target: { region, country } }`. With no setting it reads the cloud region it runs in (`AWS_REGION`, `GOOGLE_CLOUD_REGION`, `FLY_REGION`, `VERCEL_REGION`) when one is set. `buildAAR({ location })` overrides it for one action. The location is part of the sealed record, so the seal and the batch signature cover it, and Provantix shows it as declared. Nothing finer than a country is kept: a city, an address or free text is dropped before sealing, and the platform refuses a record that carries one.
- The vendored `collector.mjs` is synced from the engine (it carries `location` into the record fields).
- Requires a Provantix that accepts location, which every current platform does. A record without a location is unchanged.

## 0.2.0

- **Sealed batches.** The emitter signs the hash of every record in each batch (the batch seal) and adds it to the envelope, which moves to version 1.1. On by default; `seal: false` restores the unsealed 1.0 batch. An auditor can check the seal with the emitter's public key, without trusting Provantix, and it still verifies after a person's data is erased.
- Batches queued by an older version are sealed when 0.2.0 sends them (same records, same batch number, same creation time), so an emitter paused at the deadline can be upgraded without losing what it queued.
- Also in this release, from work done since 0.1.1 that was not yet published: approvals mapped into the record's `authorization` block (`provantix.approval.*` attributes), the delegation chain rebuilt from span parentage, tool arguments, results, data classes and the external recipient on records, an OpenTelemetry SpanExporter for one-line instrumentation, the stable target-system contract for run ids, and runnable examples. If you run 0.1.1 in production, check these against your setup before upgrading.
- The vendored `batch.mjs` and `collector.mjs` are synced from the engine. A test fails if they drift.
- Requires a Provantix that accepts seals. Sealed batches are accepted by every current platform; unsealed batches will be refused after the notice period Provantix sends.

## 0.1.1

- Vendor the integrity modules so the package is self-contained.

## 0.1.0

- First release: signed, hash-chained agent telemetry.
