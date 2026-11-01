# Provantix export verifier

Checks an export folder without access to the Provantix platform. It needs no network, no database and no account. Give an auditor this folder and the export folder, and they can run it themselves.

## Run it

```bash
node verify-export.mjs <exportDir> --keys provantix-export-keys.json   # Node 20 or later, no installs
node verify-export.mjs <exportDir> --emitter-keys emitter-keys.pem      # also check the emitter's own seals with a key you hold
python3 python/verify_export.py <exportDir> # Python 3, standard library only (emitter proof included, with a pure-Python P-256 check)
```

Add `--json` to either command for machine-readable output.

The Node verifier answers two questions. **Integrity:** do the hashes, chain links and roots recompute? A forger who edits an export can recompute all of them, so passing this alone does not show Provantix issued the export. **Authenticity:** is `manifest.sig.json` a valid signature, by one of Provantix's published export keys, over `manifest.json`? Download the keys from `https://app.provantix.tech/.well-known/provantix-export-keys.json` and pass them with `--keys`; a key inside the export is never trusted.

Node exit codes: 0 verified (integrity and authenticity), 1 failed integrity, 2 usage or unreadable input, 3 consistent but authenticity not established (unsigned, no keys given, unknown key, bad signature). `--integrity-only` exits 0 on integrity alone. The Python verifier checks integrity only, reports authenticity as `not_checked`, and exits 0 or 1 on integrity.

Both implementations are checked against the same vectors in `vectors/`. The Node and Python outputs match on every vector.

## What a passing result means

- Every record in the export recomputes to its stored hash, so no field was changed after ingest.
- Records in the same chain link correctly, so none was removed from the middle of a chain.
- For a complete export, each day's roots recompute from the records, so the day's contents match the root that was written.
- Erased personal fields still verify, because their commitments remain.

## What a passing result does not mean

- It does not prove the source systems reported every event. Completeness needs source-side counts, which are outside the export.
- It does not prove legal admissibility. That is a question for counsel.
- It does not by itself show the emitter vouched for each record. That is the separate emitter proof (see `FORMAT.md`), present only where the export carries seals, and its result says whose key it rests on. A key listed in the export, or one Provantix generated, is not independent of Provantix; a key you hold yourself, passed with `--emitter-keys`, is.

The format is in `FORMAT.md`. Anyone building a third implementation can use it and the vectors to check their work.
