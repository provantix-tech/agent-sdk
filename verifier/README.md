# Provantix export verifier

Checks an export folder without access to the Provantix platform. It needs no network, no database and no account. Give an auditor this folder and the export folder, and they can run it themselves.

## Run it

```bash
node verify-export.mjs <exportDir> --keys provantix-export-keys.json   # Node 20 or later, no installs
node verify-export.mjs <exportDir> --emitter-keys emitter-keys.pem      # also check the emitter's own seals with a key you hold
python3 python/verify_export.py <exportDir> # Python 3, standard library only (emitter proof included, with a pure-Python P-256 check)
```

Add `--json` to either command for machine-readable output.

If the export carries `transparency.json`, the Node verifier also checks it: that the export's manifest hash and each daily root are what Provantix logged in its public transparency log. Pass the log's published keys with `--log-keys provantix-log-keys.json` to check the signed tree head too. To watch the log itself, run `node verify-log.mjs https://app.provantix.tech --keys provantix-log-keys.json --state mirror-state.json` on a schedule: it recomputes the whole log and fails if history was rewritten since your last run. See `FORMAT.md`, section Transparency log.

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

## What is open, and what is not

**Open (this folder):** the export format ([FORMAT.md](FORMAT.md)) and its version history ([CHANGES.md](CHANGES.md)), the two verifiers (`verify-export.mjs`, `python/verify_export.py`), the transparency log mirror (`verify-log.mjs`) and its time-stamp check (`rfc3161.mjs`), the vectors (`vectors/`), and the conformance runner (`conformance-run.mjs`). Licensed under the Apache License 2.0 ([LICENSE](LICENSE)).

**Not open:** the Provantix platform that collects records, seals days, signs exports and runs the transparency log. It is not part of this project. What it writes is described by the specification, and only the specification is the contract. A reviewer needs the platform's code to check an export no more than they need it to read one.

Why it is split this way: a platform should not grade itself. A reviewer can rely on evidence only if they can check it with tools that are not ours, and read the rules those tools follow.

## Keep reading

- [CONFORMANCE.md](CONFORMANCE.md): show that a verifier you wrote agrees on every vector.
- [STABILITY.md](STABILITY.md): what you can build on, and what may change.
- [CONTRIBUTING.md](CONTRIBUTING.md): how a change is made, and what a format change must touch.
- Security problems: write to contactus@versalence.ai with "verifier security" in the subject.
