# Conformance: showing that your verifier agrees

A verifier agrees with this specification if, on every vector in `vectors/`, it reaches the same result as `vectors/expected.json`: the same pass or fail, and the same checks failing, by name. That is the whole test. Nothing else about how it is written matters.

## Run it

You need Node 20 or later (for the runner only; your verifier can be in any language).

```bash
node conformance-run.mjs -- <your verifier command>
```

The runner runs your command once per vector as

```
<your verifier command> <exportDir> [--emitter-keys <file>] --json
```

and reads the JSON it prints to standard output. That JSON needs:

- `"ok"`: `true` or `false`, whether every check passed.
- `"checks"`: an array of `{ "name": "...", "ok": true|false }`. Other fields are ignored.

For the verifiers in this folder:

```bash
node conformance-run.mjs -- node verify-export.mjs
node conformance-run.mjs -- python3 python/verify_export.py
```

Each vector prints `PASS` or `FAIL`. A `FAIL` line says what was expected and what your verifier reported. Exit code 0 means every vector agrees.

## Reading a failure

A vector that your verifier passes and that should fail (or the reverse) is almost always a gap in how the specification was read. Find the rule in [FORMAT.md](FORMAT.md), and if the rule was unclear, tell us: see [CONTRIBUTING.md](CONTRIBUTING.md).

## What agreeing shows, and does not

It shows that your verifier reaches the same answer as ours on these cases. It does not show it is correct on a case the vectors do not cover, which is why more vectors are welcome. It does not show an export is true: see "What verification proves and does not prove" in FORMAT.md.

## The vectors

This table is generated from `vectors/expected.json` by `node conformance-run.mjs --table`, and a test fails if it is out of date.

<!-- vectors:begin -->
| Vector | Expected | Failing checks, by name |
|---|---|---|
| `valid` | passes | none |
| `tampered-record` | fails | `record 01M50HCPA72XPGP7Z2JSRNXZZM`, `records recompute` |
| `broken-chain` | fails | `chain links hold` |
| `bad-root` | fails | `root 2026-10-15` |
| `missing-file` | fails | `file present: timeline.csv` |
| `erased-field` | passes | none |
| `sealed-valid` | passes | none |
| `sealed-valid-auditor-key` (with `sealed-valid.emitter-keys.pem`) | passes | none |
| `sealed-forged-record` | fails | `emitter proof: records match seals` |
| `sealed-missing-record` | fails | `emitter proof: no sealed record missing` |
| `sealed-refused-at-ingest` | passes | none |
| `sealed-wrong-key-no-auditor-key` | passes | none |
| `sealed-wrong-key` (with `sealed-wrong-key.emitter-keys.json`) | fails | `emitter proof: seals verify` |
| `sealed-erased` | passes | none |
| `sealed-compromised-window` | fails | `emitter proof: no seal from a compromised key` |
| `reconciled-valid` | passes | none |
| `reconciled-state-flipped` | fails | `reconciliation: results consistent with the destination records carried` |
| `reconciled-destination-altered` | fails | `reconciliation: results consistent with the destination records carried` |
| `reconciled-confirmed-without-record` | fails | `reconciliation: every confirmed result rests on a destination record carried` |
| `reconciled-binding-forged` | fails | `approval binding: results recompute from the records` |
| `reconciled-unknown-record` | fails | `reconciliation: structure` |
| `reconciled-edited-after-signing` | fails | `file hash: reconciliation.json` |
| `reconciled-payment-alias` | passes | none |
| `reconciled-payment-mismatch` | fails | `reconciliation: results consistent with the destination records carried` |
| `decision-valid` | passes | none |
| `decision-swapped-reference` | fails | `decision evidence: every decision agrees with the action that cites it` |
| `decision-wrong-action` | fails | `decision evidence: every decision agrees with the action that cites it` |
| `decision-duplicate-id` | fails | `decision evidence: every decision agrees with the action that cites it` |
| `decision-malformed` | fails | `decision evidence: decisions are well formed` |
| `decision-malformed-model-ref` | fails | `decision evidence: decisions are well formed` |
| `decision-not-in-export` | passes | none |
| `control-valid` | passes | none |
| `control-swapped-reference` | fails | `control evidence: every control decision agrees with the action that cites it` |
| `control-duplicate-id` | fails | `control evidence: every control decision agrees with the action that cites it` |
| `control-malformed` | fails | `control evidence: control decisions are well formed` |
| `control-unbound` | passes | none |
| `control-not-in-export` | passes | none |
| `exact-change-valid` | passes | none |
| `exact-change-environment-forged` | fails | `approval binding: results recompute from the records` |
| `exact-change-break-glass-hidden` | fails | `approval binding: results recompute from the records` |
| `exact-change-approved-after-action` | fails | `approval binding: results recompute from the records` |
| `exact-change-digest-swapped` | fails | `approval binding: results recompute from the records` |
| `statement-valid` | passes | none |
| `statement-cell-altered` | fails | `statement: total equals the cells`, `statement: totals by provider and model equal the cells`, `statement: allocation by department equals the cells and adds up to the total`, `statement: allocation by cost_center equals the cells and adds up to the total`, `statement: allocation by product equals the cells and adds up to the total`, `statement: allocation by agent equals the cells and adds up to the total` |
| `statement-total-altered` | fails | `statement: total equals the cells`, `statement: totals by provider and model equal the cells`, `statement: allocation by department equals the cells and adds up to the total`, `statement: allocation by cost_center equals the cells and adds up to the total`, `statement: allocation by product equals the cells and adds up to the total`, `statement: allocation by agent equals the cells and adds up to the total`, `statement: cover total equals the total`, `statement: chargeback files add up to the total` |
| `statement-chargeback-altered` | fails | `statement: chargeback files add up to the total` |
<!-- vectors:end -->

Two further fixtures are not export vectors. `vectors/anchors/` holds a real time-stamp token from a public authority and the digest it stamps; a verifier that reads log time-stamps should accept it and refuse it for any other digest. The key files named in the table are the auditor's keys for the vectors that use them.
