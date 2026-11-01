# Provantix export format and verification (version 1.0)

This is what an auditor needs to check an export without access to the Provantix platform. Two independent implementations exist: `verify-export.mjs` (Node, no dependencies) and `python/verify_export.py` (Python standard library). Both must pass the same test vectors in `vectors/`.

## Directory layout

```
manifest.json        the list of files and their SHA-256 digests (not itself hashed)
manifest.sig.json    Provantix's Ed25519 signature over the bytes of manifest.json (see Authenticity)
records.jsonl        one JSON object per line, one per record
timeline.csv         human-readable timeline (not used for verification)
coverage.json        coverage at export time (not used for verification)
roots/YYYY-MM-DD.json  daily roots, present when the day was rooted before export
```

## Authenticity

Everything in the sections below recomputes from the bundle alone, which means a forger who edits a record can recompute every hash, chain link and root and the result is still internally consistent. Authenticity (did Provantix issue this export) is a separate question answered by `manifest.sig.json`:

```json
{ "version": 1, "alg": "Ed25519", "key_id": "pek_<16 hex>", "signed_file": "manifest.json",
  "manifest_sha256": "<hex>", "signature": "<base64>", "signed_at": "<ISO time>" }
```

The signature is over the exact bytes of `manifest.json`, which lists the SHA-256 of every other file, so one signature covers the export. `key_id` is `pek_` plus the first 16 hex of the SHA-256 of the key's SPKI DER encoding. Provantix publishes its export public keys (active and retired) at `https://app.provantix.tech/.well-known/provantix-export-keys.json` as `{"keys": [{"key_id", "alg", "public_key_pem", "status", "created_at"}]}`.

A verifier checks the signature against a published key it obtained from Provantix, and never against a key found in the bundle. Results: `authentic` (valid signature by a published key), `unsigned` (no `manifest.sig.json`), `unverified` (no published keys supplied), `untrusted_key` (`key_id` is not published), `invalid_signature` (the manifest differs from what was signed, or the signature is wrong), `malformed`. Only `authentic` establishes that Provantix issued the export. The Node verifier implements this (`--keys`); the Python verifier checks integrity only and reports `not_checked`.

## Canonical JSON

Used for every hash. Object keys sorted at every depth, no whitespace, UTF-8, strings and numbers in their standard JSON form, `null` kept, `undefined` not allowed.

Test vectors use ASCII only. Implementations must match them. Other characters follow standard JSON string escaping.

## Manifest

`manifest.json` lists every other file with `path`, `sha256` (hex) and `bytes`. `complete` is true only when the export was made without a filter. Roots are checked only on complete exports, because a filtered export does not contain every record for a day.

## Record

Each line of `records.jsonl`:

- `fields`: non-erasable content, hashed in plain.
- `erasable`: for each field in the fixed order below, either `{value, salt}` (salt is 16 bytes, hex) or `{erased: true, erased_at}`.
- `integrity.commitments`: for each erasable field, the commitment in hex.
- `integrity.record_hash`: the record hash in hex.
- `chain_key`, `chain_seq`, `prev_record_hash`, `ingest_day`, `record_id`, `attribution`: positioning and attribution. Attribution is not hashed.

Erasable field order (must not change): `on_behalf_of`, `delegation_chain`, `input_summary`, `output_summary`, `attribution_evidence`, `ext`, `user_agent`.

### Recomputing a record hash

1. For each erasable field `f` in order:
   - If erased: take the commitment from `integrity.commitments[f]`.
   - Otherwise: `commitment = SHA-256(salt_bytes || canonical(value) as UTF-8)` and it must equal `integrity.commitments[f]`.
2. Merkle root over the seven commitments, in order. Pairs are hashed as `SHA-256(left || right)`. An odd node is paired with itself. With no leaves the root is `SHA-256("")`.
3. `record_hash = SHA-256( canonical(fields) as UTF-8 || "|" || merkle_root )` and it must equal `integrity.record_hash`.

Erasing a field removes its value and salt and keeps its commitment, so step 1 still verifies.

## Chains

Records sharing `chain_key` form a chain. Within a chain, a record whose `chain_seq` is one more than another record present in the export must have `prev_record_hash` equal to that record's `record_hash`. Gaps in `chain_seq` mean the export is filtered, not that the chain is broken.

## Daily roots

For a complete export and each day in `roots_included`:

1. Group that day's records by `chain_key`, sorted by key. Within each group, order by `chain_seq`.
2. Chain root: Merkle root over the group's `record_hash` values, in order.
3. Tenant root: Merkle root over the chain roots, in sorted key order.
4. The tenant root and the record count must equal those in `roots/YYYY-MM-DD.json`.

## Emitter proof (optional files)

An emitter may sign the hashes of the records in each batch (the seal). When any exported record came from a sealed batch the export carries three more things, all listed in the manifest. Without them the export verifies exactly as before and every record is reported as not emitter-sealed.

- `source` on each record in `records.jsonl`: `{collector_id, batch_seq, batch_index}`. Platform metadata, not part of the record hash.
- `seals.jsonl`: one line per sealed batch that holds an exported record: `{collector_id, batch_seq, statement, signature, key_fingerprint, not_stored}`. `statement` is `{seal_version: 2, collector_id, batch_seq, created_at, record_count, record_hashes: [hex...], rollups_digest}`. `signature` is base64 ECDSA P-256 with SHA-256 (DER) over the canonical JSON of `statement`. `key_fingerprint` is the SHA-256, in hex, of the DER SPKI encoding of the emitter's public key. `not_stored` is `[{index, why}]`, the sealed records the platform did not store; it is a platform statement and is not signed by the emitter.
- `emitters.json`: `{emitters: [{collector_id, status, keys: [{role, fingerprint, pem_sha256, public_key_pem, valid_from, valid_until, key_source}], key_events: [...]}]}`. `key_source` is `customer`, `generated` or `unknown`.

### Checks, in order, for each seal

1. Find the key. The auditor's key (see below) whose fingerprint equals `key_fingerprint` is used first; otherwise the key in `emitters.json` with that fingerprint. No key: the batch is reported as not checked, never as failed.
2. Verify `signature` over the canonical `statement`. A bad signature is a failure.
3. If a `compromised` key event for the emitter has `suspect_from` at or before `statement.created_at`, the seal is not trusted: a failure.
4. For each exported record with a `source`, `statement.record_hashes[batch_index]` must equal the record's `integrity.record_hash`. A difference is a failure.
5. For a complete export, every index of a verified seal must be present in the export or listed in `not_stored`. An index that is neither is reported as missing: a failure. Indexes listed in `not_stored` are reported by name and reason, as a platform statement, and are not failures.

The check names are `emitter proof: seals verify`, `emitter proof: records match seals`, `emitter proof: no sealed record missing` (complete exports only) and `emitter proof: no seal from a compromised key`. They appear only when the export carries seals.

### Whose key

The result states where the key came from, because that decides what the proof is worth.

| Source | Meaning |
|---|---|
| `auditor` | A key the auditor supplied with `--emitter-keys`. Independent of Provantix. |
| `bundle_attested` | A customer-supplied key listed in `emitters.json` of an export whose manifest signature is authentic. Provantix attests the key. |
| `bundle_unsigned` | A key from `emitters.json` of an export that is unsigned or whose signature was not checked. This proves nothing about who holds the key. |
| `generated` | A key Provantix generated. Provantix once held the private key, so this is only Provantix's own attestation. |
| `unknown` | The export does not record where the key came from. |

The auditor's key file is either PEM public keys one after another, or JSON: an array of PEM strings, or an object mapping an emitter id to its PEM. With the object form, a seal made with any other key for that emitter is a failure. With the other forms a seal is matched to a key by fingerprint only, so a seal whose fingerprint matches none of the auditor's keys falls back to the key in the export and is not reported as independent.

The Python verifier does not check the Provantix manifest signature, so it never reports `bundle_attested`: a customer-supplied key listed in the export is reported as `bundle_unsigned` there, even when the node verifier or the browser page finds the export authentic and says `bundle_attested`. The three implementations otherwise report the same counts and the same words on every vector.

### The result

The result is never a bare pass. It reads, for example:

```
emitter proof: 412 of 415 records signed by the emitter's key
  3 records are in batches the emitter did not seal (not covered, not failed)
  key source: a key supplied by the auditor (independent of Provantix)
```

and also names records that failed, are missing, or were refused at ingest per the platform. The vectors `sealed-*` in `vectors/` cover each case; `scripts/make-seal-vectors.mjs` regenerates them.

## What verification proves and does not prove

It proves that the exported records were not changed after ingest, that chain order is intact, and that the day roots match. When the export is also authentic, it proves the bundle is exactly what Provantix issued. It does not prove that each record carries the emitter's own signature: emitter batch signatures are verified at ingest and cannot be re-checked from an export, because the signed batch contains values that erasure later removes. It does not prove the source systems reported every event. Completeness needs source-side counts, which are outside this format. The custody statement in the manifest says the same.

## Running

```bash
node verify-export.mjs <exportDir>
python3 python/verify_export.py <exportDir>
```

Both exit 0 when verified, 1 when verification fails, and 2 on usage or unreadable input.
