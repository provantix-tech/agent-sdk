# Provantix export format and verification (version 1.1)

This is what an auditor needs to check an export without access to the Provantix platform. Two independent implementations exist: `verify-export.mjs` (Node, no dependencies) and `python/verify_export.py` (Python standard library). Both must pass the same test vectors in `vectors/`.

## Directory layout

```
manifest.json        the list of files and their SHA-256 digests (not itself hashed)
manifest.sig.json    Provantix's Ed25519 signature over the bytes of manifest.json (see Authenticity)
records.jsonl        one JSON object per line, one per record
timeline.csv         human-readable timeline (not used for verification)
coverage.json        coverage at export time (not used for verification)
roots/YYYY-MM-DD.json  daily roots, present when the day was rooted before export
transparency.json    optional: inclusion proofs in Provantix's public transparency log (see Transparency log)
reconciliation.json  optional: reconciliation results, the destination records they rest on, approval binding and later outcomes (see Reconciliation)
authority.jsonl      optional: what each acting agent was allowed to do at the time of its action (Provantix's own history, not part of the signed record)
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

`manifest.json` lists every other file with `path`, `sha256` (hex) and `bytes`. `complete` is true only when the export was made without a filter. `scope_statement` says in words what the export covers (how many records, when they were observed, and the filter), and that it says nothing about activity that was not delivered to Provantix or records outside the export. "Complete" means every record of the filter, never everything that happened. Roots are checked only on complete exports, because a filtered export does not contain every record for a day.

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

## Reconciliation (optional file, version 1.1)

Version 1.1 adds two optional files. Every 1.0 export is still valid, and a 1.1 export without them verifies as before. `manifest.export_version` names the version, and `manifest.reconciliation` is `{results, approvals, links}` or `null`. Both files are listed in the manifest, so the signature covers them.

`reconciliation.json` holds one object: `{version: 1, statement, scopes, results, destination_records, approvals, links}`.

- `statement`: what the section does and does not show. It must be present.
- `scopes`: `{scope_id, name, target_system, action_type, destination_source, provider, statement}`. What each result was reconciled against, in words.
- `results`: one current result per action, `{record_id, scope_id, state, method, confidence, reason, destination_source, destination_external_id, destination_status, collection_window: {from, to}, duplicate_records, evaluated_at, history: [{state, method, reason, evaluated_at}]}`. `state` is one of `agent_reported`, `destination_confirmed`, `conflicting`, `pending`, `unverified`. `method` is `reference`, `action_id`, `payment_amount_time` or null. `history` holds the earlier results, so a pending that became confirmed stays visible.
- `destination_records`: the destination's own record each result points at: `{source_id, external_id, kind, payment_ref, amount_minor, currency, status, failure_reason, destination_created_at, action_id, provenance, status_history}`.
- `approvals`: for each action that carries an approval: `{record_id, approval_id, present, authority, path?, reasons, checks, policy_id, policy_version_in_force}` (`path` is `break_glass` for an emergency approval and is otherwise left out; see Exact-change approvals). `authority` is `verified`, `not_covered`, `unchecked` or `binding_not_recorded`.
- `links`: later outcomes, kept apart from the action: `{original_record_id, kind, occurred_at, origin, later_record_id, external_ref}`. `kind` is `reversal`, `retry`, `dispute`, `reopened` or `human_override`.

The agent's claim is in the record, not in this file: `erasable.ext.value.claim = {action_id, destination_ref, payment_ref, amount_minor, currency}`, and the claimed outcome is `fields.quality.outcome`. If the extension was erased the claim cannot be read, and the check reports it as not checked, never as passed or failed.

### Checks

The check names are `reconciliation: structure`, `reconciliation: results consistent with the destination records carried`, `reconciliation: every confirmed result rests on a destination record carried`, `approval binding: results recompute from the records` and `later outcomes: each retry names a record in this export`. They appear only when the file is present.

1. **Structure.** The version is 1, the statement is present, every result names a known state and method, has a reason and a scope in the section, and an action has one current result. Every result, approval and later outcome names a record that is in the export. Every link kind is known and dated.
2. **Consistent with the destination record carried.** For a `destination_confirmed` or `conflicting` result that names a destination record the export carries, and whose claim is readable: compute what the claim and the record disagree about. `payment` differs when both state one and the claim's id is neither the record's `payment_ref` nor one of the ids in its `provenance.payment_aliases` (for a provider whose records name a payment by more than one id, either may be cited). `amount` differs unless the record's amount equals the claim's. `currency` differs unless equal (case-insensitive). `outcome` differs when the claim says success and the record's status is not `pending` or `succeeded`, or the claim says failure and the status is not `failed` or `canceled`. Then: matched by `reference` requires the claim's cited id to equal the record's id; matched by `action_id` requires the ids to be equal; `destination_confirmed` requires no difference; `conflicting` requires a difference, or a `duplicate_records` list of more than one id. A conflict found by asking the destination directly, with no record carried, cannot be checked here and is reported as not checked.
3. **Every confirmed result rests on a destination record.** A `destination_confirmed` result must name a destination record the export carries.
4. **Approval binding recomputes.** For each approval whose record still carries its sealed authorization (not erased): with the binding in `erasable.authorization.value.binding` (`target_system`, `target_entity_id`, `action_type`, `max_amount_minor`, `currency`, `expires_at`, `policy_version`), the action's fields, the claim's amount and the carried `policy_version_in_force` (the version of the policy in force when the action ran, not today's), recompute `authority`: `not_covered` if any stated thing fails (another target, an amount over the limit or in another currency, the action after `expires_at`, a different policy version), otherwise `unchecked` if any could not be checked (no amount recorded, no version in force carried), otherwise `verified`. A binding with nothing stated is `binding_not_recorded`. It must equal the carried `authority`.
5. **Later outcomes.** A `retry` link that names a later record must name one in the export.

### Exact-change approvals (optional fields)

An approval can say the exact production change it was given for. The binding in `erasable.authorization.value.binding` accepts these further optional fields, all strings except `break_glass`:

| Field | Compared with |
|---|---|
| `environment` | `erasable.ext.value.mutation.environment` on the action's record |
| `resource` | `erasable.ext.value.mutation.resource` |
| `change_digest` | `erasable.ext.value.mutation.change_digest` (a sha256 digest; compared as lower-case hex) |
| `operation` | `fields.action.operation` |
| `risk_ref` | nothing: carried for the reader |
| `break_glass` | the boolean `true` declares an emergency route; any other value is ignored |

The action's `ext.mutation` is `{ "environment", "resource", "change_digest" }`: what the action says it changed. The change itself is not kept, only its digest.

When a binding states any of `environment`, `resource`, `operation`, `change_digest` or `break_glass`, these apply in addition to the checks above, and each is `holds`, `fails` or `unchecked` in the same way (a value the action does not record, or whose extension was erased, is `unchecked`, never inferred):

- Each stated field is compared exactly with what the action recorded.
- `decided_before_action`: the approval's `approved_at` must not be later than the action's `observed_at` (`fails` if it is later, `unchecked` if either cannot be read).
- `approval_path`: when `break_glass` is true this is always `unchecked`, so the authority is never `verified`. It can still be `not_covered` when another check fails.

A binding that states none of these is checked exactly as before, and its `approved_at` is not newly held against it.

An approval entry in `reconciliation.json` may carry `path`: `break_glass` when the binding declared an emergency route, and otherwise it is left out (meaning `normal`). The verifier recomputes the path from the record, and the check `approval binding: results recompute from the records` fails if the section's path differs, so an emergency approval cannot be reported as an ordinary one.

**A verifier older than this addition** applies none of these rules. On an export whose approvals use the new fields it recomputes the authority without them and may report `approval binding: results recompute from the records` as failed. Use a current verifier for such exports.

**What a pass shows, and what it does not.** That each approval's coverage recomputes from the records: the environment, resource, operation and change digest the approval names are the ones the action recorded. It does not show the action recorded its change truthfully, that the digest describes the change in substance, that an emergency route was justified, or that the approver was the right person.

### The result

The result is never a bare pass. It reads, for example:

```
reconciliation: 5 results: 2 destination-confirmed, 1 conflicting, 1 pending, 1 unverified, 0 agent-reported
  3 checked against the destination record carried in the export
  approvals: 2 carried, 2 recomputed from the record; later outcomes: 2
  this does not show that the destination's record is true: it is the destination's own statement, carried and hashed, not vouched for.
```

What this proves: the section is what Provantix signed (the manifest covers it), and each result is consistent with the destination record the export carries. What it does not prove: that the destination's record is true, that a missing record means an action did not happen (`pending` and `unverified` are not failed actions), or that an approver was the right person. The vectors `reconciled-*` in `vectors/` cover each case, including a result altered with every hash recomputed; `scripts/make-reconciliation-vectors.mjs` regenerates them.

### authority.jsonl

One line per attributed action: `{record_id, agent_id, observed_at, authority_as_of}`. `authority_as_of` is `{recorded: true, as_of, in_force_since, snapshot, changed_since, autonomy}` (`autonomy` is `{recorded: true, envelope, corroborated, provenance_text}` or `{recorded: false, reason}`: the delegation in force at the time, which a snapshot only carries when one was recorded) or `{recorded: false, reason}`. It is Provantix's own append-only history of the agent, not part of the agent's signed record, and an action from before the history existed says so. Verifiers check the file's hash through the manifest and do not interpret it.

## Decision evidence (optional, in records)

Why an agent chose an action, as the agent recorded it. It needs no extra file and no version change: it lives in each record's sealed extension field (`ext`), which is already sealed by the emitter and can be erased like any other field. A verifier computes the links from `records.jsonl` alone.

A **decision record** is an ordinary record whose `source.event_type` is `AgentDecision`, emitted before the action it selects. Its `ext.decision` is:

```
{ "v": 1, "decision_id": "dec_...", "task_id": "INC-4821",            task_id optional
  "source": "agent" | "human" | "system",
  "intent_ref": { "ref": "ticket://INC-4821", "sha256": "<hex>", "kind": "ticket" },                 optional: the instruction the decision answers
  "model_ref":  { "model_id": "...", "provider": "...", "model_version": "...", "invocation_ref": "..." },   optional: the model behind it
  "hypothesis": { "summary": "...", "evidence": [ { "ref": "...", "sha256": "<hex>", "kind": "..." } ] },   optional
  "candidates": [ { "id": "c1", "action": "...", "summary": "...", "risk_ref": "..." } ],               at least one
  "selected":   { "candidate_id": "c1", "action_id": "act_7" },
  "rejected":   [ { "candidate_id": "c2", "reason": "..." } ],                                            optional
  "risk_assessment_ref": "..." }                                                                          optional
```

The **action's own record** carries `ext.decision_ref = { "decision_id", "candidate_id", "action_id" }`, a pointer back. Neither record is changed after it is sealed; the link is two records that cite each other. Text is short (a summary or a reference, never a raw prompt or a reasoning trace); a producer that offers more should keep it behind a reference.

**Well formed** means: version 1; a `decision_id`; a source of `agent`, `human` or `system`; at least one candidate, each with an `id` (unique) and an `action`; a selected candidate that is among them; every rejected candidate among them and not the selected one; and, when `intent_ref` or `model_ref` is present, an `intent_ref` with a `ref` and a `model_ref` with a `model_id`. Both are references only (an id, a ticket, a hash), never the instruction or the prompt. Left out, they read as not recorded.

**Links.** Over the records in the export, an action that carries `decision_ref` is:

| Status | Meaning |
|---|---|
| `linked` | The decision is in the export and selects this action and candidate. |
| `mismatch` | The decision is in the export but selects a different action or candidate (a swapped or edited reference). |
| `duplicate` | Two different records claim the decision id, so neither can be trusted to be the one cited. |
| `not_in_scope` | The decision it cites is not in the export (deleted, never exported, never recorded, or erased). Reported, not a failure on its own. |

A decision that selects an action no record points back at is reported as `undelivered`. That is not evidence the action did not happen.

**Checks** (named, like every other check, and part of the specification; added only when the export has a decision record or a pointer):

- `decision evidence: every decision agrees with the action that cites it` fails on any `mismatch` or `duplicate`.
- `decision evidence: decisions are well formed` fails on a decision that is not well formed.

The verifier also prints summary lines: how many decisions, how many linked, how many actions cite a decision that is not here, how many selected an action nothing points back at, and how many records have an erased extension (so a decision or pointer there cannot be read). Both verifiers print the same lines.

**What a pass shows, and what it does not.** That the decisions and the actions that cite them agree, and that each record is what the emitter sealed (the emitter proof, when the reader holds the emitter's key). It does not show the reasoning was sound or was the real reason, that the agent considered everything it could have, or that the action happened as chosen: the destination's record, in the reconciliation section, is a separate layer. Deleting a decision from an export is caught by the chain, the roots and the emitter proof; a platform that recomputes the first two can only be caught by the third. A missing rationale is "not recorded", and nothing fills it in.

## Control decision evidence (optional, in records)

An enforcement tool (an agent gateway, a policy engine, an approval step) decides before an action runs: allow, ask a person, deny, or steer the agent elsewhere. Provantix is not in that path. When the tool, or the customer's integration, records its verdict, it is an ordinary record whose `source.event_type` is `ControlDecision`, and its `ext.control` is:

```
{ "v": 1, "control_id": "ctl_...",
  "enforcer": { "name": "agent-gateway", "version": "2.4" },        name required: as the tool names itself
  "verdict": "allow" | "ask" | "deny" | "steer",
  "policy": { "id": "prod-changes", "version": "7" },               id required
  "action_id": "act_...",                                           optional: the action the verdict is about
  "decided_at": "<ISO 8601>",                                       optional
  "reason", "risk_ref", "approval_ref", "proposed": { ... } }       optional
```

The **action's own record** may carry `ext.control_ref = { "control_id", "action_id" }`, a pointer to the verdict about it. Like decision evidence, neither record changes after it is sealed; the link is two records that cite each other.

**Well formed** means: version 1; a `control_id`; an enforcer with a name; a verdict that is one of the four; a policy with an id; and, when present, a `decided_at` that is a date and time (use ISO 8601: a reader is only required to understand that form).

**Links.** Over the records in the export, an action that carries `control_ref` is:

| Status | Meaning |
|---|---|
| `linked` | The verdict is in the export and names the same action id as the action that cites it. |
| `unbound` | The verdict is in the export and names no action id, so it can neither agree nor disagree. Reported, not a failure. |
| `mismatch` | The verdict is in the export but names a different action id than the action that cites it (a swapped or edited reference). |
| `duplicate` | Two different records claim the control id, so neither can be trusted to be the one cited. |
| `not_in_scope` | The verdict it cites is not in the export (deleted, never exported, never recorded, or erased). Reported, not a failure on its own. |

A `linked` denial is counted as `denied_cited`: the enforcer said no, and a record of the action carries its pointer. That is the enforcer's statement and a record, side by side. It is reported, not failed: whether a control worked is a judgement the hosted service makes from its own data, and the verifier makes none.

**Checks** (named and part of the specification; added only when the export has a control record or a pointer):

- `control evidence: every control decision agrees with the action that cites it` fails on any `mismatch` or `duplicate`.
- `control evidence: control decisions are well formed` fails on a verdict that is not well formed.

**What a pass shows, and what it does not.** That the verdicts and the actions that cite them agree, and that each record is what the emitter sealed (the emitter proof, when the reader holds the emitter's key). It does not show the enforcement tool was in the path, that its verdict was obeyed, or that an action it denied did not happen: a missing record of an action is not proof it did not run.

## Transparency log (optional file)

An export made by the hosted service may carry `transparency.json`. It is outside the manifest, like `manifest.sig.json`, so an export that could not be logged is still a valid export. It commits Provantix, in public, to this export's manifest and to each daily root the export includes, so that a different manifest or root cannot later be issued for the same thing without the log disagreeing.

```
{ "version": 1, "log_id": "tlog_...", "org_ref": "<opaque organization reference>",
  "head":    { "version": 1, "log_id", "tree_size", "root_hash", "timestamp", "key_id", "signature" },
  "entries": [ { "index": N, "leaf": { ... }, "path": ["<hex>", ...] }, ... ] }
```

**Entries.** A leaf is a JSON object, hashed as `SHA-256(0x00 || canonical JSON)` (canonical JSON: keys sorted at every level, no whitespace, `undefined` dropped). Two kinds:

- `export_manifest`: `{ v, kind, org_ref, manifest_sha256, key_id, export_id, logged_at }`. `manifest_sha256` must equal the SHA-256 of this export's `manifest.json`.
- `day_root`: `{ v, kind, org_ref, day, tenant_root, record_count, logged_at }`. `tenant_root` must equal the root in `roots/<day>.json`. A day is logged once per organization.

`org_ref` is a keyed hash of the organization id, so the log holds no names. The export carries its own `org_ref`, and every entry in the proof must carry it.

**Inclusion.** The tree is the RFC 6962 Merkle tree over the leaf hashes (interior node `SHA-256(0x01 || left || right)`; the left subtree holds the largest power of two below `n` leaves). `path` is the audit path for the entry at `index` in a tree of `head.tree_size` leaves. Verify with RFC 9162 section 2.1.3.2 against `head.root_hash`.

**The head.** `signature` is a base64 Ed25519 signature over the canonical JSON of `{ version, log_id, tree_size, root_hash, timestamp, key_id }`, checked against the log's published public keys (`/.well-known/provantix-log-keys.json`), obtained from Provantix and never from the bundle.

**The anchor (optional, outside the signature).** A head served by the log, and carried in `transparency.json`, may have an `anchor` field. It is not covered by the head's signature, because it is obtained after the head is signed. `{ "method": "rfc3161", "authority": "<url>", "digest_sha256": "<hex>", "token": "<base64 DER>", "gen_time": "<ISO time>" }`: `token` is an RFC 3161 time-stamp token (CMS signed data holding a TSTInfo) for the SHA-256 of the head's signing bytes, the same canonical JSON the signature covers. A verifier recomputes that digest, checks it equals `digest_sha256` and the token's message imprint, checks the signed attributes bind the TSTInfo, checks the signature under the signer certificate carried in the token, and that the certificate is for time-stamping (extended key usage 1.3.6.1.5.5.7.3.8) and was valid at `gen_time`. It does not decide whether the certificate chains to a root the reader trusts (use `openssl ts -verify`). Without a token, `anchor` is absent or `{ "status": "pending", "reason": ... }`, and a verifier reports **not anchored**, never failed. Only a token that is present and does not verify is a failure. An anchor shows the head existed by `gen_time`; it does not show the log is complete or true.

**What a pass shows, and what it does not.** That Provantix committed to this manifest hash and these roots at the logged time. It does not show the log itself was never rewritten: that needs a tree head you, or a mirror, kept earlier. `verify-log.mjs` fetches every entry of the public log, recomputes every hash and the root, checks the head, and checks that every signed head you kept is signed by the log's key and is still the first part of the tree now. Its state file (`--state`) is `{"version": 2, "log_id", "saved_at", "heads": [...]}`, each head kept exactly as signed (`version`, `log_id`, `tree_size`, `root_hash`, `timestamp`, `key_id`, `signature`). A kept head the entries no longer produce is written, with the root the entries produce now, to `<state>.conflict.json`: Provantix's own signature on what it published earlier.

**The public log** (read-only, no login): `/.well-known/provantix-log/sth` (the latest signed head), `/heads?from=&limit=` (every signed head ever issued, oldest first, at most 1000 per request), `/entries?from=&to=` (entries with their hashes, at most 1000 per request), `/proof?index=&size=` (an inclusion proof), `/consistency?first=&second=` (a consistency proof, RFC 9162 section 2.1.4) and `/.well-known/provantix-log-keys.json`.

## Cost statement (optional files, version 1.1)

An export that is a cost statement (a closed month of AI spend) carries these files, listed in the manifest like any other: `statement/statement.json`, `statement/cells.json`, and optionally `statement/statement.csv`, `statement/statement.html`, `statement/README.txt` and `statement/chargeback/<department>.csv`. It carries no records (`records.jsonl` is empty). The checks below appear **only** when `statement/statement.json` is listed in the manifest, and a verifier that does not know them still passes the file hashes and the signature.

`cells.json` is an array of cells, each `{ day, agent_id, provider, model, department, cost_center, product, calls, unpriced_calls, tokens_in, tokens_out, cache_read, cache_write, cost_usd }`. An empty string for `agent_id`, `provider`, `department`, `cost_center` or `product` means the figure had no value for it. `statement.json` carries `totals` (`cost_usd`, `calls`), `cover.totals.estimated_usd`, `sections["1"].by_provider_model` (rows with `provider`, `model`, `calls`, `tokens_in`, `tokens_out`, `cost_usd`), and `sections["3"]` with an array for each of `department`, `cost_center`, `product` and `agent` (rows with that label, `calls` and `cost_usd`), and optionally `person.rows`.

A cost is compared to four decimal places: two figures are equal when they differ by less than 0.0002. Counts are compared exactly. The label of a row with no value is `(unallocated)`, or `(no agent)` for the agent array, and `(no provider)` in the provider and model rows.

### Checks, by name

- `statement: total equals the cells`: the sum of `cost_usd` over the cells equals `totals.cost_usd`, and the sum of `calls` equals `totals.calls`.
- `statement: totals by provider and model equal the cells`: the cells grouped by provider and model give exactly the rows of `sections["1"].by_provider_model` (same groups, `calls`, `tokens_in`, `tokens_out` and `cost_usd`), and the rows add up to the total.
- `statement: allocation by department equals the cells and adds up to the total`, and the same for `cost_center`, `product` and `agent`: the cells grouped by that field give exactly the rows of that array, and the rows add up to the total.
- `statement: cover total equals the total`: `cover.totals.estimated_usd` equals `totals.cost_usd`.
- `statement: allocation by person adds up to the total`, only when `sections["3"].person` is present: its rows add up to the total.
- `statement: chargeback files add up to the total`, only when files under `statement/chargeback/` are listed: the last line of each is a total line whose last column is a number, and those add up to the total.
- `statement: files readable`, only on failure: `statement.json` or `cells.json` cannot be read as described.

### What a pass shows, and what it does not

That the totals the statement states are what its cells add up to, and that its allocations and chargeback files are a split of the same figures. It does **not** show that the cells are the right figures: they are estimates frozen when the month was closed, from the organization's own price table, and the provider's own figures in the statement are what the provider reported when they were fetched. It is not an invoice and not an audit. Whether the files are unchanged since issue is the manifest and the signature, as for any export.

## What verification proves and does not prove

It proves that the exported records were not changed after ingest, that chain order is intact, and that the day roots match. When the export is also authentic, it proves the bundle is exactly what Provantix issued. It does not prove that each record carries the emitter's own signature: emitter batch signatures are verified at ingest and cannot be re-checked from an export, because the signed batch contains values that erasure later removes. It does not prove the source systems reported every event. Completeness needs source-side counts, which are outside this format. The custody statement in the manifest says the same.

## Running

```bash
node verify-export.mjs <exportDir>
python3 python/verify_export.py <exportDir>
```

Both exit 0 when verified, 1 when verification fails, and 2 on usage or unreadable input.
