#!/usr/bin/env node
// Standalone verifier for Provantix export directories.
//
// Self-contained on purpose: it uses only node:crypto and node:fs and imports nothing from this
// repository, so an auditor can run it on a copy of an export without trusting the rest of the code.
// Format and algorithms: ./FORMAT.md. An independent Python implementation lives in ./python/.
//
// Usage: node verify-export.mjs <exportDir> [--keys provantix-export-keys.json] [--integrity-only] [--json]
//
// Two separate questions are answered. Integrity: do the hashes, chain links and roots recompute
// (everything needed is inside the bundle, so a forger can recompute it all). Authenticity: did
// Provantix issue this export, checked from manifest.sig.json against Provantix's PUBLISHED export
// keys (--keys; download https://app.provantix.tech/.well-known/provantix-export-keys.json). A key
// found inside the bundle proves nothing, so none is read from it.
//
// Exit code: 0 verified (integrity ok and authentic), 1 failed integrity, 2 usage or unreadable
// export, 3 integrity ok but authenticity not established (unsigned, no keys given, unknown key,
// bad signature). --integrity-only restores the old behaviour of exiting 0 on integrity alone.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Keep in sync with the platform's record-integrity module (aar-schema/src/integrity.mjs). 'authorization' was appended
// for Epic E (2026-10-24); records sealed before it existed carry no entry or commitment and
// are skipped, so pre-E exports keep verifying unchanged.
export const ERASABLE_FIELDS = [
  'on_behalf_of',
  'delegation_chain',
  'input_summary',
  'output_summary',
  'attribution_evidence',
  'ext',
  'user_agent',
  'authorization',
];

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const hex = (buf) => Buffer.from(buf).toString('hex');

export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('non-finite number');
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
      return '{' + Object.keys(value).sort().map((k) => {
        if (value[k] === undefined) throw new TypeError(`undefined at ${k}`);
        return JSON.stringify(k) + ':' + canonicalize(value[k]);
      }).join(',') + '}';
    }
    default:
      throw new TypeError(`unsupported type ${typeof value}`);
  }
}

export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256(Buffer.concat([level[i], right])));
    }
    level = next;
  }
  return level[0];
}

/** Recompute a record hash from its exported parts. Returns {valid, reasons}. */
export function verifyRecordParts({ fields, erasable, integrity }) {
  const reasons = [];
  const commitments = [];
  for (const f of ERASABLE_FIELDS) {
    const entry = erasable?.[f];
    const claimed = integrity?.commitments?.[f];
    // Absent = sealed before this field existed in the schema (append-only evolution);
    // excluded from the leaf set, exactly as the sealer computed it.
    if (!entry || typeof claimed !== 'string') continue;
    commitments.push(Buffer.from(claimed, 'hex'));
    if (entry.erased) continue;
    const salt = Buffer.from(entry.salt, 'hex');
    const recomputed = hex(sha256(Buffer.concat([salt, Buffer.from(canonicalize(entry.value), 'utf8')])));
    if (recomputed !== claimed) reasons.push(`commitment mismatch on ${f}`);
  }
  if (reasons.length === 0) {
    const root = merkleRoot(commitments);
    const recomputed = hex(sha256(Buffer.concat([Buffer.from(canonicalize(fields), 'utf8'), Buffer.from('|'), root])));
    if (recomputed !== integrity.record_hash) reasons.push('record_hash mismatch');
  }
  return { valid: reasons.length === 0, reasons };
}

/**
 * Judge authenticity from manifest.json bytes, the text of manifest.sig.json (or null) and the
 * published keys ([{key_id, public_key_pem}] or null). Mirrors the platform's export signing.
 * Only state 'authentic' means Provantix issued this export.
 */
export function judgeAuthenticity(manifestBytes, sigText, trustedKeys) {
  if (sigText === null || sigText === undefined) {
    return { state: 'unsigned', key_id: null, detail: 'this export carries no signature, so it proves only that it is consistent with itself' };
  }
  let doc;
  try { doc = JSON.parse(sigText); } catch { return { state: 'malformed', key_id: null, detail: 'manifest.sig.json is not valid JSON' }; }
  if (doc?.version !== 1 || doc.alg !== 'Ed25519' || typeof doc.key_id !== 'string' || typeof doc.signature !== 'string') {
    return { state: 'malformed', key_id: doc?.key_id ?? null, detail: 'manifest.sig.json is not a version 1 Ed25519 signature' };
  }
  if (doc.manifest_sha256 !== hex(sha256(manifestBytes))) {
    return { state: 'invalid_signature', key_id: doc.key_id, detail: 'manifest.json is not the file that was signed' };
  }
  if (!trustedKeys || trustedKeys.length === 0) {
    return { state: 'unverified', key_id: doc.key_id, detail: `signed by ${doc.key_id}; pass Provantix's published keys with --keys to check it` };
  }
  const trusted = trustedKeys.find((k) => k.key_id === doc.key_id);
  if (!trusted) return { state: 'untrusted_key', key_id: doc.key_id, detail: `${doc.key_id} is not one of Provantix's published export keys` };
  let ok = false;
  try { ok = cryptoVerify(null, Buffer.from(manifestBytes), createPublicKey(trusted.public_key_pem), Buffer.from(doc.signature, 'base64')); } catch { ok = false; }
  return ok
    ? { state: 'authentic', key_id: doc.key_id, detail: `signed by Provantix key ${doc.key_id} at ${doc.signed_at ?? 'an unrecorded time'}` }
    : { state: 'invalid_signature', key_id: doc.key_id, detail: 'the signature does not match this manifest: the export was changed after it was issued' };
}

// ---- emitter proof (plan/24-per-record-emitter-proof.md) -----------------------------------------------------
//
// Did the emitter itself vouch for each record? The emitter signed the hash of every record in a batch (the
// seal). Where the seal verifies, with a key we can name the source of, the record is emitter-signed. The
// result is never a bare pass: it counts what is covered, names what is not and why, and says whose key
// vouches for the proof, because a key taken from the export (or held by Provantix) is not independent of
// Provantix.

const SPKI = { type: 'spki', format: 'der' };
const fingerprintOf = (pem) => hex(sha256(createPublicKey(pem).export(SPKI)));

/**
 * Read the auditor's key file. Either PEM public keys one after another, or JSON: an array of PEM strings, or
 * an object mapping an emitter id to its PEM (which also lets a seal made with any other key for that emitter
 * be reported as a failure, not just as unmatched). Returns { keys: [pem], byEmitter: {id: pem} }.
 */
export function parseEmitterKeys(text) {
  const out = { keys: [], byEmitter: {} };
  const trimmed = String(text).trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const doc = JSON.parse(trimmed);
    if (Array.isArray(doc)) out.keys.push(...doc);
    else if (Array.isArray(doc.keys)) out.keys.push(...doc.keys);
    else for (const [id, pem] of Object.entries(doc)) { out.byEmitter[id] = pem; out.keys.push(pem); }
  } else {
    out.keys.push(...(trimmed.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? []));
  }
  for (const pem of out.keys) fingerprintOf(pem); // throws on a malformed key, so a bad file is refused loudly
  return out;
}

const SOURCE_TEXT = {
  auditor: 'a key supplied by the auditor (independent of Provantix)',
  bundle_attested: 'a customer-supplied key listed in a Provantix-signed export (Provantix attests the key; not independent of Provantix)',
  bundle_unsigned: 'a key taken from the export itself, whose signature is absent or not checked (this proves nothing about who holds the key)',
  generated: 'a key Provantix generated (Provantix once held the private key, so this is only Provantix\'s own attestation)',
  unknown: 'a key whose origin the export does not record',
};

function readJsonlMaybe(file) {
  if (!fs.existsSync(file)) return null;
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/**
 * @param {object} ctx { manifest, records, authenticity, emitterKeys: {keys, byEmitter} | null }
 * @returns {{ summary: object, checks: object[] }} summary is what every verifier reports; checks are added to the list only when
 *   the export carries seals, so an export without them verifies exactly as before.
 */
export function verifyEmitterProof(dir, { manifest, records, authenticity, emitterKeys = null }) {
  const total = records.length;
  const seals = readJsonlMaybe(path.join(dir, 'seals.jsonl'));
  const summary = {
    present: Boolean(seals && seals.length), records_total: total, records_signed: 0, records_unsealed: 0, records_key_missing: 0, records_failed: 0,
    refused_at_ingest: [], missing_from_export: [], key_sources: {}, lines: [],
  };
  const checks = [];
  const sealed = new Map((seals ?? []).map((s) => [`${s.collector_id}\u0000${s.batch_seq}`, s]));

  // Keys: the auditor's first, then those the export lists.
  const emittersDoc = fs.existsSync(path.join(dir, 'emitters.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'emitters.json'), 'utf8')) : { emitters: [] };
  const auditorFp = new Map((emitterKeys?.keys ?? []).map((pem) => [fingerprintOf(pem), pem]));
  const bundleKeys = new Map();
  const events = new Map();
  for (const e of emittersDoc.emitters ?? []) {
    events.set(e.collector_id, e.key_events ?? []);
    for (const k of e.keys ?? []) if (k.public_key_pem) bundleKeys.set(`${e.collector_id}\u0000${k.fingerprint}`, k);
  }
  const authentic = authenticity?.state === 'authentic';

  const problems = { seals: [], match: [], compromised: [] };
  const keySourceOf = new Map();
  const outcome = new Map(); // batch key -> 'signed' | 'key_missing' | 'failed'

  for (const s of seals ?? []) {
    const bk = `${s.collector_id}\u0000${s.batch_seq}`;
    let pem = null;
    let source = null;
    const mapped = emitterKeys?.byEmitter?.[s.collector_id];
    if (mapped && fingerprintOf(mapped) !== s.key_fingerprint) {
      problems.seals.push(`batch ${s.collector_id}#${s.batch_seq} was sealed with a key other than the one the auditor holds for ${s.collector_id}`);
      outcome.set(bk, 'failed');
      continue;
    }
    if (auditorFp.has(s.key_fingerprint)) { pem = auditorFp.get(s.key_fingerprint); source = 'auditor'; }
    else {
      const k = bundleKeys.get(`${s.collector_id}\u0000${s.key_fingerprint}`);
      if (k) {
        pem = k.public_key_pem;
        source = k.key_source === 'generated' ? 'generated' : k.key_source === 'customer' ? (authentic ? 'bundle_attested' : 'bundle_unsigned') : 'unknown';
      }
    }
    if (!pem) { outcome.set(bk, 'key_missing'); continue; }
    let ok = false;
    try { ok = cryptoVerify('sha256', Buffer.from(canonicalize(s.statement), 'utf8'), pem, Buffer.from(s.signature, 'base64')); } catch { ok = false; }
    if (!ok) { problems.seals.push(`the seal of batch ${s.collector_id}#${s.batch_seq} does not verify with its key`); outcome.set(bk, 'failed'); continue; }
    keySourceOf.set(bk, source);
    // A seal made after the key was declared compromised is not trusted.
    const suspect = (events.get(s.collector_id) ?? []).find((e) => e.event === 'compromised' && e.suspect_from
      && Date.parse(s.statement.created_at) >= Date.parse(e.suspect_from));
    if (suspect) { problems.compromised.push(`batch ${s.collector_id}#${s.batch_seq} was sealed at ${s.statement.created_at}, after its key was declared compromised (suspect from ${suspect.suspect_from})`); outcome.set(bk, 'failed'); continue; }
    outcome.set(bk, 'signed');
  }

  // Each record against the seal of its batch, at its position.
  const present = new Map(); // batch key -> Set of indexes present in the export
  for (const r of records) {
    const src = r.source;
    const bk = src?.collector_id != null ? `${src.collector_id}\u0000${src.batch_seq}` : null;
    if (!bk || !sealed.has(bk)) { summary.records_unsealed += 1; continue; }
    if (!present.has(bk)) present.set(bk, new Set());
    present.get(bk).add(src.batch_index);
    const o = outcome.get(bk);
    if (o === 'key_missing') { summary.records_key_missing += 1; continue; }
    if (o === 'failed') { summary.records_failed += 1; continue; }
    const sealedHash = sealed.get(bk).statement.record_hashes?.[src.batch_index];
    if (sealedHash !== r.integrity.record_hash) {
      summary.records_failed += 1;
      problems.match.push(`record ${r.record_id} (${src.collector_id}#${src.batch_seq}[${src.batch_index}]) does not match the hash the emitter sealed`);
    } else summary.records_signed += 1;
  }

  // What each sealed batch lists that the export lacks: refused or skipped at ingest (a platform statement), or dropped.
  const missing = [];
  for (const s of seals ?? []) {
    const bk = `${s.collector_id}\u0000${s.batch_seq}`;
    if (outcome.get(bk) !== 'signed') continue;
    const have = present.get(bk) ?? new Set();
    const said = new Map((s.not_stored ?? []).map((x) => [x.index, x.why]));
    s.statement.record_hashes.forEach((h, i) => {
      if (have.has(i)) return;
      if (said.has(i)) summary.refused_at_ingest.push({ collector_id: s.collector_id, batch_seq: s.batch_seq, index: i, why: said.get(i) });
      else missing.push({ collector_id: s.collector_id, batch_seq: s.batch_seq, index: i, record_hash: h });
    });
  }
  summary.missing_from_export = manifest.complete ? missing : [];

  for (const v of keySourceOf.values()) summary.key_sources[v] = (summary.key_sources[v] ?? 0) + 1;

  if (summary.present) {
    const none = (list) => list.length === 0;
    checks.push({ name: 'emitter proof: seals verify', ok: none(problems.seals), detail: problems.seals.slice(0, 3).join('; ') });
    checks.push({ name: 'emitter proof: records match seals', ok: none(problems.match), detail: problems.match.slice(0, 3).join('; ') });
    if (manifest.complete) {
      checks.push({ name: 'emitter proof: no sealed record missing', ok: none(summary.missing_from_export), detail: summary.missing_from_export.slice(0, 3).map((m) => `${m.collector_id}#${m.batch_seq}[${m.index}] ${m.record_hash.slice(0, 12)}`).join('; ') });
    }
    checks.push({ name: 'emitter proof: no seal from a compromised key', ok: none(problems.compromised), detail: problems.compromised.slice(0, 3).join('; ') });
  }

  // The result line: counts, what is not covered and why, and whose key.
  const lines = [`emitter proof: ${summary.records_signed} of ${total} records signed by the emitter's key`];
  if (summary.records_unsealed) lines.push(`  ${summary.records_unsealed} records are in batches the emitter did not seal (not covered, not failed)`);
  if (summary.records_key_missing) lines.push(`  ${summary.records_key_missing} records are sealed, but no key for the seal was supplied or listed (not checked, not failed)`);
  if (summary.records_failed) lines.push(`  ${summary.records_failed} records FAILED against their seal`);
  if (summary.refused_at_ingest.length) lines.push(`  ${summary.refused_at_ingest.length} sealed records are absent from the export and the platform says it refused or skipped them at ingest (a platform statement, not signed by the emitter): ${summary.refused_at_ingest.slice(0, 5).map((x) => `${x.collector_id}#${x.batch_seq}[${x.index}] ${x.why}`).join(', ')}${summary.refused_at_ingest.length > 5 ? ', and more' : ''}`);
  if (summary.missing_from_export.length) lines.push(`  ${summary.missing_from_export.length} sealed records are MISSING from this complete export: ${summary.missing_from_export.slice(0, 5).map((m) => `${m.collector_id}#${m.batch_seq}[${m.index}]`).join(', ')}`);
  const sources = Object.keys(summary.key_sources);
  if (sources.length) lines.push(`  key source: ${sources.map((k) => SOURCE_TEXT[k]).join('; ')}`);
  else if (summary.present) lines.push('  key source: no seal could be checked');
  summary.lines = lines;
  return { summary, checks };
}

export function verifyExport(dir, { trustedKeys = null, emitterKeys = null } = {}) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  } catch (e) {
    add('manifest readable', false, e.message);
    return { ok: false, authenticity: { state: 'unsigned', key_id: null, detail: 'no readable manifest' }, checks };
  }
  add('manifest readable', true);

  for (const f of manifest.files) {
    const full = path.join(dir, f.path);
    if (!fs.existsSync(full)) {
      add(`file present: ${f.path}`, false);
      continue;
    }
    const buf = fs.readFileSync(full);
    const digest = hex(sha256(buf));
    add(`file hash: ${f.path}`, digest === f.sha256, digest === f.sha256 ? '' : 'hash differs from manifest');
  }

  let records;
  try {
    records = fs.readFileSync(path.join(dir, 'records.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch (e) {
    add('records readable', false, e.message);
    return { ok: false, authenticity: { state: 'unsigned', key_id: null, detail: 'records unreadable' }, checks };
  }

  let bad = 0;
  for (const r of records) {
    const v = verifyRecordParts(r);
    if (!v.valid) {
      bad += 1;
      add(`record ${r.record_id}`, false, v.reasons.join('; '));
    }
  }
  add('records recompute', bad === 0, `${records.length - bad} of ${records.length} ok`);

  const byChain = new Map();
  for (const r of records) {
    if (!byChain.has(r.chain_key)) byChain.set(r.chain_key, []);
    byChain.get(r.chain_key).push(r);
  }
  let breaks = 0;
  for (const list of byChain.values()) {
    list.sort((a, b) => a.chain_seq - b.chain_seq);
    const bySeq = new Map(list.map((r) => [r.chain_seq, r]));
    for (const r of list) {
      const prev = bySeq.get(r.chain_seq - 1);
      if (prev && r.prev_record_hash !== prev.integrity.record_hash) breaks += 1;
    }
  }
  add('chain links hold', breaks === 0, breaks ? `${breaks} broken links` : '');

  if (manifest.complete) {
    for (const day of manifest.roots_included ?? []) {
      const rootFile = path.join(dir, 'roots', `${day}.json`);
      if (!fs.existsSync(rootFile)) {
        add(`root ${day}`, false, 'root file missing');
        continue;
      }
      const root = JSON.parse(fs.readFileSync(rootFile, 'utf8'));
      const dayRecords = records.filter((r) => r.ingest_day === day);
      const groups = new Map();
      for (const r of dayRecords) {
        if (!groups.has(r.chain_key)) groups.set(r.chain_key, []);
        groups.get(r.chain_key).push(r);
      }
      const leaves = [...groups.keys()].sort().map((k) => {
        const list = groups.get(k).sort((a, b) => a.chain_seq - b.chain_seq);
        return merkleRoot(list.map((r) => Buffer.from(r.integrity.record_hash, 'hex')));
      });
      const tenant = hex(merkleRoot(leaves));
      const ok = tenant === root.tenant_root && dayRecords.length === root.record_count;
      add(`root ${day}`, ok, ok ? '' : 'recomputed root differs');
    }
  } else {
    add('daily roots', true, 'partial export: roots are verified against a complete export only');
  }

  const sigPath = path.join(dir, 'manifest.sig.json');
  const authenticity = judgeAuthenticity(
    fs.readFileSync(path.join(dir, 'manifest.json')),
    fs.existsSync(sigPath) ? fs.readFileSync(sigPath, 'utf8') : null,
    trustedKeys,
  );
  const proof = verifyEmitterProof(dir, { manifest, records, authenticity, emitterKeys });
  checks.push(...proof.checks);
  return { ok: checks.every((c) => c.ok), authenticity, emitter_proof: proof.summary, checks };
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const args = process.argv.slice(2);
  const keysAt = args.indexOf('--keys');
  const emitterKeysAt = args.indexOf('--emitter-keys');
  const dir = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--keys' && args[i - 1] !== '--emitter-keys');
  if (!dir) {
    console.error('usage: node verify-export.mjs <exportDir> [--keys provantix-export-keys.json] [--emitter-keys emitter-keys.pem|.json] [--integrity-only] [--json]');
    process.exit(2);
  }
  let trustedKeys = null;
  if (keysAt >= 0) {
    try {
      const parsed = JSON.parse(fs.readFileSync(args[keysAt + 1], 'utf8'));
      trustedKeys = Array.isArray(parsed) ? parsed : parsed.keys;
      if (!Array.isArray(trustedKeys)) throw new Error('expected {"keys": [...]}');
    } catch (e) {
      console.error(`cannot read the keys file: ${e.message}`);
      process.exit(2);
    }
  }
  let emitterKeys = null;
  if (emitterKeysAt >= 0) {
    try {
      emitterKeys = parseEmitterKeys(fs.readFileSync(args[emitterKeysAt + 1], 'utf8'));
    } catch (e) {
      console.error(`cannot read the emitter keys file: ${e.message}`);
      process.exit(2);
    }
  }
  let result;
  try {
    result = verifyExport(dir, { trustedKeys, emitterKeys });
  } catch (e) {
    console.error(`cannot verify ${dir}: ${e.message}`);
    process.exit(2);
  }
  const authentic = result.authenticity.state === 'authentic';
  if (args.includes('--json')) {
    console.log(JSON.stringify({ ...result, verified: result.ok && authentic }, null, 2));
  } else {
    for (const c of result.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
    console.log(`${authentic ? 'PASS' : 'NOT ESTABLISHED'}  authenticity  (${result.authenticity.detail})`);
    if (result.emitter_proof) for (const line of result.emitter_proof.lines) console.log(line);
    if (!result.ok) console.log('\nexport FAILED verification');
    else if (authentic) console.log('\nexport verified: consistent, and issued by Provantix');
    else console.log('\nexport is consistent with itself, but its authenticity is NOT established: this does not show Provantix issued it');
  }
  if (!result.ok) process.exit(1);
  process.exit(authentic || args.includes('--integrity-only') ? 0 : 3);
}
