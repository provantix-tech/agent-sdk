#!/usr/bin/env node
// Standalone verifier for Provantix export directories.
//
// Self-contained on purpose: it uses only node:crypto and node:fs and imports nothing from this
// repository, so an auditor can run it on a copy of an export without trusting the rest of the code.
// Format and algorithms: ./FORMAT.md. An independent Python implementation lives in ./python/.
//
// Usage: node verify-export.mjs <exportDir> [--keys provantix-export-keys.json] [--log-keys provantix-log-keys.json] [--integrity-only] [--json]
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

import { createHash, createPublicKey, createVerify, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Keep in sync with the platform's record-integrity module (aar-schema/src/integrity.mjs). 'authorization' was appended
// for Epic E (2026-10-24); records sealed before it existed carry no entry or commitment and
// are skipped, so pre-E exports keep verifying unchanged.
// The two things a passing check never means (PRO-16). Shown beside every result, whatever it says.
export const CAVEATS = Object.freeze([
  'A valid signature shows who signed this. It does not show that what is signed is true.',
  'Integrity is not completeness. Nothing in here was altered since it was recorded, but that does not show that every action was captured.',
]);

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

// ---- the transparency log ----------------------------------------------------------------------------------------------------
// An export made by the hosted service may carry transparency.json: its manifest hash and each included day's root, each logged in
// Provantix's public log with an inclusion proof against one signed tree head. What a passing check shows: Provantix committed to THIS
// manifest hash and THESE roots at the logged time, so it cannot later issue a different export or root for them without the log
// disagreeing. What it does not show: that the log itself was never rewritten. That needs a tree head you (or a mirror) kept
// earlier: see verify-log.mjs. The proof maths is RFC 6962 / RFC 9162; the entry bytes are canonical JSON (keys sorted).

const logCanonical = (v) => {
  if (Array.isArray(v)) return `[${v.map(logCanonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${logCanonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
};
export const logLeafHash = (entry) => createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(logCanonical(entry), 'utf8')])).digest('hex');
const logNode = (l, r) => createHash('sha256').update(Buffer.concat([Buffer.from([1]), l, r])).digest();

/** RFC 9162 2.1.3.2: does `path` prove the leaf is entry `index` of the tree of `size` leaves with this root? */
export function verifyLogInclusion(leafHashHex, index, size, path, rootHex) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size || !Array.isArray(path)) return false;
  let fn = index;
  let sn = size - 1;
  let r = Buffer.from(leafHashHex, 'hex');
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = logNode(Buffer.from(p, 'hex'), r);
      if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = logNode(r, Buffer.from(p, 'hex'));
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r.toString('hex') === rootHex;
}

// <<< rfc3161-check (the same text is embedded in verify-export.mjs and verify-log.mjs; a test keeps the copies identical)
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const EKU_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const HASHES = {
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512',
};

/** Read one TLV at `pos`. */
function read(buf, pos = 0) {
  if (pos + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[pos];
  let len = buf[pos + 1]; let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || pos + 2 + n > buf.length) throw new Error('bad DER length');
    len = 0; for (let i = 0; i < n; i += 1) len = len * 256 + buf[pos + 2 + i];
    hdr = 2 + n;
  }
  const start = pos + hdr; const end = start + len;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, start, end, raw: buf.subarray(pos, end), value: buf.subarray(start, end) };
}
function children(buf, node) {
  const out = []; let p = node.start;
  while (p < node.end) { const k = read(buf, p); out.push(k); p = k.end; }
  return out;
}
const oidOf = (node) => {
  const v = node.value; const out = [Math.floor(v[0] / 40), v[0] % 40]; let n = 0;
  for (let i = 1; i < v.length; i += 1) { n = n * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(n); n = 0; } }
  return out.join('.');
};

const generalizedTime = (s) => {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
  if (!m) throw new Error('unreadable genTime');
  return new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ? `.${m[7].slice(0, 3).padEnd(3, '0')}` : ''}Z`);
};

/**
 * Check a time-stamp token against the digest it should be about. See the header for what this does and does not establish.
 * @param {Buffer} token DER of the token (ContentInfo)
 * @param {Buffer|string} digest the SHA-256 digest that was stamped (Buffer or hex)
 * @param {{ nonce?: Buffer|string }} [opts] the nonce of the request, when you hold it
 * @returns {{ ok: boolean, gen_time?: string, signer?: string, serial?: string, policy?: string, reasons: string[], chain_checked: false }}
 */
export function checkToken(token, digest, { nonce } = {}) {
  const reasons = [];
  const fail = (r) => { reasons.push(r); return { ok: false, reasons, chain_checked: false }; };
  const want = Buffer.isBuffer(digest) ? digest : Buffer.from(String(digest), 'hex');
  try {
    const ci = read(token, 0);
    const [typeNode, wrap] = children(token, ci);
    if (oidOf(typeNode) !== OID_SIGNED_DATA) return fail('the token is not CMS signed data');
    const sd = read(token, wrap.start);
    const parts = children(token, sd);
    // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    const encap = parts[2];
    const [eType, eWrap] = children(token, encap);
    if (oidOf(eType) !== OID_TSTINFO) return fail('the signed content is not a time-stamp record');
    const tstBytes = read(token, eWrap.start).value;
    const tst = read(tstBytes, 0);
    const t = children(tstBytes, tst); // version, policy, imprint, serial, genTime, [accuracy], [ordering], [nonce], ...
    const policy = oidOf(t[1]);
    const imprint = children(tstBytes, t[2]);
    const imprintAlg = oidOf(children(tstBytes, imprint[0])[0]);
    const imprintHash = imprint[1].value;
    if (imprintAlg !== OID_SHA256) reasons.push('the token stamps a hash other than SHA-256');
    if (!imprintHash.equals(want)) reasons.push('the token is about a different digest than this head');
    const serial = t[3].value.toString('hex');
    const genTime = generalizedTime(t[4].value.toString('latin1'));
    if (nonce !== undefined) {
      const wantNonce = Buffer.isBuffer(nonce) ? nonce : Buffer.from(String(nonce), 'hex');
      const nodes = t.slice(5).filter((n) => n.tag === 0x02);
      const got = nodes[0]?.value;
      const strip = (b) => { let x = Buffer.from(b); while (x.length > 1 && x[0] === 0) x = x.subarray(1); return x; };
      if (!got || !strip(got).equals(strip(wantNonce))) reasons.push('the token answers a different request (nonce differs)');
    }
    // certificates and the signer
    const certsNode = parts.find((n) => n.tag === 0xa0);
    const certs = [];
    if (certsNode) for (const c of children(token, certsNode)) { try { certs.push({ x509: new X509Certificate(c.raw), der: c.raw }); } catch { /* skip an unreadable one */ } }
    const signerInfos = parts[parts.length - 1];
    const si = children(token, children(token, signerInfos)[0]);
    // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    const sid = si[1];
    const digestAlg = HASHES[oidOf(children(token, si[2])[0])];
    const attrsNode = si.find((n) => n.tag === 0xa0);
    const sigNode = si.filter((n) => n.tag === 0x04).pop();
    if (!digestAlg || !attrsNode || !sigNode) return fail('the signer information is not in a form this check reads');
    // the message digest attribute must equal the hash of the TSTInfo
    let attrDigest = null; let attrType = null;
    for (const a of children(token, attrsNode)) {
      const [ao, av] = children(token, a);
      const val = children(token, av)[0];
      if (oidOf(ao) === OID_MESSAGE_DIGEST) attrDigest = val.value;
      if (oidOf(ao) === OID_CONTENT_TYPE) attrType = oidOf(val);
    }
    const actual = createHash(digestAlg).update(tstBytes).digest();
    if (!attrDigest || !attrDigest.equals(actual)) reasons.push('the signed attributes do not match the time-stamp record');
    if (attrType && attrType !== OID_TSTINFO) reasons.push('the signed content type is not a time-stamp record');
    // the signature covers the attributes re-encoded as a SET
    const signedBytes = Buffer.concat([Buffer.from([0x31]), attrsNode.raw.subarray(1)]);
    const sidSerial = sid.tag === 0x30 ? children(token, sid)[1]?.value : null; // IssuerAndSerialNumber: issuer, serial
    const candidates = certs.filter((c) => !sidSerial || c.x509.serialNumber.replace(/^0+/, '').toLowerCase() === sidSerial.toString('hex').replace(/^0+/, ''));
    let signer = null;
    for (const c of candidates) {
      try { if (createVerify(digestAlg).update(signedBytes).verify(c.x509.publicKey, sigNode.value)) { signer = c; break; } } catch { /* try the next */ }
    }
    if (!signer) reasons.push(certs.length ? 'the signature does not verify under the certificate in the token' : 'the token carries no signer certificate to check the signature with');
    if (signer) {
      const eku = signer.x509.keyUsage ?? [];
      if (!eku.includes(EKU_TIMESTAMPING)) reasons.push('the signer certificate is not for time-stamping');
      if (genTime < new Date(signer.x509.validFrom) || genTime > new Date(signer.x509.validTo)) reasons.push('the stamped time is outside the signer certificate\'s validity');
    }
    return {
      ok: reasons.length === 0, gen_time: genTime.toISOString(), signer: signer ? signer.x509.subject.replace(/\n/g, ', ') : undefined,
      serial, policy, reasons, chain_checked: false,
    };
  } catch (e) {
    return fail(`the token cannot be read: ${e.message}`);
  }
}
/**
 * What a head's anchor shows, as a verifier reports it. Absence is "not anchored", never a failure; only an anchor that is present and does
 * not verify is a problem. `signingBytes` is what the head's own signature covers (the head's fields as canonical JSON, without the signature).
 * @returns {{ state: 'anchored'|'not_anchored'|'invalid', text: string, gen_time?: string, signer?: string, authority?: string }}
 */
export function anchorState(head, signingBytes) {
  const a = head?.anchor;
  if (!a) return { state: 'not_anchored', text: 'not anchored' };
  if (!a.token) return { state: 'not_anchored', text: `not anchored yet${a.reason ? ` (${a.reason})` : ''}` };
  const digest = createHash('sha256').update(signingBytes).digest();
  if (a.digest_sha256 && a.digest_sha256 !== digest.toString('hex')) return { state: 'invalid', text: 'the time-stamp is for different bytes than this head' };
  let token;
  try { token = Buffer.from(String(a.token), 'base64'); } catch { return { state: 'invalid', text: 'the time-stamp cannot be read' }; }
  const r = checkToken(token, digest);
  if (!r.ok) return { state: 'invalid', text: `the time-stamp does not verify: ${r.reasons.join('; ')}` };
  return { state: 'anchored', text: `time-stamped by ${r.signer} at ${r.gen_time} (the authority's certificate chain is not checked here: see the docs for openssl ts -verify)`, gen_time: r.gen_time, signer: r.signer, authority: a.authority };
}
// >>> rfc3161-check

/** The bytes a tree head's signature covers. */
export const logHeadSigningBytes = (h) => Buffer.from(logCanonical({
  version: h.version, log_id: h.log_id, tree_size: h.tree_size, root_hash: h.root_hash, timestamp: h.timestamp, key_id: h.key_id,
}), 'utf8');

/**
 * @param {string} dir
 * @param {{ manifestBytes: Buffer, logKeys: {key_id: string, public_key_pem: string}[]|null }} ctx
 * @returns {{ checks: {name: string, ok: boolean, detail: string}[], summary: {state: 'absent'|'checked', lines: string[]} }}
 */
export function verifyTransparency(dir, { manifestBytes, logKeys = null }) {
  const file = path.join(dir, 'transparency.json');
  if (!fs.existsSync(file)) {
    return { checks: [], summary: { state: 'absent', lines: ['transparency log: this export carries no log proof (it was not logged, or it predates the log)'] } };
  }
  const checks = [];
  const lines = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {
    add('transparency log proof readable', false, 'transparency.json is not valid JSON');
    return { checks, summary: { state: 'checked', lines } };
  }
  const head = doc?.head;
  const entries = Array.isArray(doc?.entries) ? doc.entries : [];
  if (!head || !Number.isInteger(head.tree_size) || typeof head.root_hash !== 'string' || !entries.length) {
    add('transparency log proof readable', false, 'transparency.json is missing its head or its entries');
    return { checks, summary: { state: 'checked', lines } };
  }

  // Every entry must be included in the signed head's tree, and belong to this organization.
  let allIncluded = true;
  for (const e of entries) {
    const ok = Boolean(e?.leaf) && verifyLogInclusion(logLeafHash(e.leaf), e.index, head.tree_size, e.path, head.root_hash) && e.leaf.org_ref === doc.org_ref;
    if (!ok) {
      allIncluded = false;
      add(`transparency log entry ${e?.index}`, false, "the entry is not in the log's tree head, or belongs to another organization");
    }
  }
  if (allIncluded) add('transparency log: entries are in the tree head', true, `${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} proved against a head of ${head.tree_size}`);

  // The manifest the log committed to must be this export's manifest.
  const manifestEntry = entries.find((e) => e?.leaf?.kind === 'export_manifest');
  const manifestSha = createHash('sha256').update(manifestBytes).digest('hex');
  if (!manifestEntry) {
    add('transparency log: manifest is logged', false, 'no manifest entry in the proof');
  } else {
    const same = manifestEntry.leaf.manifest_sha256 === manifestSha;
    add('transparency log: manifest is logged', same, same ? `entry #${manifestEntry.index}, logged ${manifestEntry.leaf.logged_at}` : "the logged manifest hash is not this export's manifest");
  }

  // Each root in the export must be the root Provantix logged for that day.
  const rootsDir = path.join(dir, 'roots');
  const rootFiles = fs.existsSync(rootsDir) ? fs.readdirSync(rootsDir).filter((f) => /^\d{4}-\d{2}-\d{2}\.json$/.test(f)) : [];
  let matched = 0;
  const unlogged = [];
  for (const f of rootFiles) {
    const day = f.slice(0, 10);
    let tenantRoot = null;
    try { tenantRoot = JSON.parse(fs.readFileSync(path.join(rootsDir, f), 'utf8')).tenant_root; } catch { /* the file checks report it */ }
    const logged = entries.find((e) => e?.leaf?.kind === 'day_root' && e.leaf.day === day);
    if (!logged) { unlogged.push(day); continue; }
    const same = logged.leaf.tenant_root === tenantRoot && !logged.conflict;
    add(`transparency log: root ${day} matches the logged root`, same, same ? '' : 'this root differs from the one Provantix logged for the day');
    if (same) matched += 1;
  }
  if (matched) lines.push(`transparency log: ${matched} daily root${matched === 1 ? ' matches' : 's match'} what Provantix logged`);
  if (unlogged.length) {
    lines.push(`transparency log: ${unlogged.length} root${unlogged.length === 1 ? '' : 's'} in this export ${unlogged.length === 1 ? 'has' : 'have'} no log entry (${unlogged.slice(0, 3).join(', ')}${unlogged.length > 3 ? ', ...' : ''})`);
  }

  // The head is only worth what its signature is worth: check it against the log's published keys when they were supplied.
  if (logKeys) {
    const key = logKeys.find((k) => k.key_id === head.key_id);
    let ok = false;
    if (key) {
      try { ok = cryptoVerify(null, logHeadSigningBytes(head), createPublicKey(key.public_key_pem), Buffer.from(head.signature, 'base64')); } catch { ok = false; }
    }
    add('transparency log: tree head signature', ok, ok ? `signed by log key ${head.key_id} at ${head.timestamp}` : key ? 'the head signature does not verify' : `no key ${head.key_id} in the log keys file`);
  } else {
    lines.push(`transparency log: tree head signature NOT CHECKED (pass the log's published keys with --log-keys; head of ${head.tree_size} entries, ${head.timestamp})`);
  }
  // An outside time-stamp on the head, when there is one. Absent is "not anchored", never a failure; present and wrong is.
  const anchor = anchorState(head, logHeadSigningBytes(head));
  if (anchor.state === 'invalid') add('transparency log: head time-stamp', false, anchor.text);
  else if (anchor.state === 'anchored') {
    add('transparency log: head time-stamp', true, anchor.text);
    lines.push(`transparency log: the tree head existed by ${anchor.gen_time}, fixed by an outside time-stamp authority (${anchor.signer}). This shows when the head existed, not that the log is complete or true.`);
  } else lines.push(`transparency log: the tree head is ${anchor.text} by an outside time-stamp authority`);
  lines.push('transparency log: a logged entry shows Provantix committed to this hash then. That the log itself was never rewritten is checked with a tree head you kept earlier (verify-log.mjs).');
  return { checks, summary: { state: 'checked', lines } };
}


// ---- decision evidence (optional, in records: ext.decision and ext.decision_ref) ------------------------------------------------------
// Why an agent chose an action, as the agent recorded it. Computed from records.jsonl alone, so it needs no extra file and no version change:
// a decision record and the action record that cites it either agree or they do not, and both are sealed by the emitter. This says what the agent
// said it considered. It does not show the reasoning was sound, that it was the reason, or that the action happened: the destination's record,
// in the reconciliation section, is a separate layer.
// <<< decision-evidence (the same text is embedded in verify-export.mjs, and python/verify_export.py is written to agree; a test checks both)
export const DECISION_VERSION = 1;
export const DECISION_SOURCES = ['agent', 'human', 'system'];
export const DECISION_LIMITS = { text: 500, ref: 300, items: 20 };

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' && v.trim() ? v : null);

/** The extension value of a record, in either shape, or { erased: true } when it was erased, or null when there is none. */
function extOf(rec) {
  let body = rec?.body ?? rec;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return null; } }
  const ext = body?.erasable?.ext;
  if (!ext) return null;
  if (ext.erased) return { erased: true };
  return isObj(ext.value) ? { value: ext.value } : null;
}

/** Problems with a decision's content, as readable sentences. An empty list means it is well formed (not that it is true). */
export function validateDecision(d) {
  const problems = [];
  if (!isObj(d)) return ['the decision is not an object'];
  if (d.v !== DECISION_VERSION) problems.push(`the decision version is ${JSON.stringify(d.v)}, and only ${DECISION_VERSION} is understood`);
  if (!str(d.decision_id)) problems.push('there is no decision_id');
  if (!DECISION_SOURCES.includes(d.source)) problems.push(`source must be one of ${DECISION_SOURCES.join(', ')}`);
  const cands = Array.isArray(d.candidates) ? d.candidates : [];
  if (!cands.length) problems.push('there is no candidate action');
  if (cands.length > DECISION_LIMITS.items) problems.push(`more than ${DECISION_LIMITS.items} candidates`);
  const ids = new Set();
  for (const c of cands) {
    if (!isObj(c) || !str(c.id) || !str(c.action)) { problems.push('a candidate has no id or no action'); continue; }
    if (ids.has(c.id)) problems.push(`candidate id ${c.id} is used twice`);
    ids.add(c.id);
  }
  if (!isObj(d.selected) || !str(d.selected.candidate_id) || !str(d.selected.action_id)) problems.push('the selected action needs a candidate_id and an action_id');
  else if (!ids.has(d.selected.candidate_id)) problems.push('the selected candidate is not among the candidates');
  for (const r of Array.isArray(d.rejected) ? d.rejected : []) {
    if (!isObj(r) || !str(r.candidate_id)) problems.push('a rejected alternative names no candidate');
    else if (!ids.has(r.candidate_id)) problems.push(`rejected candidate ${r.candidate_id} is not among the candidates`);
    else if (d.selected && r.candidate_id === d.selected.candidate_id) problems.push('the selected candidate is also listed as rejected');
  }
  // the instruction the decision answers, and the model invocation behind it: optional, and when given they must say what they point at
  if (d.intent_ref !== undefined && d.intent_ref !== null && (!isObj(d.intent_ref) || !str(d.intent_ref.ref))) problems.push('intent_ref needs a ref');
  if (d.model_ref !== undefined && d.model_ref !== null && (!isObj(d.model_ref) || !str(d.model_ref.model_id))) problems.push('model_ref needs a model_id');
  return problems;
}

/** A decision record, read: { record_id, decision, problems } | { record_id, erased: true } | null when the record is not a decision. */
export function decisionOf(rec) {
  const ext = extOf(rec);
  if (!ext) return null;
  if (ext.erased) return null; // an erased extension cannot say whether it held a decision: see links, where an action's pointer shows it
  const d = ext.value.decision;
  if (!isObj(d)) return null;
  return { record_id: rec.record_id, decision: d, problems: validateDecision(d) };
}

/** The pointer an action's record carries to its decision, or null. */
export function decisionRefOf(rec) {
  const ext = extOf(rec);
  if (!ext || ext.erased) return null;
  const r = ext.value.decision_ref;
  if (!isObj(r) || !str(r.decision_id)) return null;
  return { record_id: rec.record_id, decision_id: String(r.decision_id), candidate_id: str(r.candidate_id), action_id: str(r.action_id) };
}

/**
 * Link decisions and actions among these records. Nothing outside them is consulted, so an export can be checked on its own.
 *   decisions  each decision found, with whether it is well formed and which action it selected
 *   links      each action that points at a decision, and whether the two agree:
 *                linked          the decision is here and names this action and candidate
 *                mismatch        the decision is here but selects a different action or candidate (a swapped or edited reference)
 *                not_in_scope    the decision it cites is not among these records (deleted, never exported, or never recorded)
 *                duplicate       two different records claim the same decision id, so neither can be trusted to be the one cited
 *   undelivered  decisions that selected an action no record here points back at. This is not evidence the action did not happen: only
 *                that no record of it carries the pointer.
 */
export function decisionLinks(records) {
  const decisions = [];
  const refs = [];
  for (const rec of records) {
    const d = decisionOf(rec);
    if (d) decisions.push(d);
    const r = decisionRefOf(rec);
    if (r) refs.push(r);
  }
  const byId = new Map();
  for (const d of decisions) byId.set(d.decision.decision_id, [...(byId.get(d.decision.decision_id) ?? []), d]);
  const links = refs.map((r) => {
    const found = byId.get(r.decision_id) ?? [];
    const base = { action_record_id: r.record_id, decision_id: r.decision_id, candidate_id: r.candidate_id, action_id: r.action_id };
    if (!found.length) return { ...base, status: 'not_in_scope', reason: 'the decision this action cites is not among these records' };
    if (found.length > 1) return { ...base, status: 'duplicate', reason: 'more than one record claims this decision id' };
    const sel = found[0].decision.selected ?? {};
    if (sel.action_id !== r.action_id || sel.candidate_id !== r.candidate_id) {
      return { ...base, decision_record_id: found[0].record_id, status: 'mismatch', reason: 'the decision selects a different action or candidate than the one that cites it' };
    }
    return { ...base, decision_record_id: found[0].record_id, status: 'linked', reason: null };
  });
  const cited = new Set(refs.map((r) => `${r.decision_id}|${r.action_id}`));
  const undelivered = decisions
    .filter((d) => d.decision.selected?.action_id && !cited.has(`${d.decision.decision_id}|${d.decision.selected.action_id}`))
    .map((d) => ({ decision_record_id: d.record_id, decision_id: d.decision.decision_id, action_id: d.decision.selected.action_id }));
  return {
    decisions: decisions.map((d) => ({
      record_id: d.record_id, decision_id: d.decision.decision_id, task_id: d.decision.task_id ?? null, source: d.decision.source ?? null,
      selected: d.decision.selected ?? null, candidates: Array.isArray(d.decision.candidates) ? d.decision.candidates.length : 0,
      rejected: Array.isArray(d.decision.rejected) ? d.decision.rejected.length : 0, well_formed: d.problems.length === 0, problems: d.problems,
    })),
    links,
    undelivered,
  };
}
// >>> decision-evidence

// ---- control decision evidence (optional, in records: ext.control and ext.control_ref) ------------------------------------------------
// What an enforcement tool said it decided about an action (allow, ask, deny, steer), as the emitter sealed it, and whether the records agree
// with each other. This is an integrity check over the records in the export. It does not show the enforcer was in the path, that its verdict was
// obeyed, or that an action it denied did not happen: a missing record of an action is not proof it did not run.
// <<< control-evidence (the same text is embedded in verify-export.mjs, and python/verify_export.py is written to agree; a test checks both)
// It relies on isObj, str and extOf, which the verifier's decision evidence block and this file both define the same way.
export const CONTROL_VERSION = 1;
export const CONTROL_VERDICTS = ['allow', 'ask', 'deny', 'steer'];

/** Problems with a control decision's content, as readable sentences. Empty means well formed, not true. */
export function validateControl(c) {
  const problems = [];
  if (!isObj(c)) return ['the control decision is not an object'];
  if (c.v !== CONTROL_VERSION) problems.push(`the control decision version is ${c.v === undefined ? 'missing' : JSON.stringify(c.v)}, and only ${CONTROL_VERSION} is understood`);
  if (!str(c.control_id)) problems.push('there is no control_id');
  if (!isObj(c.enforcer) || !str(c.enforcer.name)) problems.push('the enforcer needs a name');
  if (!CONTROL_VERDICTS.includes(c.verdict)) problems.push(`verdict must be one of ${CONTROL_VERDICTS.join(', ')}`);
  if (!isObj(c.policy) || !str(c.policy.id)) problems.push('the policy that decided needs an id');
  if (c.decided_at !== undefined && c.decided_at !== null && Number.isNaN(Date.parse(c.decided_at))) problems.push('decided_at must be a date and time');
  return problems;
}

/** A control record, read: { record_id, control, problems } or null when the record is not a control decision. */
export function controlOf(rec) {
  const ext = extOf(rec);
  if (!ext || ext.erased) return null;
  const c = ext.value.control;
  if (!isObj(c)) return null;
  return { record_id: rec.record_id, control: c, problems: validateControl(c) };
}

/** The pointer an action's record carries to the control decision about it, or null. */
export function controlRefOf(rec) {
  const ext = extOf(rec);
  if (!ext || ext.erased) return null;
  const r = ext.value.control_ref;
  if (!isObj(r) || !str(r.control_id)) return null;
  return { record_id: rec.record_id, control_id: String(r.control_id), action_id: str(r.action_id) };
}

/**
 * Check that control decisions and the actions that cite them agree, among these records only. This is an integrity check on the records, not a
 * comparison of what the enforcer said with what happened (that is controlLinks, which needs the engine's data):
 *   linked        the decision is here and names the same action id as the action that cites it
 *   unbound       the decision is here and carries no action id, so it can neither agree nor disagree
 *   mismatch      the decision is here but names a different action id than the action that cites it (a swapped or edited reference)
 *   not_in_scope  the decision the action cites is not among these records (deleted, never exported, or never recorded)
 *   duplicate     two records claim the same control id
 * `denied_cited` counts denials that an action record here cites by action id: the enforcer said no, and a record of the action carries its
 * pointer. It is what the enforcer said and what a record shows, side by side. It is not a finding that the control failed.
 */
export function controlRefLinks(records) {
  const controls = [];
  const refs = [];
  for (const rec of records) {
    const c = controlOf(rec);
    if (c) controls.push(c);
    const r = controlRefOf(rec);
    if (r) refs.push(r);
  }
  const byId = new Map();
  for (const c of controls) byId.set(c.control.control_id, [...(byId.get(c.control.control_id) ?? []), c]);
  const links = refs.map((r) => {
    const found = byId.get(r.control_id) ?? [];
    const base = { action_record_id: r.record_id, control_id: r.control_id, action_id: r.action_id };
    if (!found.length) return { ...base, status: 'not_in_scope', reason: 'the control decision this action cites is not among these records' };
    if (found.length > 1) return { ...base, status: 'duplicate', reason: 'more than one record claims this control id' };
    const want = str(found[0].control.action_id);
    if (!want) return { ...base, control_record_id: found[0].record_id, verdict: found[0].control.verdict ?? null, status: 'unbound', reason: null };
    if (want !== r.action_id) return { ...base, control_record_id: found[0].record_id, verdict: found[0].control.verdict ?? null, status: 'mismatch', reason: 'the control decision names a different action than the one that cites it' };
    return { ...base, control_record_id: found[0].record_id, verdict: found[0].control.verdict ?? null, status: 'linked', reason: null };
  });
  return {
    controls: controls.map((c) => ({
      record_id: c.record_id, control_id: c.control.control_id ?? null, verdict: c.control.verdict ?? null, enforcer: isObj(c.control.enforcer) ? str(c.control.enforcer.name) : null,
      action_id: str(c.control.action_id), well_formed: c.problems.length === 0, problems: c.problems,
    })),
    links,
    denied_cited: links.filter((l) => l.status === 'linked' && l.verdict === 'deny').length,
  };
}
// >>> control-evidence

/**
 * @returns {{ checks: {name: string, ok: boolean, detail: string}[], summary: object }}
 */
export function verifyControlEvidence({ records }) {
  const r = controlRefLinks(records);
  const count = (s) => r.links.filter((l) => l.status === s).length;
  const counts = {
    controls: r.controls.length, actions_citing: r.links.length, linked: count('linked'), unbound: count('unbound'), mismatched: count('mismatch'), duplicates: count('duplicate'),
    not_in_scope: count('not_in_scope'), malformed: r.controls.filter((c) => !c.well_formed).length, denied_cited: r.denied_cited,
  };
  if (!counts.controls && !counts.actions_citing) {
    return { checks: [], summary: { present: false, ...counts, lines: ['control evidence: this export carries no control decision records'] } };
  }
  const checks = [];
  checks.push({
    name: 'control evidence: every control decision agrees with the action that cites it', ok: counts.mismatched + counts.duplicates === 0,
    detail: counts.mismatched + counts.duplicates === 0 ? `${counts.linked + counts.unbound} of ${counts.actions_citing} cited` : `${counts.mismatched} name a different action than the one citing them, ${counts.duplicates} cite a control id claimed by two records`,
  });
  checks.push({
    name: 'control evidence: control decisions are well formed', ok: counts.malformed === 0,
    detail: counts.malformed === 0 ? '' : r.controls.filter((c) => !c.well_formed).map((c) => `${c.control_id}: ${c.problems[0]}`).join('; '),
  });
  const parts = [`${counts.controls} control decision${counts.controls === 1 ? '' : 's'} recorded, ${counts.linked} linked to the action each named`];
  if (counts.denied_cited) parts.push(`${counts.denied_cited} denied by the enforcer and cited by an action record in this export (what the enforcer said and what a record shows, side by side; not a finding about the control)`);
  if (counts.not_in_scope) parts.push(`${counts.not_in_scope} ${counts.not_in_scope === 1 ? 'action cites' : 'actions cite'} a control decision that is not in this export (not recorded here, which is not the same as there being none)`);
  const lines = [
    `control evidence: ${parts.join('; ')}`,
    'control evidence: a control decision is what the enforcement tool said it decided. It does not show the tool was in the path, that its verdict was obeyed, or that an action it denied did not happen.',
  ];
  return { checks, summary: { present: true, ...counts, control_list: r.controls, links: r.links, lines } };
}

/**
 * @returns {{ checks: {name: string, ok: boolean, detail: string}[], summary: object }}
 */
export function verifyDecisionEvidence({ records }) {
  const r = decisionLinks(records);
  const erased = records.filter((rec) => rec?.erasable?.ext?.erased).length;
  const count = (s) => r.links.filter((l) => l.status === s).length;
  const counts = {
    decisions: r.decisions.length, actions_citing: r.links.length, linked: count('linked'), mismatched: count('mismatch'), duplicates: count('duplicate'),
    not_in_scope: count('not_in_scope'), undelivered: r.undelivered.length, malformed: r.decisions.filter((d) => !d.well_formed).length, erased_extensions: erased,
  };
  if (!counts.decisions && !counts.actions_citing) {
    return { checks: [], summary: { present: false, ...counts, lines: ['decision evidence: this export carries no decision records'] } };
  }
  const checks = [];
  checks.push({
    name: 'decision evidence: every decision agrees with the action that cites it', ok: counts.mismatched + counts.duplicates === 0,
    detail: counts.mismatched + counts.duplicates === 0 ? `${counts.linked} of ${counts.actions_citing} cited` : `${counts.mismatched} differ from what the decision selected, ${counts.duplicates} cite a decision id claimed by two records`,
  });
  checks.push({
    name: 'decision evidence: decisions are well formed', ok: counts.malformed === 0,
    detail: counts.malformed === 0 ? '' : r.decisions.filter((d) => !d.well_formed).map((d) => `${d.decision_id}: ${d.problems[0]}`).join('; '),
  });
  const parts = [`${counts.decisions} decision${counts.decisions === 1 ? '' : 's'} recorded, ${counts.linked} linked to the action each selected`];
  if (counts.not_in_scope) parts.push(`${counts.not_in_scope} ${counts.not_in_scope === 1 ? 'action cites' : 'actions cite'} a decision that is not in this export (not recorded here, which is not the same as there being none)`);
  if (counts.undelivered) parts.push(`${counts.undelivered} decision${counts.undelivered === 1 ? '' : 's'} selected an action that no record here points back at (this is not evidence the action did not happen)`);
  if (counts.erased_extensions) parts.push(`${counts.erased_extensions} record${counts.erased_extensions === 1 ? ' has' : 's have'} an erased extension, so a decision or a pointer there cannot be read`);
  const lines = [
    `decision evidence: ${parts.join('; ')}`,
    'decision evidence: a decision is what the agent said it considered and chose. It does not show the reasoning was sound or was the reason, or that the action happened as chosen.',
  ];
  return { checks, summary: { present: true, ...counts, decision_list: r.decisions, links: r.links, lines } };
}

// ---- reconciliation, approval binding and later outcomes (export 1.1, optional reconciliation.json) ----------------------------------
// The section says what Provantix compared. This checks that it is well formed, that each result is consistent with the destination
// record the export carries, and that each approval's coverage recomputes from the record and the policy version carried. It does not
// claim the destination's record is true: that is the destination's own statement, carried and hashed, not vouched for.

const RECON_STATES = ['agent_reported', 'destination_confirmed', 'conflicting', 'pending', 'unverified'];
const RECON_METHODS = ['reference', 'action_id', 'payment_amount_time'];
const LINK_KINDS = ['reversal', 'retry', 'dispute', 'reopened', 'human_override'];
const AUTHORITY = ['verified', 'not_covered', 'unchecked', 'binding_not_recorded'];
const SUCCESS_STATES = new Set(['pending', 'succeeded']);
const FAILURE_STATES = new Set(['failed', 'canceled']);

/** The agent's claim as carried in the record's sealed extension, or why it cannot be read. */
function claimOfRecord(r) {
  const ext = r.erasable?.ext;
  if (ext?.erased) return { unreadable: 'the claim was erased' };
  const c = ext?.value?.claim;
  if (!c || typeof c !== 'object') return { unreadable: 'the record carries no claim' };
  const amount = c.amount_minor !== null && c.amount_minor !== '' && c.amount_minor !== undefined && Number.isInteger(Number(c.amount_minor)) ? Number(c.amount_minor) : null;
  const claim = {
    action_id: c.action_id ? String(c.action_id) : null,
    destination_ref: c.destination_ref ? String(c.destination_ref) : null,
    payment_ref: c.payment_ref ? String(c.payment_ref) : (r.fields?.action?.target_entity_id ? String(r.fields.action.target_entity_id) : null),
    amount_minor: amount,
    currency: c.currency ? String(c.currency).toUpperCase() : null,
    outcome: r.fields?.quality?.outcome ?? null,
  };
  if (claim.amount_minor === null || !claim.currency) return { unreadable: 'the claim has no amount and currency', claim };
  return { claim };
}

/** What the claim and the destination's record disagree about. Empty means they agree. Mirrors the engine's comparison. */
function claimDiffers(claim, rec) {
  const differs = [];
  if (claim.payment_ref && rec.payment_ref && ![rec.payment_ref, ...(Array.isArray(rec.provenance?.payment_aliases) ? rec.provenance.payment_aliases : [])].includes(claim.payment_ref)) differs.push('payment');
  if (Number(rec.amount_minor) !== claim.amount_minor) differs.push('amount');
  if (String(rec.currency ?? '').toUpperCase() !== claim.currency) differs.push('currency');
  if (claim.outcome === 'success' || claim.outcome === 'failure') {
    const ok = claim.outcome === 'success' ? SUCCESS_STATES.has(rec.status) : FAILURE_STATES.has(rec.status);
    if (!ok) differs.push('outcome');
  }
  return differs;
}

const txt = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);

/** Whether an approval covers its action, recomputed from the record and the carried policy version. Mirrors the engine. */
function bindingAuthority(r, approval) {
  const az = r.erasable?.authorization;
  if (az?.erased) return { skip: 'the approval was erased from the record' };
  const raw = az?.value?.binding;
  const b = raw && typeof raw === 'object' && !Array.isArray(raw) ? {
    target_system: raw.target_system ?? null, target_entity_id: raw.target_entity_id ?? null, action_type: raw.action_type ?? null,
    max_amount_minor: raw.max_amount_minor !== null && raw.max_amount_minor !== undefined && raw.max_amount_minor !== '' && Number.isSafeInteger(Number(raw.max_amount_minor)) ? Number(raw.max_amount_minor) : null,
    currency: raw.currency ? String(raw.currency).toUpperCase() : null, expires_at: raw.expires_at ?? null, policy_version: raw.policy_version ?? null,
    // exact-change fields (all optional): an approval that states none of them is checked exactly as before
    environment: txt(raw.environment), resource: txt(raw.resource), operation: txt(raw.operation), change_digest: txt(raw.change_digest)?.toLowerCase() ?? null,
    risk_ref: txt(raw.risk_ref), break_glass: raw.break_glass === true ? true : null,
  } : null;
  if (!b || !Object.values(b).some((v) => v !== null)) return { authority: 'binding_not_recorded', path: 'normal' };
  const a = r.fields?.action ?? {};
  const st = [];
  if (b.target_system !== null) st.push(!a.target_system ? 'unchecked' : a.target_system === b.target_system ? 'holds' : 'fails');
  if (b.target_entity_id !== null) st.push(!a.target_entity_id ? 'unchecked' : a.target_entity_id === b.target_entity_id ? 'holds' : 'fails');
  if (b.action_type !== null) st.push(a.action_type === b.action_type ? 'holds' : 'fails');
  if (b.max_amount_minor !== null) {
    const { claim } = claimOfRecord(r);
    const readable = claim && claim.amount_minor !== null && claim.currency && (claim.destination_ref || claim.action_id || claim.payment_ref);
    if (!readable) st.push('unchecked');
    else if (b.currency && claim.currency && b.currency !== claim.currency) st.push('fails');
    else st.push(claim.amount_minor > b.max_amount_minor ? 'fails' : 'holds');
  }
  if (b.expires_at !== null) {
    const exp = Date.parse(b.expires_at);
    const at = Date.parse(r.fields?.observed_at);
    st.push(Number.isNaN(exp) || Number.isNaN(at) ? 'unchecked' : at <= exp ? 'holds' : 'fails');
  }
  if (b.policy_version !== null) {
    const inForce = approval.policy_version_in_force ?? null;
    st.push(inForce === null ? 'unchecked' : inForce === b.policy_version ? 'holds' : 'fails');
  }
  if (b.environment || b.resource || b.operation || b.change_digest || b.break_glass) {
    const ext = r.erasable?.ext;
    const m = ext?.erased ? { erased: true } : ext?.value?.mutation && typeof ext.value.mutation === 'object' && !Array.isArray(ext.value.mutation) ? {
      environment: txt(ext.value.mutation.environment), resource: txt(ext.value.mutation.resource), change_digest: txt(ext.value.mutation.change_digest)?.toLowerCase() ?? null,
    } : null;
    const mut = (key, want) => { if (want !== null) st.push(m?.erased || !m || !m[key] ? 'unchecked' : m[key] === want ? 'holds' : 'fails'); };
    mut('environment', b.environment); mut('resource', b.resource); mut('change_digest', b.change_digest);
    if (b.operation !== null) st.push(!a.operation ? 'unchecked' : a.operation === b.operation ? 'holds' : 'fails');
    const approvedAt = Date.parse(az?.value?.approved_at);
    const at = Date.parse(r.fields?.observed_at);
    st.push(Number.isNaN(approvedAt) || Number.isNaN(at) ? 'unchecked' : approvedAt <= at ? 'holds' : 'fails');
    if (b.break_glass) st.push('unchecked');
  }
  return { authority: st.includes('fails') ? 'not_covered' : st.includes('unchecked') ? 'unchecked' : 'verified', path: b.break_glass ? 'break_glass' : 'normal' };
}

export function verifyReconciliation(dir, { manifest, records }) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  const file = (manifest.files ?? []).find((f) => f.path === 'reconciliation.json');
  const summary = { present: Boolean(file), lines: [] };
  if (!file) {
    summary.lines.push('reconciliation: this export carries no reconciliation section (nothing was checked against a destination system for it).');
    return { checks, summary };
  }
  let sec;
  try {
    sec = JSON.parse(fs.readFileSync(path.join(dir, 'reconciliation.json'), 'utf8'));
  } catch (e) {
    add('reconciliation: structure', false, `unreadable: ${e.message}`);
    return { checks, summary };
  }
  const byId = new Map(records.map((r) => [r.record_id, r]));
  const problems = [];
  const arr = (k) => (Array.isArray(sec[k]) ? sec[k] : (problems.push(`${k} is not a list`), []));
  const scopes = arr('scopes'); const results = arr('results'); const dests = arr('destination_records'); const approvals = arr('approvals'); const links = arr('links');
  if (sec.version !== 1) problems.push(`unknown section version ${sec.version}`);
  if (typeof sec.statement !== 'string' || !sec.statement) problems.push('the statement of what the section does and does not show is missing');
  const scopeIds = new Set(scopes.map((s) => s.scope_id));
  for (const s of scopes) if (!s.scope_id || !s.destination_source || !s.statement) problems.push('a scope is missing its id, destination or statement');
  const seenResult = new Set();
  for (const r of results) {
    if (!byId.has(r.record_id)) problems.push(`a result is for ${r.record_id}, which is not in this export`);
    if (seenResult.has(r.record_id)) problems.push(`two current results for ${r.record_id}`);
    seenResult.add(r.record_id);
    if (!RECON_STATES.includes(r.state)) problems.push(`result for ${r.record_id} has an unknown state "${r.state}"`);
    if (r.method !== null && r.method !== undefined && !RECON_METHODS.includes(r.method)) problems.push(`result for ${r.record_id} has an unknown method "${r.method}"`);
    if (!r.reason) problems.push(`result for ${r.record_id} has no reason`);
    if (!scopeIds.has(r.scope_id)) problems.push(`result for ${r.record_id} names a scope that is not in the section`);
    for (const h of r.history ?? []) if (!RECON_STATES.includes(h.state) || !h.reason) problems.push(`result history for ${r.record_id} is malformed`);
  }
  for (const a of approvals) {
    if (!byId.has(a.record_id)) problems.push(`an approval entry is for ${a.record_id}, which is not in this export`);
    if (!AUTHORITY.includes(a.authority)) problems.push(`approval for ${a.record_id} has an unknown authority "${a.authority}"`);
  }
  for (const l of links) {
    if (!byId.has(l.original_record_id)) problems.push(`a later outcome is for ${l.original_record_id}, which is not in this export`);
    if (!LINK_KINDS.includes(l.kind)) problems.push(`a later outcome has an unknown kind "${l.kind}"`);
    if (Number.isNaN(Date.parse(l.occurred_at))) problems.push('a later outcome has no usable time');
  }
  add('reconciliation: structure', problems.length === 0, problems.slice(0, 3).join('; '));

  // Each result against the destination record carried
  const destByKey = new Map(dests.map((d) => [`${d.source_id}|${d.external_id}`, d]));
  const inconsistent = [];
  let checked = 0;
  const notChecked = [];
  const unsupported = [];
  for (const r of results) {
    const rec = byId.get(r.record_id);
    if (!rec) continue;
    if (r.state === 'destination_confirmed' && !(r.destination_external_id && destByKey.has(`${r.destination_source}|${r.destination_external_id}`))) {
      unsupported.push(r.record_id);
      continue;
    }
    if (r.state !== 'destination_confirmed' && r.state !== 'conflicting') continue;
    const dest = r.destination_external_id ? destByKey.get(`${r.destination_source}|${r.destination_external_id}`) : null;
    if (!dest) { notChecked.push(`${r.record_id}: no destination record carried`); continue; }
    const { claim, unreadable } = claimOfRecord(rec);
    if (unreadable || !claim) { notChecked.push(`${r.record_id}: ${unreadable}`); continue; }
    checked += 1;
    const differs = claimDiffers(claim, dest);
    if (r.method === 'reference' && claim.destination_ref && claim.destination_ref !== dest.external_id) inconsistent.push(`${r.record_id}: matched by the cited refund id, but the claim cites ${claim.destination_ref} and the record carried is ${dest.external_id}`);
    else if (r.method === 'action_id' && claim.action_id && claim.action_id !== dest.action_id) inconsistent.push(`${r.record_id}: matched by action id, but the ids differ`);
    else if (r.state === 'destination_confirmed' && differs.length) inconsistent.push(`${r.record_id}: marked destination-confirmed, but the claim and the destination record differ in ${differs.join(', ')}`);
    else if (r.state === 'conflicting' && !differs.length && !(Array.isArray(r.duplicate_records) && r.duplicate_records.length > 1)) inconsistent.push(`${r.record_id}: marked conflicting, but the claim and the destination record agree`);
  }
  add('reconciliation: results consistent with the destination records carried', inconsistent.length === 0, inconsistent.slice(0, 3).join('; '));
  add('reconciliation: every confirmed result rests on a destination record carried', unsupported.length === 0, unsupported.slice(0, 3).map((id) => `${id}: no destination record`).join('; '));

  // Approvals: present, and whether each covers its action
  const wrong = [];
  let approvalsChecked = 0;
  const approvalsSkipped = [];
  for (const a of approvals) {
    const rec = byId.get(a.record_id);
    if (!rec) continue;
    const out = bindingAuthority(rec, a);
    if (out.skip) { approvalsSkipped.push(`${a.record_id}: ${out.skip}`); continue; }
    approvalsChecked += 1;
    if (out.authority !== a.authority) wrong.push(`${a.record_id}: the section says ${a.authority}, the record gives ${out.authority}`);
    else if ((a.path ?? 'normal') !== out.path) wrong.push(`${a.record_id}: the section says the approval path was ${a.path ?? 'normal'}, the record says ${out.path}`);
  }
  add('approval binding: results recompute from the records', wrong.length === 0, wrong.slice(0, 3).join('; '));

  // Later outcomes: separate from the action, never a change to it
  const linkProblems = links.filter((l) => l.later_record_id && !byId.has(l.later_record_id) && l.kind === 'retry').length;
  add('later outcomes: each retry names a record in this export', linkProblems === 0, linkProblems ? `${linkProblems} retr${linkProblems === 1 ? 'y names' : 'ies name'} a record that is not in the export` : '');

  const count = (s) => results.filter((r) => r.state === s).length;
  summary.results = results.length; summary.checked = checked; summary.approvals = approvals.length; summary.links = links.length;
  summary.lines.push(`reconciliation: ${results.length} result${results.length === 1 ? '' : 's'}: ${count('destination_confirmed')} destination-confirmed, ${count('conflicting')} conflicting, ${count('pending')} pending, ${count('unverified')} unverified, ${count('agent_reported')} agent-reported`);
  summary.lines.push(`  ${checked} checked against the destination record carried in the export${notChecked.length ? `; ${notChecked.length} could not be (${notChecked.slice(0, 2).join('; ')})` : ''}`);
  summary.lines.push(`  approvals: ${approvals.length} carried, ${approvalsChecked} recomputed from the record${approvalsSkipped.length ? `, ${approvalsSkipped.length} not (${approvalsSkipped[0]})` : ''}; later outcomes: ${links.length}`);
  summary.lines.push('  this does not show that the destination\'s record is true: it is the destination\'s own statement, carried and hashed, not vouched for.');
  return { checks, summary };
}

// ---- Cost statement (optional files, version 1.1): the figures added up from the cells --------------------------------------------------------
// A cost statement bundle carries statement/statement.json, statement/cells.json (every figure the totals are built from) and, optionally, statement/chargeback/*.csv.
// These checks appear only when statement/statement.json is listed in the manifest. They show that the stated totals are what the cells add up to. They do NOT show
// that the cells are the right figures: they are estimates frozen at close, from the organization's own price table.
export const STATEMENT_TOLERANCE = 0.0002; // dollars: figures are kept to four decimal places
const stNum = (v) => (v === null || v === undefined ? 0 : Number(v));
const stNear = (a, b) => Math.abs(stNum(a) - stNum(b)) < STATEMENT_TOLERANCE;
const stSum = (list, f) => list.reduce((acc, x) => acc + stNum(f(x)), 0);
const ST_DIMS = [['department', 'department', '(unallocated)'], ['cost_center', 'cost_center', '(unallocated)'], ['product', 'product', '(unallocated)'], ['agent_id', 'agent', '(no agent)']];

function stGroup(cells, keyOf) {
  const m = new Map();
  for (const c of cells) { const k = keyOf(c); const e = m.get(k) ?? { calls: 0, cost: 0, tokens_in: 0, tokens_out: 0 }; e.calls += stNum(c.calls); e.cost += stNum(c.cost_usd); e.tokens_in += stNum(c.tokens_in); e.tokens_out += stNum(c.tokens_out); m.set(k, e); }
  return m;
}
/** Whether rows (each with a label, calls and cost_usd) are exactly the groups of the cells, and add up to the stated total. */
function stRowsMatch(rows, groups, labelOf, total) {
  if (!Array.isArray(rows) || rows.length !== groups.size) return false;
  for (const r of rows) {
    const g = groups.get(labelOf(r));
    if (!g || stNum(r.calls) !== g.calls || !stNear(r.cost_usd, g.cost)) return false;
  }
  return stNear(stSum(rows, (r) => r.cost_usd), total);
}

export function verifyStatement(dir, { manifest }) {
  const listed = (manifest.files ?? []).map((f) => f.path);
  if (!listed.includes('statement/statement.json')) return { checks: [], summary: { present: false, lines: ['statement: this export carries no cost statement'] } };
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  let st; let cells;
  try {
    st = JSON.parse(fs.readFileSync(path.join(dir, 'statement/statement.json'), 'utf8'));
    cells = JSON.parse(fs.readFileSync(path.join(dir, 'statement/cells.json'), 'utf8'));
    if (!Array.isArray(cells) || !st.totals || !st.sections) throw new Error('statement.json or cells.json is not in the expected shape');
  } catch (e) {
    add('statement: files readable', false, e.message);
    return { checks, summary: { present: true, lines: [`statement: cannot be read (${e.message})`] } };
  }
  const total = st.totals.cost_usd;
  const cellsTotal = stSum(cells, (c) => c.cost_usd); const cellsCalls = stSum(cells, (c) => c.calls);
  add('statement: total equals the cells', stNear(cellsTotal, total) && cellsCalls === stNum(st.totals.calls), `${Math.round(cellsTotal * 10000) / 10000} from the cells, ${total} stated`);
  const byPm = stGroup(cells, (c) => `${c.provider || '(no provider)'}\u0000${c.model}`);
  const s1 = st.sections?.['1']?.by_provider_model;
  add('statement: totals by provider and model equal the cells', Array.isArray(s1) && s1.length === byPm.size && s1.every((r) => { const g = byPm.get(`${r.provider}\u0000${r.model}`); return g && stNum(r.calls) === g.calls && stNear(r.cost_usd, g.cost) && stNum(r.tokens_in) === g.tokens_in && stNum(r.tokens_out) === g.tokens_out; }) && stNear(stSum(s1, (r) => r.cost_usd), total));
  for (const [field, label, none] of ST_DIMS) {
    const rows = st.sections?.['3']?.[label];
    add(`statement: allocation by ${label} equals the cells and adds up to the total`, stRowsMatch(rows, stGroup(cells, (c) => c[field] || none), (r) => r[label], total));
  }
  add('statement: cover total equals the total', stNear(st.cover?.totals?.estimated_usd, total));
  const person = st.sections?.['3']?.person;
  if (person) add('statement: allocation by person adds up to the total', stNear(stSum(person.rows ?? [], (r) => r.cost_usd), total));
  const chargeback = listed.filter((f) => f.startsWith('statement/chargeback/'));
  if (chargeback.length) {
    let sum = 0; let readable = true;
    for (const f of chargeback) {
      try { const last = fs.readFileSync(path.join(dir, f), 'utf8').trim().split('\n').pop().split(','); sum += Number(last[last.length - 1]); } catch { readable = false; }
    }
    add('statement: chargeback files add up to the total', readable && stNear(sum, total), `${Math.round(sum * 10000) / 10000} across ${chargeback.length} files, ${total} stated`);
  }
  const failing = checks.filter((c) => !c.ok).length;
  return { checks, summary: { present: true, cells: cells.length, total_cost_usd: total, calls: st.totals.calls, failing, lines: [
    `statement: ${cells.length} cells add up to ${total} USD over ${st.totals.calls} calls${failing ? `; ${failing} check${failing === 1 ? '' : 's'} failed` : ''}`,
    'statement: the check shows the stated totals are what the cells add up to. It does not show the cells are right: they are estimates frozen at close from the organization\'s own price table, not an invoice, and the statement is not an audit.',
  ] } };
}

export function verifyExport(dir, { trustedKeys = null, emitterKeys = null, logKeys = null } = {}) {
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
  const tlog = verifyTransparency(dir, { manifestBytes: fs.readFileSync(path.join(dir, 'manifest.json')), logKeys });
  checks.push(...tlog.checks);
  const recon = verifyReconciliation(dir, { manifest, records });
  checks.push(...recon.checks);
  const decisions = verifyDecisionEvidence({ records });
  checks.push(...decisions.checks);
  const controlEv = verifyControlEvidence({ records });
  checks.push(...controlEv.checks);
  const statement = verifyStatement(dir, { manifest });
  checks.push(...statement.checks);
  return { ok: checks.every((c) => c.ok), authenticity, emitter_proof: proof.summary, transparency: tlog.summary, reconciliation: recon.summary, decision_evidence: decisions.summary, control_evidence: controlEv.summary, statement: statement.summary, caveats: CAVEATS, checks };
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const args = process.argv.slice(2);
  const keysAt = args.indexOf('--keys');
  const emitterKeysAt = args.indexOf('--emitter-keys');
  const logKeysAt = args.indexOf('--log-keys');
  const dir = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--keys' && args[i - 1] !== '--emitter-keys' && args[i - 1] !== '--log-keys');
  if (!dir) {
    console.error('usage: node verify-export.mjs <exportDir> [--keys provantix-export-keys.json] [--emitter-keys emitter-keys.pem|.json] [--log-keys provantix-log-keys.json] [--integrity-only] [--json]');
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
  let logKeys = null;
  if (logKeysAt >= 0) {
    try {
      const parsed = JSON.parse(fs.readFileSync(args[logKeysAt + 1], 'utf8'));
      logKeys = Array.isArray(parsed) ? parsed : parsed.keys;
      if (!Array.isArray(logKeys)) throw new Error('expected {"keys": [...]}');
    } catch (e) {
      console.error(`cannot read the log keys file: ${e.message}`);
      process.exit(2);
    }
  }
  let result;
  try {
    result = verifyExport(dir, { trustedKeys, emitterKeys, logKeys });
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
    if (result.transparency) for (const line of result.transparency.lines) console.log(line);
    if (result.reconciliation) for (const line of result.reconciliation.lines) console.log(line);
    if (result.decision_evidence && result.decision_evidence.present) for (const line of result.decision_evidence.lines) console.log(line);
    if (result.control_evidence && result.control_evidence.present) for (const line of result.control_evidence.lines) console.log(line);
    if (result.statement && result.statement.present) for (const line of result.statement.lines) console.log(line);
    console.log('\nWhat a pass never means:');
    for (const c of CAVEATS) console.log(`  - ${c}`);
    if (!result.ok) console.log('\nexport FAILED verification');
    else if (authentic) console.log('\nexport verified: consistent, and issued by Provantix');
    else console.log('\nexport is consistent with itself, but its authenticity is NOT established: this does not show Provantix issued it');
  }
  if (!result.ok) process.exit(1);
  process.exit(authentic || args.includes('--integrity-only') ? 0 : 3);
}
