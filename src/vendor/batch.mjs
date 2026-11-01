// Signed batch envelope shipped from a collector to ingest.
// Signature: ECDSA P-256 over canonical JSON of the envelope body (everything except signature).
// Digest: SHA-256 over canonical JSON of {records, rollups}, so the body is bound to its content.
//
// Batch seal (plan/24-per-record-emitter-proof.md): an optional second statement the emitter signs, holding
// only the hashes the records already commit to. It survives erasure because a record hash never contained an
// erased value, so an auditor can later check, with the emitter's public key alone, that the emitter vouched
// for exactly these records. The seal sits inside the envelope body, so the batch signature covers it and it
// cannot be moved to another envelope.

import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { canonicalize, sha256, hex } from './aar.mjs';

export const BATCH_VERSION = '1.0';
/** The envelope version of a batch that carries a seal. */
export const SEALED_BATCH_VERSION = '1.1';
export const SEAL_VERSION = 2;

export function generateCollectorKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

export function batchDigest(records, rollups) {
  return hex(sha256(Buffer.from(canonicalize({ records, rollups }), 'utf8')));
}

/** SHA-256 of the SPKI DER of a public key, hex: what names a key in a seal record and in an export. */
export function publicKeyFingerprint(publicKeyPem) {
  return hex(sha256(createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' })));
}

/** The statement an emitter signs: no erasable content, only record hashes and what binds them to one batch. */
export function buildSealStatement({ collectorId, batchSeq, createdAt, records, rollups }) {
  return {
    seal_version: SEAL_VERSION,
    collector_id: collectorId,
    batch_seq: batchSeq,
    created_at: createdAt,
    record_count: records.length,
    record_hashes: records.map((r) => r.integrity.record_hash),
    rollups_digest: hex(sha256(Buffer.from(canonicalize(rollups), 'utf8'))),
  };
}

/** `{ statement, signature }`: ECDSA P-256 over the canonical statement, base64. */
export function buildSeal(args, privateKeyPem) {
  const statement = buildSealStatement(args);
  return { statement, signature: sign('sha256', Buffer.from(canonicalize(statement), 'utf8'), privateKeyPem).toString('base64') };
}

/**
 * Check a seal against the envelope it came in and a public key. Never throws; the code is what ingest
 * records and what a verifier reports. Order matters only for the message: any failure rejects the batch.
 * @returns {{ ok: true } | { ok: false, code: 'seal_invalid', reason: string }}
 */
export function verifySeal(envelope, publicKeyPem) {
  const bad = (reason) => ({ ok: false, code: 'seal_invalid', reason });
  const seal = envelope?.seal;
  if (!seal || typeof seal !== 'object' || !seal.statement || typeof seal.signature !== 'string') return bad('the seal is missing its statement or signature');
  const st = seal.statement;
  if (st.seal_version !== SEAL_VERSION) return bad(`seal_version ${st.seal_version} is not supported`);
  for (const [key, field] of [['collector_id', 'collector_id'], ['batch_seq', 'batch_seq'], ['created_at', 'created_at'], ['record_count', 'record_count']]) {
    if (st[key] !== envelope[field]) return bad(`the seal's ${key} does not match the batch`);
  }
  const records = envelope.records;
  if (!Array.isArray(records) || !Array.isArray(st.record_hashes) || st.record_hashes.length !== records.length) return bad('the seal lists a different number of records than the batch holds');
  for (let i = 0; i < records.length; i += 1) {
    if (st.record_hashes[i] !== records[i]?.integrity?.record_hash) return bad(`record ${i} does not match the hash the emitter sealed`);
  }
  if (st.rollups_digest !== hex(sha256(Buffer.from(canonicalize(envelope.rollups), 'utf8')))) return bad('the rollups do not match the digest the emitter sealed');
  let valid = false;
  try { valid = verify('sha256', Buffer.from(canonicalize(st), 'utf8'), publicKeyPem, Buffer.from(seal.signature, 'base64')); } catch { valid = false; }
  return valid ? { ok: true } : bad('the seal signature does not verify with the emitter key');
}

/** `seal: true` adds the batch seal and moves the envelope to version 1.1; the default is unchanged. */
export function buildBatch({ collectorId, batchSeq, records, rollups, createdAt, privateKeyPem, seal = false }) {
  const body = {
    batch_version: seal ? SEALED_BATCH_VERSION : BATCH_VERSION,
    collector_id: collectorId,
    batch_seq: batchSeq,
    created_at: createdAt,
    record_count: records.length,
    batch_digest: batchDigest(records, rollups),
    rollups,
    records,
    ...(seal ? { seal: buildSeal({ collectorId, batchSeq, createdAt, records, rollups }, privateKeyPem) } : {}),
  };
  const signature = sign('sha256', Buffer.from(canonicalize(body), 'utf8'), privateKeyPem).toString('base64');
  return { ...body, signature };
}

export function verifyBatchSignature(envelope, publicKeyPem) {
  try {
    const { signature, ...body } = envelope;
    if (typeof signature !== 'string') return false;
    return verify('sha256', Buffer.from(canonicalize(body), 'utf8'), publicKeyPem, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Strictly validate a bring-your-own collector public key (round-2 review H3: customers can
 * register an emitter with a key the control plane never saw privately).
 * Throws with an actionable message unless the PEM is an ECDSA P-256 SPKI public key.
 */
export function parseCollectorPublicKeyPem(pem) {
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new Error('public_key_pem must be an SPKI PEM public key (-----BEGIN PUBLIC KEY-----)');
  }
  const key = createPublicKey(pem); // throws on malformed PEM
  const jwk = key.export({ format: 'jwk' });
  if (key.asymmetricKeyType !== 'ec' || jwk.crv !== 'P-256') {
    throw new Error('public key must be ECDSA P-256 (prime256v1), matching the batch signature scheme');
  }
  return pem;
}
