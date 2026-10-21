// Signed batch envelope shipped from a collector to ingest.
// Signature: ECDSA P-256 over canonical JSON of the envelope body (everything except signature).
// Digest: SHA-256 over canonical JSON of {records, rollups}, so the body is bound to its content.

import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { canonicalize, sha256, hex } from './aar.mjs';

export const BATCH_VERSION = '1.0';

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

export function buildBatch({ collectorId, batchSeq, records, rollups, createdAt, privateKeyPem }) {
  const body = {
    batch_version: BATCH_VERSION,
    collector_id: collectorId,
    batch_seq: batchSeq,
    created_at: createdAt,
    record_count: records.length,
    batch_digest: batchDigest(records, rollups),
    rollups,
    records,
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
