// Integrity primitives: field commitments, Merkle root, record hash, erasure.
// Design: plan/02-data-model.md sections 1.3 and 8.
//
// A stored record is split into:
//   fields    - non-erasable fields (ids, actions, timestamps, counts). Hashed in plain.
//   erasable  - personal or content fields. Each value lives with its salt.
//   commitments - SHA-256(salt || canonical(value)) per erasable field, in a fixed order.
//
// record_hash = SHA-256( canonical(fields) + "|" + merkleRoot(commitments in fixed order) )
//
// Erasure removes the value and the salt and keeps the commitment, so the hash still verifies.

import { createHash, randomBytes } from 'node:crypto';
import { canonicalize } from './canonical.mjs';

// Fixed order matters: it defines the Merkle leaves. Never reorder; add new fields at the end
// with a schema version bump.
export const ERASABLE_FIELDS = Object.freeze([
  'on_behalf_of',
  'delegation_chain',
  'input_summary',
  'output_summary',
  'attribution_evidence',
  'ext',
  'user_agent',
]);

const EMPTY_HASH = createHash('sha256').update('').digest();

export function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

export function hex(buf) {
  return Buffer.from(buf).toString('hex');
}

export function newSalt() {
  return randomBytes(16);
}

// commitment = SHA-256(salt || canonical(value)). Salt is 16 bytes.
export function commit(salt, value) {
  if (!Buffer.isBuffer(salt) || salt.length !== 16) {
    throw new TypeError('commit: salt must be 16 bytes');
  }
  return sha256(Buffer.concat([salt, Buffer.from(canonicalize(value), 'utf8')]));
}

// Merkle root over an ordered list of 32-byte leaves.
// Pairs are hashed left||right; an odd node is paired with itself.
export function merkleRoot(leaves) {
  if (leaves.length === 0) return EMPTY_HASH;
  let level = leaves.map((l) => Buffer.from(l));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256(Buffer.concat([left, right])));
    }
    level = next;
  }
  return level[0];
}

export function recordHash(fields, commitments) {
  const leaves = ERASABLE_FIELDS.map((f) => {
    const c = commitments[f];
    if (!c) throw new Error(`recordHash: missing commitment for ${f}`);
    return Buffer.from(c, 'hex');
  });
  const root = merkleRoot(leaves);
  return sha256(Buffer.concat([Buffer.from(canonicalize(fields), 'utf8'), Buffer.from('|'), root]));
}

// Build a stored record from non-erasable fields and erasable values.
// Missing erasable fields are stored as null (explicit absence, still committed).
export function sealRecord(callerFields, callerErasable, saltFn = newSalt) {
  // Copy inputs so later changes by the caller cannot alter the sealed record.
  const fields = structuredClone(callerFields);
  const erasableValues = structuredClone(callerErasable);
  const erasable = {};
  const commitments = {};
  for (const f of ERASABLE_FIELDS) {
    const value = erasableValues[f] === undefined ? null : erasableValues[f];
    const salt = saltFn();
    erasable[f] = { value, salt: salt.toString('hex') };
    commitments[f] = hex(commit(salt, value));
  }
  const hash = hex(recordHash(fields, commitments));
  return {
    fields,
    erasable,
    integrity: { record_hash: hash, commitments },
  };
}

// Erase one erasable field: drop the value and the salt, keep the commitment.
export function eraseField(stored, field, erasedAt) {
  if (!ERASABLE_FIELDS.includes(field)) {
    throw new Error(`eraseField: ${field} is not erasable`);
  }
  const next = structuredClone(stored);
  next.erasable[field] = { erased: true, erased_at: erasedAt };
  return next;
}

// Recompute everything from what is stored. Returns { valid, reasons }.
export function verifyRecord(stored) {
  const reasons = [];
  const commitments = {};
  for (const f of ERASABLE_FIELDS) {
    const entry = stored.erasable[f];
    const claimed = stored.integrity.commitments[f];
    if (!entry || !claimed) {
      reasons.push(`missing ${f}`);
      continue;
    }
    commitments[f] = claimed;
    if (entry.erased) continue;
    const salt = Buffer.from(entry.salt, 'hex');
    const recomputed = hex(commit(salt, entry.value));
    if (recomputed !== claimed) reasons.push(`commitment mismatch on ${f}`);
  }
  if (reasons.length === 0) {
    const hash = hex(recordHash(stored.fields, commitments));
    if (hash !== stored.integrity.record_hash) reasons.push('record_hash mismatch');
  }
  return { valid: reasons.length === 0, reasons };
}

// Hash chain link: chain_seq positions within (tenant, connector_instance, ingest_day).
export function chainLink(prevRecordHash, record) {
  return hex(sha256(Buffer.concat([
    prevRecordHash ? Buffer.from(prevRecordHash, 'hex') : Buffer.alloc(32),
    Buffer.from(record.integrity.record_hash, 'hex'),
  ])));
}
