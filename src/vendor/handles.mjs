// Human handles: pseudonymous, keyed by a secret the customer holds.
// Same person -> same handle inside one tenant. Without the key the handle reveals nothing.
// Spec: plan/02-data-model.md section 6.

import { createHmac, randomBytes } from 'node:crypto';

export function newHandleKey() {
  return randomBytes(32);
}

export function makeHandle(handleKey, identifier) {
  if (!Buffer.isBuffer(handleKey) || handleKey.length < 32) {
    throw new TypeError('handle key must be a Buffer of at least 32 bytes');
  }
  if (typeof identifier !== 'string' || identifier.trim() === '') {
    throw new TypeError('identifier must be a non-empty string');
  }
  const normalized = identifier.trim().toLowerCase();
  return 'hdl:' + createHmac('sha256', handleKey).update(normalized, 'utf8').digest('hex').slice(0, 16);
}
