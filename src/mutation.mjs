// Exact-change evidence for the SDK (PRO-37): say what production change an action made, so an approval for that exact change can be checked against it.
//
// An approval can state the environment, the resource, the operation and a digest of the proposed change (`authorization.binding`). The action's own record
// says what it actually changed, in its sealed extension: `ext: { mutation: buildMutation({ environment, resource, change }) }`. Provantix compares the two.
// The change itself is never kept: only its digest, so an approval can name the exact change without the record holding the change (a command, a diff, a
// payload that may carry secrets). The same function computes the digest on the approval side and the action side, so the two agree for the same change.
//
//   const change = { op: 'rollback', deploy: 41 };
//   const binding = { environment: 'production', resource: 'payments-api', operation: 'rollback', change_digest: changeDigest(change) };
//   // ... when the action runs:
//   buildAAR({ ..., authorization: { approval_id, approver, approved_at, binding }, ext: { mutation: buildMutation({ environment: 'production', resource: 'payments-api', change }) } });
//
// An emergency route is declared with `break_glass: true` in the binding. It is recorded as an emergency approval and is never shown as an ordinary one.

import { createHash } from 'node:crypto';

const MAX = 200;

/** JSON with object keys in a fixed order, so the same change always gives the same text. */
function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
}

/** The sha256 of a change, as lower-case hex. A string is hashed as it is; anything else as canonical JSON (keys sorted). */
export function changeDigest(change) {
  if (change === undefined) throw new TypeError('changeDigest needs the change to describe');
  const text = typeof change === 'string' ? change : canonical(change);
  return createHash('sha256').update(text).digest('hex');
}

const need = (v, name) => {
  if (typeof v !== 'string' || !v.trim()) throw new TypeError(`${name} is required`);
  if (v.length > MAX) throw new TypeError(`${name} is too long (up to ${MAX} characters)`);
  return v.trim();
};

/**
 * What an action changed, for its record's extension. Give the environment and the resource, and either the change (digested here, never kept) or a digest
 * you already have. Anything else is refused, so nothing but ids and a digest can be put on a record this way.
 */
export function buildMutation(a) {
  if (!a || typeof a !== 'object') throw new TypeError('a mutation needs its details');
  for (const k of Object.keys(a)) if (!['environment', 'resource', 'change', 'changeDigest'].includes(k)) throw new TypeError(`mutation: "${k}" is not accepted. Send the environment, the resource and the change (or its digest)`);
  const out = { environment: need(a.environment, 'environment'), resource: need(a.resource, 'resource') };
  if (a.change !== undefined && a.changeDigest !== undefined) throw new TypeError('give the change or its digest, not both');
  if (a.change !== undefined) out.change_digest = changeDigest(a.change);
  else if (a.changeDigest !== undefined) {
    if (!/^[0-9a-f]{64}$/i.test(String(a.changeDigest))) throw new TypeError('changeDigest must be a 64 character hex digest');
    out.change_digest = String(a.changeDigest).toLowerCase();
  }
  return out;
}
