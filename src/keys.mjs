// Key generation for the bring-your-own-key flow (round-2 review H3).
//
// Customers generate the emitter keypair on their side and register only the public key
// with the control plane (POST /api/emitters with public_key_pem) — the private key never
// exists on the server. The same generator backs the server-side fallback when customers
// opt for a generated key.

import { generateCollectorKeys } from '../../../ledger/packages/collector-core/src/batch.mjs';

export function generateEmitterKeys() {
  return generateCollectorKeys();
}
