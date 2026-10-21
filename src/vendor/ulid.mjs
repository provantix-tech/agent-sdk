// ULID: 26 characters, Crockford base32. 48-bit millisecond timestamp then 80 random bits.
// Lexicographic order equals creation order (to the millisecond).

import { randomBytes } from 'node:crypto';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function ulid(nowMs = Date.now()) {
  let time = '';
  let t = nowMs;
  for (let i = 0; i < 10; i++) {
    time = ALPHABET[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const rand = randomBytes(16);
  let randPart = '';
  for (let i = 0; i < 16; i++) {
    randPart += ALPHABET[rand[i] % 32];
  }
  return time + randPart;
}
