// Time-stamp tokens (PRO-19): the check agrees with a real authority's token, catches every way a token can be wrong, and says what it did not check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildTimestampRequest, parseTimestampRequest, parseTimestampResponse, checkToken, requestTimestamp } from '../rfc3161.mjs';
import { makeFakeTsa } from './fake-tsa.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const real = JSON.parse(fs.readFileSync(path.join(here, '..', 'vectors', 'anchors', 'digicert-2026-11-09.json'), 'utf8'));
const sha = (s) => createHash('sha256').update(s).digest();

test('a real token from DigiCert verifies against its digest, and says the chain was not checked here', () => {
  const r = checkToken(Buffer.from(real.token_base64, 'base64'), real.digest_sha256);
  assert.equal(r.ok, true, r.reasons.join('; '));
  assert.equal(r.gen_time, real.gen_time);
  assert.match(r.signer, /DigiCert/);
  assert.equal(r.chain_checked, false, 'trusting the authority is a separate step, and the result says so');
});

test('a real token is refused for another digest, with a flipped byte, and when truncated', () => {
  const token = Buffer.from(real.token_base64, 'base64');
  assert.match(checkToken(token, sha('another head')).reasons.join(), /different digest/);
  const flipped = Buffer.from(token); flipped[flipped.length - 5] ^= 1;
  assert.equal(checkToken(flipped, real.digest_sha256).ok, false);
  assert.equal(checkToken(token.subarray(0, 200), real.digest_sha256).ok, false, 'truncated');
  assert.equal(checkToken(Buffer.from('nonsense'), real.digest_sha256).ok, false, 'not DER at all');
});

test('a request round-trips, and a test authority answers it with a token that verifies', async () => {
  const digest = sha('a signed head');
  const { der, nonce } = buildTimestampRequest(digest);
  const parsed = parseTimestampRequest(der);
  assert.deepEqual([parsed.digest.toString('hex'), parsed.nonce.toString('hex'), parsed.alg], [digest.toString('hex'), nonce.toString('hex'), '2.16.840.1.101.3.4.2.1']);
  const tsa = makeFakeTsa({ now: () => new Date('2026-11-12T08:00:00Z') });
  const got = await requestTimestamp('https://tsa.example.test', digest, { fetchImpl: tsa.fetchImpl });
  assert.equal(got.ok, true);
  const r = checkToken(got.token, digest, { nonce: got.nonce });
  assert.deepEqual([r.ok, r.gen_time], [true, '2026-11-12T08:00:00.000Z']);
});

test('the ways a token can be wrong are each named: another request, no time-stamping certificate, expired certificate, another digest', async () => {
  const digest = sha('a signed head');
  const tsa = makeFakeTsa({ now: () => new Date('2026-11-12T08:00:00Z') });
  const token = tsa.stamp(digest, Buffer.from([1, 2, 3, 4]));
  assert.equal(checkToken(token, digest, { nonce: Buffer.from([1, 2, 3, 4]) }).ok, true);
  assert.match(checkToken(token, digest, { nonce: Buffer.from([9, 9, 9, 9]) }).reasons.join(), /different request/, 'a replayed answer to another request');
  assert.match(checkToken(makeFakeTsa({ eku: false }).stamp(digest), digest).reasons.join(), /not for time-stamping/);
  assert.match(checkToken(makeFakeTsa({ validTo: new Date('2026-01-01T00:00:00Z') }).stamp(digest, null, new Date('2026-11-12T00:00:00Z')), digest).reasons.join(), /outside the signer certificate/);
  assert.match(checkToken(tsa.stamp(sha('something else')), digest).reasons.join(), /different digest/);
  // a token signed by one key but carrying another authority's certificate does not verify
  const other = makeFakeTsa();
  const forged = Buffer.from(tsa.stamp(digest));
  const certA = tsa.cert; const certB = other.cert;
  const at = forged.indexOf(certA);
  assert.ok(at > 0, 'the token carries the authority certificate');
  assert.equal(certA.length, certB.length, 'two test certificates are the same size, so one can replace the other');
  certB.copy(forged, at);
  assert.match(checkToken(forged, digest).reasons.join(), /does not verify under the certificate/);
});

test('an authority that is down, refuses, answers with rubbish or stamps something else is reported, never thrown', async () => {
  const digest = sha('a signed head');
  const tsa = makeFakeTsa();
  tsa.setMode('down');
  assert.match((await requestTimestamp('https://tsa.example.test', digest, { fetchImpl: tsa.fetchImpl })).reason, /could not be reached/);
  tsa.setMode('refuse');
  assert.match((await requestTimestamp('https://tsa.example.test', digest, { fetchImpl: tsa.fetchImpl })).reason, /answered 503/);
  tsa.setMode('garbage');
  assert.match((await requestTimestamp('https://tsa.example.test', digest, { fetchImpl: tsa.fetchImpl })).reason, /answered badly/);
  tsa.setMode('wrong-digest');
  const answer = await requestTimestamp('https://tsa.example.test', digest, { fetchImpl: tsa.fetchImpl });
  assert.equal(answer.ok, true, 'the answer parses');
  assert.match(checkToken(answer.token, digest, { nonce: answer.nonce }).reasons.join(), /different digest/, 'and the check refuses it');
  assert.equal(parseTimestampResponse(Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02])).granted, false, 'a rejection status is not a stamp');
});
