// RFC 3161 time-stamp tokens, with no dependencies: build a request for a SHA-256 digest, read the authority's answer, and check a token.
//
// What a token shows: the time-stamp authority (TSA) signed "this digest existed at <genTime>". Provantix anchors each signed log head with
// one, so the head is fixed in time by a party Provantix does not control, even if nobody was watching the log.
// What it does not show: that the log is complete or true, only that this head existed by that time.
//
// checkToken() verifies, in this file, with Node's crypto only:
//   1. the token is about this digest (the message imprint) and, when given, this request (the nonce);
//   2. the signed attributes bind the token's content (the message digest attribute equals the hash of the TSTInfo);
//   3. the signature over those attributes verifies under the signer certificate carried in the token;
//   4. that certificate is for time-stamping (extended key usage) and was valid at genTime.
// It does NOT check that the signer certificate chains to a root you trust, or that it was not revoked. That is a trust decision about the
// authority; do it with `openssl ts -verify -CAfile <the authority's roots>` (the docs give the steps). The result says so.

import { createHash, createVerify, randomBytes, X509Certificate } from 'node:crypto';

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

// ---- DER: building ----------------------------------------------------------------------------------------------------------------------

const lenBytes = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = []; let v = n;
  while (v > 0) { b.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), lenBytes(body.length), body]); };
const oidBytes = (oid) => {
  const p = oid.split('.').map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) { const s = [n & 0x7f]; let v = Math.floor(n / 128); while (v > 0) { s.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); } out.push(...s); }
  return Buffer.from(out);
};
const derInt = (buf) => { let b = Buffer.from(buf); while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };

// ---- request -----------------------------------------------------------------------------------------------------------------------------

/**
 * A TimeStampReq for a SHA-256 digest (a Buffer of 32 bytes), asking for the signer certificate to be included.
 * @returns {{ der: Buffer, nonce: Buffer }}
 */
export function buildTimestampRequest(digest, nonce = randomBytes(8)) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) throw new Error('a SHA-256 digest of 32 bytes is required');
  const n = Buffer.from(nonce); n[0] &= 0x7f; // keep the integer positive
  const imprint = tlv(0x30, tlv(0x30, tlv(0x06, oidBytes(OID_SHA256)), tlv(0x05)), tlv(0x04, digest));
  const der = tlv(0x30, derInt(Buffer.from([1])), imprint, derInt(n), tlv(0x01, Buffer.from([0xff])));
  return { der, nonce: n };
}

/** Read a TimeStampReq (what an authority does first): the digest to stamp and the nonce. Used by test authorities and by anyone building one. */
export function parseTimestampRequest(buf) {
  const req = read(buf, 0);
  const parts = children(buf, req); // version, messageImprint, [reqPolicy], [nonce], [certReq]
  const imprint = children(buf, parts[1]);
  const nonceNode = parts.slice(2).find((n) => n.tag === 0x02);
  return { digest: Buffer.from(imprint[1].value), nonce: nonceNode ? Buffer.from(nonceNode.value) : null, alg: oidOf(children(buf, imprint[0])[0]) };
}

// ---- response ----------------------------------------------------------------------------------------------------------------------------

const PKI_STATUS = ['granted', 'granted with modifications', 'rejection', 'waiting', 'revocation warning', 'revocation notification'];

/**
 * Read a TimeStampResp. Returns { granted, status, token } where `token` is the DER of the time-stamp token (a CMS ContentInfo) when granted.
 * Throws on something that is not a TimeStampResp.
 */
export function parseTimestampResponse(buf) {
  const resp = read(buf, 0);
  if (resp.tag !== 0x30) throw new Error('not a TimeStampResp');
  const [statusInfo, token] = children(buf, resp);
  if (!statusInfo || statusInfo.tag !== 0x30) throw new Error('not a TimeStampResp');
  const statusNode = read(buf, statusInfo.start);
  const status = Number(statusNode.value.readUIntBE(0, Math.min(6, statusNode.value.length)));
  const granted = status === 0 || status === 1;
  if (granted && !token) throw new Error('granted without a token');
  return { granted, status, status_text: PKI_STATUS[status] ?? `status ${status}`, token: granted ? Buffer.from(token.raw) : null };
}

/** The digest a head is stamped under: SHA-256 of its signed bytes (the canonical fields without the signature). */
export const headDigest = (headSigningBytes) => createHash('sha256').update(headSigningBytes).digest();

/** Ask an authority to stamp a digest. Never throws: returns { ok, token?, nonce, reason? } so a failure can be recorded and retried. */
export async function requestTimestamp(url, digest, { fetchImpl = fetch, timeoutMs = 15_000 } = {}) {
  const { der, nonce } = buildTimestampRequest(digest);
  try {
    const res = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' }, body: der, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { ok: false, nonce, reason: `the authority answered ${res.status}` };
    const parsed = parseTimestampResponse(Buffer.from(await res.arrayBuffer()));
    if (!parsed.granted) return { ok: false, nonce, reason: `the authority did not grant the stamp (${parsed.status_text})` };
    return { ok: true, token: parsed.token, nonce };
  } catch (e) {
    return { ok: false, nonce, reason: `the authority could not be reached or answered badly: ${String(e.message ?? e).slice(0, 200)}` };
  }
}

export { tlv as _tlv, oidBytes as _oidBytes, derInt as _derInt };
