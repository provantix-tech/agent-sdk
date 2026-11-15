#!/usr/bin/env node
// Mirror and check Provantix's public transparency log. Self-contained like verify-export.mjs: node:crypto and fetch only.
//
// Usage: node verify-log.mjs <baseUrl> [--keys provantix-log-keys.json] [--state mirror-state.json] [--json]
//   <baseUrl>  e.g. https://app.provantix.tech
//   --keys     the log's published public keys. Save them once and pass them each time: keys fetched from the same server on every
//              run are only as trustworthy as the server. Without --keys the run fetches them and says so.
//   --state    a file this tool reads and writes: every signed tree head you have seen, exactly as Provantix signed it. Run it on a
//              schedule (daily is enough). Each run fetches every entry, recomputes every hash and the tree root, checks the signed
//              head, and checks that every head you kept is signed by the log's key and is still the first part of the tree now. If the
//              log was rewritten, or entries were dropped, that check fails, and the signed head that no longer matches is written to
//              <state>.conflict.json: Provantix's own signature on what it published earlier, which you can hand to anyone.
//
// Exit code: 0 the log checks out (and adds the head to your state file), 1 a check failed (the log is inconsistent), 2 usage or
// network error.
//
// What this does and does not give you. It shows that, as far as you have watched, the log only grew and every head Provantix
// published is consistent with the one before. It cannot show what Provantix did before you started watching, or what it shows to
// someone else: the more independent mirrors keep their own state files, the harder it is to show different people different logs.

import { createHash, createPublicKey, createVerify, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import fs from 'node:fs';

const canonical = (v) => {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
};
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const leafHash = (entry) => sha(Buffer.from([0]), Buffer.from(canonical(entry), 'utf8')).toString('hex');

/** RFC 6962 Merkle tree hash of leaf hashes (hex). */
export function treeRoot(leaves) {
  const mth = (lo, hi) => {
    const n = hi - lo;
    if (n === 0) return sha();
    if (n === 1) return Buffer.from(leaves[lo], 'hex');
    let k = 1; while (k * 2 < n) k *= 2;
    return sha(Buffer.from([1]), mth(lo, lo + k), mth(lo + k, hi));
  };
  return mth(0, leaves.length).toString('hex');
}

const headBytes = (h) => Buffer.from(canonical({ version: h.version, log_id: h.log_id, tree_size: h.tree_size, root_hash: h.root_hash, timestamp: h.timestamp, key_id: h.key_id }), 'utf8');

const headSignatureOk = (h, keys) => {
  const key = keys.find((k) => k.key_id === h.key_id);
  if (!key || !h.signature) return false;
  try { return cryptoVerify(null, headBytes(h), createPublicKey(key.public_key_pem), Buffer.from(h.signature, 'base64')); } catch { return false; }
};

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

/**
 * Check a log from its entries. Pure: no network, so it can be tested and reused.
 * @param {{ head: object, entries: {seq: number, leaf: object, leaf_hash: string}[], keys: object[]|null, previous: {tree_size: number, root_hash: string}|null, retained?: object[] }} input
 *   `retained` is every signed head kept from earlier runs. `previous` is the unsigned head an older state file kept.
 * @returns {{ ok: boolean, checks: {name: string, ok: boolean, detail: string}[], evidence: object[] }}
 *   `evidence` lists each kept signed head that the entries no longer produce, with the root they produce now.
 */
export function checkLog({ head, entries, keys, previous, retained = [] }) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });

  const contiguous = entries.length === head.tree_size && entries.every((e, i) => e.seq === i);
  add('entries are complete and in order', contiguous, contiguous ? `${entries.length} entries` : `got ${entries.length} entries for a head of ${head.tree_size}, or a gap in the numbering`);
  const hashesOk = entries.every((e) => leafHash(e.leaf) === e.leaf_hash);
  add('every entry hashes to its stated leaf hash', hashesOk);
  const root = treeRoot(entries.slice(0, head.tree_size).map((e) => e.leaf_hash));
  add('recomputed tree root matches the head', root === head.root_hash, root === head.root_hash ? '' : 'the entries do not produce the root Provantix signed');

  if (keys) {
    const key = keys.find((k) => k.key_id === head.key_id);
    let ok = false;
    if (key) { try { ok = cryptoVerify(null, headBytes(head), createPublicKey(key.public_key_pem), Buffer.from(head.signature, 'base64')); } catch { ok = false; } }
    add('tree head signature', ok, ok ? `signed by ${head.key_id} at ${head.timestamp}` : key ? 'the signature does not verify' : `no key ${head.key_id} in the keys`);
  }
  if (previous) {
    if (previous.tree_size > head.tree_size) {
      add('the log only grew since your last run', false, `your saved head covered ${previous.tree_size} entries; the log now has ${head.tree_size}: entries were removed`);
    } else {
      const prefix = treeRoot(entries.slice(0, previous.tree_size).map((e) => e.leaf_hash));
      const same = prefix === previous.root_hash;
      add('the log only grew since your last run', same, same ? `the ${previous.tree_size} entries you saw last time are unchanged` : 'the first entries no longer produce the head you saw before: history was rewritten');
    }
  }
  const evidence = [];
  if (retained.length) {
    if (keys) {
      const unsigned = retained.filter((h) => !headSignatureOk(h, keys));
      add('every head you kept is signed by the log\'s key', unsigned.length === 0,
        unsigned.length === 0 ? `${retained.length} signed head${retained.length === 1 ? '' : 's'} kept` : `${unsigned.length} of the heads in your state file do not verify against the keys (a damaged file, or not this log's keys)`);
    }
    for (const h of retained) {
      if (h.tree_size > head.tree_size) { evidence.push({ retained_head: h, entries_now: head.tree_size, reason: 'the log now has fewer entries than this head committed to' }); continue; }
      const prefix = treeRoot(entries.slice(0, h.tree_size).map((e) => e.leaf_hash));
      if (prefix !== h.root_hash) evidence.push({ retained_head: h, root_now: prefix, reason: 'the first entries no longer produce the root this head committed to' });
    }
    add('every head you kept is still the start of the log', evidence.length === 0,
      evidence.length === 0 ? `all ${retained.length} unchanged` : `${evidence.length} of ${retained.length} no longer match: history was rewritten or entries were dropped`);
  }
  // Outside time-stamps on the heads, where Provantix has attached them. Absent is "not anchored", never a failure; present and wrong is.
  const all = [head, ...retained.filter((h) => h.tree_size !== head.tree_size || h.root_hash !== head.root_hash)];
  const states = all.map((h) => ({ tree_size: h.tree_size, ...anchorState(h, headBytes(h)) }));
  const anchored = states.filter((s) => s.state === 'anchored');
  const invalid = states.filter((s) => s.state === 'invalid');
  if (anchored.length || invalid.length) {
    add('outside time-stamps on the heads verify', invalid.length === 0,
      invalid.length === 0 ? `${anchored.length} of ${states.length} head${states.length === 1 ? '' : 's'} carry one (earliest ${anchored.map((s) => s.gen_time).sort()[0]}); the others are not anchored` : `head ${invalid[0].tree_size}: ${invalid[0].text}`);
  }
  return { ok: checks.every((c) => c.ok), checks, evidence, anchors: { total: states.length, anchored: anchored.length, not_anchored: states.length - anchored.length - invalid.length, invalid: invalid.length, latest: states[0] } };
}

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.json();
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
  const base = args.find((a, i) => !a.startsWith('--') && !['--keys', '--state'].includes(args[i - 1]));
  if (!base) {
    console.error('usage: node verify-log.mjs <baseUrl> [--keys provantix-log-keys.json] [--state mirror-state.json] [--json]');
    process.exit(2);
  }
  const root = `${base.replace(/\/+$/, '')}/.well-known/provantix-log`;
  let head; let entries = []; let keys;
  let keysFrom = 'the file you passed';
  try {
    head = await getJson(`${root}/sth`);
    for (let from = 0; from < head.tree_size; from = entries.length) {
      const page = await getJson(`${root}/entries?from=${from}&to=${Math.min(head.tree_size, from + 1000)}`);
      if (!page.entries.length) break;
      entries.push(...page.entries);
    }
    if (opt('--keys')) keys = JSON.parse(fs.readFileSync(opt('--keys'), 'utf8')).keys;
    else { keys = (await getJson(`${base.replace(/\/+$/, '')}/.well-known/provantix-log-keys.json`)).keys; keysFrom = 'the same server (pass --keys with keys you saved earlier to avoid trusting it for them)'; }
  } catch (e) {
    console.error(`cannot read the log: ${e.message}`);
    process.exit(2);
  }
  let previous = null; let retained = []; let stateLogId = null;
  const stateFile = opt('--state');
  if (stateFile && fs.existsSync(stateFile)) {
    try {
      const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      stateLogId = state.log_id ?? null;
      if (Array.isArray(state.heads)) retained = state.heads;
      else if (state.head) previous = state.head; // an older state file: the head without its signature
    } catch { console.error('cannot read the state file'); process.exit(2); }
  }
  // Time-stamps are attached to a head after it is signed, so a head you kept earlier may have been anchored since. Pick those up.
  try {
    const served = [];
    for (let from = 0; ;) {
      const page = (await getJson(`${root}/heads?from=${from}&limit=1000`)).heads ?? [];
      served.push(...page);
      if (page.length < 1000) break;
      from = page.at(-1).tree_size + 1;
    }
    const bySize = new Map(served.map((h) => [h.tree_size, h]));
    const refresh = (h) => { const s = bySize.get(h.tree_size); return s && s.root_hash === h.root_hash && s.signature === h.signature && s.anchor?.token && !h.anchor?.token ? { ...h, anchor: s.anchor } : h; };
    retained = retained.map(refresh);
    head = refresh(head);
  } catch { /* the heads listing is optional: without it, anchors on heads you already hold are simply not refreshed */ }
  const result = checkLog({ head, entries, keys, previous, retained });
  // A different log id is a different log, not a later state of the one you were watching.
  if (stateLogId && stateLogId !== head.log_id) {
    result.checks.push({ name: 'this is the log your state file was started on', ok: false, detail: `your state file is for ${stateLogId}; the server now reports ${head.log_id}` });
    result.ok = false;
  }
  if (result.ok && stateFile) {
    // Keep the head exactly as signed, so what you hold is Provantix's own signature and not only your word for it.
    const kept = retained.some((h) => h.tree_size === head.tree_size && h.root_hash === head.root_hash) ? retained : [...retained, head];
    fs.writeFileSync(stateFile, JSON.stringify({ version: 2, log_id: head.log_id, saved_at: new Date().toISOString(), heads: kept }, null, 2));
  }
  let conflictFile = null;
  if (!result.ok && stateFile && result.evidence.length) {
    conflictFile = `${stateFile}.conflict.json`;
    fs.writeFileSync(conflictFile, JSON.stringify({ log_id: head.log_id, found_at: new Date().toISOString(), what: 'Signed tree heads Provantix published earlier that the log it serves now no longer matches. Each retained_head carries Provantix\'s signature.', current_head: head, evidence: result.evidence }, null, 2));
  }
  if (args.includes('--json')) console.log(JSON.stringify({ ...result, head, keys_from: keysFrom, conflict_file: conflictFile }, null, 2));
  else {
    for (const c of result.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
    if (result.anchors.anchored || result.anchors.invalid) console.log(`\noutside time-stamps: ${result.anchors.anchored} of ${result.anchors.total} head${result.anchors.total === 1 ? '' : 's'} anchored${result.anchors.not_anchored ? `, ${result.anchors.not_anchored} not anchored` : ''}${result.anchors.invalid ? `, ${result.anchors.invalid} INVALID` : ''}. A time-stamp shows when a head existed, not that the log is complete or true.`);
    else console.log('\noutside time-stamps: not anchored (the log does not carry one on its heads yet)');
    console.log(`\nlog ${head.log_id}: ${head.tree_size} entries, head signed ${head.timestamp}; keys from ${keysFrom}`);
    console.log(previous || retained.length ? `${retained.length} earlier head${retained.length === 1 ? '' : 's'} kept in your state file` : 'no earlier state: this run starts your record. Run it again later with the same --state to catch a rewrite.');
    if (conflictFile) console.log(`signed evidence of the mismatch written to ${conflictFile}`);
    console.log(result.ok ? 'the log checks out' : 'THE LOG FAILED A CHECK');
  }
  process.exit(result.ok ? 0 : 1);
}

import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
