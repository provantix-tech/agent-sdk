// A test time-stamp authority: builds real RFC 3161 tokens (CMS signed data, self-signed time-stamping certificate) for any digest, so the code
// that anchors a head and the code that checks the anchor are exercised in tests without a network. Not a real authority: its certificate is
// generated here and chains to nothing, which is exactly what checkToken says about every certificate ("chain not checked").
import { generateKeyPairSync, createSign, createHash } from 'node:crypto';
import { _tlv as tlv, _oidBytes as oidBytes, _derInt as derInt, parseTimestampRequest } from '../rfc3161.mjs';

const OID = {
  sha256: '2.16.840.1.101.3.4.2.1', rsaEnc: '1.2.840.113549.1.1.1', sha256Rsa: '1.2.840.113549.1.1.11', signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4', msgDigest: '1.2.840.113549.1.9.4', contentType: '1.2.840.113549.1.9.3', cn: '2.5.4.3', eku: '2.5.29.37', timeStamping: '1.3.6.1.5.5.7.3.8',
};
const oid = (o) => tlv(0x06, oidBytes(o));
const alg = (o) => tlv(0x30, oid(o), tlv(0x05));
const name = (cn) => tlv(0x30, tlv(0x31, tlv(0x30, oid(OID.cn), tlv(0x0c, Buffer.from(cn)))));
const utc = (d) => tlv(0x17, Buffer.from(`${d.toISOString().slice(2, 19).replace(/[-:T]/g, '')}Z`));
const gen = (d) => tlv(0x18, Buffer.from(`${d.toISOString().slice(0, 19).replace(/[-:T]/g, '')}Z`));

/**
 * @param {{ now?: () => Date, serial?: number, signWith?: object, eku?: boolean, validFrom?: Date, validTo?: Date, tamper?: (token: Buffer) => Buffer }} [opts]
 * @returns an authority: { fetchImpl, requests, setMode } where mode is 'ok' | 'down' | 'refuse' | 'wrong-digest' | 'garbage'
 */
export function makeFakeTsa({ now = () => new Date(), eku = true, validFrom = new Date('2020-01-01T00:00:00Z'), validTo = new Date('2040-01-01T00:00:00Z') } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const issuer = name('Test Time-Stamp Authority');
  const certSerial = Buffer.from([0x01, 0x23]);
  const tbs = tlv(0x30,
    tlv(0xa0, derInt(Buffer.from([2]))), derInt(certSerial), alg(OID.sha256Rsa), issuer,
    tlv(0x30, utc(validFrom), utc(validTo)), issuer, publicKey.export({ type: 'spki', format: 'der' }),
    ...(eku ? [tlv(0xa3, tlv(0x30, tlv(0x30, oid(OID.eku), tlv(0x01, Buffer.from([0xff])), tlv(0x04, tlv(0x30, oid(OID.timeStamping))))))] : []));
  const certSig = createSign('sha256').update(tbs).sign(privateKey);
  const cert = tlv(0x30, tbs, alg(OID.sha256Rsa), tlv(0x03, Buffer.from([0]), certSig));

  let mode = 'ok';
  let serial = 1000;
  const requests = [];

  const makeToken = (digest, nonce, genTime) => {
    const tst = tlv(0x30, derInt(Buffer.from([1])), oid('1.2.3.4.5'), tlv(0x30, alg(OID.sha256), tlv(0x04, digest)), derInt(Buffer.from([(serial >> 8) & 0x7f, serial & 0xff])), gen(genTime), ...(nonce ? [derInt(nonce)] : []));
    serial += 1;
    const attrs = [
      tlv(0x30, oid(OID.contentType), tlv(0x31, oid(OID.tstInfo))),
      tlv(0x30, oid(OID.msgDigest), tlv(0x31, tlv(0x04, createHash('sha256').update(tst).digest()))),
    ];
    const signedContent = Buffer.concat(attrs);
    const signature = createSign('sha256').update(tlv(0x31, signedContent)).sign(privateKey);
    const signerInfo = tlv(0x30, derInt(Buffer.from([1])), tlv(0x30, issuer, derInt(certSerial)), alg(OID.sha256), tlv(0xa0, signedContent), alg(OID.rsaEnc), tlv(0x04, signature));
    const signedData = tlv(0x30, derInt(Buffer.from([3])), tlv(0x31, alg(OID.sha256)), tlv(0x30, oid(OID.tstInfo), tlv(0xa0, tlv(0x04, tst))), tlv(0xa0, cert), tlv(0x31, signerInfo));
    return tlv(0x30, oid(OID.signedData), tlv(0xa0, signedData));
  };

  return {
    requests,
    setMode: (m) => { mode = m; },
    cert,
    /** Stamp this digest now, directly (for tests that need a token without going through a request). */
    stamp: (digest, nonce = null, genTime = now()) => makeToken(digest, nonce, genTime),
    fetchImpl: async (_url, init) => {
      requests.push(init.body);
      if (mode === 'down') throw new Error('connect ECONNREFUSED');
      if (mode === 'refuse') return new Response('busy', { status: 503 });
      if (mode === 'garbage') return new Response(Buffer.from('not a time-stamp response'), { status: 200 });
      const req = parseTimestampRequest(Buffer.from(init.body));
      const digest = mode === 'wrong-digest' ? createHash('sha256').update('something else').digest() : req.digest;
      const token = makeToken(digest, req.nonce, now());
      return new Response(tlv(0x30, tlv(0x30, derInt(Buffer.from([0]))), token), { status: 200 });
    },
  };
}
