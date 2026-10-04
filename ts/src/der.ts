// DER reader and X.509 certificate / CRL parser for AMD's ARK, ASK, VCEK, VLEK certificates and KDS CRLs.
import { fail, Fail } from './errors.ts';
import { copy, protect } from './bytes.ts';

interface Tlv {
  tag: number;
  /** offset of first content byte */
  start: number;
  /** offset one past last content byte */
  end: number;
  /** offset of the tag byte */
  at: number;
}

const TAG = { INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04, OID: 0x06, UTF8: 0x0c, SEQUENCE: 0x30, SET: 0x31,
  PRINTABLE: 0x13, IA5: 0x16, UTCTIME: 0x17, GENTIME: 0x18, BOOLEAN: 0x01, CTX0: 0xa0, CTX1: 0xa1, CTX2: 0xa2, CTX3: 0xa3 } as const;
export { TAG };

export function readTlv(b: Uint8Array, at: number, limit = b.length): Tlv {
  if (at + 2 > limit) fail('CERT_MALFORMED', 'DER: truncated header');
  const tag = b[at];
  if ((tag & 0x1f) === 0x1f) fail('CERT_MALFORMED', 'DER: multi-byte tags unsupported');
  let i = at + 1;
  let len = b[i++];
  if (len === 0x80) fail('CERT_MALFORMED', 'DER: indefinite length');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || i + n > limit) fail('CERT_MALFORMED', 'DER: bad length');
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + b[i++];
    if (len < 0x80 && n === 1) fail('CERT_MALFORMED', 'DER: non-minimal length');
  }
  if (i + len > limit) fail('CERT_MALFORMED', 'DER: content exceeds bounds');
  return { tag, start: i, end: i + len, at };
}

export function children(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let o = t.start;
  while (o < t.end) { const c = readTlv(b, o, t.end); out.push(c); o = c.end; }
  return out;
}

export function expect(t: Tlv, tag: number, what: string): Tlv {
  if (t.tag !== tag) fail('CERT_MALFORMED', `DER: ${what}: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
  return t;
}

export const raw = (b: Uint8Array, t: Tlv) => b.subarray(t.at, t.end);
export const content = (b: Uint8Array, t: Tlv) => b.subarray(t.start, t.end);

export function oidToString(b: Uint8Array, t: Tlv): string {
  expect(t, TAG.OID, 'OID');
  const c = content(b, t);
  if (c.length === 0) fail('CERT_MALFORMED', 'DER: empty OID');
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < c.length; i++) {
    v = v * 128 + (c[i] & 0x7f);
    if (!(c[i] & 0x80)) {
      if (parts.length === 0) { parts.push(Math.min(2, Math.floor(v / 40)), v - 40 * Math.min(2, Math.floor(v / 40))); }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

/** Small non-negative INTEGER (fits in a JS number). */
export function smallInt(b: Uint8Array, t: Tlv, what: string): number {
  expect(t, TAG.INTEGER, what);
  const c = content(b, t);
  if (c.length === 0 || c.length > 6) fail('CERT_MALFORMED', `DER: ${what}: bad integer length`);
  if (c[0] & 0x80) fail('CERT_MALFORMED', `DER: ${what}: negative integer`);
  let v = 0;
  for (const x of c) v = v * 256 + x;
  return v;
}

function parseTime(b: Uint8Array, t: Tlv): number {
  const s = String.fromCharCode(...content(b, t));
  let m: RegExpMatchArray | null;
  let year: number;
  if (t.tag === TAG.UTCTIME) {
    m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) fail('CERT_MALFORMED', `bad UTCTime ${s}`);
    year = parseInt(m[1], 10); year += year >= 50 ? 1900 : 2000;
  } else if (t.tag === TAG.GENTIME) {
    m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) fail('CERT_MALFORMED', `bad GeneralizedTime ${s}`);
    year = parseInt(m[1], 10);
  } else fail('CERT_MALFORMED', 'bad time tag');
  const month = +m[2], day = +m[3], hour = +m[4], minute = +m[5], second = +m[6];
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, 0);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day || d.getUTCHours() !== hour || d.getUTCMinutes() !== minute || d.getUTCSeconds() !== second)
    fail('CERT_MALFORMED', `invalid certificate time ${s}`);
  return d.getTime() / 1000;
}

/** Input size caps. AMD certificates are about 2 KiB, CRLs a few hundred bytes. */
export const MAX_CERT_BYTES = 16 * 1024;
export const MAX_CRL_BYTES = 1024 * 1024;

export interface Extension { oid: string; critical: boolean; value: Uint8Array /* content of the OCTET STRING */ }

export interface SignatureAlgorithm {
  oid: string;
  /** For RSASSA-PSS: parsed params. */
  pss?: { hash: 'SHA-256' | 'SHA-384' | 'SHA-512'; saltLength: number };
}

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  serial: Uint8Array;
  issuer: Uint8Array;   // raw Name DER
  subject: Uint8Array;  // raw Name DER
  subjectName: Name;
  /** Convenience: subjectName.cn */
  subjectCN: string;
  notBefore: number;    // unix seconds
  notAfter: number;
  spki: Uint8Array;     // raw SubjectPublicKeyInfo DER
  spkiAlgorithm: string; // OID
  spkiCurve?: string;    // OID, for EC keys
  signatureAlgorithm: SignatureAlgorithm;
  signature: Uint8Array; // raw signature bytes (BIT STRING content minus unused-bits byte)
  extensions: Map<string, Extension>;
}

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  p384: '1.3.132.0.34',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  mgf1: '1.2.840.113549.1.1.8',
  cn: '2.5.4.3',
  o: '2.5.4.10',
  ou: '2.5.4.11',
} as const;
export { OID };

function parseSigAlg(b: Uint8Array, t: Tlv): SignatureAlgorithm {
  expect(t, TAG.SEQUENCE, 'AlgorithmIdentifier');
  const [oidT, params] = children(b, t);
  const oid = oidToString(b, oidT);
  if (oid !== OID.rsassaPss) return { oid };
  if (!params) fail('CERT_ALGO_UNSUPPORTED', 'RSASSA-PSS without parameters');
  // RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength, [3] trailerField }
  let hash: 'SHA-256' | 'SHA-384' | 'SHA-512' | undefined;
  let saltLength = 20;
  let mgfHash = '';
  for (const p of children(b, params)) {
    const inner = children(b, p)[0];
    if (p.tag === TAG.CTX0) hash = hashName(oidToString(b, children(b, inner)[0]));
    else if (p.tag === TAG.CTX1) {
      const [mgfOid, mgfParams] = children(b, inner);
      if (oidToString(b, mgfOid) !== OID.mgf1) fail('CERT_ALGO_UNSUPPORTED', 'PSS MGF is not MGF1');
      mgfHash = hashName(oidToString(b, children(b, mgfParams)[0]));
    } else if (p.tag === TAG.CTX2) saltLength = smallInt(b, inner, 'saltLength');
    else if (p.tag === TAG.CTX3) { if (smallInt(b, inner, 'trailerField') !== 1) fail('CERT_ALGO_UNSUPPORTED', 'PSS trailerField'); }
  }
  if (!hash) fail('CERT_ALGO_UNSUPPORTED', 'PSS without explicit hash (SHA-1 default) is not accepted');
  if (mgfHash !== hash) fail('CERT_ALGO_UNSUPPORTED', 'PSS MGF1 must explicitly use the message hash');
  return { oid, pss: { hash, saltLength } };
}

function hashName(oid: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
  if (oid === OID.sha256) return 'SHA-256';
  if (oid === OID.sha384) return 'SHA-384';
  if (oid === OID.sha512) return 'SHA-512';
  return fail('CERT_ALGO_UNSUPPORTED', `unsupported hash OID ${oid}`);
}

export interface Name { cn: string; o: string; ou: string }

function parseName(b: Uint8Array, name: Tlv): Name {
  const out: Name = { cn: '', o: '', ou: '' };
  for (const rdn of children(b, name)) {
    for (const atv of children(b, rdn)) {
      const [oidT, val] = children(b, atv);
      const bytes = content(b, val);
      if (bytes.length > 4096) fail('CERT_MALFORMED', 'distinguished-name field too long');
      let str = '';
      for (const x of bytes) str += String.fromCharCode(x);
      const oid = oidToString(b, oidT);
      if (oid === OID.cn) out.cn = str; else if (oid === OID.o) out.o = str; else if (oid === OID.ou) out.ou = str;
    }
  }
  return out;
}

function bitStringContent(b: Uint8Array, t: Tlv): Uint8Array {
  expect(t, TAG.BIT_STRING, 'BIT STRING');
  if (b[t.start] !== 0) fail('CERT_MALFORMED', 'BIT STRING with unused bits');
  return b.subarray(t.start + 1, t.end);
}

function parseExtensions(b: Uint8Array, extsSeq: Tlv): Map<string, Extension> {
  const map = new Map<string, Extension>();
  for (const ext of children(b, expect(extsSeq, TAG.SEQUENCE, 'Extensions'))) {
    const parts = children(b, ext);
    const oid = oidToString(b, parts[0]);
    let critical = false;
    let i = 1;
    if (parts[i].tag === TAG.BOOLEAN) { critical = content(b, parts[i])[0] !== 0; i++; }
    const value = content(b, expect(parts[i], TAG.OCTET_STRING, 'extnValue'));
    if (map.has(oid)) fail('CERT_MALFORMED', `duplicate extension ${oid}`);
    map.set(oid, { oid, critical, value });
  }
  return map;
}

const sameAlg = (a: SignatureAlgorithm, b: SignatureAlgorithm) => a.oid === b.oid && a.pss?.hash === b.pss?.hash && a.pss?.saltLength === b.pss?.saltLength;

export function parseCertificate(der: Uint8Array): Certificate {
  if (der.length > MAX_CERT_BYTES) fail('CERT_MALFORMED', `certificate is ${der.length} bytes, limit ${MAX_CERT_BYTES}`);
  der = copy(der); // private copy; all views below point into it
  try {
  const cert = readTlv(der, 0);
  expect(cert, TAG.SEQUENCE, 'Certificate');
  if (cert.end !== der.length) fail('CERT_MALFORMED', 'trailing bytes after certificate');
  const [tbsT, sigAlgT, sigValT] = children(der, cert);
  if (!sigValT) fail('CERT_MALFORMED', 'Certificate: missing fields');
  expect(tbsT, TAG.SEQUENCE, 'TBSCertificate');
  const f = children(der, tbsT);
  let i = 0;
  if (f[0]?.tag === TAG.CTX0) { if (smallInt(der, children(der, f[0])[0], 'version') !== 2) fail('CERT_MALFORMED', 'not X.509 v3'); i = 1; }
  else fail('CERT_MALFORMED', 'not X.509 v3');
  const [serialT, tbsSigAlgT, issuerT, validityT, subjectT, spkiT, ...rest] = f.slice(i);
  if (!spkiT) fail('CERT_MALFORMED', 'TBSCertificate: missing fields');
  const [nbT, naT] = children(der, expect(validityT, TAG.SEQUENCE, 'Validity'));
  const spkiKids = children(der, expect(spkiT, TAG.SEQUENCE, 'SPKI'));
  const spkiAlgKids = children(der, expect(spkiKids[0], TAG.SEQUENCE, 'SPKI alg'));
  const spkiAlgorithm = oidToString(der, spkiAlgKids[0]);
  const spkiCurve = spkiAlgorithm === OID.ecPublicKey && spkiAlgKids[1]?.tag === TAG.OID ? oidToString(der, spkiAlgKids[1]) : undefined;
  const extT = rest.find(t => t.tag === TAG.CTX3);
  const sigAlg = parseSigAlg(der, sigAlgT);
  if (!sameAlg(sigAlg, parseSigAlg(der, tbsSigAlgT))) fail('CERT_MALFORMED', 'signatureAlgorithm mismatch between TBS and outer');
  const subjectName = parseName(der, subjectT);
  return protect({
    der,
    tbs: raw(der, tbsT),
    serial: content(der, expect(serialT, TAG.INTEGER, 'serialNumber')),
    issuer: raw(der, issuerT),
    subject: raw(der, subjectT),
    subjectName,
    subjectCN: subjectName.cn,
    notBefore: parseTime(der, nbT),
    notAfter: parseTime(der, naT),
    spki: raw(der, spkiT),
    spkiAlgorithm,
    spkiCurve,
    signatureAlgorithm: sigAlg,
    signature: bitStringContent(der, sigValT),
    extensions: extT ? parseExtensions(der, children(der, extT)[0]) : new Map(),
  });
  } catch (e) {
    if (e instanceof Fail) throw e;
    if (e instanceof TypeError || e instanceof RangeError) fail('CERT_MALFORMED', 'malformed certificate structure');
    throw e;
  }
}

export interface Crl {
  der: Uint8Array;
  tbs: Uint8Array;
  issuer: Uint8Array;
  thisUpdate: number;
  nextUpdate?: number;
  revokedSerials: Uint8Array[];
  extensions: Map<string, Extension>;
  signatureAlgorithm: SignatureAlgorithm;
  signature: Uint8Array;
}

export function parseCrl(der: Uint8Array): Crl {
  if (der.length > MAX_CRL_BYTES) fail('CRL_INVALID', `CRL is ${der.length} bytes, limit ${MAX_CRL_BYTES}`);
  der = copy(der);
  try {
  const crl = readTlv(der, 0);
  expect(crl, TAG.SEQUENCE, 'CertificateList');
  if (crl.end !== der.length) fail('CRL_INVALID', 'trailing bytes after CRL');
  const [tbsT, sigAlgT, sigValT] = children(der, crl);
  if (!sigValT) fail('CRL_INVALID', 'CRL: missing fields');
  const f = children(der, expect(tbsT, TAG.SEQUENCE, 'TBSCertList'));
  const i = f[0].tag === TAG.INTEGER ? 1 : 0; // optional version
  const issuerT = f[i + 1];
  const thisUpdateT = f[i + 2];
  if (!thisUpdateT) fail('CRL_INVALID', 'TBSCertList: missing fields');
  let j = i + 3;
  let nextUpdate: number | undefined;
  if (f[j] && (f[j].tag === TAG.UTCTIME || f[j].tag === TAG.GENTIME)) { nextUpdate = parseTime(der, f[j]); j++; }
  const revokedSerials: Uint8Array[] = [];
  if (f[j] && f[j].tag === TAG.SEQUENCE) {
    for (const entry of children(der, f[j])) revokedSerials.push(content(der, expect(children(der, entry)[0], TAG.INTEGER, 'revoked serial')));
    j++;
  }
  const extensions = f[j]?.tag === TAG.CTX0 ? parseExtensions(der, children(der, f[j])[0]) : new Map<string, Extension>();
  if (f[j]?.tag === TAG.CTX0) j++;
  if (j !== f.length) fail('CRL_INVALID', 'unexpected CRL fields');
  const signatureAlgorithm = parseSigAlg(der, sigAlgT);
  if (!sameAlg(signatureAlgorithm, parseSigAlg(der, f[i]))) fail('CRL_INVALID', 'signatureAlgorithm mismatch between TBS and outer');
  return protect({
    der,
    tbs: raw(der, tbsT),
    issuer: raw(der, issuerT),
    thisUpdate: parseTime(der, thisUpdateT),
    nextUpdate,
    revokedSerials,
    extensions,
    signatureAlgorithm,
    signature: bitStringContent(der, sigValT),
  });
  } catch (e) {
    if (e instanceof Fail) {
      if (e.violation.code === 'CERT_MALFORMED') fail('CRL_INVALID', e.violation.message);
      throw e;
    }
    if (e instanceof TypeError || e instanceof RangeError) fail('CRL_INVALID', 'malformed CRL structure');
    throw e;
  }
}
