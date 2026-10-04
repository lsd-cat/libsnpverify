// AMD endorsement chain: ARK (pinned) -> ASK/ASVK -> VCEK/VLEK. VCEK extension parsing (57230). Optional CRL.
import { fail, stageAsync, type Result } from './errors.ts';
import { children, content, expect, parseCertificate, parseCrl, readTlv, smallInt, TAG, OID, MAX_CERT_BYTES, MAX_CRL_BYTES, type Certificate } from './der.ts';
import type { CryptoProvider } from './crypto.ts';
import { copy, equal, hex, protect } from './bytes.ts';
import { embeddedRoots } from './roots.ts';
import { PRODUCTS, productFromName } from './products.ts';
import type { Product, SigningKey, TcbVersion } from './report.ts';

const KDS = {
  structVersion: '1.3.6.1.4.1.3704.1.1', productName: '1.3.6.1.4.1.3704.1.2',
  bl: '1.3.6.1.4.1.3704.1.3.1', tee: '1.3.6.1.4.1.3704.1.3.2', snp: '1.3.6.1.4.1.3704.1.3.3', spl4: '1.3.6.1.4.1.3704.1.3.4',
  spl5: '1.3.6.1.4.1.3704.1.3.5', spl6: '1.3.6.1.4.1.3704.1.3.6', spl7: '1.3.6.1.4.1.3704.1.3.7', ucode: '1.3.6.1.4.1.3704.1.3.8',
  fmc: '1.3.6.1.4.1.3704.1.3.9', hwid: '1.3.6.1.4.1.3704.1.4', cspId: '1.3.6.1.4.1.3704.1.5',
} as const;

export interface EndorsementKey {
  kind: SigningKey;
  product: Product;
  productName: string;          // e.g. "Genoa-B2"
  hwid?: Uint8Array;            // VCEK: 64 (Milan/Genoa) or 8 (Turin)
  cspId?: string;               // VLEK
  tcb: TcbVersion;
  cert: Certificate;
}

export interface ChainInput {
  leaf: Uint8Array;             // VCEK or VLEK, DER
  intermediate?: Uint8Array;    // ASK or ASVK, DER; default embedded for the leaf's product
  root?: Uint8Array;            // ARK, DER; default embedded
  crl?: Uint8Array;             // DER, ARK-signed
  now: number;                  // unix seconds
}

export interface CrlInfo { thisUpdate: number; nextUpdate?: number; revokedCount: number }
export interface Chain { leaf: EndorsementKey; intermediate: Certificate; root: Certificate; crl?: CrlInfo }

function extInt(cert: Certificate, oid: string, what: string): number {
  const e = cert.extensions.get(oid) ?? fail('VCEK_EXTENSION_INVALID', `missing ${what} extension`);
  const t = readTlv(e.value, 0);
  if (t.end !== e.value.length) fail('VCEK_EXTENSION_INVALID', `${what}: trailing bytes`);
  const v = smallInt(e.value, t, what);
  if (v > 255) fail('VCEK_EXTENSION_INVALID', `${what} out of range`);
  return v;
}

function extString(cert: Certificate, oid: string, what: string): string | undefined {
  const e = cert.extensions.get(oid);
  if (!e) return undefined;
  const t = readTlv(e.value, 0);
  if (t.tag !== TAG.IA5 && t.tag !== TAG.UTF8 && t.tag !== TAG.PRINTABLE) fail('VCEK_EXTENSION_INVALID', `${what}: not a string`);
  const value = content(e.value, t);
  if (value.length > 4096 || value.some(x => x > 0x7f)) fail('VCEK_EXTENSION_INVALID', `${what}: invalid ASCII`);
  let out = '';
  for (const x of value) out += String.fromCharCode(x);
  return out;
}

/** Parse the AMD extensions of a VCEK/VLEK. KDS emits HWID either raw or wrapped in an OCTET STRING. */
export function parseEndorsementKey(cert: Certificate): EndorsementKey {
  const productName = extString(cert, KDS.productName, 'productName') ?? fail('VCEK_EXTENSION_INVALID', 'missing productName extension');
  const product = productFromName(productName) ?? fail('VCEK_EXTENSION_INVALID', `unknown product "${productName}"`);
  const info = PRODUCTS[product];
  const structVersion = extInt(cert, KDS.structVersion, 'structVersion');
  if (structVersion !== info.structVersion) fail('VCEK_EXTENSION_INVALID', `structVersion ${structVersion} does not match ${product}`);

  const hwidExt = cert.extensions.get(KDS.hwid);
  const cspId = extString(cert, KDS.cspId, 'cspId');
  if (hwidExt && cspId !== undefined) fail('VCEK_EXTENSION_INVALID', 'certificate has both HWID and CSP_ID');
  if (!hwidExt && cspId === undefined) fail('VCEK_EXTENSION_INVALID', 'certificate has neither HWID (VCEK) nor CSP_ID (VLEK)');
  let hwid: Uint8Array | undefined;
  if (hwidExt) {
    hwid = hwidExt.value;
    if (hwid.length !== info.hwidLength && hwid[0] === TAG.OCTET_STRING) hwid = content(hwid, expect(readTlv(hwid, 0), TAG.OCTET_STRING, 'HWID'));
    if (hwid.length !== info.hwidLength) fail('VCEK_EXTENSION_INVALID', `HWID is ${hwid.length} bytes, want ${info.hwidLength}`);
  }

  const tcb: TcbVersion = { bootloader: extInt(cert, KDS.bl, 'blSPL'), tee: extInt(cert, KDS.tee, 'teeSPL'), snp: extInt(cert, KDS.snp, 'snpSPL'), microcode: extInt(cert, KDS.ucode, 'ucodeSPL') };
  for (const [oid, what] of [[KDS.spl5, 'spl5'], [KDS.spl6, 'spl6'], [KDS.spl7, 'spl7']] as const) if (extInt(cert, oid, what) !== 0) fail('VCEK_EXTENSION_INVALID', `${what} must be 0`);
  if (info.tcbLayout === 'v0') {
    if (cert.extensions.has(KDS.fmc)) fail('VCEK_EXTENSION_INVALID', 'fmcSPL not valid for this product');
    if (extInt(cert, KDS.spl4, 'spl4') !== 0) fail('VCEK_EXTENSION_INVALID', 'spl4 must be 0');
  } else {
    if (cert.extensions.has(KDS.spl4)) fail('VCEK_EXTENSION_INVALID', 'spl4 not valid for this product');
    tcb.fmc = extInt(cert, KDS.fmc, 'fmcSPL');
  }
  const kind: SigningKey = hwid ? 'VCEK' : 'VLEK';
  if (!cert.subjectCN.startsWith(`SEV-${kind}`)) fail('VCEK_EXTENSION_INVALID', `leaf CN "${cert.subjectCN}" is not SEV-${kind}`);
  return protect({ kind, product, productName, hwid, cspId, tcb, cert });
}

const iso = (t: number) => new Date(t * 1000).toISOString().substring(0, 19) + 'Z';

function checkValidity(cert: Certificate, now: number, what: string): void {
  if (now < cert.notBefore) fail('CERT_NOT_YET_VALID', `${what} not valid before ${iso(cert.notBefore)}`);
  if (now > cert.notAfter) fail('CERT_EXPIRED', `${what} expired at ${iso(cert.notAfter)}`);
}

function checkCertificatePurpose(cert: Certificate, ca: boolean): void {
  for (const ext of cert.extensions.values())
    if (ext.critical && ext.oid !== '2.5.29.19' && ext.oid !== '2.5.29.15') fail('CERT_MALFORMED', `unsupported critical certificate extension ${ext.oid}`);
  const constraints = cert.extensions.get('2.5.29.19');
  if (ca && !constraints) fail('CERT_MALFORMED', 'CA certificate lacks basicConstraints');
  if (constraints) {
    const t = expect(readTlv(constraints.value, 0), TAG.SEQUENCE, 'basicConstraints');
    if (t.end !== constraints.value.length) fail('CERT_MALFORMED', 'basicConstraints trailing bytes');
    const fields = children(constraints.value, t);
    const isCa = fields[0]?.tag === TAG.BOOLEAN && content(constraints.value, fields[0]).length === 1 && content(constraints.value, fields[0])[0] === 0xff;
    if (ca !== isCa) fail('CERT_MALFORMED', `basicConstraints CA=${isCa} is wrong for ${ca ? 'issuer' : 'leaf'}`);
  }
  const ku = keyUsageBits(cert);
  if (ku !== undefined && !(ku & (ca ? 0x04 : 0x80))) fail('CERT_MALFORMED', `keyUsage does not permit ${ca ? 'certificate signing' : 'digital signing'}`);
}

/** First keyUsage byte, or undefined when the extension is absent. */
function keyUsageBits(cert: Certificate): number | undefined {
  const e = cert.extensions.get('2.5.29.15');
  if (!e) return undefined;
  const t = expect(readTlv(e.value, 0), TAG.BIT_STRING, 'keyUsage');
  if (t.end !== e.value.length || t.end - t.start < 2) fail('CERT_MALFORMED', 'invalid keyUsage');
  return e.value[t.start + 1];
}

async function signedBy(crypto: CryptoProvider, signed: { signatureAlgorithm: Certificate['signatureAlgorithm']; signature: Uint8Array; tbs: Uint8Array }, issuer: Certificate): Promise<boolean> {
  const alg = signed.signatureAlgorithm;
  if (alg.oid !== OID.rsassaPss || !alg.pss) fail('CERT_ALGO_UNSUPPORTED', `signature algorithm ${alg.oid}`);
  if (alg.pss.hash !== 'SHA-384' || alg.pss.saltLength !== 48) fail('CERT_ALGO_UNSUPPORTED', 'RSASSA-PSS must use SHA-384 with salt length 48');
  if (issuer.spkiAlgorithm !== OID.rsaEncryption) fail('CERT_ALGO_UNSUPPORTED', 'issuer key is not RSA');
  return crypto.verifyRsaPss(issuer.spki, signed.tbs, signed.signature, 48);
}

/**
 * Verify the chain. `trustedRoots` must contain a DER byte-equal to the root used (default: embedded ARK of the leaf's product).
 */
export function verifyChain(callerInput: ChainInput, trustedRoots: Uint8Array[] | undefined, crypto: CryptoProvider): Promise<Result<Chain>> {
  return stageAsync(async () => {
    // Check sizes, then copy every input before the first await.
    checkCollateralSizes(callerInput);
    const input: ChainInput = {
      leaf: copy(callerInput.leaf),
      intermediate: callerInput.intermediate && copy(callerInput.intermediate),
      root: callerInput.root && copy(callerInput.root),
      crl: callerInput.crl && copy(callerInput.crl),
      now: Number(callerInput.now),
    };
    trustedRoots = trustedRoots?.map(copy);
    if (!Number.isFinite(input.now)) fail('POLICY_INVALID', '`now` must be a unix timestamp in seconds');
    const leafCert = parseCertificate(input.leaf);
    const leaf = parseEndorsementKey(leafCert);
    const defaults = embeddedRoots(leaf.product);
    const rootDer = input.root ?? defaults?.ark ?? fail('ARK_UNTRUSTED', `no embedded root for ${leaf.product}; pass one`);
    const interDer = input.intermediate ?? defaults?.ask ?? fail('CERT_MALFORMED', `no embedded intermediate for ${leaf.product}; pass one`);
    const trusted = trustedRoots ?? (defaults ? [defaults.ark] : []);
    if (!trusted.some(t => equal(t, rootDer))) fail('ARK_UNTRUSTED', 'root certificate is not a trusted ARK');
    const root = parseCertificate(rootDer);
    const intermediate = parseCertificate(interDer);

    // Product consistency: ARK "ARK-Genoa", ASK "SEV-Genoa", ASVK "SEV-VLEK-Genoa". Siena/Bergamo use the Genoa chain.
    const p = leaf.product;
    if (!root.subjectCN.endsWith(`-${p}`)) fail('PRODUCT_MISMATCH', `ARK "${root.subjectCN}" is not for ${p}`);
    if (!intermediate.subjectCN.endsWith(`-${p}`)) fail('PRODUCT_MISMATCH', `intermediate "${intermediate.subjectCN}" is not for ${p}`);
    if ((leaf.kind === 'VLEK') !== intermediate.subjectCN.startsWith('SEV-VLEK')) fail('PRODUCT_MISMATCH', `${leaf.kind} must be issued by ${leaf.kind === 'VLEK' ? 'an ASVK' : 'an ASK'}`);

    // All AMD endorsement certificates carry O=Advanced Micro Devices, OU=Engineering.
    for (const [c, what] of [[root, 'ARK'], [intermediate, 'ASK'], [leafCert, leaf.kind]] as const) {
      if (c.subjectName.o !== 'Advanced Micro Devices' || c.subjectName.ou !== 'Engineering') fail('CHAIN_NAME_MISMATCH', `${what} subject is not AMD Engineering`);
    }
    if (!equal(leafCert.issuer, intermediate.subject)) fail('CHAIN_NAME_MISMATCH', 'leaf issuer != intermediate subject');
    if (!equal(intermediate.issuer, root.subject)) fail('CHAIN_NAME_MISMATCH', 'intermediate issuer != root subject');
    if (!equal(root.issuer, root.subject)) fail('CHAIN_NAME_MISMATCH', 'root is not self-issued');

    checkValidity(root, input.now, 'ARK');
    checkValidity(intermediate, input.now, 'ASK');
    checkValidity(leafCert, input.now, leaf.kind);
    checkCertificatePurpose(root, true);
    checkCertificatePurpose(intermediate, true);
    checkCertificatePurpose(leafCert, false);
    if (leafCert.spkiAlgorithm !== OID.ecPublicKey || leafCert.spkiCurve !== OID.p384) fail('CERT_ALGO_UNSUPPORTED', `${leaf.kind} key is not EC P-384`);

    if (!(await signedBy(crypto, root, root))) fail('CHAIN_SIGNATURE_INVALID', 'ARK self-signature invalid');
    if (!(await signedBy(crypto, intermediate, root))) fail('CHAIN_SIGNATURE_INVALID', 'ASK not signed by ARK');
    if (!(await signedBy(crypto, leafCert, intermediate))) fail('CHAIN_SIGNATURE_INVALID', `${leaf.kind} not signed by ASK`);

    let crl: CrlInfo | undefined;
    if (input.crl) crl = await checkCrl(input.crl, root, intermediate, input.now, crypto);
    return { leaf, intermediate, root, crl };
  });
}

/** Size caps, checked before any copy or parse. */
export function checkCollateralSizes(c: { leaf?: Uint8Array; intermediate?: Uint8Array; root?: Uint8Array; crl?: Uint8Array }): void {
  for (const [what, b] of [['leaf', c.leaf], ['intermediate', c.intermediate], ['root', c.root]] as const) {
    if (b && b.length > MAX_CERT_BYTES) fail('CERT_MALFORMED', `${what} certificate is ${b.length} bytes, limit ${MAX_CERT_BYTES}`);
  }
  if (c.crl && c.crl.length > MAX_CRL_BYTES) fail('CRL_INVALID', `CRL is ${c.crl.length} bytes, limit ${MAX_CRL_BYTES}`);
}

/** KDS CRLs are ARK-signed and list revoked ASK/ASVK serials. VCEKs (serial 0) are never revoked; TCB supersedes them. */
export async function checkCrl(crlDer: Uint8Array, root: Certificate, intermediate: Certificate, now: number, crypto: CryptoProvider): Promise<CrlInfo> {
  const crl = parseCrl(crlDer);
  if (crl.nextUpdate === undefined) fail('CRL_INVALID', 'CRL has no nextUpdate');
  if (crl.extensions.has('2.5.29.27')) fail('CRL_INVALID', 'delta CRL requires a base CRL');
  for (const ext of crl.extensions.values()) if (ext.critical) fail('CRL_INVALID', `unsupported critical CRL extension ${ext.oid}`);
  const ku = keyUsageBits(root) ?? fail('CRL_INVALID', 'CRL issuer lacks keyUsage');
  if (!(ku & 0x02)) fail('CRL_INVALID', 'CRL issuer keyUsage does not permit CRL signing');
  if (!equal(crl.issuer, root.subject)) fail('CRL_INVALID', 'CRL issuer is not the ARK');
  if (!(await signedBy(crypto, crl, root))) fail('CRL_INVALID', 'CRL signature invalid');
  if (now < crl.thisUpdate) fail('CRL_INVALID', 'CRL thisUpdate is in the future');
  if (now > crl.nextUpdate) fail('CRL_EXPIRED', `CRL nextUpdate ${iso(crl.nextUpdate)} passed`);
  for (const serial of crl.revokedSerials) {
    if (equal(serial, intermediate.serial)) fail('CERT_REVOKED', `intermediate serial ${hex(serial)} is revoked`);
    if (equal(serial, root.serial)) fail('CERT_REVOKED', `root serial ${hex(serial)} is revoked`);
  }
  return { thisUpdate: crl.thisUpdate, nextUpdate: crl.nextUpdate, revokedCount: crl.revokedSerials.length };
}
