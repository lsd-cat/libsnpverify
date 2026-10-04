// Regression cases: policy validation, input ownership, certificate purpose, CRL rules, masked CHIP_ID, VLEK. Test certificates are generated and signed in-process.
import { test } from 'vitest';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { constants, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  SnpVerifier, baseVcekPolicy, baseVlekPolicy, fromBase64, fromHex, pemToDer, parseCrl, parseCertificate,
  webCrypto, type Policy, type VerifyInput,
} from '../src/index.ts';
import { readTlv, children, raw, oidToString } from '../src/der.ts';

const vectors = new URL('../../vectors/', import.meta.url);
const read = (p: string) => fs.readFileSync(new URL(p, vectors));
function fixture(name = '200-real-sev-snp-happy'): VerifyInput {
  const x = JSON.parse(read(`attestation-sev/${name}/input.json`).toString());
  return {
    report: new Uint8Array(zlib.gunzipSync(fromBase64(x.attestation_doc_b64))),
    vcek: fromBase64(x.vcek_der_b64),
    ask: x.ask_pem ? pemToDer(x.ask_pem)[0] : undefined,
    ark: x.amd_root_ca_pem ? pemToDer(x.amd_root_ca_pem)[0] : undefined,
    now: x.expiration_check_date_unix ?? 1780272000,
    policy: { measurement: 'any' },
  };
}
const makeVerifier = (i: VerifyInput) => new SnpVerifier(i.ark ? { trustedArks: [i.ark] } : {});
const accepted = async (i: VerifyInput, v = makeVerifier(i)) => {
  const r = await v.verify(i);
  assert.ok(r.ok, !r.ok ? JSON.stringify(r.violations) : '');
  return r.attestation;
};

test('R1: undefined debug rule cannot disable the default prohibition', async () => {
  const i = fixture('600-synth-debug-bit-set');
  assert.equal((await makeVerifier(i).verify(i)).ok, false);
  const r = await makeVerifier(i).verify({ ...i, policy: { measurement: 'any', guestPolicy: { debug: undefined } } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_INVALID');
});

test('R1: invalid report-data mode is rejected', async () => {
  const i = fixture();
  assert.equal((await makeVerifier(i).verify({ ...i, policy: { measurement: 'any', reportData: { kind: 'exact', value: new Uint8Array(64) } } })).ok, false);
  const r = await makeVerifier(i).verify({ ...i, policy: { measurement: 'any', reportData: { kind: 'excat', value: new Uint8Array(64) } } as unknown as Policy });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_INVALID');
});

test('R1: numeric policy ranges are validated', async () => {
  const r = await makeVerifier(fixture()).verify({ ...fixture(), policy: { measurement: 'any', minGuestSvn: NaN, minReportVersion: -1, minTcb: { Genoa: { snp: -1 } } } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_INVALID');
});

test('R2: a Buffer cannot change the accepted measurement after real ECDSA verification', async () => {
  const i = fixture();
  const report = Buffer.from(i.report);
  const verifier = new SnpVerifier({ crypto: {
    ...webCrypto,
    async verifyEcdsaP384(...args) {
      const valid = await webCrypto.verifyEcdsaP384(...args);
      assert.equal(valid, true);
      report.fill(0, 0x90, 0xc0); // deterministic scheduling of concurrent buffer reuse
      return valid;
    },
  } });
  const r = await verifier.verify({ ...i, report, policy: { measurement: [new Uint8Array(48)] } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_MEASUREMENT_MISMATCH');
  assert.ok(i.report.slice(0x90, 0xc0).some(x => x !== 0));
});

test('R2: verification uses the initial policy snapshot', async () => {
  const i = fixture();
  const policy: Policy = { measurement: 'any', minGuestSvn: 100 };
  const pending = new SnpVerifier().verify({ ...i, policy });
  policy.minGuestSvn = 0;
  const r = await pending;
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_GUEST_SVN');
});

test('R2: reported verification time matches the time used for chain checks', async () => {
  const i = fixture();
  const checkedAt = i.now;
  const pending = makeVerifier(i).verify(i);
  i.now += 86400 * 365;
  const r = await pending;
  assert.ok(r.ok);
  assert.equal(r.attestation.verifiedAt, checkedAt);
});

test('R3: malformed leaf returns a chain violation', async () => {
  const r = await new SnpVerifier().verify({ ...fixture(), vcek: fromHex('300a3002a000300003020000') });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CERT_MALFORMED');
});

test('R3: malformed CRL returns a chain violation', async () => {
  const r = await new SnpVerifier().verify({ ...fixture(), crl: fromHex('3006300030000300') });
  assert.ok(!r.ok);
  assert.equal(r.stage, 'chain');
});

test('R4: independently masked CHIP_ID can be enabled by allowMaskedChipId', async () => {
  const i = fixture('267-mask-chip-id-accept');
  i.report[0x48] &= ~2; // MaskChipKey=0, CHIP_ID remains zero (MaskChipId semantics).
  const sig = sign('sha384', i.report.subarray(0, 0x2a0), {
    key: read('attestation-sev/_assets/synth_chain/vcek_priv.pem'), dsaEncoding: 'ieee-p1363',
  });
  i.report.set(Uint8Array.from(sig.subarray(0, 48)).reverse(), 0x2a0);
  i.report.set(Uint8Array.from(sig.subarray(48)).reverse(), 0x2e8);
  await accepted({ ...i, policy: { measurement: 'any', allowMaskedChipId: true } });
  const r = await makeVerifier(i).verify({ ...i, policy: { measurement: 'any' } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_CHIP_ID_MASKED');
});

test('R5: the default accepts the AES-256-XTS requirement', async () => {
  const i = fixture('606-guest-policy-mem-aes256-xts');
  await accepted(i);
  const r = await makeVerifier(i).verify({ ...i, policy: { measurement: 'any', guestPolicy: { memAes256Xts: 'forbidden' } } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].field, 'guest_policy.mem_aes_256_xts');
});

// Real RSA signatures with a new, explicitly trusted TEST root. This demonstrates
// certificate-profile validation gaps; it does not claim to forge AMD signatures.
const concat = (...p: Uint8Array[]) => Buffer.concat(p);
function tlv(tag: number, b: Uint8Array): Uint8Array {
  const n = b.length;
  const len = n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >>> 8, n & 255];
  return concat(Uint8Array.from([tag, ...len]), b);
}
const seq = (...p: Uint8Array[]) => tlv(0x30, concat(...p));
const kids = (b: Uint8Array) => children(b, readTlv(b, 0)).map(t => raw(b, t));
const ext = (oidHex: string, value: Uint8Array, critical = true) => seq(tlv(6, fromHex(oidHex)), ...(critical ? [fromHex('0101ff')] : []), tlv(4, value));
const caKeys = generateKeyPairSync('rsa', { modulusLength: 4096 });
const askKeys = generateKeyPairSync('rsa', { modulusLength: 4096 });
const [askTemplate, rootTemplate] = pemToDer(read('kds/Genoa.cert_chain.pem').toString());
function cert(template: Uint8Array, issuer: KeyObject, spki?: Uint8Array, extensions?: Uint8Array[], names?: { issuer?: Uint8Array; subject?: Uint8Array }) {
  const [oldTbs, alg] = kids(template);
  const fields = kids(oldTbs);
  if (names?.issuer) fields[3] = names.issuer;
  if (names?.subject) fields[5] = names.subject;
  if (spki) fields[6] = spki;
  if (extensions) fields[7] = tlv(0xa3, seq(...extensions));
  const tbs = seq(...fields);
  const sig = sign('sha384', tbs, { key: issuer, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  return seq(tbs, alg, tlv(3, concat(Uint8Array.of(0), sig)));
}
const root = cert(rootTemplate, caKeys.privateKey, caKeys.publicKey.export({ type: 'spki', format: 'der' }));
const rootNoCrlSign = cert(rootTemplate, caKeys.privateKey, caKeys.publicKey.export({ type: 'spki', format: 'der' }),
  kids(kids(kids(kids(rootTemplate)[0])[7])[0]).map(e => oidToString(e, children(e, readTlv(e, 0))[0]) === '2.5.29.15'
    ? ext('551d0f', fromHex('03020204')) : e));
const askSpki = askKeys.publicKey.export({ type: 'spki', format: 'der' });
const ask = cert(askTemplate, caKeys.privateKey, askSpki);
const leaf = cert(fixture().vcek, askKeys.privateKey);
const testChain = { ...fixture(), vcek: leaf, ask, ark: root };

test('R6: a signed non-CA intermediate without keyCertSign is rejected', async () => {
  const invalidAsk = cert(askTemplate, caKeys.privateKey, askSpki, [
    ext('551d13', fromHex('3000')), // critical basicConstraints: CA=false
    ext('551d0f', fromHex('03020780')), // critical keyUsage: digitalSignature only
  ]);
  const r = await makeVerifier(testChain).verify({ ...testChain, ask: invalidAsk });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CERT_MALFORMED');
});

test('R6: a signed unknown critical certificate extension is rejected', async () => {
  const fields = kids(kids(fixture().vcek)[0]);
  const extensions = kids(kids(fields[7])[0]);
  const badLeaf = cert(fixture().vcek, askKeys.privateKey, undefined, [...extensions, ext('2a0304', fromHex('0500'))]);
  assert.ok(parseCertificate(badLeaf).extensions.get('1.2.3.4')?.critical);
  const r = await makeVerifier(testChain).verify({ ...testChain, vcek: badLeaf });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CERT_MALFORMED');
});

function makeCrl(delta: boolean, nextUpdate: boolean) {
  const crl = new Uint8Array(read('kds/Genoa.crl'));
  const fields = kids(kids(crl)[0]);
  const alg = fields[1];
  const end = fields[4];
  const tbs = seq(...fields.slice(0, 4), ...(nextUpdate ? [end] : []),
    ...(delta ? [tlv(0xa0, seq(ext('551d1b', fromHex('020101'))))] : []));
  const sig = sign('sha384', tbs, { key: caKeys.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  return seq(tbs, alg, tlv(3, concat(Uint8Array.of(0), sig)));
}
test('R6: a critical delta CRL cannot stand alone', async () => {
  const crl = makeCrl(true, true);
  const r = await makeVerifier(testChain).verify({ ...testChain, crl, now: parseCrl(crl).thisUpdate + 60, policy: { measurement: 'any', requireCrl: true } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CRL_INVALID');
});
test('R6: a CRL issuer without cRLSign cannot authorize revocation status', async () => {
  const crl = makeCrl(false, true);
  const i = { ...testChain, ark: rootNoCrlSign, crl, now: parseCrl(crl).thisUpdate + 60 };
  const r = await makeVerifier(i).verify(i);
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CRL_INVALID');
});

test('R7: requireCrl rejects a CRL without expiry', async () => {
  const crl = makeCrl(false, false);
  assert.equal(parseCrl(crl).nextUpdate, undefined);
  const r = await makeVerifier(testChain).verify({ ...testChain, crl, now: parseCrl(crl).thisUpdate + 365 * 86400, policy: { measurement: 'any', requireCrl: true } });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'CRL_INVALID');
});

test('P1: VCEK base policy accepts the pinned fixture and rejects missing CRL', async () => {
  const i = fixture();
  i.crl = new Uint8Array(read('kds/Genoa.crl'));
  i.now = parseCrl(i.crl).thisUpdate + 60;
  const policy = baseVcekPolicy({
    products: ['Genoa'], measurements: [i.report.slice(0x90, 0xc0)], reportData: i.report.slice(0x50, 0x90),
    minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } },
  });
  await accepted({ ...i, policy });
  const r = await makeVerifier(i).verify({ ...i, crl: undefined, policy });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_INVALID');
});

test('P2: base VLEK policy requires a provider identity', () => {
  const config = { products: ['Genoa'] as const, measurements: [new Uint8Array(48)], reportData: new Uint8Array(64).fill(1), minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } } };
  assert.throws(() => baseVlekPolicy({ ...config, products: [...config.products], cspIds: [] }));
  const p = baseVlekPolicy({ ...config, products: [...config.products], cspIds: ['provider-1'] });
  assert.deepEqual(p.cspIds, ['provider-1']);
  assert.equal(p.signingKey, 'VLEK');
});

function renameCn(name: Uint8Array, cn: string): Uint8Array {
  return seq(...kids(name).map(rdn => tlv(0x31, concat(...kids(rdn).map(atv => {
    const [oid, value] = kids(atv);
    return oidToString(oid, readTlv(oid, 0)) === '2.5.4.3' ? seq(oid, tlv(value[0], Buffer.from(cn))) : atv;
  })))));
}

function syntheticVlek() {
  const original = fixture('604-synth-baseline-accept');
  const rootKeys = generateKeyPairSync('rsa', { modulusLength: 4096 });
  const asvkKeys = generateKeyPairSync('rsa', { modulusLength: 4096 });
  const originalRootFields = kids(kids(original.ark!)[0]);
  const originalRootExtensions = kids(kids(originalRootFields[7])[0]).filter(e => oidToString(e, children(e, readTlv(e, 0))[0]) !== '2.5.29.15');
  const rootDer = cert(original.ark!, rootKeys.privateKey, rootKeys.publicKey.export({ type: 'spki', format: 'der' }),
    [...originalRootExtensions, ext('551d0f', fromHex('03020106'))]); // keyCertSign + cRLSign
  const asvkName = renameCn(parseCertificate(original.ask!).subject, 'SEV-VLEK-Genoa');
  const asvkDer = cert(original.ask!, rootKeys.privateKey, asvkKeys.publicKey.export({ type: 'spki', format: 'der' }), undefined, { subject: asvkName });
  const oldLeaf = parseCertificate(original.vcek);
  const leafFields = kids(kids(original.vcek)[0]);
  const leafExtensions = kids(kids(leafFields[7])[0]).filter(e => oidToString(e, children(e, readTlv(e, 0))[0]) !== '1.3.6.1.4.1.3704.1.4');
  leafExtensions.push(ext('2b060104019c780105', tlv(0x16, Buffer.from('provider-1')), false));
  const leafDer = cert(original.vcek, asvkKeys.privateKey, undefined, leafExtensions, { issuer: asvkName, subject: renameCn(oldLeaf.subject, 'SEV-VLEK') });
  const crlBytes = new Uint8Array(read('kds/Genoa.crl'));
  const crlFields = kids(kids(crlBytes)[0]);
  crlFields[2] = parseCertificate(rootDer).subject;
  const tbs = seq(...crlFields);
  const signature = sign('sha384', tbs, { key: rootKeys.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  const crlDer = seq(tbs, kids(crlBytes)[1], tlv(3, concat(Uint8Array.of(0), signature)));
  const report = new Uint8Array(original.report);
  report[0x48] = 4; // SIGNING_KEY=VLEK
  report.fill(0, 0x1a0, 0x1e0); // provider privacy
  const reportSignature = sign('sha384', report.subarray(0, 0x2a0), { key: read('attestation-sev/_assets/synth_chain/vcek_priv.pem'), dsaEncoding: 'ieee-p1363' });
  report.set(Uint8Array.from(reportSignature.subarray(0, 48)).reverse(), 0x2a0);
  report.set(Uint8Array.from(reportSignature.subarray(48)).reverse(), 0x2e8);
  return { report, vcek: leafDer, ask: asvkDer, ark: rootDer, crl: crlDer, now: parseCrl(crlDer).thisUpdate + 60, policy: { measurement: 'any' } as Policy };
}
const vlek = syntheticVlek();

test('P2: VLEK base policy accepts the right CSP_ID and rejects another provider', async () => {
  const config = {
    products: ['Genoa'] as const,
    measurements: [vlek.report.slice(0x90, 0xc0)], reportData: vlek.report.slice(0x50, 0x90),
    minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } },
  };
  await accepted({ ...vlek, policy: baseVlekPolicy({ ...config, products: [...config.products], cspIds: ['provider-1'] }) });
  const r = await makeVerifier(vlek).verify({ ...vlek, policy: baseVlekPolicy({ ...config, products: [...config.products], cspIds: ['provider-2'] }) });
  assert.ok(!r.ok);
  assert.equal(r.violations[0].code, 'POLICY_SIGNER_NOT_ALLOWED');
});

// Public test collateral for the Kotlin mirror test lives in vectors/review. Regenerated only when absent
// (or when SNP_VECTORS_REGEN is set) so the checked-in fixtures stay stable. No private test keys are persisted.
const reviewDir = new URL('../../vectors/review/', import.meta.url).pathname;
if (process.env.SNP_VECTORS_REGEN || !fs.existsSync(`${reviewDir}/root.der`)) {
  const dir = reviewDir;
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(`${dir}/root.der`, root);
  fs.writeFileSync(`${dir}/root-no-crl-sign.der`, rootNoCrlSign);
  fs.writeFileSync(`${dir}/non-ca.der`, cert(askTemplate, caKeys.privateKey, askSpki, [ext('551d13', fromHex('3000')), ext('551d0f', fromHex('03020780'))]));
  fs.writeFileSync(`${dir}/ask.der`, ask);
  fs.writeFileSync(`${dir}/leaf.der`, leaf);
  fs.writeFileSync(`${dir}/delta.crl`, makeCrl(true, true));
  fs.writeFileSync(`${dir}/valid.crl`, makeCrl(false, true));
  fs.writeFileSync(`${dir}/no-expiry.crl`, makeCrl(false, false));
  fs.writeFileSync(`${dir}/vlek-root.der`, vlek.ark!);
  fs.writeFileSync(`${dir}/asvk.der`, vlek.ask!);
  fs.writeFileSync(`${dir}/vlek.der`, vlek.vcek);
  fs.writeFileSync(`${dir}/vlek.crl`, vlek.crl!);
  fs.writeFileSync(`${dir}/vlek.report`, vlek.report);
  { // R4: vector 267 with MASK_CHIP_KEY cleared and re-signed by the synthetic VCEK key (CHIP_ID stays zero)
    const i = fixture('267-mask-chip-id-accept');
    i.report[0x48] &= ~2;
    const sig = sign('sha384', i.report.subarray(0, 0x2a0), { key: read('attestation-sev/_assets/synth_chain/vcek_priv.pem'), dsaEncoding: 'ieee-p1363' });
    i.report.set(Uint8Array.from(sig.subarray(0, 48)).reverse(), 0x2a0);
    i.report.set(Uint8Array.from(sig.subarray(48)).reverse(), 0x2e8);
    fs.writeFileSync(`${dir}/masked-resigned.report`, i.report);
  }
  { // R6: test-chain leaf with a signed unknown critical extension
    const fields = kids(kids(fixture().vcek)[0]);
    const extensions = kids(kids(fields[7])[0]);
    fs.writeFileSync(`${dir}/unknown-critical-ext.der`, cert(fixture().vcek, askKeys.privateKey, undefined, [...extensions, ext('2a0304', fromHex('0500'))]));
  }
}
