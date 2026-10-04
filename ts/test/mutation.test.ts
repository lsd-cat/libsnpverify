// Mutation and API tests on the real Genoa fixture (vectors/attestation-sev/200) and the live KDS CRL snapshot (vectors/kds).
import { test } from 'vitest';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { SnpVerifier, fromBase64, pemToDer, parseCrl, toJson, type Policy, type VerifyInput } from '../src/index.ts';

const VECTORS = path.resolve(import.meta.dirname, '../../vectors');
const input = JSON.parse(fs.readFileSync(path.join(VECTORS, 'attestation-sev/200-real-sev-snp-happy/input.json'), 'utf8'));
const report = new Uint8Array(zlib.gunzipSync(fromBase64(input.attestation_doc_b64)));
const vcek = fromBase64(input.vcek_der_b64);
const crl = new Uint8Array(fs.readFileSync(path.join(VECTORS, 'kds/Genoa.crl')));
const [ask, ark] = pemToDer(fs.readFileSync(path.join(VECTORS, 'kds/Genoa.cert_chain.pem'), 'utf8'));
const NOW = parseCrl(crl).thisUpdate + 60; // inside the CRL snapshot's window and the VCEK's 7-year window
const policy: Policy = { measurement: [report.slice(0x90, 0xc0)], products: ['Genoa'], requireCrl: true };
const base: VerifyInput = { report, vcek, crl, now: NOW, policy };
const v = new SnpVerifier();

const flip = (b: Uint8Array, at: number) => { const c = b.slice(); c[at] ^= 1; return c; };
const expectFail = async (i: VerifyInput, stage: string, code: string, what: string) => {
  const r = await v.verify(i);
  assert.ok(!r.ok, `${what}: expected rejection`);
  assert.equal(r.stage, stage, `${what}: stage`);
  assert.equal(r.violations[0].code, code, `${what}: ${JSON.stringify(r.violations)}`);
};

test('real Genoa report verifies with KDS chain and CRL', async () => {
  const r = await v.verify({ ...base, ask, ark });
  assert.ok(r.ok, JSON.stringify(toJson(r)));
  const a = r.attestation;
  assert.equal(a.platform.product, 'Genoa');
  assert.equal(a.evidence.reportVersion, 3);
  assert.deepEqual(a.platform.tcb.reported, { bootloader: 10, tee: 0, snp: 23, microcode: 84 });
  assert.deepEqual(a.evidence.endorsementKey.tcb, a.platform.tcb.reported);
  assert.ok(a.evidence.crl !== undefined && a.evidence.crl.revokedCount >= 0);
  assert.equal(a.evidence.reportSha256.length, 32);
  assert.equal(a.policyApplied.vmpl, 0);
  assert.equal(a.verifiedAt, NOW);
  const j = toJson(a) as Record<string, Record<string, unknown>>;
  assert.equal(typeof j.identity.chipId, 'string');
  assert.equal((j.identity.chipId as string).length, 128);
  JSON.stringify(j); // must be serialisable
});

test('embedded roots equal the KDS snapshot', async () => {
  const r = await v.verify(base);
  assert.ok(r.ok);
});

test('flipped signature byte', () => expectFail({ ...base, report: flip(report, 0x2a0) }, 'signature', 'REPORT_SIGNATURE_INVALID', 'sig'));
test('flipped measurement (signed region)', () => expectFail({ ...base, report: flip(report, 0x90) }, 'signature', 'REPORT_SIGNATURE_INVALID', 'measurement'));
test('flipped reported_tcb', () => expectFail({ ...base, report: flip(report, 0x180) }, 'bind', 'VCEK_TCB_MISMATCH', 'tcb'));
test('flipped chip_id', () => expectFail({ ...base, report: flip(report, 0x1a0) }, 'bind', 'VCEK_HWID_MISMATCH', 'chip'));
test('trailing byte', () => expectFail({ ...base, report: new Uint8Array([...report, 0]) }, 'parse', 'REPORT_TRUNCATED', 'trailing'));
test('version 6', () => { const r = report.slice(); r[0] = 6; return expectFail({ ...base, report: r }, 'parse', 'REPORT_VERSION_UNSUPPORTED', 'v6'); });
test('host-requested report (vmpl 0xFFFFFFFF)', () => { const r = report.slice(); r.fill(0xff, 0x30, 0x34); return expectFail({ ...base, report: r }, 'parse', 'REPORT_HOST_REQUESTED', 'host'); });
test('reserved byte set', () => expectFail({ ...base, report: flip(report, 0x4c) }, 'parse', 'REPORT_MALFORMED', 'mbz'));
test('flipped VCEK byte', () => expectFail({ ...base, vcek: flip(vcek, vcek.length - 1) }, 'chain', 'CHAIN_SIGNATURE_INVALID', 'vcek'));
test('untrusted root', () => expectFail({ ...base, ark: ask, ask: ark }, 'chain', 'ARK_UNTRUSTED', 'swap'));
test('expired at verification time', () => expectFail({ ...base, now: 2100000000 }, 'chain', 'CERT_EXPIRED', 'expired'));
test('not yet valid', () => expectFail({ ...base, now: 1600000000 }, 'chain', 'CERT_NOT_YET_VALID', 'early'));
test('flipped CRL byte', () => expectFail({ ...base, crl: flip(crl, crl.length - 1) }, 'chain', 'CRL_INVALID', 'crl'));
test('CRL required but absent', () => expectFail({ ...base, crl: undefined }, 'policy', 'POLICY_INVALID', 'nocrl'));
test('measurement pin mismatch', () => expectFail({ ...base, policy: { ...policy, measurement: [new Uint8Array(48)] } }, 'policy', 'POLICY_MEASUREMENT_MISMATCH', 'meas'));
test('report_data prefix pin', async () => {
  const ok = await v.verify({ ...base, policy: { ...policy, reportData: { kind: 'prefix', value: report.slice(0x50, 0x70) } } });
  assert.ok(ok.ok);
  await expectFail({ ...base, policy: { ...policy, reportData: { kind: 'prefix', value: new Uint8Array(32) } } }, 'policy', 'POLICY_REPORT_DATA_MISMATCH', 'prefix');
});
test('chip_id allowlist', async () => {
  assert.ok((await v.verify({ ...base, policy: { ...policy, chipIds: [report.slice(0x1a0, 0x1e0)] } })).ok);
  await expectFail({ ...base, policy: { ...policy, chipIds: [new Uint8Array(64)] } }, 'policy', 'POLICY_CHIP_ID_NOT_ALLOWED', 'chipIds');
});
test('report_id pin and product allowlist', async () => {
  assert.ok((await v.verify({ ...base, policy: { ...policy, reportId: report.slice(0x140, 0x160) } })).ok);
  await expectFail({ ...base, policy: { ...policy, products: ['Turin'] } }, 'policy', 'POLICY_PRODUCT_NOT_ALLOWED', 'product');
});
test('policy reports all violations', async () => {
  const r = await v.verify({ ...base, policy: { ...policy, vmpl: 1, minGuestSvn: 5, guestPolicy: { smt: 'forbidden' } } });
  assert.ok(!r.ok && r.stage === 'policy');
  assert.deepEqual(r.violations.map(x => x.code).sort(), ['POLICY_GUEST_POLICY', 'POLICY_GUEST_SVN', 'POLICY_VMPL']);
});
test('malformed policy', async () => {
  const r = await v.verify({ ...base, policy: { measurement: [new Uint8Array(47)] } });
  assert.ok(!r.ok && r.violations[0].code === 'POLICY_INVALID');
});
test('TCB floor per product', async () => {
  assert.ok((await v.verify({ ...base, policy: { ...policy, minTcb: { Genoa: { snp: 23, microcode: 84 } } } })).ok);
  await expectFail({ ...base, policy: { ...policy, minTcb: { Genoa: { snp: 24 } } } }, 'policy', 'POLICY_TCB_OUT_OF_DATE', 'floor');
});

test('matches the cross-port golden result', async () => {
  const r = await v.verify({ ...base, ask, ark, policy: { ...policy, reportData: { kind: 'prefix', value: report.slice(0x50, 0x60) }, minTcb: { Genoa: { snp: 20 } } } });
  assert.ok(r.ok);
  const sort = (x: unknown): unknown => Array.isArray(x) ? x.map(sort) : x && typeof x === 'object' ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b)).map(([k, y]) => [k, sort(y)])) : x;
  const file = path.join(VECTORS, 'golden/real-genoa.json');
  if (process.env.SNP_VECTORS_REGEN || !fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(sort(toJson(r.attestation)), null, 1) + '\n');
  assert.deepEqual(sort(toJson(r.attestation)), JSON.parse(fs.readFileSync(file, 'utf8')));
});

test('stage API: parsed records cannot be altered between stages', async () => {
  const parsed = (await import('../src/index.ts')).parseReport(report);
  assert.ok(parsed.ok);
  const rep = parsed.value;
  rep.measurement[0] ^= 1;                 // mutate a returned copy
  assert.throws(() => { (rep as { measurement: Uint8Array }).measurement = new Uint8Array(48); }); // frozen
  assert.deepEqual(rep.measurement, report.slice(0x90, 0xc0));
  const chain = await v.verifyChain({ leaf: vcek, intermediate: ask, root: ark, crl, now: NOW });
  assert.ok(chain.ok);
  chain.value.leaf.cert.spki[30] ^= 1;    // returned copy; the chain's key is untouched
  chain.value.leaf.hwid![0] ^= 1;
  assert.ok((await v.verifyReportSignature(rep, chain.value)).ok);
  const { bindEndorsement } = await import('../src/index.ts');
  assert.ok(bindEndorsement(rep, chain.value.leaf).ok);
});
test('oversized collateral is rejected before parsing', async () => {
  const big = new Uint8Array(16 * 1024 + 1); big.set(vcek);
  await expectFail({ ...base, vcek: big }, 'chain', 'CERT_MALFORMED', 'bigcert');
  const bigCrl = new Uint8Array(1024 * 1024 + 1); bigCrl.set(crl);
  await expectFail({ ...base, crl: bigCrl }, 'chain', 'CRL_INVALID', 'bigcrl');
});

test('stage API: extensions and CRL serials do not alias caller memory', async () => {
  const { parseCertificate, parseCrl } = await import('../src/index.ts');
  const myArk = ark.slice(), myCrl = crl.slice();
  const cert = parseCertificate(myArk), parsedCrl = parseCrl(myCrl);
  const ku = cert.extensions.get('2.5.29.15')!.value.slice();
  myArk.fill(0); myCrl.fill(0);                                   // caller mutates its own buffers after parsing
  cert.extensions.get('2.5.29.15')!.value[0] ^= 1;                // and a returned copy
  cert.extensions.delete('2.5.29.15');                            // and a returned Map
  assert.deepEqual(cert.extensions.get('2.5.29.15')!.value, ku);
  const n = parsedCrl.revokedSerials.length;
  if (n) { parsedCrl.revokedSerials[0][0] ^= 1; parsedCrl.revokedSerials.length = 0; }
  assert.equal(parsedCrl.revokedSerials.length, n);
  assert.ok((await v.verifyChain({ leaf: vcek, intermediate: ask, root: ark, crl, now: NOW })).ok);
});

test('stage API: verifyChain snapshots its inputs before awaiting', async () => {
  const live = { leaf: vcek, intermediate: ask, root: ark, crl: crl.slice(), now: NOW };
  const pending = v.verifyChain(live);
  live.now = 2100000000; live.crl.fill(0); live.crl = new Uint8Array(1); // mutate after the call started
  assert.ok((await pending).ok);
  const expired = { leaf: vcek, intermediate: ask, root: ark, crl, now: 2100000000 };
  const p2 = v.verifyChain(expired); expired.now = NOW;
  const r2 = await p2; assert.ok(!r2.ok && r2.error.code === 'CERT_EXPIRED');
});

test('Node Buffer inputs never alias: parsers, verifyChain, verify', async () => {
  const { parseCertificate, parseCrl, parseReport } = await import('../src/index.ts');
  const bArk = Buffer.from(ark), bCrl = Buffer.from(crl), bReport = Buffer.from(report), bVcek = Buffer.from(vcek), bAsk = Buffer.from(ask);
  const cert = parseCertificate(bArk), parsedCrl = parseCrl(bCrl), rep = parseReport(bReport);
  const ku = cert.extensions.get('2.5.29.15')!.value, serials = parsedCrl.revokedSerials, meas = (rep as { ok: true; value: { measurement: Uint8Array } }).value.measurement;
  const pending = v.verifyChain({ leaf: bVcek, intermediate: bAsk, root: bArk, crl: bCrl, now: NOW });
  const pendingVerify = v.verify({ ...base, report: bReport, vcek: bVcek, ask: bAsk, ark: bArk, crl: bCrl });
  bArk.fill(0); bCrl.fill(0); bReport.fill(0); bVcek.fill(0); bAsk.fill(0);   // caller scribbles over every Buffer it handed us
  assert.deepEqual(cert.extensions.get('2.5.29.15')!.value, ku);
  assert.deepEqual(parsedCrl.revokedSerials, serials);
  assert.deepEqual((rep as { ok: true; value: { measurement: Uint8Array } }).value.measurement, meas);
  assert.ok((await pending).ok);
  assert.ok((await pendingVerify).ok);
  assert.ok(!(cert.der instanceof Buffer), 'returned bytes are plain Uint8Array copies');
});

test('source invariant: no .slice() on bytes in src (Buffer.slice aliases)', () => {
  const src = path.resolve(import.meta.dirname, '../src');
  const offenders: string[] = [];
  for (const f of fs.readdirSync(src)) {
    fs.readFileSync(path.join(src, f), 'utf8').split('\n').forEach((line, i) => {
      if (/\.slice\(/.test(line) && !/s\.slice\(2 \* i|f\.slice\(i\)|^\s*\*|\/\//.test(line)) offenders.push(`${f}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(offenders, []);
});
