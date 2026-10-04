// Cross-port violation vector: records stage, code, field and message for a fixed set of rejections.
// Written to vectors/expected-violations.json when absent or when SNP_VECTORS_REGEN is set; otherwise compared.
import { test } from 'vitest';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { SnpVerifier, fromBase64, pemToDer, parseCrl, type Policy, type VerifyInput } from '../src/index.ts';

const VECTORS = path.resolve(import.meta.dirname, '../../vectors');
const input = JSON.parse(fs.readFileSync(path.join(VECTORS, 'attestation-sev/200-real-sev-snp-happy/input.json'), 'utf8'));
const report = new Uint8Array(zlib.gunzipSync(fromBase64(input.attestation_doc_b64)));
const vcek = fromBase64(input.vcek_der_b64);
const crl = new Uint8Array(fs.readFileSync(path.join(VECTORS, 'kds/Genoa.crl')));
const [ask, ark] = pemToDer(fs.readFileSync(path.join(VECTORS, 'kds/Genoa.cert_chain.pem'), 'utf8'));
const NOW = parseCrl(crl).thisUpdate + 60;
const policy: Policy = { measurement: [report.slice(0x90, 0xc0)], products: ['Genoa'], requireCrl: true };
const base: VerifyInput = { report, vcek, ask, ark, crl, now: NOW, policy };
const flip = (b: Uint8Array, at: number) => { const c = b.slice(); c[at] ^= 1; return c; };

/** The same cases, by the same names, exist in kotlin/src/test/.../ViolationsTest.kt. */
const CASES: Record<string, VerifyInput> = {
  'flipped-signature': { ...base, report: flip(report, 0x2a0) },
  'flipped-reported-tcb': { ...base, report: flip(report, 0x180) },
  'flipped-chip-id': { ...base, report: flip(report, 0x1a0) },
  'trailing-byte': { ...base, report: new Uint8Array([...report, 0]) },
  'version-6': { ...base, report: (() => { const r = report.slice(); r[0] = 6; return r; })() },
  'host-requested': { ...base, report: (() => { const r = report.slice(); r.fill(0xff, 0x30, 0x34); return r; })() },
  'reserved-byte': { ...base, report: flip(report, 0x4c) },
  'flipped-vcek': { ...base, vcek: flip(vcek, vcek.length - 1) },
  'untrusted-root': { ...base, ark: ask, ask: ark },
  'expired': { ...base, now: 2100000000 },
  'not-yet-valid': { ...base, now: 1600000000 },
  'flipped-crl': { ...base, crl: flip(crl, crl.length - 1) },
  'crl-absent': { ...base, crl: undefined },
  'measurement-mismatch': { ...base, policy: { ...policy, measurement: [new Uint8Array(48)] } },
  'report-data-prefix-mismatch': { ...base, policy: { ...policy, reportData: { kind: 'prefix', value: new Uint8Array(32) } } },
  'chip-id-not-allowed': { ...base, policy: { ...policy, chipIds: [new Uint8Array(64)] } },
  'product-not-allowed': { ...base, policy: { ...policy, products: ['Turin'] } },
  'several-policy-violations': { ...base, policy: { ...policy, vmpl: 1, minGuestSvn: 5, guestPolicy: { smt: 'forbidden' } } },
  'tcb-floor': { ...base, policy: { ...policy, minTcb: { Genoa: { snp: 24 } } } },
  'oversized-vcek': { ...base, vcek: (() => { const b = new Uint8Array(16 * 1024 + 1); b.set(vcek); return b; })() },
};

test('cross-port violation vector', async () => {
  const v = new SnpVerifier();
  const actual: Record<string, unknown> = {};
  for (const [name, i] of Object.entries(CASES)) {
    const r = await v.verify(i);
    assert.ok(!r.ok, name);
    actual[name] = { stage: r.stage, violations: r.violations };
  }
  const file = path.join(VECTORS, 'expected-violations.json');
  if (process.env.SNP_VECTORS_REGEN || !fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(actual, null, 1) + '\n');
  assert.deepEqual(actual, JSON.parse(fs.readFileSync(file, 'utf8')));
});
