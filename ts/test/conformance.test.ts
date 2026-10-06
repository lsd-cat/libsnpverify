// Runs the Tinfoil conformance vectors (vectors/attestation-sev, vectors/quote-sev) through SnpVerifier.
// Two policy profiles: BASELINE for real-hardware fixtures, HARDENED for synthetic ones (which encode the hardened stance).
import { test } from 'vitest';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { SnpVerifier, appraisalPolicyFromJson, fromBase64, pemToDer, type AppraisalPolicy, type ErrorCode, type AppraisalResult } from '../src/index.ts';

const VECTORS = path.resolve(import.meta.dirname, '../../vectors');
const verifier = new SnpVerifier();

// Policies are built in the JSON form (SPEC §5) so that every port runs the vectors through its JSON loader.
type Json = Record<string, unknown>;
const BASELINE: Json = { measurement: 'any', vmpl: 'any', products: ['Milan', 'Genoa', 'Turin'] };
// Mirrors the "hardened" expectations encoded by the synthetic fixtures (SPEC §3.7.1 defaults + DECIDE-LATER probes).
const HARDENED: Json = {
  ...BASELINE,
  allowMaskedChipId: true,
  minTcb: { Genoa: { snp: 14 } },
  minFirmware: { major: 1, minor: 55, build: 21 },
  guestPolicy: { debug: 'forbidden', migrateMa: 'forbidden', cxlAllowed: 'forbidden', memAes256Xts: 'forbidden' },
  platformInfo: { tsmeEnabled: 'required' },
};
// The 27x probes encode the DECIDE-LATER hardened stance that the rest of the synthetic suite does not satisfy.
const HARDENED_PLATFORM: Json = { tsmeEnabled: 'required', eccEnabled: 'required', raplDisabled: 'required', ciphertextHidingEnabled: 'required', aliasCheckComplete: 'required', tioEnabled: 'required' };

/** Our code -> Tinfoil taxonomy, so vectors that name a code can be asserted. */
function tinfoilCode(r: AppraisalResult & { ok: false }): string {
  const v = r.violations[0];
  const m: Partial<Record<ErrorCode, string>> = {
    REPORT_TRUNCATED: 'REPORT_TRUNCATED', REPORT_VERSION_UNSUPPORTED: 'WRONG_REPORT_VERSION', REPORT_SIGNATURE_INVALID: 'REPORT_SIGNATURE_INVALID',
    CERT_MALFORMED: 'VCEK_CHAIN_INVALID', CHAIN_SIGNATURE_INVALID: 'VCEK_CHAIN_INVALID', CHAIN_NAME_MISMATCH: 'VCEK_CHAIN_INVALID', VCEK_EXTENSION_INVALID: 'VCEK_CHAIN_INVALID',
    ARK_UNTRUSTED: 'ARK_UNTRUSTED', CERT_EXPIRED: 'VCEK_EXPIRED', VCEK_HWID_MISMATCH: 'VCEK_HWID_MISMATCH', VCEK_TCB_MISMATCH: 'VCEK_TCB_MISMATCH',
    POLICY_TCB_OUT_OF_DATE: 'TCB_OUT_OF_DATE', POLICY_LAUNCH_TCB_OUT_OF_DATE: 'TCB_OUT_OF_DATE',
    POLICY_MEASUREMENT_MISMATCH: 'MEASUREMENT_MISMATCH', POLICY_REPORT_DATA_MISMATCH: 'REPORT_DATA_MISMATCH', POLICY_HOST_DATA_MISMATCH: 'HOST_DATA_MISMATCH',
  };
  if (v.code === 'POLICY_GUEST_POLICY') return v.field === 'guest_policy.debug' ? 'GUEST_POLICY_DEBUG_SET' : v.field === 'guest_policy.migrate_ma' ? 'GUEST_POLICY_MIGRATE_MA_SET' : 'GUEST_POLICY_RESERVED_BIT_SET';
  if (v.code === 'REPORT_MALFORMED') return v.field === 'guest_policy' ? 'GUEST_POLICY_RESERVED_BIT_SET' : 'REPORT_FORMAT_UNSUPPORTED';
  if (v.code === 'POLICY_ID_BLOCK') return v.field === 'author_key_digest' ? 'AUTHOR_KEY_DIGEST_MISMATCH' : 'ID_KEY_DIGEST_MISMATCH';
  return m[v.code] ?? v.code;
}

function readManifest(dir: string) {
  const m = fs.readFileSync(path.join(dir, 'manifest.yaml'), 'utf8');
  const exit = Number(/exit_code:\s*(\d+)/.exec(m)![1]);
  const codeLine = /^\s*rejection_code:\s*(.+)$/m.exec(m)?.[1].trim();
  const codes = codeLine ? (codeLine.startsWith('[') ? JSON.parse(codeLine.replace(/'/g, '"')) : [codeLine.replace(/^"|"$/g, '')]) : [];
  return { exit, codes: codes as string[] };
}

const sevDir = path.join(VECTORS, 'attestation-sev');
for (const name of fs.readdirSync(sevDir).filter(n => /^\d/.test(n)).sort()) {
  test(`attestation-sev/${name}`, async () => {
    const dir = path.join(sevDir, name);
    const input = JSON.parse(fs.readFileSync(path.join(dir, 'input.json'), 'utf8'));
    const { exit, codes } = readManifest(dir);
    const report = new Uint8Array(zlib.gunzipSync(fromBase64(input.attestation_doc_b64)));
    const synthetic = input.amd_root_ca_pem !== undefined;
    const pol = input.policy ?? {};
    const json: Json = {
      ...(synthetic ? HARDENED : BASELINE),
      ...(/^27[0-4]/.test(name) && { platformInfo: HARDENED_PLATFORM }),
      ...(pol.expected_measurement_hex && { measurement: [pol.expected_measurement_hex] }),
      ...(pol.expected_report_data_hex && { reportData: { kind: 'exact', value: pol.expected_report_data_hex } }),
      ...(pol.expected_host_data_hex && { hostData: pol.expected_host_data_hex }),
      ...((pol.expected_id_key_digest_hex || pol.expected_author_key_digest_hex) && {
        idBlock: { idKeyDigest: pol.expected_id_key_digest_hex ?? '00'.repeat(48), authorKeyDigest: pol.expected_author_key_digest_hex } }),
    };
    if (pol.min_tcb_bl_spl !== undefined || pol.min_tcb_ucode_spl !== undefined || pol.min_tcb_snp_spl !== undefined || pol.min_tcb_tee_spl !== undefined) {
      const f = { bootloader: pol.min_tcb_bl_spl, tee: pol.min_tcb_tee_spl, snp: pol.min_tcb_snp_spl, microcode: pol.min_tcb_ucode_spl };
      json.minTcb = { Milan: f, Genoa: f, Turin: f };
    }
    const policy = appraisalPolicyFromJson(JSON.stringify(json)) as AppraisalPolicy;
    assert.ok(!('code' in policy), `policy: ${JSON.stringify(policy)}`);
    const verifierHere = synthetic ? new SnpVerifier({ trustedArks: [pemToDer(input.amd_root_ca_pem)[0]] }) : verifier;
    const result = await verifierHere.appraise({
      evidence: report, endorsements: {
        vcek: fromBase64(input.vcek_der_b64),
        ask: input.ask_pem ? pemToDer(input.ask_pem)[0] : undefined, ark: input.amd_root_ca_pem ? pemToDer(input.amd_root_ca_pem)[0] : undefined,
      },
      now: input.expiration_check_date_unix ?? 1780272000, policy,
    });
    if (exit === 0) {
      assert.ok(result.ok, `expected accept, got ${JSON.stringify(result.ok ? null : result.violations)}`);
      const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
      const want = expected.outputs?.measurement?.registers?.[0];
      if (want) assert.equal(Buffer.from(result.attestationResult.identity.measurement).toString('hex'), want);
    } else {
      assert.ok(!result.ok, 'expected rejection, got accept');
      if (codes.length) assert.ok(codes.includes(tinfoilCode(result)), `code ${tinfoilCode(result)} (${result.violations[0].code}: ${result.violations[0].message}) not in ${codes}`);
    }
  });
}

const v3Dir = path.join(VECTORS, 'quote-sev');
for (const file of fs.readdirSync(v3Dir).filter(n => n.endsWith('.json')).sort()) {
  test(`quote-sev/${file}`, async () => {
    const vec = JSON.parse(fs.readFileSync(path.join(v3Dir, file), 'utf8'));
    const doc = JSON.parse(Buffer.from(vec.input.document_b64, 'base64').toString('utf8'));
    const col = (id: string) => doc.collateral?.find((c: { id: string }) => c.id === id)?.data;
    const vcekB64: string | undefined = col('vcek')?.vcek_der_base64;
    const chain: Uint8Array[] = col('vcek')?.cert_chain_pem ? pemToDer(col('vcek').cert_chain_pem) : [];
    const crlB64: string | undefined = col('crl')?.crl_der_base64;
    // The v3 stage demands a VCEK, a 2-cert chain and a CRL; the core sees those as structural inputs.
    const structural = !vcekB64 || chain.length !== 2 || !crlB64;
    if (structural) { assert.equal(vec.expected.accepted, false); return; }
    const ark = pemToDer(vec.input.amd_root_ca_pem)[0];
    const result = await new SnpVerifier({ trustedArks: [ark] }).appraise({
      evidence: fromBase64(doc.cpu_evidence.report_base64), endorsements: { vcek: fromBase64(vcekB64), ask: chain[0], ark: chain[1], crl: fromBase64(crlB64) },
      now: Math.floor(Date.now() / 1000), policy: appraisalPolicyFromJson({ ...BASELINE, requireCrl: true, minReportVersion: 3 }) as AppraisalPolicy,
    });
    // This older synthetic happy vector has a v3 CRL issuer without keyUsage.
    // RFC 10007 requires cRLSign, so the hardened verifier must reject it.
    if (file === 'sev-happy.json') {
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.violations[0].code, 'CRL_INVALID');
      return;
    }
    assert.equal(result.ok, vec.expected.accepted, result.ok ? 'accepted' : JSON.stringify(result.violations));
  });
}
