// Cross-port policy vector: JSON policies with their resolved form, or the POLICY_INVALID message they produce.
// Written to vectors/policy.json when absent or when SNP_VECTORS_REGEN is set; otherwise compared.
import { test } from 'vitest';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { appraisalPolicyFromJson, appraisalPolicyToJson, resolveAppraisalPolicy } from '../src/index.ts';

const VECTORS = path.resolve(import.meta.dirname, '../../vectors');
const ANY = { measurement: 'any' };
const hex = (n: number, fill = '00') => fill.repeat(n);
const recommended = JSON.parse(/```json\n([\s\S]*?)```/.exec(fs.readFileSync(path.join(VECTORS, '../MITIGATIONS.md'), 'utf8'))![1]);

/** The same cases, by the same names, run from vectors/policy.json in the other ports. */
const CASES: Record<string, unknown> = {
  'minimal': ANY,
  'mitigations-recommended': recommended,
  'all-fields': {
    measurement: [hex(48, '11'), hex(48, '22')], products: ['Milan', 'Genoa', 'Turin'], signingKey: 'VLEK', allowMaskedChipId: true,
    chipIds: [hex(64, '33')], endorsementKeyFingerprints: [hex(32, '44')], cspIds: ['provider-1', 'provider-2'], requireCrl: true,
    guestPolicy: { debug: 'forbidden', migrateMa: 'any', smt: 'required', singleSocket: 'any', cxlAllowed: 'forbidden', memAes256Xts: 'required', raplDisabled: 'required', ciphertextHidingDram: 'required', pageSwapDisabled: 'any', minAbi: { major: 1, minor: 55 } },
    platformInfo: { smtEnabled: 'required', tsmeEnabled: 'any', eccEnabled: 'required', raplDisabled: 'forbidden', ciphertextHidingEnabled: 'any', aliasCheckComplete: 'required', iommuWriteSafe: 'any', tioEnabled: 'forbidden', allowUnknownBits: true },
    vmpl: 2, minReportVersion: 5, minGuestSvn: 4294967295,
    minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 }, Turin: { fmc: 1, bootloader: 2, tee: 3, snp: 4, microcode: 5 } },
    minLaunchTcb: { Genoa: { snp: 20 } }, minFirmware: { major: 1, minor: 55, build: 21 }, allowProvisionalFirmware: true,
    minLaunchMitVector: '18446744073709551615', minCurrentMitVector: '3',
    reportData: { kind: 'prefix', value: hex(16, 'ab') }, hostData: hex(32, '55'), familyId: hex(16, '66'), imageId: hex(16, '77'), reportId: hex(32, '88'),
    idBlock: { idKeyDigest: hex(48, '99'), authorKeyDigest: hex(48) },
  },
  'comments-ignored': { $comment: 'top', measurement: 'any', vmpl: 'any', guestPolicy: { $comment: 'inner', smt: 'forbidden' }, minTcb: { $comment: 'x', Genoa: { $comment: 'y', snp: 1 } } },
  'id-block-any': { ...ANY, idBlock: 'any' },
  'id-block-without-author': { ...ANY, idBlock: { idKeyDigest: hex(48, '0a') } },
  'report-data-exact': { ...ANY, reportData: { kind: 'exact', value: hex(64, '0b') } },
  'report-data-any': { ...ANY, reportData: { kind: 'any' } },
  'min-firmware-partial': { ...ANY, minFirmware: { minor: 58 } },
  'launch-floor-defaults-to-min-tcb': { ...ANY, minTcb: { Genoa: { snp: 23 } } },
  'not-json': 'not json {',
  'not-object': [1, 2],
  'unknown-field': { ...ANY, foo: 1 },
  'measurement-missing': {},
  'measurement-empty': { measurement: [] },
  'measurement-not-hex': { measurement: ['zz'] },
  'measurement-not-string': { measurement: [1] },
  'measurement-wrong-length': { measurement: [hex(47)] },
  'measurement-other-string': { measurement: 'all' },
  'products-unknown': { ...ANY, products: ['Rome'] },
  'products-empty': { ...ANY, products: [] },
  'signing-key-invalid': { ...ANY, signingKey: 'vcek' },
  'require-crl-not-boolean': { ...ANY, requireCrl: 'yes' },
  'chip-ids-not-array': { ...ANY, chipIds: hex(64) },
  'chip-id-wrong-length': { ...ANY, chipIds: [hex(63)] },
  'fingerprint-not-hex': { ...ANY, endorsementKeyFingerprints: ['xyz'] },
  'csp-ids-empty': { ...ANY, cspIds: [] },
  'csp-id-empty-string': { ...ANY, cspIds: [''] },
  'guest-policy-not-object': { ...ANY, guestPolicy: 'strict' },
  'guest-policy-unknown-field': { ...ANY, guestPolicy: { dbg: 'forbidden' } },
  'guest-policy-bit-invalid': { ...ANY, guestPolicy: { debug: 'maybe' } },
  'min-abi-partial': { ...ANY, guestPolicy: { minAbi: { major: 1 } } },
  'min-abi-range': { ...ANY, guestPolicy: { minAbi: { major: 256, minor: 0 } } },
  'platform-info-bit-invalid': { ...ANY, platformInfo: { tsmeEnabled: true } },
  'allow-unknown-bits-not-boolean': { ...ANY, platformInfo: { allowUnknownBits: 1 } },
  'vmpl-string': { ...ANY, vmpl: 'all' },
  'vmpl-range': { ...ANY, vmpl: 4 },
  'min-report-version-range': { ...ANY, minReportVersion: 6 },
  'min-guest-svn-negative': { ...ANY, minGuestSvn: -1 },
  'min-tcb-unknown-product': { ...ANY, minTcb: { Rome: { snp: 1 } } },
  'min-tcb-unknown-component': { ...ANY, minTcb: { Genoa: { spl: 1 } } },
  'min-tcb-range': { ...ANY, minTcb: { Genoa: { snp: 256 } } },
  'min-launch-tcb-not-object': { ...ANY, minLaunchTcb: 3 },
  'min-firmware-range': { ...ANY, minFirmware: { build: -1 } },
  'mit-vector-number': { ...ANY, minLaunchMitVector: 3 },
  'mit-vector-overflow': { ...ANY, minCurrentMitVector: '18446744073709551616' },
  'report-data-kind-invalid': { ...ANY, reportData: { kind: 'excat', value: hex(64) } },
  'report-data-exact-length': { ...ANY, reportData: { kind: 'exact', value: hex(63) } },
  'report-data-prefix-empty': { ...ANY, reportData: { kind: 'prefix', value: '' } },
  'report-data-any-with-value': { ...ANY, reportData: { kind: 'any', value: hex(1) } },
  'host-data-length': { ...ANY, hostData: hex(31) },
  'family-id-not-hex': { ...ANY, familyId: 'nothex' },
  'id-block-invalid': { ...ANY, idBlock: 'maybe' },
  'id-block-missing-digest': { ...ANY, idBlock: { authorKeyDigest: hex(48) } },
  'id-block-digest-length': { ...ANY, idBlock: { idKeyDigest: hex(47) } },
  // Type confusion and number forms: the same message in every port, whatever its JSON library does with the value.
  'measurement-null': { measurement: null },
  'vmpl-null': { ...ANY, vmpl: null },
  'vmpl-float': { ...ANY, vmpl: 1.5 },
  'vmpl-negative': { ...ANY, vmpl: -1 },
  'vmpl-boolean': { ...ANY, vmpl: true },
  'products-string': { ...ANY, products: 'Genoa' },
  'products-null': { ...ANY, products: null },
  'products-not-strings': { ...ANY, products: [1] },
  'signing-key-null': { ...ANY, signingKey: null },
  'bool-number': { ...ANY, allowMaskedChipId: 1 },
  'chip-ids-null': { ...ANY, chipIds: null },
  'chip-ids-not-strings': { ...ANY, chipIds: [1] },
  'csp-ids-string': { ...ANY, cspIds: 'provider-1' },
  'csp-ids-not-strings': { ...ANY, cspIds: ['provider-1', 1] },
  'guest-policy-array': { ...ANY, guestPolicy: [] },
  'guest-policy-null': { ...ANY, guestPolicy: null },
  'min-abi-null': { ...ANY, guestPolicy: { minAbi: null } },
  'min-abi-array': { ...ANY, guestPolicy: { minAbi: [] } },
  'min-firmware-array': { ...ANY, minFirmware: [] },
  'report-data-array': { ...ANY, reportData: [] },
  'min-abi-string-component': { ...ANY, guestPolicy: { minAbi: { major: '1', minor: 0 } } },
  'platform-info-array': { ...ANY, platformInfo: [] },
  'min-tcb-array': { ...ANY, minTcb: [] },
  'min-tcb-product-null': { ...ANY, minTcb: { Genoa: null } },
  'min-tcb-component-string': { ...ANY, minTcb: { Genoa: { snp: '1' } } },
  'min-tcb-component-float': { ...ANY, minTcb: { Genoa: { snp: 1.5 } } },
  'min-guest-svn-float': { ...ANY, minGuestSvn: 1.5 },
  'min-guest-svn-huge': { ...ANY, minGuestSvn: 1e100 },
  'min-firmware-null': { ...ANY, minFirmware: null },
  'min-firmware-component-string': { ...ANY, minFirmware: { major: '1' } },
  'mit-vector-null': { ...ANY, minLaunchMitVector: null },
  'mit-vector-empty': { ...ANY, minLaunchMitVector: '' },
  'mit-vector-signed': { ...ANY, minLaunchMitVector: '+1' },
  'mit-vector-hex': { ...ANY, minLaunchMitVector: '0x10' },
  'mit-vector-zero': { ...ANY, minLaunchMitVector: '0', minCurrentMitVector: '0' },
  'report-data-string': { ...ANY, reportData: 'any' },
  'report-data-null-kind': { ...ANY, reportData: { kind: null } },
  'report-data-value-null': { ...ANY, reportData: { kind: 'exact', value: null } },
  'report-data-missing-value': { ...ANY, reportData: { kind: 'prefix' } },
  'host-data-null': { ...ANY, hostData: null },
  'host-data-empty': { ...ANY, hostData: '' },
  'host-data-odd-length': { ...ANY, hostData: '0' },
  'host-data-uppercase': { ...ANY, hostData: hex(32, 'AB') },
  'id-block-array': { ...ANY, idBlock: [] },
  'id-block-null': { ...ANY, idBlock: null },
  'id-block-digest-null': { ...ANY, idBlock: { idKeyDigest: null } },
  'id-block-author-null': { ...ANY, idBlock: { idKeyDigest: hex(48), authorKeyDigest: null } },
  'comment-not-string': { $comment: 5, measurement: 'any' },
  'text-trailing-garbage': '{"measurement":"any"} x',
  'text-array': '[]',
  'text-empty': '',
  'text-number-forms': '{"measurement":"any","vmpl":1e0,"minGuestSvn":5.0,"minReportVersion":3.0,"minTcb":{"Genoa":{"snp":2.0}},"guestPolicy":{"minAbi":{"major":1.0,"minor":0}}}',
};

test('cross-port policy vector', () => {
  const actual: Record<string, unknown> = {};
  for (const [name, policy] of Object.entries(CASES)) {
    const parsed = appraisalPolicyFromJson(policy);
    if ('code' in parsed) { actual[name] = { policy, error: parsed.message }; continue; }
    const resolved = resolveAppraisalPolicy(parsed);
    assert.ok(!('code' in resolved), name);
    const json = appraisalPolicyToJson(resolved);
    // The resolved form is itself a valid policy that resolves to the same thing.
    const again = appraisalPolicyFromJson(JSON.stringify(json));
    assert.ok(!('code' in again), name);
    const resolvedAgain = resolveAppraisalPolicy(again);
    assert.deepEqual(resolvedAgain, resolved, name);
    actual[name] = { policy, resolved: json };
  }
  const file = path.join(VECTORS, 'policy.json');
  if (process.env.SNP_VECTORS_REGEN || !fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(actual, null, 1) + '\n');
  assert.deepEqual(actual, JSON.parse(fs.readFileSync(file, 'utf8')));
});
