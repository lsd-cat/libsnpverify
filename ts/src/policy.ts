// AppraisalPolicy definition, defaults and checks. checkAppraisalPolicy returns all violations.
import type { ErrorCode, Violation } from './errors.ts';
import { equal, hex, isZero, copy } from './bytes.ts';
import { KNOWN_PLATFORM_INFO_BITS, tcbAtLeast, type FirmwareVersion, type Product, type Report, type TcbVersion } from './report.ts';
import type { EndorsementKey } from './chain.ts';
import { PRODUCTS } from './products.ts';
import type { Tcbs } from './bind.ts';

export type Bit = 'required' | 'forbidden' | 'any';
export type ReportDataPin = { kind: 'exact'; value: Uint8Array } | { kind: 'prefix'; value: Uint8Array } | { kind: 'any' };
export type IdBlockPin = 'forbid' | 'any' | { idKeyDigest: Uint8Array; authorKeyDigest?: Uint8Array };

export interface AppraisalPolicy {
  products?: Product[];                        // default ['Genoa', 'Turin']
  signingKey?: 'VCEK' | 'VLEK' | 'any';        // default 'VCEK'
  allowMaskedChipId?: boolean;                 // default false
  chipIds?: Uint8Array[];                      // CHIP_ID allowlist (VCEK, unmasked)
  endorsementKeyFingerprints?: Uint8Array[];   // SHA-256(DER) allowlist of the leaf cert; reissuance changes it
  cspIds?: string[];                            // exact CSP_ID allowlist for VLEK deployments
  requireCrl?: boolean;                        // default false

  guestPolicy?: {
    debug?: Bit; migrateMa?: Bit; smt?: Bit; singleSocket?: Bit; cxlAllowed?: Bit; memAes256Xts?: Bit;
    raplDisabled?: Bit; ciphertextHidingDram?: Bit; pageSwapDisabled?: Bit;
    minAbi?: { major: number; minor: number };
  };                                           // defaults: debug, migrateMa, cxlAllowed forbidden; rest any
  platformInfo?: {
    smtEnabled?: Bit; tsmeEnabled?: Bit; eccEnabled?: Bit; raplDisabled?: Bit; ciphertextHidingEnabled?: Bit;
    aliasCheckComplete?: Bit; iommuWriteSafe?: Bit; tioEnabled?: Bit;
    allowUnknownBits?: boolean;                // default false
  };

  vmpl?: number | 'any';                       // default 0
  minReportVersion?: number;                   // default 2; 3 requires the CPUID product cross-check
  minGuestSvn?: number;
  minTcb?: Partial<Record<Product, Partial<TcbVersion>>>;        // floor for current, committed, reported
  minLaunchTcb?: Partial<Record<Product, Partial<TcbVersion>>>;  // floor for launch; default = minTcb
  minFirmware?: Partial<FirmwareVersion>;
  allowProvisionalFirmware?: boolean;          // default false
  minLaunchMitVector?: bigint; minCurrentMitVector?: bigint;

  measurement: Uint8Array[] | 'any';           // REQUIRED
  reportData?: ReportDataPin;                  // default { kind: 'any' }
  hostData?: Uint8Array; familyId?: Uint8Array; imageId?: Uint8Array; reportId?: Uint8Array;
  idBlock?: IdBlockPin;                        // default 'forbid'
}

/** AppraisalPolicy with defaults filled in; recorded in the result as appraisalPolicy. */
export type ResolvedAppraisalPolicy = Required<Omit<AppraisalPolicy, 'hostData' | 'familyId' | 'imageId' | 'reportId' | 'minLaunchMitVector' | 'minCurrentMitVector' | 'chipIds' | 'endorsementKeyFingerprints' | 'cspIds'>>
  & Pick<AppraisalPolicy, 'hostData' | 'familyId' | 'imageId' | 'reportId' | 'minLaunchMitVector' | 'minCurrentMitVector' | 'chipIds' | 'endorsementKeyFingerprints' | 'cspIds'>;

class Invalid extends Error {}
const need = (cond: boolean, msg: string) => { if (!cond) throw new Invalid(msg); };
const isObject = (v: unknown): v is object => v !== null && typeof v === 'object' && !Array.isArray(v);
const len = (v: Uint8Array | undefined, n: number, what: string) => need(v === undefined || (v instanceof Uint8Array && v.length === n), `policy.${what} must be ${n} bytes`);
const requiredLen = (v: unknown, n: number, what: string) => need(v instanceof Uint8Array && v.length === n, `policy.${what} must be ${n} bytes`);
const keys = (v: object, allowed: readonly string[], what: string) => need(Object.keys(v).every(k => allowed.includes(k)), `policy${what && '.' + what} has unknown fields`);
const uint = (v: number | undefined, max: number, what: string) => need(v === undefined || (Number.isInteger(v) && v >= 0 && v <= max), `policy.${what} must be an integer in 0..${max}`);
const bool = (v: boolean | undefined, what: string) => need(v === undefined || typeof v === 'boolean', `policy.${what} must be boolean`);
const bits = (v: object, names: readonly string[], what: string) => {
  keys(v, names, what);
  for (const [k, x] of Object.entries(v)) if (k !== 'minAbi' && k !== 'allowUnknownBits') need(x === 'required' || x === 'forbidden' || x === 'any', `policy.${what}.${k} is not a Bit`);
};
const bytes = copy;
const PRODUCT_NAMES = Object.keys(PRODUCTS);
const POLICY_KEYS = [
  'measurement', 'products', 'signingKey', 'allowMaskedChipId', 'chipIds', 'endorsementKeyFingerprints', 'cspIds', 'requireCrl',
  'guestPolicy', 'platformInfo', 'vmpl', 'minReportVersion', 'minGuestSvn', 'minTcb', 'minLaunchTcb', 'minFirmware', 'allowProvisionalFirmware',
  'minLaunchMitVector', 'minCurrentMitVector', 'reportData', 'hostData', 'familyId', 'imageId', 'reportId', 'idBlock',
];

/** Fill defaults and validate shapes. A malformed policy yields a POLICY_INVALID violation. */
export function resolveAppraisalPolicy(p: AppraisalPolicy): ResolvedAppraisalPolicy | Violation {
  try {
    need(isObject(p), 'policy must be an object');
    keys(p, POLICY_KEYS, '');
    need(p.measurement !== undefined, 'policy.measurement is required: an allowlist or the explicit string "any"');
    if (p.measurement !== 'any') { need(Array.isArray(p.measurement) && p.measurement.length > 0, 'policy.measurement must be a nonempty array or "any"'); for (const m of p.measurement) requiredLen(m, 48, 'measurement[]'); }
    if (p.reportData !== undefined) {
      need(isObject(p.reportData), 'policy.reportData must be an object');
      need(['any', 'exact', 'prefix'].includes(p.reportData.kind), 'policy.reportData.kind is invalid');
      keys(p.reportData, p.reportData.kind === 'any' ? ['kind'] : ['kind','value'], 'reportData');
      if (p.reportData.kind !== 'any') {
        need(p.reportData.value instanceof Uint8Array && p.reportData.value.length >= 1 && p.reportData.value.length <= 64, 'policy.reportData.value must be 1..64 bytes');
        if (p.reportData.kind === 'exact') len(p.reportData.value, 64, 'reportData.value');
      }
    }
    len(p.hostData, 32, 'hostData'); len(p.familyId, 16, 'familyId'); len(p.imageId, 16, 'imageId'); len(p.reportId, 32, 'reportId');
    if (p.products !== undefined) need(Array.isArray(p.products) && p.products.length > 0 && p.products.every(x => PRODUCT_NAMES.includes(x)), 'policy.products must be a nonempty Product list');
    need(p.signingKey === undefined || ['VCEK','VLEK','any'].includes(p.signingKey), 'policy.signingKey is invalid');
    bool(p.allowMaskedChipId, 'allowMaskedChipId'); bool(p.requireCrl, 'requireCrl'); bool(p.allowProvisionalFirmware, 'allowProvisionalFirmware');
    if (p.chipIds !== undefined) need(Array.isArray(p.chipIds), 'policy.chipIds must be an array');
    if (p.endorsementKeyFingerprints !== undefined) need(Array.isArray(p.endorsementKeyFingerprints), 'policy.endorsementKeyFingerprints must be an array');
    for (const c of p.chipIds ?? []) requiredLen(c, 64, 'chipIds[]');
    for (const f of p.endorsementKeyFingerprints ?? []) requiredLen(f, 32, 'endorsementKeyFingerprints[]');
    if (p.cspIds !== undefined) need(Array.isArray(p.cspIds) && p.cspIds.length > 0 && p.cspIds.every(x => typeof x === 'string' && x.length > 0), 'policy.cspIds must be nonempty strings');
    if (p.idBlock !== undefined) {
      need(p.idBlock === 'forbid' || p.idBlock === 'any' || isObject(p.idBlock), 'policy.idBlock is invalid');
      if (typeof p.idBlock === 'object') {
        keys(p.idBlock, ['idKeyDigest', 'authorKeyDigest'], 'idBlock');
        need(p.idBlock.idKeyDigest !== undefined, 'policy.idBlock.idKeyDigest is required');
        len(p.idBlock.idKeyDigest, 48, 'idBlock.idKeyDigest');
        len(p.idBlock.authorKeyDigest, 48, 'idBlock.authorKeyDigest');
      }
    }
    if (p.guestPolicy !== undefined) {
      need(isObject(p.guestPolicy), 'policy.guestPolicy must be an object');
      bits(p.guestPolicy, ['debug','migrateMa','smt','singleSocket','cxlAllowed','memAes256Xts','raplDisabled','ciphertextHidingDram','pageSwapDisabled','minAbi'], 'guestPolicy');
      if (p.guestPolicy.minAbi !== undefined) {
        const abi = p.guestPolicy.minAbi;
        need(isObject(abi), 'policy.guestPolicy.minAbi must be an object');
        keys(abi, ['major', 'minor'], 'guestPolicy.minAbi');
        need(abi.major !== undefined && abi.minor !== undefined, 'policy.guestPolicy.minAbi requires major and minor');
        uint(abi.major, 255, 'guestPolicy.minAbi.major');
        uint(abi.minor, 255, 'guestPolicy.minAbi.minor');
      }
    }
    if (p.platformInfo !== undefined) {
      need(isObject(p.platformInfo), 'policy.platformInfo must be an object');
      bits(p.platformInfo, ['smtEnabled','tsmeEnabled','eccEnabled','raplDisabled','ciphertextHidingEnabled','aliasCheckComplete','iommuWriteSafe','tioEnabled','allowUnknownBits'], 'platformInfo');
      bool(p.platformInfo.allowUnknownBits, 'platformInfo.allowUnknownBits');
    }
    if (typeof p.vmpl === 'number') need(Number.isInteger(p.vmpl) && p.vmpl >= 0 && p.vmpl <= 3, 'policy.vmpl must be 0..3');
    else need(p.vmpl === undefined || p.vmpl === 'any', 'policy.vmpl must be 0..3 or any');
    need(p.minReportVersion === undefined || (Number.isInteger(p.minReportVersion) && p.minReportVersion >= 2 && p.minReportVersion <= 5), 'policy.minReportVersion must be 2..5');
    uint(p.minGuestSvn, 0xffffffff, 'minGuestSvn');
    for (const [what, table] of [['minTcb', p.minTcb], ['minLaunchTcb', p.minLaunchTcb]] as const) if (table !== undefined) {
      need(isObject(table), `policy.${what} must be an object`);
      keys(table, PRODUCT_NAMES, what);
      for (const [product, floor] of Object.entries(table)) {
        need(isObject(floor), `policy.${what}.${product} must be an object`);
        keys(floor, ['bootloader','tee','snp','microcode','fmc'], `${what}.${product}`);
        for (const [k, x] of Object.entries(floor)) uint(x as number, 255, `${what}.${product}.${k}`);
      }
    }
    if (p.minFirmware !== undefined) {
      need(isObject(p.minFirmware), 'policy.minFirmware must be an object');
      keys(p.minFirmware, ['major', 'minor', 'build'], 'minFirmware');
      for (const [k, x] of Object.entries(p.minFirmware)) {
        need(x !== undefined, `policy.minFirmware.${k} cannot be undefined`);
        uint(x as number, 255, `minFirmware.${k}`);
      }
    }
    for (const [k, x] of [['minLaunchMitVector', p.minLaunchMitVector], ['minCurrentMitVector', p.minCurrentMitVector]] as const) need(x === undefined || (typeof x === 'bigint' && x >= 0n && x <= 0xffffffffffffffffn), `policy.${k} must be uint64`);
    const minTcb = p.minTcb ?? {};
    return {
      products: [...(p.products ?? ['Genoa', 'Turin'])],
      signingKey: p.signingKey ?? 'VCEK',
      allowMaskedChipId: p.allowMaskedChipId ?? false,
      chipIds: p.chipIds?.map(bytes),
      endorsementKeyFingerprints: p.endorsementKeyFingerprints?.map(bytes),
      cspIds: p.cspIds && [...p.cspIds],
      requireCrl: p.requireCrl ?? false,
      guestPolicy: { ...p.guestPolicy, debug: p.guestPolicy?.debug ?? 'forbidden', migrateMa: p.guestPolicy?.migrateMa ?? 'forbidden', cxlAllowed: p.guestPolicy?.cxlAllowed ?? 'forbidden', memAes256Xts: p.guestPolicy?.memAes256Xts ?? 'any' },
      platformInfo: { allowUnknownBits: false, ...p.platformInfo },
      vmpl: p.vmpl ?? 0,
      minReportVersion: p.minReportVersion ?? 2,
      minGuestSvn: p.minGuestSvn ?? 0,
      minTcb: Object.fromEntries(Object.entries(minTcb).map(([k,v]) => [k, {...v}])),
      minLaunchTcb: Object.fromEntries(Object.entries(p.minLaunchTcb ?? minTcb).map(([k,v]) => [k, {...v}])),
      minFirmware: { major: 0, minor: 0, build: 0, ...p.minFirmware },
      allowProvisionalFirmware: p.allowProvisionalFirmware ?? false,
      minLaunchMitVector: p.minLaunchMitVector, minCurrentMitVector: p.minCurrentMitVector,
      measurement: p.measurement === 'any' ? 'any' : p.measurement.map(bytes),
      reportData: !p.reportData || p.reportData.kind === 'any' ? { kind: 'any' } : { kind: p.reportData.kind, value: bytes(p.reportData.value) },
      hostData: p.hostData && bytes(p.hostData), familyId: p.familyId && bytes(p.familyId), imageId: p.imageId && bytes(p.imageId), reportId: p.reportId && bytes(p.reportId),
      idBlock: p.idBlock === undefined ? 'forbid'
        : typeof p.idBlock === 'string' ? p.idBlock
        : { idKeyDigest: bytes(p.idBlock.idKeyDigest), authorKeyDigest: p.idBlock.authorKeyDigest && bytes(p.idBlock.authorKeyDigest) },
    };
  } catch (e) {
    if (e instanceof Invalid) return { code: 'POLICY_INVALID', message: e.message };
    throw e;
  }
}

export interface AppraisalContext { tcb: Tcbs; crlPresent: boolean; leafFingerprint: Uint8Array }

/** Check a signature-verified report against the policy. Empty array = satisfied. */
export function checkAppraisalPolicy(report: Report, ek: EndorsementKey, ctx: AppraisalContext, policy: AppraisalPolicy): Violation[] {
  const p = resolveAppraisalPolicy(policy);
  if ('code' in p) return [p];
  return checkResolvedAppraisalPolicy(report, ek, ctx, p);
}

export function checkResolvedAppraisalPolicy(report: Report, ek: EndorsementKey, ctx: AppraisalContext, p: ResolvedAppraisalPolicy): Violation[] {
  const v: Violation[] = [];
  const bad = (code: ErrorCode, message: string, field?: string) => v.push(field ? { code, message, field } : { code, message });
  const bit = (code: ErrorCode, field: string, want: Bit | undefined, got: boolean) => {
    if (want === 'required' && !got) bad(code, `${field} is required but not set`, field);
    if (want === 'forbidden' && got) bad(code, `${field} is set but forbidden`, field);
  };
  const pin = (code: ErrorCode, field: string, want: Uint8Array | undefined, got: Uint8Array) => { if (want && !equal(want, got)) bad(code, `${field} ${hex(got)} != expected ${hex(want)}`, field); };

  // Who signed, on what.
  if (!p.products.includes(ek.product)) bad('POLICY_PRODUCT_NOT_ALLOWED', `product ${ek.product} not in [${p.products.join(', ')}]`);
  if (p.signingKey !== 'any' && ek.kind !== p.signingKey) bad('POLICY_SIGNER_NOT_ALLOWED', `signed by ${ek.kind}, policy requires ${p.signingKey}`, 'signer_info.signing_key');
  if (ek.kind === 'VCEK' && isZero(report.chipId) && !p.allowMaskedChipId) bad('POLICY_CHIP_ID_MASKED', 'CHIP_ID is masked; chip identity is not in the report', 'chip_id'); // VLEK reports carry no CHIP_ID by design
  if (p.chipIds && !p.chipIds.some(c => equal(c, report.chipId))) bad('POLICY_CHIP_ID_NOT_ALLOWED', `chip_id ${hex(report.chipId)} not in allowlist`, 'chip_id');
  if (p.endorsementKeyFingerprints && !p.endorsementKeyFingerprints.some(f => equal(f, ctx.leafFingerprint))) bad('POLICY_CHIP_ID_NOT_ALLOWED', `${ek.kind} fingerprint ${hex(ctx.leafFingerprint)} not in allowlist`);
  if (p.cspIds && (ek.kind !== 'VLEK' || !ek.cspId || !p.cspIds.includes(ek.cspId))) bad('POLICY_SIGNER_NOT_ALLOWED', 'VLEK CSP_ID is not in the allowed list', 'endorsement_key.csp_id');
  if (p.requireCrl && !ctx.crlPresent) bad('POLICY_INVALID', 'policy requires a CRL but none was supplied');

  // Guest policy.
  const gp = report.policy, g = p.guestPolicy;
  bit('POLICY_GUEST_POLICY', 'guest_policy.debug', g.debug, gp.debug);
  bit('POLICY_GUEST_POLICY', 'guest_policy.migrate_ma', g.migrateMa, gp.migrateMa);
  bit('POLICY_GUEST_POLICY', 'guest_policy.smt', g.smt, gp.smt);
  bit('POLICY_GUEST_POLICY', 'guest_policy.single_socket', g.singleSocket, gp.singleSocket);
  bit('POLICY_GUEST_POLICY', 'guest_policy.cxl_allow', g.cxlAllowed, gp.cxlAllowed);
  bit('POLICY_GUEST_POLICY', 'guest_policy.mem_aes_256_xts', g.memAes256Xts, gp.memAes256Xts);
  bit('POLICY_GUEST_POLICY', 'guest_policy.rapl_dis', g.raplDisabled, gp.raplDisabled);
  bit('POLICY_GUEST_POLICY', 'guest_policy.ciphertext_hiding_dram', g.ciphertextHidingDram, gp.ciphertextHidingDram);
  bit('POLICY_GUEST_POLICY', 'guest_policy.page_swap_disable', g.pageSwapDisabled, gp.pageSwapDisabled);
  if (g.minAbi && (gp.abiMajor < g.minAbi.major || (gp.abiMajor === g.minAbi.major && gp.abiMinor < g.minAbi.minor)))
    bad('POLICY_ABI_VERSION', `guest_policy ABI ${gp.abiMajor}.${gp.abiMinor} < ${g.minAbi.major}.${g.minAbi.minor}`, 'guest_policy.abi_major');

  // Platform info.
  const pi = report.platformInfo, q = p.platformInfo;
  bit('POLICY_PLATFORM_INFO', 'platform_info.smt_en', q.smtEnabled, pi.smtEnabled);
  bit('POLICY_PLATFORM_INFO', 'platform_info.tsme_en', q.tsmeEnabled, pi.tsmeEnabled);
  bit('POLICY_PLATFORM_INFO', 'platform_info.ecc_en', q.eccEnabled, pi.eccEnabled);
  bit('POLICY_PLATFORM_INFO', 'platform_info.rapl_dis', q.raplDisabled, pi.raplDisabled);
  bit('POLICY_PLATFORM_INFO', 'platform_info.ciphertext_hiding_dram_en', q.ciphertextHidingEnabled, pi.ciphertextHidingEnabled);
  bit('POLICY_PLATFORM_INFO', 'platform_info.alias_check_complete', q.aliasCheckComplete, pi.aliasCheckComplete);
  bit('POLICY_PLATFORM_INFO', 'platform_info.iommu_write_safe', q.iommuWriteSafe, pi.iommuWriteSafe);
  bit('POLICY_PLATFORM_INFO', 'platform_info.tio_en', q.tioEnabled, pi.tioEnabled);
  if (!q.allowUnknownBits && (pi.raw & ~KNOWN_PLATFORM_INFO_BITS) !== 0n) bad('POLICY_PLATFORM_INFO', `platform_info has unknown bits: 0x${pi.raw.toString(16)}`, 'platform_info');

  if (report.version < p.minReportVersion) bad('POLICY_INVALID', `report version ${report.version} < required ${p.minReportVersion}`, 'version');
  if (p.vmpl !== 'any' && report.vmpl !== p.vmpl) bad('POLICY_VMPL', `vmpl ${report.vmpl} != ${p.vmpl}`, 'vmpl');
  if (report.guestSvn < p.minGuestSvn) bad('POLICY_GUEST_SVN', `guest_svn ${report.guestSvn} < ${p.minGuestSvn}`, 'guest_svn');

  // TCB floors, per product.
  const floor = p.minTcb[ek.product] ?? {}, launchFloor = p.minLaunchTcb[ek.product] ?? {};
  for (const name of ['current', 'committed', 'reported'] as const) {
    if (!tcbAtLeast(ctx.tcb[name], floor)) bad('POLICY_TCB_OUT_OF_DATE', `${name}_tcb ${fmtTcb(ctx.tcb[name])} below minimum ${fmtTcb(floor)}`, `${name}_tcb`);
  }
  if (!tcbAtLeast(ctx.tcb.launch, launchFloor)) bad('POLICY_LAUNCH_TCB_OUT_OF_DATE', `launch_tcb ${fmtTcb(ctx.tcb.launch)} below minimum ${fmtTcb(launchFloor)}`, 'launch_tcb');
  if (!tcbAtLeast(ctx.tcb.current, ek.tcb)) bad('POLICY_TCB_OUT_OF_DATE', `current_tcb ${fmtTcb(ctx.tcb.current)} below the endorsement key TCB ${fmtTcb(ek.tcb)}`, 'current_tcb');

  // Firmware.
  for (const name of ['current', 'committed'] as const) {
    const fw = report[`${name}Version`];
    if (!fwAtLeast(fw, p.minFirmware)) bad('POLICY_FIRMWARE_VERSION', `${name} firmware ${fw.major}.${fw.minor}.${fw.build} below minimum`, `${name}_build`);
  }
  if (!p.allowProvisionalFirmware) {
    const c = report.currentVersion, m = report.committedVersion;
    if (c.major !== m.major || c.minor !== m.minor || c.build !== m.build || report.currentTcb !== report.committedTcb)
      bad('POLICY_PROVISIONAL_FIRMWARE', 'committed firmware/TCB differs from current (uncommitted update; rollback possible)', 'committed_tcb');
  }
  if (p.minLaunchMitVector !== undefined && ((report.launchMitVector ?? 0n) & p.minLaunchMitVector) !== p.minLaunchMitVector) bad('POLICY_MITIGATION_VECTOR', 'launch_mit_vector lacks required bits', 'launch_mit_vector');
  if (p.minCurrentMitVector !== undefined && ((report.currentMitVector ?? 0n) & p.minCurrentMitVector) !== p.minCurrentMitVector) bad('POLICY_MITIGATION_VECTOR', 'current_mit_vector lacks required bits', 'current_mit_vector');

  // Identity pins.
  if (p.measurement !== 'any' && !p.measurement.some(m => equal(m, report.measurement))) bad('POLICY_MEASUREMENT_MISMATCH', `measurement ${hex(report.measurement)} not in allowlist`, 'measurement');
  const rd = p.reportData;
  if (rd.kind === 'exact') pin('POLICY_REPORT_DATA_MISMATCH', 'report_data', rd.value, report.reportData);
  if (rd.kind === 'prefix' && !equal(rd.value, report.reportData.subarray(0, rd.value.length))) bad('POLICY_REPORT_DATA_MISMATCH', `report_data does not start with ${hex(rd.value)}`, 'report_data');
  pin('POLICY_HOST_DATA_MISMATCH', 'host_data', p.hostData, report.hostData);
  pin('POLICY_FAMILY_ID_MISMATCH', 'family_id', p.familyId, report.familyId);
  pin('POLICY_IMAGE_ID_MISMATCH', 'image_id', p.imageId, report.imageId);
  pin('POLICY_REPORT_ID_MISMATCH', 'report_id', p.reportId, report.reportId);
  if (p.idBlock === 'forbid') {
    if (report.signerInfo.authorKeyEnabled) bad('POLICY_ID_BLOCK', 'author_key_en set but ID block forbidden', 'signer_info.author_key_en');
    if (report.idKeyDigest.some(x => x)) bad('POLICY_ID_BLOCK', 'id_key_digest nonzero but ID block forbidden', 'id_key_digest');
    if (report.authorKeyDigest.some(x => x)) bad('POLICY_ID_BLOCK', 'author_key_digest nonzero but ID block forbidden', 'author_key_digest');
  } else if (typeof p.idBlock === 'object') {
    pin('POLICY_ID_BLOCK', 'id_key_digest', p.idBlock.idKeyDigest, report.idKeyDigest);
    if (p.idBlock.authorKeyDigest) {
      const wantAuthor = p.idBlock.authorKeyDigest.some(x => x); // all-zero pin means "no author key"
      if (report.signerInfo.authorKeyEnabled !== wantAuthor) bad('POLICY_ID_BLOCK', `author_key_en is ${report.signerInfo.authorKeyEnabled ? 1 : 0}, pinned author_key_digest implies ${wantAuthor ? 1 : 0}`, 'author_key_digest');
      pin('POLICY_ID_BLOCK', 'author_key_digest', p.idBlock.authorKeyDigest, report.authorKeyDigest);
    }
  }
  return v;
}

function fwAtLeast(fw: FirmwareVersion, min: Partial<FirmwareVersion>): boolean {
  const a = [fw.major, fw.minor, fw.build], b = [min.major ?? 0, min.minor ?? 0, min.build ?? 0];
  for (let i = 0; i < 3; i++) { if (a[i] > b[i]) return true; if (a[i] < b[i]) return false; }
  return true;
}

function fmtTcb(t: Partial<TcbVersion>): string {
  const f = (x?: number) => (x === undefined ? '*' : String(x));
  return `bl=${f(t.bootloader)} tee=${f(t.tee)} snp=${f(t.snp)} ucode=${f(t.microcode)}${t.fmc !== undefined ? ` fmc=${t.fmc}` : ''}`;
}
