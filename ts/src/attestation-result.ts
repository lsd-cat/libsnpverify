// The result record (SPEC §6) and its JSON projection.
import { hex } from './bytes.ts';
import type { Report, Product, GuestPolicy, PlatformInfo, FirmwareVersion, TcbVersion, SigningKey, SignerInfo } from './report.ts';
import type { Chain, CrlInfo } from './chain.ts';
import type { Certificate } from './der.ts';
import type { Tcbs } from './bind.ts';
import type { ResolvedAppraisalPolicy } from './policy.ts';
import type { CryptoProvider } from './crypto.ts';

export interface CertSummary { sha256: Uint8Array; serial: Uint8Array; subjectCn: string; notBefore: number; notAfter: number }

export interface AttestationResult {
  identity: {
    chipId: Uint8Array; reportId: Uint8Array; reportIdMa: Uint8Array; measurement: Uint8Array; hostData: Uint8Array; reportData: Uint8Array;
    familyId: Uint8Array; imageId: Uint8Array; guestSvn: number; vmpl: number;
  };
  platform: {
    product: Product; productName: string; cpuid?: Report['cpuid'];
    guestPolicy: GuestPolicy; platformInfo: PlatformInfo; tcb: Tcbs;
    firmware: { current: FirmwareVersion; committed: FirmwareVersion };
    mitVectors?: { launch: bigint; current: bigint };
    signer: SignerInfo;
    idKeyDigest: Uint8Array; authorKeyDigest: Uint8Array;
  };
  evidence: {
    reportVersion: number; reportSha256: Uint8Array; signature: { r: Uint8Array; s: Uint8Array };
  };
  endorsements: {
    endorsementKey: CertSummary & { kind: SigningKey; hwid?: Uint8Array; cspId?: string; tcb: TcbVersion };
    ask: CertSummary; ark: CertSummary; crl?: CrlInfo;
  };
  appraisalPolicy: ResolvedAppraisalPolicy;
  appraisedAt: number;
}

export async function buildAttestationResult(report: Report, chain: Chain, tcb: Tcbs, policy: ResolvedAppraisalPolicy, now: number, crypto: CryptoProvider): Promise<AttestationResult> {
  const sum = async (c: Certificate): Promise<CertSummary> => ({ sha256: await crypto.sha256(c.der), serial: c.serial, subjectCn: c.subjectCN, notBefore: c.notBefore, notAfter: c.notAfter });
  const ek = chain.leaf;
  return {
    identity: { chipId: report.chipId, reportId: report.reportId, reportIdMa: report.reportIdMa, measurement: report.measurement, hostData: report.hostData, reportData: report.reportData,
      familyId: report.familyId, imageId: report.imageId, guestSvn: report.guestSvn, vmpl: report.vmpl },
    platform: { product: ek.product, productName: ek.productName, cpuid: report.cpuid, guestPolicy: report.policy, platformInfo: report.platformInfo, tcb,
      firmware: { current: report.currentVersion, committed: report.committedVersion },
      mitVectors: report.launchMitVector !== undefined ? { launch: report.launchMitVector, current: report.currentMitVector! } : undefined,
      signer: report.signerInfo, idKeyDigest: report.idKeyDigest, authorKeyDigest: report.authorKeyDigest },
    evidence: { reportVersion: report.version, reportSha256: await crypto.sha256(report.raw), signature: report.signature },
    endorsements: {
      endorsementKey: { ...(await sum(ek.cert)), kind: ek.kind, hwid: ek.hwid, cspId: ek.cspId, tcb: ek.tcb },
      ask: await sum(chain.intermediate), ark: await sum(chain.root), crl: chain.crl },
    appraisalPolicy: policy,
    appraisedAt: now,
  };
}

/** JSON-safe projection: bytes as lowercase hex, bigints as decimal strings. Same shape in the Kotlin port. */
export function toJson(value: unknown): unknown {
  if (value instanceof Uint8Array) return hex(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(toJson);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = toJson(v);
    return out;
  }
  return value;
}
