// libsnpverify-ts: AMD SEV-SNP attestation report verification.
//
//   const verifier = new SnpVerifier();                     // WebCrypto, embedded AMD roots
//   const result = await verifier.verify({ report, vcek, crl, now, policy: { measurement: [m], reportData: { kind: 'prefix', value: nonce } } });
//   if (result.ok) use(result.attestation) else show(result.violations)
//
// Inputs: report bytes, AMD certificates, optional CRL, verification time, policy. No network, no clock. See SPEC.md.
import { stage, type Result, type Stage, type Violation } from './errors.ts';
import { parseReport, type Report } from './report.ts';
import { verifyChain, checkCollateralSizes, type Chain } from './chain.ts';
import { bindEndorsement, verifyReportSignature, type Tcbs } from './bind.ts';
import { checkResolvedPolicy, resolvePolicy, type Policy } from './policy.ts';
import { buildAttestation, type Attestation } from './attestation.ts';
import { webCrypto, type CryptoProvider } from './crypto.ts';
import { copy } from './bytes.ts';

export type { ErrorCode, Stage, Violation, Result } from './errors.ts';
export {
  parseReport, REPORT_SIZE,
  type Report, type Product, type TcbVersion, type GuestPolicy, type PlatformInfo, type SignerInfo, type SigningKey, type FirmwareVersion, type TcbLayout,
} from './report.ts';
export { resolvePolicy, checkPolicy, type Policy, type ResolvedPolicy, type PolicyContext, type Bit, type ReportDataPin, type IdBlockPin } from './policy.ts';
export { baseVcekPolicy, baseVlekPolicy, type BasePolicyConfig } from './base-policies.ts';
export { PRODUCTS, productFromName, productFromCpuid, type ProductInfo } from './products.ts';
export { verifyChain, type ChainInput, type EndorsementKey, type Chain, type CrlInfo } from './chain.ts';
export { bindEndorsement, verifyReportSignature, type Tcbs } from './bind.ts';
export { parseCertificate, parseCrl, type Certificate, type Crl } from './der.ts';
export { embeddedRoots } from './roots.ts';
export { webCrypto, type CryptoProvider } from './crypto.ts';
export { toJson, type Attestation, type CertSummary } from './attestation.ts';
export { hex, fromHex, fromBase64, pemToDer, equal } from './bytes.ts';

export interface VerifyInput {
  report: Uint8Array;      // exactly 1184 bytes
  vcek: Uint8Array;        // VCEK or VLEK, DER
  ask?: Uint8Array;        // ASK or ASVK, DER; default embedded for the product
  ark?: Uint8Array;        // ARK, DER; default embedded for the product
  crl?: Uint8Array;        // ARK-signed CRL, DER
  now: number;             // verification time, unix seconds
  policy: Policy;
}

export type VerifyResult =
  | { ok: true; attestation: Attestation }
  | { ok: false; stage: Stage; violations: Violation[]; partial?: { report?: Report; chain?: Chain; tcb?: Tcbs } };

export interface VerifierOptions {
  /** Default: WebCrypto. */
  crypto?: CryptoProvider;
  /** DER ARKs the verifier trusts; the root used must be byte-equal to one. Default: embedded ARK of the leaf's product. */
  trustedArks?: Uint8Array[];
}

export class SnpVerifier {
  private readonly crypto: CryptoProvider;
  private readonly trustedArks?: Uint8Array[];

  constructor(options: VerifierOptions = {}) {
    this.crypto = options.crypto ?? webCrypto;
    this.trustedArks = options.trustedArks?.map(copy);
  }

  verifyChain(input: Parameters<typeof verifyChain>[0]): Promise<Result<Chain>> { return verifyChain(input, this.trustedArks, this.crypto); }
  verifyReportSignature(report: Report, chain: Chain): Promise<Result<void>> { return verifyReportSignature(report, chain.leaf, this.crypto); }

  async verify(input: VerifyInput): Promise<VerifyResult> {
    const resolved = resolvePolicy(input.policy);
    if ('code' in resolved) return { ok: false, stage: 'policy', violations: [resolved] };
    // Parse the report (it checks its length before copying), check collateral sizes, then copy every input before any await.
    const parsed = parseReport(input.report);
    if (!parsed.ok) return { ok: false, stage: 'parse', violations: [parsed.error] };
    const report = parsed.value;
    const sized = stage(() => checkCollateralSizes({ leaf: input.vcek, intermediate: input.ask, root: input.ark, crl: input.crl }));
    if (!sized.ok) return { ok: false, stage: 'chain', violations: [sized.error] };
    const evidence = {
      vcek: copy(input.vcek),
      ask: input.ask && copy(input.ask), ark: input.ark && copy(input.ark),
      crl: input.crl && copy(input.crl), now: input.now,
    };
    const chain = await this.verifyChain({ leaf: evidence.vcek, intermediate: evidence.ask, root: evidence.ark, crl: evidence.crl, now: evidence.now });
    if (!chain.ok) return { ok: false, stage: 'chain', violations: [chain.error], partial: { report } };
    const bound = bindEndorsement(report, chain.value.leaf);
    if (!bound.ok) return { ok: false, stage: 'bind', violations: [bound.error], partial: { report, chain: chain.value } };
    const sig = await this.verifyReportSignature(report, chain.value);
    if (!sig.ok) return { ok: false, stage: 'signature', violations: [sig.error], partial: { report, chain: chain.value, tcb: bound.value } };
    const leafFingerprint = await this.crypto.sha256(chain.value.leaf.cert.der);
    const violations = checkResolvedPolicy(report, chain.value.leaf, { tcb: bound.value, crlPresent: chain.value.crl !== undefined, leafFingerprint }, resolved);
    if (violations.length) return { ok: false, stage: 'policy', violations, partial: { report, chain: chain.value, tcb: bound.value } };
    return { ok: true, attestation: await buildAttestation(report, chain.value, bound.value, resolved, evidence.now, this.crypto) };
  }
}
