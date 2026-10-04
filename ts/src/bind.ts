// Bind the endorsement key to the report, then verify the report signature.
import { fail, stage, stageAsync, type Result } from './errors.ts';
import { equal, hex, isZero } from './bytes.ts';
import { decodeTcb, tcbEqual, type Report, type TcbVersion } from './report.ts';
import { PRODUCTS, productFromCpuid } from './products.ts';
import type { EndorsementKey } from './chain.ts';
import type { CryptoProvider } from './crypto.ts';

export interface Tcbs { current: TcbVersion; committed: TcbVersion; reported: TcbVersion; launch: TcbVersion }

/** The key must derive from exactly REPORTED_TCB, on this chip (unless masked), for the product the CPU reports. */
export function bindEndorsement(report: Report, ek: EndorsementKey): Result<Tcbs> {
  return stage(() => {
    if (ek.kind !== report.signerInfo.signingKey) fail('SIGNER_KIND_MISMATCH', `report says ${report.signerInfo.signingKey}, certificate is a ${ek.kind}`, 'signer_info.signing_key');
    const layout = PRODUCTS[ek.product].tcbLayout;
    const tcb: Tcbs = { current: decodeTcb(report.currentTcb, layout), committed: decodeTcb(report.committedTcb, layout), reported: decodeTcb(report.reportedTcb, layout), launch: decodeTcb(report.launchTcb, layout) };
    if (!tcbEqual(tcb.reported, ek.tcb)) fail('VCEK_TCB_MISMATCH', `reported_tcb does not match the ${ek.kind} certificate TCB`, 'reported_tcb');
    // A zero CHIP_ID means the host masked it; there is nothing to compare with the HWID.
    if (ek.kind === 'VCEK' && !isZero(report.chipId)) {
      const hwid = ek.hwid!, chip = report.chipId.subarray(0, hwid.length);
      if (!equal(chip, hwid)) fail('VCEK_HWID_MISMATCH', `chip_id ${hex(chip)} != VCEK HWID ${hex(hwid)}`, 'chip_id');
    }
    if (report.cpuid) {
      const fromCpu = productFromCpuid(report.cpuid.family, report.cpuid.model);
      if (fromCpu !== ek.product) fail('PRODUCT_MISMATCH', `CPUID family 0x${report.cpuid.family.toString(16)} model 0x${report.cpuid.model.toString(16)} is ${fromCpu ?? 'unknown'}, certificate says ${ek.product}`, 'cpuid_fam_id');
    }
    return tcb;
  });
}

export function verifyReportSignature(report: Report, ek: EndorsementKey, crypto: CryptoProvider): Promise<Result<void>> {
  return stageAsync(async () => {
    if (!(await crypto.verifyEcdsaP384(ek.cert.spki, report.signedBytes, report.signature.r, report.signature.s))) fail('REPORT_SIGNATURE_INVALID', `report signature does not verify with the ${ek.kind}`, 'signature');
  });
}
