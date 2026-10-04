// Error codes. The set is shared with the Kotlin port and is not extended per port.
export type ErrorCode =
  // parse
  | 'REPORT_TRUNCATED' | 'REPORT_VERSION_UNSUPPORTED' | 'REPORT_HOST_REQUESTED' | 'REPORT_MALFORMED' | 'REPORT_SIGNATURE_ALGO_UNSUPPORTED'
  // chain
  | 'CERT_MALFORMED' | 'CERT_ALGO_UNSUPPORTED' | 'ARK_UNTRUSTED' | 'CHAIN_SIGNATURE_INVALID' | 'CHAIN_NAME_MISMATCH'
  | 'CERT_NOT_YET_VALID' | 'CERT_EXPIRED' | 'VCEK_EXTENSION_INVALID' | 'PRODUCT_MISMATCH'
  | 'CRL_INVALID' | 'CRL_EXPIRED' | 'CERT_REVOKED'
  // bind
  | 'VCEK_TCB_MISMATCH' | 'VCEK_HWID_MISMATCH' | 'SIGNER_KIND_MISMATCH'
  // signature
  | 'REPORT_SIGNATURE_INVALID'
  // policy
  | 'POLICY_INVALID' | 'POLICY_PRODUCT_NOT_ALLOWED' | 'POLICY_SIGNER_NOT_ALLOWED' | 'POLICY_CHIP_ID_MASKED' | 'POLICY_CHIP_ID_NOT_ALLOWED'
  | 'POLICY_GUEST_POLICY' | 'POLICY_ABI_VERSION' | 'POLICY_PLATFORM_INFO' | 'POLICY_VMPL' | 'POLICY_GUEST_SVN'
  | 'POLICY_TCB_OUT_OF_DATE' | 'POLICY_LAUNCH_TCB_OUT_OF_DATE' | 'POLICY_PROVISIONAL_FIRMWARE' | 'POLICY_FIRMWARE_VERSION'
  | 'POLICY_MITIGATION_VECTOR' | 'POLICY_MEASUREMENT_MISMATCH' | 'POLICY_REPORT_DATA_MISMATCH' | 'POLICY_HOST_DATA_MISMATCH'
  | 'POLICY_FAMILY_ID_MISMATCH' | 'POLICY_IMAGE_ID_MISMATCH' | 'POLICY_REPORT_ID_MISMATCH' | 'POLICY_ID_BLOCK';

export type Stage = 'parse' | 'chain' | 'bind' | 'signature' | 'policy';

export interface Violation {
  code: ErrorCode;
  message: string;
  /** Report or policy field in 56860 snake_case, e.g. "guest_policy.debug". */
  field?: string;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: Violation };

export const ok = <T>(value: T): Result<T> => ({ ok: true, value });

/** Internal: thrown inside a stage, converted to a Result at the stage boundary by `stage()`. */
export class Fail extends Error {
  readonly violation: Violation;
  constructor(violation: Violation) { super(`${violation.code}: ${violation.message}`); this.violation = violation; }
}

export function fail(code: ErrorCode, message: string, field?: string): never {
  throw new Fail(field ? { code, message, field } : { code, message });
}

/** Run `fn`; a `Fail` becomes `{ok:false}`, anything else (a bug) propagates. */
export function stage<T>(fn: () => T): Result<T> {
  try { return ok(fn()); } catch (e) { if (e instanceof Fail) return { ok: false, error: e.violation }; throw e; }
}

export async function stageAsync<T>(fn: () => Promise<T>): Promise<Result<T>> {
  try { return ok(await fn()); } catch (e) { if (e instanceof Fail) return { ok: false, error: e.violation }; throw e; }
}
