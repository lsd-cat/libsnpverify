// JSON form of the appraisal policy: the shape toJson() renders as attestationResult.appraisalPolicy, read back.
// Bytes are lowercase hex, 64-bit values decimal strings, enumerations strings; a "$comment" key in any object is ignored.
import { fromHex } from './bytes.ts';
import type { Violation } from './errors.ts';
import { resolveAppraisalPolicy, type AppraisalPolicy, type ResolvedAppraisalPolicy } from './policy.ts';
import { toJson } from './attestation-result.ts';

class Invalid extends Error {}
function bad(msg: string): never { throw new Invalid(msg); }
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Deep copy without "$comment" keys. */
function stripComments(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripComments);
  if (isObj(v)) return Object.fromEntries(Object.entries(v).filter(([k]) => k !== '$comment').map(([k, x]) => [k, stripComments(x)]));
  return v;
}

function hex(x: unknown, path: string): Uint8Array {
  if (typeof x !== 'string' || x.length % 2 !== 0 || /[^0-9a-fA-F]/.test(x)) bad(`${path} must be a hex string`);
  return fromHex(x);
}
const hexList = (x: unknown, path: string) => (Array.isArray(x) ? x.map(m => hex(m, `${path}[]`)) : x);
const hexOpt = (x: unknown, path: string) => (x === undefined ? undefined : hex(x, path));
function u64(x: unknown, path: string): unknown {
  if (x === undefined) return undefined;
  if (typeof x !== 'string' || !/^\d+$/.test(x)) bad(`${path} must be uint64`);
  return BigInt(x);
}

/** Parse the JSON form (text or already-parsed value). Validation is resolveAppraisalPolicy's; a malformed document yields POLICY_INVALID. */
export function appraisalPolicyFromJson(json: unknown): AppraisalPolicy | Violation {
  try {
    let v = json;
    if (typeof v === 'string') { try { v = JSON.parse(v); } catch { bad('policy is not valid JSON'); } }
    if (!isObj(v)) bad('policy must be an object');
    const p = stripComments(v) as Obj;
    if (p.measurement !== 'any') p.measurement = hexList(p.measurement, 'policy.measurement');
    if ('chipIds' in p) p.chipIds = hexList(p.chipIds, 'policy.chipIds');
    if ('endorsementKeyFingerprints' in p) p.endorsementKeyFingerprints = hexList(p.endorsementKeyFingerprints, 'policy.endorsementKeyFingerprints');
    if (isObj(p.reportData) && 'value' in p.reportData) p.reportData = { ...p.reportData, value: hex(p.reportData.value, 'policy.reportData.value') };
    for (const k of ['hostData', 'familyId', 'imageId', 'reportId'] as const) if (k in p) p[k] = hexOpt(p[k], `policy.${k}`);
    if (isObj(p.idBlock)) p.idBlock = { ...p.idBlock, idKeyDigest: hexOpt(p.idBlock.idKeyDigest, 'policy.idBlock.idKeyDigest'), authorKeyDigest: hexOpt(p.idBlock.authorKeyDigest, 'policy.idBlock.authorKeyDigest') };
    for (const k of ['minLaunchMitVector', 'minCurrentMitVector'] as const) if (k in p) p[k] = u64(p[k], `policy.${k}`);
    const resolved = resolveAppraisalPolicy(p as unknown as AppraisalPolicy);
    if ('code' in resolved) return resolved;
    return p as unknown as AppraisalPolicy;
  } catch (e) {
    if (e instanceof Invalid) return { code: 'POLICY_INVALID', message: e.message };
    throw e;
  }
}

/** The JSON form of a resolved policy; appraisalPolicyFromJson reads it back. */
export const appraisalPolicyToJson = (policy: ResolvedAppraisalPolicy): unknown => toJson(policy);
