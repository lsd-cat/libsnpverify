import { copy, isZero } from './bytes.ts';
import { resolvePolicy, type Policy } from './policy.ts';
import type { Product, TcbVersion } from './report.ts';

/** Caller-maintained reference values. `reportData` must bind this verification to a fresh session. */
export interface BasePolicyConfig {
  products: Product[];
  measurements: Uint8Array[];
  reportData: Uint8Array; // exactly 64 bytes, e.g. a SHA-512 digest of nonce and peer key
  minTcb: Partial<Record<Product, TcbVersion>>; // explicit component floors for every allowed product
}

function common(config: BasePolicyConfig): Policy {
  if (!Array.isArray(config.products) || config.products.length === 0 || !config.products.every(p => ['Milan','Genoa','Turin'].includes(p)))
    throw new Error('base policy requires supported products');
  if (!Array.isArray(config.measurements) || config.measurements.length === 0 || !config.measurements.every(m => m instanceof Uint8Array && m.length === 48))
    throw new Error('base policy requires one or more 48-byte measurements');
  if (!(config.reportData instanceof Uint8Array) || config.reportData.length !== 64 || isZero(config.reportData))
    throw new Error('base policy requires a nonzero, 64-byte report-data binding');
  if (!config.minTcb || config.products.some(p => {
    const f = config.minTcb[p];
    return !f || ['bootloader','tee','snp','microcode', ...(p === 'Turin' ? ['fmc'] : [])].some(k => !Number.isInteger(f[k as keyof TcbVersion]));
  })) throw new Error('base policy requires all TCB component floors for each product');
  const policy: Policy = {
    products: [...config.products], measurement: config.measurements.map(copy),
    reportData: { kind: 'exact', value: copy(config.reportData) },
    minTcb: Object.fromEntries(config.products.map(p => [p, { ...config.minTcb[p] }])),
    minReportVersion: 3, requireCrl: true, vmpl: 0, idBlock: 'any',
  };
  const result = resolvePolicy(policy);
  if ('code' in result) throw new Error(result.message);
  return policy;
}

/** Guest-owned endorsement key. CHIP_ID must be present; optionally add a chip allowlist. */
export function baseVcekPolicy(config: BasePolicyConfig): Policy {
  return { ...common(config), signingKey: 'VCEK' };
}

/** Cloud-provider endorsement key. A signed CSP_ID pin selects the allowed provider. */
export function baseVlekPolicy(config: BasePolicyConfig & { cspIds: string[] }): Policy {
  if (!Array.isArray(config.cspIds) || config.cspIds.length === 0 || config.cspIds.some(x => typeof x !== 'string' || !x))
    throw new Error('base VLEK policy requires one or more CSP_IDs');
  return { ...common(config), signingKey: 'VLEK', cspIds: [...config.cspIds] };
}
