// Product table. A new CPU generation is a row here, its roots, and a TCB layout if the bytes differ.
import type { Product, TcbLayout } from './report.ts';

export interface ProductInfo {
  tcbLayout: TcbLayout;
  /** Length of the HWID extension in VCEK certificates. */
  hwidLength: number;
  /** structVersion expected in the VCEK extensions (KDS spec 57230). */
  structVersion: number;
  /** CPUID (family, model range) values that report this product (report version >= 3). */
  cpuid: { family: number; modelMin: number; modelMax: number }[];
}

export const PRODUCTS: Record<Product, ProductInfo> = {
  Milan:  { tcbLayout: 'v0', hwidLength: 64, structVersion: 0, cpuid: [{ family: 0x19, modelMin: 0x00, modelMax: 0x0f }] },
  Genoa:  { tcbLayout: 'v0', hwidLength: 64, structVersion: 0, cpuid: [{ family: 0x19, modelMin: 0x10, modelMax: 0x1f }, { family: 0x19, modelMin: 0xa0, modelMax: 0xaf }] }, // Bergamo/Siena
  Turin:  { tcbLayout: 'v1', hwidLength: 8,  structVersion: 1, cpuid: [{ family: 0x1a, modelMin: 0x00, modelMax: 0x1f }] },
  // Venice: TCB layout v2 and roots pending; reports are rejected.
  Venice: { tcbLayout: 'v2', hwidLength: 8,  structVersion: 1, cpuid: [{ family: 0x1a, modelMin: 0x50, modelMax: 0x5f }] },
};

/** Product named by a VCEK productName extension ("Genoa-B2", "Siena", "Turin-B1"). */
export function productFromName(name: string): Product | undefined {
  const line = name.split('-')[0];
  if (line === 'Siena' || line === 'Bergamo') return 'Genoa';
  return Object.prototype.hasOwnProperty.call(PRODUCTS, line) ? (line as Product) : undefined;
}

export function productFromCpuid(family: number, model: number): Product | undefined {
  for (const [p, info] of Object.entries(PRODUCTS) as [Product, ProductInfo][]) {
    if (info.cpuid.some(c => c.family === family && model >= c.modelMin && model <= c.modelMax)) return p;
  }
  return undefined;
}
