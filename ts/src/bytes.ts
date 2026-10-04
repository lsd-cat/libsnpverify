// Byte helpers.

export function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error('invalid hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function isZero(b: Uint8Array, start = 0, end = b.length): boolean {
  for (let i = start; i < end; i++) if (b[i] !== 0) return false;
  return true;
}

export function u32le(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

export function u64le(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
  return v;
}

/** Copy into a fresh ArrayBuffer. Use this for every byte copy; a Node Buffer slice aliases its source. */
export const copy = (u: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(u);
export const copyRange = (u: Uint8Array, start: number, end: number): Uint8Array<ArrayBuffer> => new Uint8Array(u.subarray(start, end));

/** Freeze a parsed record. Byte fields, Maps and arrays become getters that return copies of private buffers. */
export function protect<T extends object>(o: T): T {
  if (Object.isFrozen(o)) return o;
  const getter = (k: string, get: () => unknown) => Object.defineProperty(o, k, { get, enumerable: true });
  for (const [k, v] of Object.entries(o)) {
    if (v instanceof Uint8Array) {
      const b = copy(v);
      getter(k, () => copy(b));
    } else if (v instanceof Map) {
      const m = new Map([...v].map(([mk, mv]) => [mk, mv && typeof mv === 'object' ? protect(mv) : mv]));
      getter(k, () => new Map(m));
    } else if (Array.isArray(v)) {
      const a = v.map(x => (x instanceof Uint8Array ? copy(x) : x && typeof x === 'object' ? protect(x) : x));
      getter(k, () => a.map(x => (x instanceof Uint8Array ? copy(x) : x)));
    } else if (v && typeof v === 'object') {
      protect(v);
    }
  }
  return Object.freeze(o);
}

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Extract all DER blobs from a PEM string, in order. */
export function pemToDer(pem: string): Uint8Array[] {
  return [...pem.matchAll(/-----BEGIN [^-]+-----([^-]+)-----END [^-]+-----/g)].map(m => fromBase64(m[1]));
}
