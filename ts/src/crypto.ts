// Crypto provider interface and the WebCrypto implementation.
import { copy as buf } from './bytes.ts';

export interface CryptoProvider {
  /** RSASSA-PSS with SHA-384 and MGF1-SHA-384 over `msg`, public key as SPKI DER. */
  verifyRsaPss(spki: Uint8Array, msg: Uint8Array, sig: Uint8Array, saltLength: number): Promise<boolean>;
  /** ECDSA P-384 with SHA-384, r and s as 48-byte big-endian integers, public key as SPKI DER. */
  verifyEcdsaP384(spki: Uint8Array, msg: Uint8Array, r: Uint8Array, s: Uint8Array): Promise<boolean>;
  sha256(data: Uint8Array): Promise<Uint8Array>;
}

/** Default provider: WebCrypto (browsers, Node >= 20, Deno, Bun). */
export const webCrypto: CryptoProvider = {
  async verifyRsaPss(spki, msg, sig, saltLength) {
    const subtle = globalThis.crypto.subtle;
    let key: CryptoKey;
    try { key = await subtle.importKey('spki', buf(spki), { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']); } catch { return false; }
    if ((key.algorithm as RsaHashedKeyAlgorithm).modulusLength < 4096) return false;
    return subtle.verify({ name: 'RSA-PSS', saltLength }, key, buf(sig), buf(msg));
  },
  async verifyEcdsaP384(spki, msg, r, s) {
    const subtle = globalThis.crypto.subtle;
    let key: CryptoKey;
    try { key = await subtle.importKey('spki', buf(spki), { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']); } catch { return false; }
    const sig = new Uint8Array(96); sig.set(r, 0); sig.set(s, 48);
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, sig, buf(msg));
  },
  async sha256(data) { return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buf(data))); },
};
