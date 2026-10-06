//! Crypto provider trait and the `ring` implementation. Mirrors ts/src/crypto.ts.

use crate::der::{children, content, read_tlv, Tag};

pub trait CryptoProvider {
    /// RSASSA-PSS with SHA-384 and MGF1-SHA-384 over `msg`, public key as SPKI DER.
    fn verify_rsa_pss(&self, spki: &[u8], msg: &[u8], sig: &[u8], salt_length: usize) -> bool;
    /// ECDSA P-384 with SHA-384, r and s as 48-byte big-endian integers, public key as SPKI DER.
    fn verify_ecdsa_p384(&self, spki: &[u8], msg: &[u8], r: &[u8], s: &[u8]) -> bool;
    fn sha256(&self, data: &[u8]) -> Vec<u8>;
}

/// Default provider, backed by [`ring`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RingCrypto;

/// The BIT STRING content of a SubjectPublicKeyInfo: RSAPublicKey DER for RSA, the uncompressed point for EC.
fn spki_key_bytes(spki: &[u8]) -> Option<&[u8]> {
    let seq = read_tlv(spki, 0, spki.len()).ok()?;
    let kids = children(spki, &seq).ok()?;
    let bits = kids.get(1).filter(|t| t.tag == Tag::BIT_STRING)?;
    let c = content(spki, bits);
    (c.first() == Some(&0)).then(|| &c[1..])
}

impl CryptoProvider for RingCrypto {
    fn verify_rsa_pss<'a>(&self, spki: &'a [u8], msg: &[u8], sig: &[u8], salt_length: usize) -> bool {
        // ring verifies PSS with the salt length equal to the digest length only.
        if salt_length != 48 {
            return false;
        }
        let Some(key) = spki_key_bytes(spki) else { return false };
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let Ok(seq) = read_tlv(key, 0, key.len()) else { return false };
        let Ok(kids) = children(key, &seq) else { return false };
        let (Some(n), Some(e)) = (kids.first(), kids.get(1)) else { return false };
        // ring wants minimal big-endian encodings: drop the DER sign-padding zero.
        let strip = |b: &'a [u8]| &b[b.iter().position(|&x| x != 0).unwrap_or(b.len())..];
        let (n, e) = (strip(content(key, n)), strip(content(key, e)));
        let modulus_bits = n.first().map_or(0, |first| n.len() * 8 - first.leading_zeros() as usize);
        if modulus_bits < 4096 {
            return false;
        }
        let components = ring::signature::RsaPublicKeyComponents { n, e };
        components.verify(&ring::signature::RSA_PSS_2048_8192_SHA384, msg, sig).is_ok()
    }

    fn verify_ecdsa_p384(&self, spki: &[u8], msg: &[u8], r: &[u8], s: &[u8]) -> bool {
        let Some(point) = spki_key_bytes(spki) else { return false };
        if r.len() != 48 || s.len() != 48 {
            return false;
        }
        let sig = [r, s].concat();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, point).verify(msg, &sig).is_ok()
    }

    fn sha256(&self, data: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
    }
}
