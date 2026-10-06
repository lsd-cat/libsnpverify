//! Byte helpers. Mirrors ts/src/bytes.ts.

use base64::Engine;

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode a hex string. Panics on invalid input, like the other ports throw.
pub fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit()), "invalid hex");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// Decode standard base64, ignoring whitespace. Panics on invalid input.
pub fn from_base64(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact).expect("invalid base64")
}

/// Extract all DER blobs from a PEM string, in order.
pub fn pem_to_der(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(begin) = rest.find("-----BEGIN ") {
        let Some(body_start) = rest[begin..].find("-----\n").map(|i| begin + i + 6) else { break };
        let Some(end) = rest[body_start..].find("-----END ").map(|i| body_start + i) else { break };
        out.push(from_base64(&rest[body_start..end]));
        rest = &rest[end + 9..];
    }
    out
}

pub(crate) fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

pub(crate) fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

pub(crate) fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
