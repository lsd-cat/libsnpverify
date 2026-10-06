//! DER reader and X.509 certificate / CRL parser for AMD's ARK, ASK, VCEK, VLEK certificates and KDS CRLs. Mirrors ts/src/der.ts.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::errors::{fail, ErrorCode, Result, Violation};

/// `at` is the offset of the tag byte, `start` the first content byte, `end` one past the last content byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv {
    pub tag: u8,
    pub start: usize,
    pub end: usize,
    pub at: usize,
}

pub(crate) struct Tag;
impl Tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTF8: u8 = 0x0c;
    pub const SEQUENCE: u8 = 0x30;
    pub const PRINTABLE: u8 = 0x13;
    pub const IA5: u8 = 0x16;
    pub const UTCTIME: u8 = 0x17;
    pub const GENTIME: u8 = 0x18;
    pub const CTX0: u8 = 0xa0;
    pub const CTX1: u8 = 0xa1;
    pub const CTX2: u8 = 0xa2;
    pub const CTX3: u8 = 0xa3;
}

pub(crate) struct Oid;
impl Oid {
    pub const RSA_ENCRYPTION: &'static str = "1.2.840.113549.1.1.1";
    pub const RSASSA_PSS: &'static str = "1.2.840.113549.1.1.10";
    pub const EC_PUBLIC_KEY: &'static str = "1.2.840.10045.2.1";
    pub const P384: &'static str = "1.3.132.0.34";
    pub const SHA256: &'static str = "2.16.840.1.101.3.4.2.1";
    pub const SHA384: &'static str = "2.16.840.1.101.3.4.2.2";
    pub const SHA512: &'static str = "2.16.840.1.101.3.4.2.3";
    pub const MGF1: &'static str = "1.2.840.113549.1.1.8";
    pub const CN: &'static str = "2.5.4.3";
    pub const O: &'static str = "2.5.4.10";
    pub const OU: &'static str = "2.5.4.11";
}

pub(crate) fn read_tlv(b: &[u8], at: usize, limit: usize) -> Result<Tlv> {
    if at + 2 > limit {
        fail!(ErrorCode::CertMalformed, "DER: truncated header");
    }
    let tag = b[at];
    if tag & 0x1f == 0x1f {
        fail!(ErrorCode::CertMalformed, "DER: multi-byte tags unsupported");
    }
    let mut i = at + 1;
    let mut len = b[i] as usize;
    i += 1;
    if len == 0x80 {
        fail!(ErrorCode::CertMalformed, "DER: indefinite length");
    }
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || i + n > limit {
            fail!(ErrorCode::CertMalformed, "DER: bad length");
        }
        len = 0;
        for _ in 0..n {
            len = len * 256 + b[i] as usize;
            i += 1;
        }
        if len < 0x80 && n == 1 {
            fail!(ErrorCode::CertMalformed, "DER: non-minimal length");
        }
    }
    if i + len > limit {
        fail!(ErrorCode::CertMalformed, "DER: content exceeds bounds");
    }
    Ok(Tlv { tag, start: i, end: i + len, at })
}

pub(crate) fn children(b: &[u8], t: &Tlv) -> Result<Vec<Tlv>> {
    let mut out = Vec::new();
    let mut o = t.start;
    while o < t.end {
        let c = read_tlv(b, o, t.end)?;
        out.push(c);
        o = c.end;
    }
    Ok(out)
}

/// The i-th child, or CERT_MALFORMED (the other ports hit an index-out-of-bounds here).
fn nth(kids: &[Tlv], i: usize) -> Result<Tlv> {
    kids.get(i).copied().ok_or_else(|| Violation::new(ErrorCode::CertMalformed, "malformed certificate structure"))
}

pub(crate) fn expect(t: &Tlv, tag: u8, what: &str) -> Result<Tlv> {
    if t.tag != tag {
        fail!(ErrorCode::CertMalformed, "DER: {what}: expected tag 0x{tag:x}, got 0x{:x}", t.tag);
    }
    Ok(*t)
}

pub(crate) fn content<'a>(b: &'a [u8], t: &Tlv) -> &'a [u8] {
    &b[t.start..t.end]
}

pub(crate) fn oid_to_string(b: &[u8], t: &Tlv) -> Result<String> {
    expect(t, Tag::OID, "OID")?;
    let c = content(b, t);
    if c.is_empty() {
        fail!(ErrorCode::CertMalformed, "DER: empty OID");
    }
    let mut parts: Vec<String> = Vec::new();
    let mut v: u64 = 0;
    for &x in c {
        if v >= 1 << 56 {
            fail!(ErrorCode::CertMalformed, "DER: OID arc too large");
        }
        v = v * 128 + (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.push(first.to_string());
                parts.push((v - 40 * first).to_string());
            } else {
                parts.push(v.to_string());
            }
            v = 0;
        }
    }
    Ok(parts.join("."))
}

/// Small non-negative INTEGER.
pub(crate) fn small_int(b: &[u8], t: &Tlv, what: &str) -> Result<u64> {
    expect(t, Tag::INTEGER, what)?;
    let c = content(b, t);
    if c.is_empty() || c.len() > 6 {
        fail!(ErrorCode::CertMalformed, "DER: {what}: bad integer length");
    }
    if c[0] & 0x80 != 0 {
        fail!(ErrorCode::CertMalformed, "DER: {what}: negative integer");
    }
    Ok(c.iter().fold(0u64, |v, &x| v * 256 + x as u64))
}

/// Unix seconds for a civil UTC date-time; None if any component is out of range.
fn unix_time(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month[month as usize - 1] || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from civil, Howard Hinnant's algorithm.
    let (y, m) = if month <= 2 { (year - 1, month as i64 + 9) } else { (year, month as i64 - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64)
}

fn parse_time(b: &[u8], t: &Tlv) -> Result<i64> {
    let s = String::from_utf8_lossy(content(b, t)).into_owned();
    let year_digits = match t.tag {
        Tag::UTCTIME => 2,
        Tag::GENTIME => 4,
        _ => fail!(ErrorCode::CertMalformed, "bad time tag"),
    };
    let n = year_digits + 10;
    if s.len() != n + 1 || !s.ends_with('Z') || !s[..n].bytes().all(|c| c.is_ascii_digit()) {
        fail!(ErrorCode::CertMalformed, "bad time {s}");
    }
    let num = |a: usize, z: usize| s[a..z].parse::<u32>().unwrap();
    let mut year = num(0, year_digits) as i64;
    if year_digits == 2 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let r = &s[year_digits..n];
    let (mo, d, h, mi, sec) = (
        num(year_digits, year_digits + 2),
        r[2..4].parse().unwrap(),
        r[4..6].parse().unwrap(),
        r[6..8].parse().unwrap(),
        r[8..10].parse().unwrap(),
    );
    match unix_time(year, mo, d, h, mi, sec) {
        Some(t) => Ok(t),
        None => fail!(ErrorCode::CertMalformed, "invalid certificate time {s}"),
    }
}

/// Immutable: `value` borrows the private copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    value: Vec<u8>,
}

impl Extension {
    /// Content of the OCTET STRING.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PssParams {
    /// "SHA-256", "SHA-384" or "SHA-512".
    pub hash: &'static str,
    pub salt_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithm {
    pub oid: String,
    /// For RSASSA-PSS: parsed params.
    pub pss: Option<PssParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Name {
    pub cn: String,
    pub o: String,
    pub ou: String,
}

/// Immutable: owns a private copy of the DER; byte-valued accessors borrow from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: Range<usize>,
    serial: Range<usize>,
    issuer: Range<usize>,
    subject: Range<usize>,
    pub subject_name: Name,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    spki: Range<usize>,
    /// OID.
    pub spki_algorithm: String,
    /// OID, for EC keys.
    pub spki_curve: Option<String>,
    pub signature_algorithm: SignatureAlgorithm,
    signature: Range<usize>,
    extensions: BTreeMap<String, Extension>,
}

impl Certificate {
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn tbs(&self) -> &[u8] {
        &self.der[self.tbs.clone()]
    }
    pub fn serial(&self) -> &[u8] {
        &self.der[self.serial.clone()]
    }
    /// Raw Name DER.
    pub fn issuer(&self) -> &[u8] {
        &self.der[self.issuer.clone()]
    }
    /// Raw Name DER.
    pub fn subject(&self) -> &[u8] {
        &self.der[self.subject.clone()]
    }
    /// Raw SubjectPublicKeyInfo DER.
    pub fn spki(&self) -> &[u8] {
        &self.der[self.spki.clone()]
    }
    /// Raw signature bytes (BIT STRING content minus the unused-bits byte).
    pub fn signature(&self) -> &[u8] {
        &self.der[self.signature.clone()]
    }
    pub fn subject_cn(&self) -> &str {
        &self.subject_name.cn
    }
    /// Keyed by OID.
    pub fn extensions(&self) -> &BTreeMap<String, Extension> {
        &self.extensions
    }
}

/// Immutable: owns private copies; byte-valued accessors borrow from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    der: Vec<u8>,
    tbs: Range<usize>,
    issuer: Range<usize>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    revoked_serials: Vec<Vec<u8>>,
    extensions: BTreeMap<String, Extension>,
    pub signature_algorithm: SignatureAlgorithm,
    signature: Range<usize>,
}

impl Crl {
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn tbs(&self) -> &[u8] {
        &self.der[self.tbs.clone()]
    }
    pub fn issuer(&self) -> &[u8] {
        &self.der[self.issuer.clone()]
    }
    pub fn signature(&self) -> &[u8] {
        &self.der[self.signature.clone()]
    }
    pub fn revoked_serials(&self) -> &[Vec<u8>] {
        &self.revoked_serials
    }
    pub fn extensions(&self) -> &BTreeMap<String, Extension> {
        &self.extensions
    }
}

fn hash_name(oid: &str) -> Result<&'static str> {
    match oid {
        Oid::SHA256 => Ok("SHA-256"),
        Oid::SHA384 => Ok("SHA-384"),
        Oid::SHA512 => Ok("SHA-512"),
        _ => fail!(ErrorCode::CertAlgoUnsupported, "unsupported hash OID {oid}"),
    }
}

fn parse_sig_alg(b: &[u8], t: &Tlv) -> Result<SignatureAlgorithm> {
    expect(t, Tag::SEQUENCE, "AlgorithmIdentifier")?;
    let kids = children(b, t)?;
    let oid = oid_to_string(b, &nth(&kids, 0)?)?;
    if oid != Oid::RSASSA_PSS {
        return Ok(SignatureAlgorithm { oid, pss: None });
    }
    let Some(params) = kids.get(1) else {
        fail!(ErrorCode::CertAlgoUnsupported, "RSASSA-PSS without parameters")
    };
    // RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength, [3] trailerField }
    let (mut hash, mut mgf_hash, mut salt_length) = (None, "", 20);
    for p in children(b, params)? {
        let inner = nth(&children(b, &p)?, 0)?;
        match p.tag {
            Tag::CTX0 => hash = Some(hash_name(&oid_to_string(b, &nth(&children(b, &inner)?, 0)?)?)?),
            Tag::CTX1 => {
                let mgf = children(b, &inner)?;
                if oid_to_string(b, &nth(&mgf, 0)?)? != Oid::MGF1 {
                    fail!(ErrorCode::CertAlgoUnsupported, "PSS MGF is not MGF1");
                }
                mgf_hash = hash_name(&oid_to_string(b, &nth(&children(b, &nth(&mgf, 1)?)?, 0)?)?)?;
            }
            Tag::CTX2 => salt_length = small_int(b, &inner, "saltLength")?,
            Tag::CTX3 if small_int(b, &inner, "trailerField")? != 1 => fail!(ErrorCode::CertAlgoUnsupported, "PSS trailerField"),
            _ => {}
        }
    }
    let Some(hash) = hash else {
        fail!(ErrorCode::CertAlgoUnsupported, "PSS without explicit hash (SHA-1 default) is not accepted")
    };
    if mgf_hash != hash {
        fail!(ErrorCode::CertAlgoUnsupported, "PSS MGF1 must explicitly use the message hash");
    }
    Ok(SignatureAlgorithm {
        oid,
        pss: Some(PssParams { hash, salt_length }),
    })
}

fn parse_name(b: &[u8], name: &Tlv) -> Result<Name> {
    let mut out = Name::default();
    for rdn in children(b, name)? {
        for atv in children(b, &rdn)? {
            let kids = children(b, &atv)?;
            let (oid_t, v) = (nth(&kids, 0)?, nth(&kids, 1)?);
            if v.end - v.start > 4096 {
                fail!(ErrorCode::CertMalformed, "DN attribute too long");
            }
            let s = String::from_utf8_lossy(content(b, &v)).into_owned();
            match oid_to_string(b, &oid_t)?.as_str() {
                Oid::CN => out.cn = s,
                Oid::O => out.o = s,
                Oid::OU => out.ou = s,
                _ => {}
            }
        }
    }
    Ok(out)
}

fn bit_string_content(b: &[u8], t: &Tlv) -> Result<Range<usize>> {
    expect(t, Tag::BIT_STRING, "BIT STRING")?;
    if t.end == t.start {
        fail!(ErrorCode::CertMalformed, "DER: BIT STRING is empty");
    }
    if b[t.start] != 0 {
        fail!(ErrorCode::CertMalformed, "BIT STRING with unused bits");
    }
    Ok(t.start + 1..t.end)
}

fn parse_extensions(b: &[u8], exts_seq: &Tlv) -> Result<BTreeMap<String, Extension>> {
    let mut map = BTreeMap::new();
    for ext in children(b, &expect(exts_seq, Tag::SEQUENCE, "Extensions")?)? {
        let parts = children(b, &ext)?;
        let oid = oid_to_string(b, &nth(&parts, 0)?)?;
        let mut critical = false;
        let mut i = 1;
        if nth(&parts, i)?.tag == Tag::BOOLEAN {
            let flag = content(b, &parts[i]);
            if flag.len() != 1 {
                fail!(ErrorCode::CertMalformed, "DER: extension critical flag must be one byte");
            }
            critical = flag[0] != 0;
            i += 1;
        }
        let value = content(b, &expect(&nth(&parts, i)?, Tag::OCTET_STRING, "extnValue")?).to_vec();
        if map.contains_key(&oid) {
            fail!(ErrorCode::CertMalformed, "duplicate extension {oid}");
        }
        map.insert(oid.clone(), Extension { oid, critical, value });
    }
    Ok(map)
}

/// Input size caps. AMD certificates are about 2 KiB, CRLs a few hundred bytes.
pub const MAX_CERT_BYTES: usize = 16 * 1024;
pub const MAX_CRL_BYTES: usize = 1024 * 1024;

pub fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    if der.len() > MAX_CERT_BYTES {
        fail!(ErrorCode::CertMalformed, "certificate is {} bytes, limit {MAX_CERT_BYTES}", der.len());
    }
    let der = der.to_vec(); // private copy; all ranges below point into it
    let b = &der[..];
    let cert = read_tlv(b, 0, b.len())?;
    expect(&cert, Tag::SEQUENCE, "Certificate")?;
    if cert.end != b.len() {
        fail!(ErrorCode::CertMalformed, "trailing bytes after certificate");
    }
    let top = children(b, &cert)?;
    if top.len() < 3 {
        fail!(ErrorCode::CertMalformed, "Certificate: missing fields");
    }
    let (tbs_t, sig_alg_t, sig_val_t) = (top[0], top[1], top[2]);
    expect(&tbs_t, Tag::SEQUENCE, "TBSCertificate")?;
    let f = children(b, &tbs_t)?;
    if f.is_empty() || f[0].tag != Tag::CTX0 || small_int(b, &nth(&children(b, &f[0])?, 0)?, "version")? != 2 {
        fail!(ErrorCode::CertMalformed, "not X.509 v3");
    }
    if f.len() < 7 {
        fail!(ErrorCode::CertMalformed, "TBSCertificate: missing fields");
    }
    let (serial_t, tbs_sig_alg_t, issuer_t, validity_t, subject_t, spki_t) = (f[1], f[2], f[3], f[4], f[5], f[6]);
    let validity = children(b, &expect(&validity_t, Tag::SEQUENCE, "Validity")?)?;
    let spki_kids = children(b, &expect(&spki_t, Tag::SEQUENCE, "SPKI")?)?;
    let spki_alg_kids = children(b, &expect(&nth(&spki_kids, 0)?, Tag::SEQUENCE, "SPKI alg")?)?;
    let spki_algorithm = oid_to_string(b, &nth(&spki_alg_kids, 0)?)?;
    let spki_curve = match spki_alg_kids.get(1) {
        Some(t) if spki_algorithm == Oid::EC_PUBLIC_KEY && t.tag == Tag::OID => Some(oid_to_string(b, t)?),
        _ => None,
    };
    let extensions = match f[7..].iter().find(|t| t.tag == Tag::CTX3) {
        Some(ext_t) => parse_extensions(b, &nth(&children(b, ext_t)?, 0)?)?,
        None => BTreeMap::new(),
    };
    let sig_alg = parse_sig_alg(b, &sig_alg_t)?;
    if sig_alg != parse_sig_alg(b, &tbs_sig_alg_t)? {
        fail!(ErrorCode::CertMalformed, "signatureAlgorithm mismatch between TBS and outer");
    }
    let serial = expect(&serial_t, Tag::INTEGER, "serialNumber")?;
    Ok(Certificate {
        tbs: tbs_t.at..tbs_t.end,
        serial: serial.start..serial.end,
        issuer: issuer_t.at..issuer_t.end,
        subject: subject_t.at..subject_t.end,
        subject_name: parse_name(b, &subject_t)?,
        not_before: parse_time(b, &nth(&validity, 0)?)?,
        not_after: parse_time(b, &nth(&validity, 1)?)?,
        spki: spki_t.at..spki_t.end,
        spki_algorithm,
        spki_curve,
        signature_algorithm: sig_alg,
        signature: bit_string_content(b, &sig_val_t)?,
        extensions,
        der,
    })
}

pub fn parse_crl(der: &[u8]) -> Result<Crl> {
    parse_crl_inner(der).map_err(|e| {
        if e.code == ErrorCode::CertMalformed {
            Violation::new(ErrorCode::CrlInvalid, e.message)
        } else {
            e
        }
    })
}

fn parse_crl_inner(der: &[u8]) -> Result<Crl> {
    if der.len() > MAX_CRL_BYTES {
        fail!(ErrorCode::CrlInvalid, "CRL is {} bytes, limit {MAX_CRL_BYTES}", der.len());
    }
    let der = der.to_vec();
    let b = &der[..];
    let crl = read_tlv(b, 0, b.len())?;
    expect(&crl, Tag::SEQUENCE, "CertificateList")?;
    if crl.end != b.len() {
        fail!(ErrorCode::CrlInvalid, "trailing bytes after CRL");
    }
    let top = children(b, &crl)?;
    if top.len() < 3 {
        fail!(ErrorCode::CrlInvalid, "CRL: missing fields");
    }
    let (tbs_t, sig_alg_t, sig_val_t) = (top[0], top[1], top[2]);
    let f = children(b, &expect(&tbs_t, Tag::SEQUENCE, "TBSCertList")?)?;
    let i = if nth(&f, 0)?.tag == Tag::INTEGER { 1 } else { 0 }; // optional version
    let (Some(issuer_t), Some(this_update_t)) = (f.get(i + 1), f.get(i + 2)) else {
        fail!(ErrorCode::CrlInvalid, "TBSCertList: missing fields")
    };
    let mut j = i + 3;
    let mut next_update = None;
    if f.get(j).is_some_and(|t| t.tag == Tag::UTCTIME || t.tag == Tag::GENTIME) {
        next_update = Some(parse_time(b, &f[j])?);
        j += 1;
    }
    let mut revoked = Vec::new();
    if f.get(j).is_some_and(|t| t.tag == Tag::SEQUENCE) {
        for entry in children(b, &f[j])? {
            revoked.push(content(b, &expect(&nth(&children(b, &entry)?, 0)?, Tag::INTEGER, "revoked serial")?).to_vec());
        }
        j += 1;
    }
    let mut extensions = BTreeMap::new();
    if f.get(j).is_some_and(|t| t.tag == Tag::CTX0) {
        extensions = parse_extensions(b, &nth(&children(b, &f[j])?, 0)?)?;
        j += 1;
    }
    if j != f.len() {
        fail!(ErrorCode::CrlInvalid, "unexpected CRL fields");
    }
    let sig_alg = parse_sig_alg(b, &sig_alg_t)?;
    if sig_alg != parse_sig_alg(b, &f[i])? {
        fail!(ErrorCode::CrlInvalid, "signatureAlgorithm mismatch between TBS and outer");
    }
    Ok(Crl {
        tbs: tbs_t.at..tbs_t.end,
        issuer: issuer_t.at..issuer_t.end,
        this_update: parse_time(b, this_update_t)?,
        next_update,
        revoked_serials: revoked,
        extensions,
        signature_algorithm: sig_alg,
        signature: bit_string_content(b, &sig_val_t)?,
        der,
    })
}
