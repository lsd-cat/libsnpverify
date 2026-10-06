//! AMD endorsement chain: ARK (pinned) -> ASK/ASVK -> VCEK/VLEK. VCEK extension parsing (57230). Optional CRL. Mirrors ts/src/chain.ts.

use crate::bytes::hex;
use crate::crypto::CryptoProvider;
use crate::der::{children, content, expect, parse_certificate, parse_crl, read_tlv, small_int, Certificate, Oid, SignatureAlgorithm, Tag, MAX_CERT_BYTES, MAX_CRL_BYTES};
use crate::errors::{fail, ErrorCode, Result};
use crate::products::product_from_name;
use crate::report::{Product, SigningKey, TcbLayout, TcbVersion};
use crate::roots::embedded_roots;

struct Kds;
impl Kds {
    const STRUCT_VERSION: &'static str = "1.3.6.1.4.1.3704.1.1";
    const PRODUCT_NAME: &'static str = "1.3.6.1.4.1.3704.1.2";
    const BL: &'static str = "1.3.6.1.4.1.3704.1.3.1";
    const TEE: &'static str = "1.3.6.1.4.1.3704.1.3.2";
    const SNP: &'static str = "1.3.6.1.4.1.3704.1.3.3";
    const SPL4: &'static str = "1.3.6.1.4.1.3704.1.3.4";
    const SPL5: &'static str = "1.3.6.1.4.1.3704.1.3.5";
    const SPL6: &'static str = "1.3.6.1.4.1.3704.1.3.6";
    const SPL7: &'static str = "1.3.6.1.4.1.3704.1.3.7";
    const UCODE: &'static str = "1.3.6.1.4.1.3704.1.3.8";
    const FMC: &'static str = "1.3.6.1.4.1.3704.1.3.9";
    const HWID: &'static str = "1.3.6.1.4.1.3704.1.4";
    const CSP_ID: &'static str = "1.3.6.1.4.1.3704.1.5";
}

/// The parsed VCEK or VLEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementKey {
    pub kind: SigningKey,
    pub product: Product,
    /// e.g. "Genoa-B2".
    pub product_name: String,
    hwid: Option<Vec<u8>>,
    /// VLEK only.
    pub csp_id: Option<String>,
    pub tcb: TcbVersion,
    pub cert: Certificate,
}

impl EndorsementKey {
    /// VCEK: 64 (Milan/Genoa) or 8 (Turin) bytes; `None` for a VLEK.
    pub fn hwid(&self) -> Option<&[u8]> {
        self.hwid.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainInput {
    /// VCEK or VLEK, DER.
    pub leaf: Vec<u8>,
    /// ASK or ASVK, DER; default embedded for the leaf's product.
    pub intermediate: Option<Vec<u8>>,
    /// ARK, DER; default embedded.
    pub root: Option<Vec<u8>>,
    /// DER, ARK-signed.
    pub crl: Option<Vec<u8>>,
    /// Unix seconds.
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlInfo {
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub leaf: EndorsementKey,
    pub intermediate: Certificate,
    pub root: Certificate,
    pub crl: Option<CrlInfo>,
}

fn ext_int(cert: &Certificate, oid: &str, what: &str) -> Result<u8> {
    let Some(e) = cert.extensions().get(oid) else {
        fail!(ErrorCode::VcekExtensionInvalid, "missing {what} extension")
    };
    let v = e.value();
    let t = read_tlv(v, 0, v.len())?;
    if t.end != v.len() {
        fail!(ErrorCode::VcekExtensionInvalid, "{what}: trailing bytes");
    }
    let n = small_int(v, &t, what)?;
    if n > 255 {
        fail!(ErrorCode::VcekExtensionInvalid, "{what} out of range");
    }
    Ok(n as u8)
}

fn ext_string(cert: &Certificate, oid: &str, what: &str) -> Result<Option<String>> {
    let Some(e) = cert.extensions().get(oid) else { return Ok(None) };
    let v = e.value();
    let t = read_tlv(v, 0, v.len())?;
    if t.tag != Tag::IA5 && t.tag != Tag::UTF8 && t.tag != Tag::PRINTABLE {
        fail!(ErrorCode::VcekExtensionInvalid, "{what}: not a string");
    }
    let value = content(v, &t);
    if value.len() > 4096 || !value.is_ascii() {
        fail!(ErrorCode::VcekExtensionInvalid, "{what}: invalid ASCII");
    }
    Ok(Some(String::from_utf8_lossy(value).into_owned()))
}

/// Parse the AMD extensions of a VCEK/VLEK. KDS emits HWID either raw or wrapped in an OCTET STRING.
pub(crate) fn parse_endorsement_key(cert: Certificate) -> Result<EndorsementKey> {
    let Some(product_name) = ext_string(&cert, Kds::PRODUCT_NAME, "productName")? else {
        fail!(ErrorCode::VcekExtensionInvalid, "missing productName extension")
    };
    let Some(product) = product_from_name(&product_name) else {
        fail!(ErrorCode::VcekExtensionInvalid, "unknown product \"{product_name}\"")
    };
    let info = product.info();
    let struct_version = ext_int(&cert, Kds::STRUCT_VERSION, "structVersion")?;
    if struct_version as u64 != info.struct_version {
        fail!(ErrorCode::VcekExtensionInvalid, "structVersion {struct_version} does not match {product}");
    }

    let hwid_ext = cert.extensions().get(Kds::HWID);
    let csp_id = ext_string(&cert, Kds::CSP_ID, "cspId")?;
    if hwid_ext.is_some() && csp_id.is_some() {
        fail!(ErrorCode::VcekExtensionInvalid, "certificate has both HWID and CSP_ID");
    }
    if hwid_ext.is_none() && csp_id.is_none() {
        fail!(ErrorCode::VcekExtensionInvalid, "certificate has neither HWID (VCEK) nor CSP_ID (VLEK)");
    }
    let mut hwid = None;
    if let Some(e) = hwid_ext {
        let mut h = e.value();
        if h.len() != info.hwid_length && h.first() == Some(&Tag::OCTET_STRING) {
            h = content(h, &expect(&read_tlv(h, 0, h.len())?, Tag::OCTET_STRING, "HWID")?);
        }
        if h.len() != info.hwid_length {
            fail!(ErrorCode::VcekExtensionInvalid, "HWID is {} bytes, want {}", h.len(), info.hwid_length);
        }
        hwid = Some(h.to_vec());
    }

    let mut tcb = TcbVersion {
        bootloader: ext_int(&cert, Kds::BL, "blSPL")?,
        tee: ext_int(&cert, Kds::TEE, "teeSPL")?,
        snp: ext_int(&cert, Kds::SNP, "snpSPL")?,
        microcode: ext_int(&cert, Kds::UCODE, "ucodeSPL")?,
        fmc: None,
    };
    for (oid, what) in [(Kds::SPL5, "spl5"), (Kds::SPL6, "spl6"), (Kds::SPL7, "spl7")] {
        if ext_int(&cert, oid, what)? != 0 {
            fail!(ErrorCode::VcekExtensionInvalid, "{what} must be 0");
        }
    }
    if info.tcb_layout == TcbLayout::V0 {
        if cert.extensions().contains_key(Kds::FMC) {
            fail!(ErrorCode::VcekExtensionInvalid, "fmcSPL not valid for this product");
        }
        if ext_int(&cert, Kds::SPL4, "spl4")? != 0 {
            fail!(ErrorCode::VcekExtensionInvalid, "spl4 must be 0");
        }
    } else {
        if cert.extensions().contains_key(Kds::SPL4) {
            fail!(ErrorCode::VcekExtensionInvalid, "spl4 not valid for this product");
        }
        tcb.fmc = Some(ext_int(&cert, Kds::FMC, "fmcSPL")?);
    }
    let kind = if hwid.is_some() { SigningKey::Vcek } else { SigningKey::Vlek };
    if !cert.subject_cn().starts_with(&format!("SEV-{kind}")) {
        fail!(ErrorCode::VcekExtensionInvalid, "leaf CN \"{}\" is not SEV-{kind}", cert.subject_cn());
    }
    Ok(EndorsementKey {
        kind,
        product,
        product_name,
        hwid,
        csp_id,
        tcb,
        cert,
    })
}

/// ISO 8601 UTC, seconds precision.
fn iso(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Civil from days, Howard Hinnant's algorithm.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, (secs % 3600) / 60, secs % 60)
}

fn check_validity(cert: &Certificate, now: i64, what: &str) -> Result<()> {
    if now < cert.not_before {
        fail!(ErrorCode::CertNotYetValid, "{what} not valid before {}", iso(cert.not_before));
    }
    if now > cert.not_after {
        fail!(ErrorCode::CertExpired, "{what} expired at {}", iso(cert.not_after));
    }
    Ok(())
}

fn check_certificate_purpose(cert: &Certificate, ca: bool) -> Result<()> {
    for e in cert.extensions().values() {
        if e.critical && e.oid != "2.5.29.19" && e.oid != "2.5.29.15" {
            fail!(ErrorCode::CertMalformed, "unsupported critical certificate extension {}", e.oid);
        }
    }
    let bc = cert.extensions().get("2.5.29.19");
    if ca && bc.is_none() {
        fail!(ErrorCode::CertMalformed, "CA certificate lacks basicConstraints");
    }
    if let Some(bc) = bc {
        let v = bc.value();
        let t = expect(&read_tlv(v, 0, v.len())?, Tag::SEQUENCE, "basicConstraints")?;
        if t.end != v.len() {
            fail!(ErrorCode::CertMalformed, "basicConstraints trailing bytes");
        }
        let fields = children(v, &t)?;
        let is_ca = fields.first().is_some_and(|f| f.tag == Tag::BOOLEAN && content(v, f) == [0xff]);
        if ca != is_ca {
            fail!(ErrorCode::CertMalformed, "basicConstraints CA={is_ca} is wrong for {}", if ca { "issuer" } else { "leaf" });
        }
    }
    if let Some(ku) = key_usage_bits(cert)? {
        if ku & (if ca { 0x04 } else { 0x80 }) == 0 {
            fail!(ErrorCode::CertMalformed, "keyUsage does not permit {}", if ca { "certificate signing" } else { "digital signing" });
        }
    }
    Ok(())
}

/// First keyUsage byte, or `None` when the extension is absent.
fn key_usage_bits(cert: &Certificate) -> Result<Option<u8>> {
    let Some(e) = cert.extensions().get("2.5.29.15") else { return Ok(None) };
    let v = e.value();
    let t = expect(&read_tlv(v, 0, v.len())?, Tag::BIT_STRING, "keyUsage")?;
    if t.end != v.len() || t.end - t.start < 2 {
        fail!(ErrorCode::CertMalformed, "invalid keyUsage");
    }
    Ok(Some(v[t.start + 1]))
}

fn signed_by(crypto: &dyn CryptoProvider, alg: &SignatureAlgorithm, signature: &[u8], tbs: &[u8], issuer: &Certificate) -> Result<bool> {
    let Some(pss) = alg.pss.as_ref().filter(|_| alg.oid == Oid::RSASSA_PSS) else {
        fail!(ErrorCode::CertAlgoUnsupported, "signature algorithm {}", alg.oid)
    };
    if pss.hash != "SHA-384" || pss.salt_length != 48 {
        fail!(ErrorCode::CertAlgoUnsupported, "RSASSA-PSS must use SHA-384 with salt length 48");
    }
    if issuer.spki_algorithm != Oid::RSA_ENCRYPTION {
        fail!(ErrorCode::CertAlgoUnsupported, "issuer key is not RSA");
    }
    Ok(crypto.verify_rsa_pss(issuer.spki(), tbs, signature, 48))
}

/// Verify the chain. `trusted_roots` must contain a DER byte-equal to the root used (`None`: the embedded ARK of the leaf's product).
pub fn verify_chain(input: &ChainInput, trusted_roots: Option<&[Vec<u8>]>, crypto: &dyn CryptoProvider) -> Result<Chain> {
    check_endorsement_sizes(&input.leaf, input.intermediate.as_deref(), input.root.as_deref(), input.crl.as_deref())?;
    let leaf = parse_endorsement_key(parse_certificate(&input.leaf)?)?;
    let defaults = embedded_roots(leaf.product);
    let root_der: &[u8] = match (&input.root, &defaults) {
        (Some(r), _) => r,
        (None, Some(d)) => &d.ark,
        (None, None) => fail!(ErrorCode::ArkUntrusted, "no embedded root for {}; pass one", leaf.product),
    };
    let inter_der: &[u8] = match (&input.intermediate, &defaults) {
        (Some(i), _) => i,
        (None, Some(d)) => &d.ask,
        (None, None) => fail!(ErrorCode::CertMalformed, "no embedded intermediate for {}; pass one", leaf.product),
    };
    let trusted: Vec<&[u8]> = match (trusted_roots, &defaults) {
        (Some(t), _) => t.iter().map(Vec::as_slice).collect(),
        (None, Some(d)) => vec![&d.ark],
        (None, None) => vec![],
    };
    if !trusted.contains(&root_der) {
        fail!(ErrorCode::ArkUntrusted, "root certificate is not a trusted ARK");
    }
    let root = parse_certificate(root_der)?;
    let intermediate = parse_certificate(inter_der)?;

    // Product consistency: ARK "ARK-Genoa", ASK "SEV-Genoa", ASVK "SEV-VLEK-Genoa". Siena/Bergamo use the Genoa chain.
    let p = leaf.product;
    if !root.subject_cn().ends_with(&format!("-{p}")) {
        fail!(ErrorCode::ProductMismatch, "ARK \"{}\" is not for {p}", root.subject_cn());
    }
    if !intermediate.subject_cn().ends_with(&format!("-{p}")) {
        fail!(ErrorCode::ProductMismatch, "intermediate \"{}\" is not for {p}", intermediate.subject_cn());
    }
    if (leaf.kind == SigningKey::Vlek) != intermediate.subject_cn().starts_with("SEV-VLEK") {
        fail!(
            ErrorCode::ProductMismatch,
            "{} must be issued by {}",
            leaf.kind,
            if leaf.kind == SigningKey::Vlek { "an ASVK" } else { "an ASK" }
        );
    }

    // All AMD endorsement certificates carry O=Advanced Micro Devices, OU=Engineering.
    for (c, what) in [(&root, "ARK"), (&intermediate, "ASK"), (&leaf.cert, leaf.kind.as_str())] {
        if c.subject_name.o != "Advanced Micro Devices" || c.subject_name.ou != "Engineering" {
            fail!(ErrorCode::ChainNameMismatch, "{what} subject is not AMD Engineering");
        }
    }
    if leaf.cert.issuer() != intermediate.subject() {
        fail!(ErrorCode::ChainNameMismatch, "leaf issuer != intermediate subject");
    }
    if intermediate.issuer() != root.subject() {
        fail!(ErrorCode::ChainNameMismatch, "intermediate issuer != root subject");
    }
    if root.issuer() != root.subject() {
        fail!(ErrorCode::ChainNameMismatch, "root is not self-issued");
    }

    check_validity(&root, input.now, "ARK")?;
    check_validity(&intermediate, input.now, "ASK")?;
    check_validity(&leaf.cert, input.now, leaf.kind.as_str())?;
    check_certificate_purpose(&root, true)?;
    check_certificate_purpose(&intermediate, true)?;
    check_certificate_purpose(&leaf.cert, false)?;
    if leaf.cert.spki_algorithm != Oid::EC_PUBLIC_KEY || leaf.cert.spki_curve.as_deref() != Some(Oid::P384) {
        fail!(ErrorCode::CertAlgoUnsupported, "{} key is not EC P-384", leaf.kind);
    }

    if !signed_by(crypto, &root.signature_algorithm, root.signature(), root.tbs(), &root)? {
        fail!(ErrorCode::ChainSignatureInvalid, "ARK self-signature invalid");
    }
    if !signed_by(crypto, &intermediate.signature_algorithm, intermediate.signature(), intermediate.tbs(), &root)? {
        fail!(ErrorCode::ChainSignatureInvalid, "ASK not signed by ARK");
    }
    if !signed_by(crypto, &leaf.cert.signature_algorithm, leaf.cert.signature(), leaf.cert.tbs(), &intermediate)? {
        fail!(ErrorCode::ChainSignatureInvalid, "{} not signed by ASK", leaf.kind);
    }

    let crl = match &input.crl {
        Some(crl) => Some(check_crl(crl, &root, &intermediate, input.now, crypto)?),
        None => None,
    };
    Ok(Chain { leaf, intermediate, root, crl })
}

/// Size caps, checked before any copy or parse.
pub(crate) fn check_endorsement_sizes(leaf: &[u8], intermediate: Option<&[u8]>, root: Option<&[u8]>, crl: Option<&[u8]>) -> Result<()> {
    for (what, b) in [("leaf", Some(leaf)), ("intermediate", intermediate), ("root", root)] {
        if let Some(b) = b {
            if b.len() > MAX_CERT_BYTES {
                fail!(ErrorCode::CertMalformed, "{what} certificate is {} bytes, limit {MAX_CERT_BYTES}", b.len());
            }
        }
    }
    if let Some(crl) = crl {
        if crl.len() > MAX_CRL_BYTES {
            fail!(ErrorCode::CrlInvalid, "CRL is {} bytes, limit {MAX_CRL_BYTES}", crl.len());
        }
    }
    Ok(())
}

/// KDS CRLs are ARK-signed and list revoked ASK/ASVK serials. VCEKs (serial 0) are never revoked; TCB supersedes them.
pub(crate) fn check_crl(crl_der: &[u8], root: &Certificate, intermediate: &Certificate, now: i64, crypto: &dyn CryptoProvider) -> Result<CrlInfo> {
    let crl = parse_crl(crl_der)?;
    let Some(next_update) = crl.next_update else {
        fail!(ErrorCode::CrlInvalid, "CRL has no nextUpdate")
    };
    if crl.extensions().contains_key("2.5.29.27") {
        fail!(ErrorCode::CrlInvalid, "delta CRL requires a base CRL");
    }
    for ext in crl.extensions().values() {
        if ext.critical {
            fail!(ErrorCode::CrlInvalid, "unsupported critical CRL extension {}", ext.oid);
        }
    }
    let Some(ku) = key_usage_bits(root)? else {
        fail!(ErrorCode::CrlInvalid, "CRL issuer lacks keyUsage")
    };
    if ku & 0x02 == 0 {
        fail!(ErrorCode::CrlInvalid, "CRL issuer keyUsage does not permit CRL signing");
    }
    if crl.issuer() != root.subject() {
        fail!(ErrorCode::CrlInvalid, "CRL issuer is not the ARK");
    }
    if !signed_by(crypto, &crl.signature_algorithm, crl.signature(), crl.tbs(), root)? {
        fail!(ErrorCode::CrlInvalid, "CRL signature invalid");
    }
    if now < crl.this_update {
        fail!(ErrorCode::CrlInvalid, "CRL thisUpdate is in the future");
    }
    if now > next_update {
        fail!(ErrorCode::CrlExpired, "CRL nextUpdate {} passed", iso(next_update));
    }
    for serial in crl.revoked_serials() {
        if serial == intermediate.serial() {
            fail!(ErrorCode::CertRevoked, "intermediate serial {} is revoked", hex(serial));
        }
        if serial == root.serial() {
            fail!(ErrorCode::CertRevoked, "root serial {} is revoked", hex(serial));
        }
    }
    Ok(CrlInfo {
        this_update: crl.this_update,
        next_update,
        revoked_count: crl.revoked_serials().len(),
    })
}
