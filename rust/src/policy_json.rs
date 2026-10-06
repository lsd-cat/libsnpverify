//! JSON form of the appraisal policy: the shape `to_json` renders as `appraisalPolicy`, read back. Mirrors ts/src/policy-json.ts.
//! Bytes are lowercase hex, 64-bit values decimal strings, enumerations strings; a `"$comment"` key in any object is ignored.
//! The checks run in the same order as the TypeScript port, so the same document yields the same POLICY_INVALID message.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::bytes::from_hex;
use crate::errors::{ErrorCode, Result, Violation};
use crate::policy::{AppraisalPolicy, Bit, GuestPolicyRules, IdBlockPin, MeasurementPin, PlatformInfoRules, ReportDataPin, SigningKeyPolicy};
use crate::report::{FirmwareVersion, Product, TcbFloor};

type Obj = Map<String, Value>;

const POLICY_KEYS: &[&str] = &[
    "measurement",
    "products",
    "signingKey",
    "allowMaskedChipId",
    "chipIds",
    "endorsementKeyFingerprints",
    "cspIds",
    "requireCrl",
    "guestPolicy",
    "platformInfo",
    "vmpl",
    "minReportVersion",
    "minGuestSvn",
    "minTcb",
    "minLaunchTcb",
    "minFirmware",
    "allowProvisionalFirmware",
    "minLaunchMitVector",
    "minCurrentMitVector",
    "reportData",
    "hostData",
    "familyId",
    "imageId",
    "reportId",
    "idBlock",
];
const GUEST_POLICY_KEYS: &[&str] = &[
    "debug",
    "migrateMa",
    "smt",
    "singleSocket",
    "cxlAllowed",
    "memAes256Xts",
    "raplDisabled",
    "ciphertextHidingDram",
    "pageSwapDisabled",
    "minAbi",
];
const PLATFORM_INFO_KEYS: &[&str] = &[
    "smtEnabled",
    "tsmeEnabled",
    "eccEnabled",
    "raplDisabled",
    "ciphertextHidingEnabled",
    "aliasCheckComplete",
    "iommuWriteSafe",
    "tioEnabled",
    "allowUnknownBits",
];
const FLOOR_KEYS: &[&str] = &["bootloader", "tee", "snp", "microcode", "fmc"];

fn need(cond: bool, msg: impl Into<String>) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Violation::new(ErrorCode::PolicyInvalid, msg))
    }
}

/// Parse the JSON form from text. A malformed document yields a POLICY_INVALID violation.
pub fn appraisal_policy_from_json(text: &str) -> Result<AppraisalPolicy> {
    let v: Value = serde_json::from_str(text).map_err(|_| Violation::new(ErrorCode::PolicyInvalid, "policy is not valid JSON"))?;
    appraisal_policy_from_value(&v)
}

fn strip_comments(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.iter().filter(|(k, _)| k.as_str() != "$comment").map(|(k, x)| (k.clone(), strip_comments(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(strip_comments).collect()),
        other => other.clone(),
    }
}

fn object<'a>(v: &'a Value, path: &str) -> Result<&'a Obj> {
    v.as_object().ok_or_else(|| Violation::new(ErrorCode::PolicyInvalid, format!("{path} must be an object")))
}

fn keys(o: &Obj, path: &str, allowed: &[&str]) -> Result<()> {
    need(o.keys().all(|k| allowed.contains(&k.as_str())), format!("{path} has unknown fields"))
}

fn boolean(o: &Obj, key: &str, path: &str) -> Result<Option<bool>> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(Violation::new(ErrorCode::PolicyInvalid, format!("{path} must be boolean"))),
    }
}

/// An integral JSON number, whether written as `1`, `1.0` or `1e0`, like the other ports' number handling.
fn integer(v: &Value) -> Option<i64> {
    v.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 9.0e18).map(|f| f as i64)
}

fn uint(v: &Value, max: u64, path: &str) -> Result<u64> {
    match integer(v) {
        Some(n) if n >= 0 && n as u64 <= max => Ok(n as u64),
        _ => Err(Violation::new(ErrorCode::PolicyInvalid, format!("{path} must be an integer in 0..{max}"))),
    }
}

fn is_hex_string(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn hex_syntax(v: &Value, path: &str) -> Result<()> {
    need(is_hex_string(v), format!("{path} must be a hex string"))
}

fn hex_list_syntax(v: Option<&Value>, path: &str) -> Result<()> {
    if let Some(Value::Array(a)) = v {
        for x in a {
            hex_syntax(x, &format!("{path}[]"))?;
        }
    }
    Ok(())
}

/// Mirrors the conversion pass of the TypeScript port, which runs before its shape validation.
fn check_hex_syntax(p: &Obj) -> Result<()> {
    if p.get("measurement") != Some(&Value::String("any".into())) {
        hex_list_syntax(p.get("measurement"), "policy.measurement")?;
    }
    hex_list_syntax(p.get("chipIds"), "policy.chipIds")?;
    hex_list_syntax(p.get("endorsementKeyFingerprints"), "policy.endorsementKeyFingerprints")?;
    if let Some(v) = p.get("reportData").and_then(Value::as_object).and_then(|rd| rd.get("value")) {
        hex_syntax(v, "policy.reportData.value")?;
    }
    for k in ["hostData", "familyId", "imageId", "reportId"] {
        if let Some(v) = p.get(k) {
            hex_syntax(v, &format!("policy.{k}"))?;
        }
    }
    if let Some(ib) = p.get("idBlock").and_then(Value::as_object) {
        for k in ["idKeyDigest", "authorKeyDigest"] {
            if let Some(v) = ib.get(k) {
                hex_syntax(v, &format!("policy.idBlock.{k}"))?;
            }
        }
    }
    for k in ["minLaunchMitVector", "minCurrentMitVector"] {
        if let Some(v) = p.get(k) {
            need(v.as_str().is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())), format!("policy.{k} must be uint64"))?;
        }
    }
    Ok(())
}

/// Decodes a value already checked by `check_hex_syntax`; `None` when absent.
fn hex_len(v: Option<&Value>, n: usize, path: &str) -> Result<Option<Vec<u8>>> {
    let Some(v) = v else { return Ok(None) };
    let b = from_hex(v.as_str().unwrap_or_default());
    need(b.len() == n, format!("{path} must be {n} bytes"))?;
    Ok(Some(b))
}

fn hex_list(a: &[Value], n: usize, path: &str) -> Result<Vec<Vec<u8>>> {
    a.iter().map(|x| hex_len(Some(x), n, path).map(Option::unwrap)).collect()
}

fn bit(o: &Obj, key: &str, path: &str) -> Result<Option<Bit>> {
    match o.get(key).map(Value::as_str) {
        None => Ok(None),
        Some(Some("required")) => Ok(Some(Bit::Required)),
        Some(Some("forbidden")) => Ok(Some(Bit::Forbidden)),
        Some(Some("any")) => Ok(Some(Bit::Any)),
        Some(_) => Err(Violation::new(ErrorCode::PolicyInvalid, format!("{path}.{key} is not a Bit"))),
    }
}

fn floors(v: &Value, path: &str) -> Result<BTreeMap<Product, TcbFloor>> {
    let o = object(v, path)?;
    keys(o, path, &Product::ALL.map(Product::as_str))?;
    let mut out = BTreeMap::new();
    for product in Product::ALL {
        let Some(fv) = o.get(product.as_str()) else { continue };
        let fpath = format!("{path}.{product}");
        let fo = object(fv, &fpath)?;
        keys(fo, &fpath, FLOOR_KEYS)?;
        let component = |key: &str| fo.get(key).map(|x| uint(x, 255, &format!("{fpath}.{key}")).map(|n| n as u8)).transpose();
        out.insert(
            product,
            TcbFloor {
                bootloader: component("bootloader")?,
                tee: component("tee")?,
                snp: component("snp")?,
                microcode: component("microcode")?,
                fmc: component("fmc")?,
            },
        );
    }
    Ok(out)
}

/// Parse the JSON form from an already-parsed value.
pub fn appraisal_policy_from_value(v: &Value) -> Result<AppraisalPolicy> {
    need(v.is_object(), "policy must be an object")?;
    let stripped = strip_comments(v);
    let p = stripped.as_object().unwrap();
    check_hex_syntax(p)?;
    keys(p, "policy", POLICY_KEYS)?;

    let Some(m) = p.get("measurement") else {
        return Err(Violation::new(ErrorCode::PolicyInvalid, "policy.measurement is required: an allowlist or the explicit string \"any\""));
    };
    let measurement = if m == "any" {
        MeasurementPin::Any
    } else {
        let a = m.as_array().filter(|a| !a.is_empty());
        need(a.is_some(), "policy.measurement must be a nonempty array or \"any\"")?;
        MeasurementPin::Allowlist(hex_list(a.unwrap(), 48, "policy.measurement[]")?)
    };
    let mut out = AppraisalPolicy::new(measurement);
    if let Some(v) = p.get("reportData") {
        let o = object(v, "policy.reportData")?;
        let kind = o.get("kind").and_then(Value::as_str).unwrap_or("");
        need(matches!(kind, "any" | "exact" | "prefix"), "policy.reportData.kind is invalid")?;
        out.report_data = Some(if kind == "any" {
            keys(o, "policy.reportData", &["kind"])?;
            ReportDataPin::Any
        } else {
            keys(o, "policy.reportData", &["kind", "value"])?;
            let value = o.get("value").map(|x| from_hex(x.as_str().unwrap_or_default()));
            need(value.as_ref().is_some_and(|b| (1..=64).contains(&b.len())), "policy.reportData.value must be 1..64 bytes")?;
            let value = value.unwrap();
            if kind == "exact" {
                need(value.len() == 64, "policy.reportData.value must be 64 bytes")?;
                ReportDataPin::Exact(value)
            } else {
                ReportDataPin::Prefix(value)
            }
        });
    }
    out.host_data = hex_len(p.get("hostData"), 32, "policy.hostData")?;
    out.family_id = hex_len(p.get("familyId"), 16, "policy.familyId")?;
    out.image_id = hex_len(p.get("imageId"), 16, "policy.imageId")?;
    out.report_id = hex_len(p.get("reportId"), 32, "policy.reportId")?;
    if let Some(v) = p.get("products") {
        let products: Option<Vec<Product>> = v
            .as_array()
            .filter(|a| !a.is_empty())
            .and_then(|a| a.iter().map(|x| x.as_str().and_then(|s| Product::ALL.into_iter().find(|p| p.as_str() == s))).collect());
        need(products.is_some(), "policy.products must be a nonempty Product list")?;
        out.products = products;
    }
    if let Some(v) = p.get("signingKey") {
        out.signing_key = Some(match v.as_str() {
            Some("VCEK") => SigningKeyPolicy::Vcek,
            Some("VLEK") => SigningKeyPolicy::Vlek,
            Some("any") => SigningKeyPolicy::Any,
            _ => return Err(Violation::new(ErrorCode::PolicyInvalid, "policy.signingKey is invalid")),
        });
    }
    out.allow_masked_chip_id = boolean(p, "allowMaskedChipId", "policy.allowMaskedChipId")?;
    out.require_crl = boolean(p, "requireCrl", "policy.requireCrl")?;
    out.allow_provisional_firmware = boolean(p, "allowProvisionalFirmware", "policy.allowProvisionalFirmware")?;
    let chip_ids = p.get("chipIds");
    let fingerprints = p.get("endorsementKeyFingerprints");
    need(chip_ids.is_none_or(Value::is_array), "policy.chipIds must be an array")?;
    need(fingerprints.is_none_or(Value::is_array), "policy.endorsementKeyFingerprints must be an array")?;
    if let Some(a) = chip_ids.and_then(Value::as_array) {
        out.chip_ids = Some(hex_list(a, 64, "policy.chipIds[]")?);
    }
    if let Some(a) = fingerprints.and_then(Value::as_array) {
        out.endorsement_key_fingerprints = Some(hex_list(a, 32, "policy.endorsementKeyFingerprints[]")?);
    }
    if let Some(v) = p.get("cspIds") {
        let ids: Option<Vec<String>> = v
            .as_array()
            .filter(|a| !a.is_empty())
            .and_then(|a| a.iter().map(|x| x.as_str().filter(|s| !s.is_empty()).map(str::to_string)).collect());
        need(ids.is_some(), "policy.cspIds must be nonempty strings")?;
        out.csp_ids = ids;
    }
    if let Some(v) = p.get("idBlock") {
        out.id_block = Some(match v {
            Value::String(s) if s == "forbid" => IdBlockPin::Forbid,
            Value::String(s) if s == "any" => IdBlockPin::Any,
            Value::Object(o) => {
                keys(o, "policy.idBlock", &["idKeyDigest", "authorKeyDigest"])?;
                need(o.contains_key("idKeyDigest"), "policy.idBlock.idKeyDigest is required")?;
                IdBlockPin::Pinned {
                    id_key_digest: hex_len(o.get("idKeyDigest"), 48, "policy.idBlock.idKeyDigest")?.unwrap(),
                    author_key_digest: hex_len(o.get("authorKeyDigest"), 48, "policy.idBlock.authorKeyDigest")?,
                }
            }
            _ => return Err(Violation::new(ErrorCode::PolicyInvalid, "policy.idBlock is invalid")),
        });
    }
    if let Some(v) = p.get("guestPolicy") {
        let o = object(v, "policy.guestPolicy")?;
        keys(o, "policy.guestPolicy", GUEST_POLICY_KEYS)?;
        let b = |key: &str| bit(o, key, "policy.guestPolicy");
        let mut g = GuestPolicyRules {
            debug: b("debug")?,
            migrate_ma: b("migrateMa")?,
            smt: b("smt")?,
            single_socket: b("singleSocket")?,
            cxl_allowed: b("cxlAllowed")?,
            mem_aes256_xts: b("memAes256Xts")?,
            rapl_disabled: b("raplDisabled")?,
            ciphertext_hiding_dram: b("ciphertextHidingDram")?,
            page_swap_disabled: b("pageSwapDisabled")?,
            min_abi: None,
        };
        if let Some(a) = o.get("minAbi") {
            let ao = object(a, "policy.guestPolicy.minAbi")?;
            keys(ao, "policy.guestPolicy.minAbi", &["major", "minor"])?;
            need(ao.contains_key("major") && ao.contains_key("minor"), "policy.guestPolicy.minAbi requires major and minor")?;
            g.min_abi = Some((
                uint(&ao["major"], 255, "policy.guestPolicy.minAbi.major")? as u8,
                uint(&ao["minor"], 255, "policy.guestPolicy.minAbi.minor")? as u8,
            ));
        }
        out.guest_policy = Some(g);
    }
    if let Some(v) = p.get("platformInfo") {
        let o = object(v, "policy.platformInfo")?;
        keys(o, "policy.platformInfo", PLATFORM_INFO_KEYS)?;
        let b = |key: &str| bit(o, key, "policy.platformInfo");
        out.platform_info = Some(PlatformInfoRules {
            smt_enabled: b("smtEnabled")?,
            tsme_enabled: b("tsmeEnabled")?,
            ecc_enabled: b("eccEnabled")?,
            rapl_disabled: b("raplDisabled")?,
            ciphertext_hiding_enabled: b("ciphertextHidingEnabled")?,
            alias_check_complete: b("aliasCheckComplete")?,
            iommu_write_safe: b("iommuWriteSafe")?,
            tio_enabled: b("tioEnabled")?,
            allow_unknown_bits: boolean(o, "allowUnknownBits", "policy.platformInfo.allowUnknownBits")?,
        });
    }
    if let Some(v) = p.get("vmpl") {
        if v.is_number() {
            need(integer(v).is_some_and(|n| (0..=3).contains(&n)), "policy.vmpl must be 0..3")?;
            out.vmpl = integer(v).map(|n| n as u32);
        } else {
            need(v == "any", "policy.vmpl must be 0..3 or any")?;
            out.vmpl_any = true;
        }
    }
    if let Some(v) = p.get("minReportVersion") {
        need(integer(v).is_some_and(|n| (2..=5).contains(&n)), "policy.minReportVersion must be 2..5")?;
        out.min_report_version = integer(v).map(|n| n as u32);
    }
    if let Some(v) = p.get("minGuestSvn") {
        out.min_guest_svn = Some(uint(v, 0xffffffff, "policy.minGuestSvn")? as u32);
    }
    if let Some(v) = p.get("minTcb") {
        out.min_tcb = Some(floors(v, "policy.minTcb")?);
    }
    if let Some(v) = p.get("minLaunchTcb") {
        out.min_launch_tcb = Some(floors(v, "policy.minLaunchTcb")?);
    }
    if let Some(v) = p.get("minFirmware") {
        let o = object(v, "policy.minFirmware")?;
        keys(o, "policy.minFirmware", &["major", "minor", "build"])?;
        let component = |key: &str| o.get(key).map_or(Ok(0), |x| uint(x, 255, &format!("policy.minFirmware.{key}")).map(|n| n as u8));
        out.min_firmware = Some(FirmwareVersion {
            major: component("major")?,
            minor: component("minor")?,
            build: component("build")?,
        });
    }
    let u64_field = |key: &str| -> Result<Option<u64>> {
        p.get(key)
            .map(|x| {
                x.as_str()
                    .unwrap_or_default()
                    .parse::<u64>()
                    .map_err(|_| Violation::new(ErrorCode::PolicyInvalid, format!("policy.{key} must be uint64")))
            })
            .transpose()
    };
    out.min_launch_mit_vector = u64_field("minLaunchMitVector")?;
    out.min_current_mit_vector = u64_field("minCurrentMitVector")?;
    Ok(out)
}
