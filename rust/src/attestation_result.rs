//! The result record (SPEC §6) and its JSON projection. Mirrors ts/src/attestation-result.ts.

use serde_json::{json, Map, Value};

use crate::bind::Tcbs;
use crate::bytes::hex;
use crate::chain::{Chain, CrlInfo};
use crate::crypto::CryptoProvider;
use crate::der::Certificate;
use crate::policy::{signing_key_policy_name, Bit, IdBlockPin, MeasurementPin, ReportDataPin, ResolvedAppraisalPolicy};
use crate::report::{Cpuid, EcdsaSignature, FirmwareVersion, GuestPolicy, PlatformInfo, Product, Report, SignerInfo, SigningKey, TcbFloor, TcbVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSummary {
    pub sha256: Vec<u8>,
    pub serial: Vec<u8>,
    pub subject_cn: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementKeySummary {
    pub cert: CertSummary,
    pub kind: SigningKey,
    pub hwid: Option<Vec<u8>>,
    pub csp_id: Option<String>,
    pub tcb: TcbVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub chip_id: Vec<u8>,
    pub report_id: Vec<u8>,
    pub report_id_ma: Vec<u8>,
    pub measurement: Vec<u8>,
    pub host_data: Vec<u8>,
    pub report_data: Vec<u8>,
    pub family_id: Vec<u8>,
    pub image_id: Vec<u8>,
    pub guest_svn: u32,
    pub vmpl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub product: Product,
    pub product_name: String,
    pub cpuid: Option<Cpuid>,
    pub guest_policy: GuestPolicy,
    pub platform_info: PlatformInfo,
    pub tcb: Tcbs,
    pub firmware_current: FirmwareVersion,
    pub firmware_committed: FirmwareVersion,
    pub launch_mit_vector: Option<u64>,
    pub current_mit_vector: Option<u64>,
    pub signer: SignerInfo,
    pub id_key_digest: Vec<u8>,
    pub author_key_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub report_version: u32,
    pub report_sha256: Vec<u8>,
    pub signature: EcdsaSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementsSummary {
    pub endorsement_key: EndorsementKeySummary,
    pub ask: CertSummary,
    pub ark: CertSummary,
    pub crl: Option<CrlInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationResult {
    pub identity: Identity,
    pub platform: Platform,
    pub evidence: EvidenceSummary,
    pub endorsements: EndorsementsSummary,
    pub appraisal_policy: ResolvedAppraisalPolicy,
    pub appraised_at: i64,
}

pub(crate) fn build_attestation_result(report: &Report, chain: &Chain, tcb: Tcbs, policy: ResolvedAppraisalPolicy, now: i64, crypto: &dyn CryptoProvider) -> AttestationResult {
    let sum = |c: &Certificate| CertSummary {
        sha256: crypto.sha256(c.der()),
        serial: c.serial().to_vec(),
        subject_cn: c.subject_cn().to_string(),
        not_before: c.not_before,
        not_after: c.not_after,
    };
    let ek = &chain.leaf;
    AttestationResult {
        identity: Identity {
            chip_id: report.chip_id().to_vec(),
            report_id: report.report_id().to_vec(),
            report_id_ma: report.report_id_ma().to_vec(),
            measurement: report.measurement().to_vec(),
            host_data: report.host_data().to_vec(),
            report_data: report.report_data().to_vec(),
            family_id: report.family_id().to_vec(),
            image_id: report.image_id().to_vec(),
            guest_svn: report.guest_svn,
            vmpl: report.vmpl,
        },
        platform: Platform {
            product: ek.product,
            product_name: ek.product_name.clone(),
            cpuid: report.cpuid,
            guest_policy: report.policy,
            platform_info: report.platform_info,
            tcb,
            firmware_current: report.current_version,
            firmware_committed: report.committed_version,
            launch_mit_vector: report.launch_mit_vector,
            current_mit_vector: report.current_mit_vector,
            signer: report.signer_info,
            id_key_digest: report.id_key_digest().to_vec(),
            author_key_digest: report.author_key_digest().to_vec(),
        },
        evidence: EvidenceSummary {
            report_version: report.version,
            report_sha256: crypto.sha256(report.raw()),
            signature: report.signature(),
        },
        endorsements: EndorsementsSummary {
            endorsement_key: EndorsementKeySummary {
                cert: sum(&ek.cert),
                kind: ek.kind,
                hwid: ek.hwid().map(<[u8]>::to_vec),
                csp_id: ek.csp_id.clone(),
                tcb: ek.tcb,
            },
            ask: sum(&chain.intermediate),
            ark: sum(&chain.root),
            crl: chain.crl,
        },
        appraisal_policy: policy,
        appraised_at: now,
    }
}

/// JSON projection: bytes as lowercase hex, unsigned 64-bit as decimal strings, enums as names, absent values omitted. Same keys as the other ports.
pub fn to_json(a: &AttestationResult) -> Value {
    filter_nulls_deep(json!({
        "identity": {
            "chipId": hex(&a.identity.chip_id), "reportId": hex(&a.identity.report_id), "reportIdMa": hex(&a.identity.report_id_ma), "measurement": hex(&a.identity.measurement),
            "hostData": hex(&a.identity.host_data), "reportData": hex(&a.identity.report_data), "familyId": hex(&a.identity.family_id), "imageId": hex(&a.identity.image_id),
            "guestSvn": a.identity.guest_svn, "vmpl": a.identity.vmpl,
        },
        "platform": {
            "product": a.platform.product.as_str(), "productName": a.platform.product_name,
            "cpuid": a.platform.cpuid.map(|c| json!({"family": c.family, "model": c.model, "stepping": c.stepping})),
            "guestPolicy": guest_policy_json(&a.platform.guest_policy),
            "platformInfo": platform_info_json(&a.platform.platform_info),
            "tcb": {"current": tcb_json(&a.platform.tcb.current), "committed": tcb_json(&a.platform.tcb.committed), "reported": tcb_json(&a.platform.tcb.reported), "launch": tcb_json(&a.platform.tcb.launch)},
            "firmware": {"current": fw_json(&a.platform.firmware_current), "committed": fw_json(&a.platform.firmware_committed)},
            "mitVectors": a.platform.launch_mit_vector.map(|l| json!({"launch": l.to_string(), "current": a.platform.current_mit_vector.unwrap_or(0).to_string()})),
            "signer": {"signingKey": a.platform.signer.signing_key.as_str(), "maskChipKey": a.platform.signer.mask_chip_key, "authorKeyEnabled": a.platform.signer.author_key_enabled},
            "idKeyDigest": hex(&a.platform.id_key_digest), "authorKeyDigest": hex(&a.platform.author_key_digest),
        },
        "evidence": {"reportVersion": a.evidence.report_version, "reportSha256": hex(&a.evidence.report_sha256), "signature": {"r": hex(&a.evidence.signature.r), "s": hex(&a.evidence.signature.s)}},
        "endorsements": {
            "endorsementKey": endorsement_key_json(&a.endorsements.endorsement_key),
            "ask": cert_json(&a.endorsements.ask), "ark": cert_json(&a.endorsements.ark),
            "crl": a.endorsements.crl.map(|c| json!({"thisUpdate": c.this_update, "nextUpdate": c.next_update, "revokedCount": c.revoked_count})),
        },
        "appraisalPolicy": appraisal_policy_to_json(&a.appraisal_policy),
        "appraisedAt": a.appraised_at,
    }))
}

/// The JSON form of a resolved policy; `appraisal_policy_from_json` reads it back.
pub fn appraisal_policy_to_json(p: &ResolvedAppraisalPolicy) -> Value {
    let (g, q) = (&p.guest_policy, &p.platform_info);
    filter_nulls_deep(json!({
        "products": p.products.iter().map(|x| x.as_str()).collect::<Vec<_>>(), "signingKey": signing_key_policy_name(p.signing_key), "allowMaskedChipId": p.allow_masked_chip_id,
        "chipIds": p.chip_ids.as_ref().map(|v| hex_list(v)), "endorsementKeyFingerprints": p.endorsement_key_fingerprints.as_ref().map(|v| hex_list(v)), "cspIds": p.csp_ids, "requireCrl": p.require_crl,
        "guestPolicy": {
            "debug": bit_json(g.debug), "migrateMa": bit_json(g.migrate_ma), "smt": bit_json(g.smt), "singleSocket": bit_json(g.single_socket), "cxlAllowed": bit_json(g.cxl_allowed),
            "memAes256Xts": bit_json(g.mem_aes256_xts), "raplDisabled": bit_json(g.rapl_disabled), "ciphertextHidingDram": bit_json(g.ciphertext_hiding_dram), "pageSwapDisabled": bit_json(g.page_swap_disabled),
            "minAbi": g.min_abi.map(|(major, minor)| json!({"major": major, "minor": minor})),
        },
        "platformInfo": {
            "smtEnabled": bit_json(q.smt_enabled), "tsmeEnabled": bit_json(q.tsme_enabled), "eccEnabled": bit_json(q.ecc_enabled), "raplDisabled": bit_json(q.rapl_disabled),
            "ciphertextHidingEnabled": bit_json(q.ciphertext_hiding_enabled), "aliasCheckComplete": bit_json(q.alias_check_complete), "iommuWriteSafe": bit_json(q.iommu_write_safe),
            "tioEnabled": bit_json(q.tio_enabled), "allowUnknownBits": q.allow_unknown_bits,
        },
        "vmpl": p.vmpl.map_or(json!("any"), |v| json!(v)), "minReportVersion": p.min_report_version, "minGuestSvn": p.min_guest_svn,
        "minTcb": floors_json(&p.min_tcb), "minLaunchTcb": floors_json(&p.min_launch_tcb), "minFirmware": fw_json(&p.min_firmware), "allowProvisionalFirmware": p.allow_provisional_firmware,
        "minLaunchMitVector": p.min_launch_mit_vector.map(|x| x.to_string()), "minCurrentMitVector": p.min_current_mit_vector.map(|x| x.to_string()),
        "measurement": match &p.measurement { MeasurementPin::Allowlist(v) => json!(hex_list(v)), MeasurementPin::Any => json!("any") },
        "reportData": match &p.report_data {
            ReportDataPin::Exact(v) => json!({"kind": "exact", "value": hex(v)}),
            ReportDataPin::Prefix(v) => json!({"kind": "prefix", "value": hex(v)}),
            ReportDataPin::Any => json!({"kind": "any"}),
        },
        "hostData": p.host_data.as_deref().map(hex), "familyId": p.family_id.as_deref().map(hex), "imageId": p.image_id.as_deref().map(hex), "reportId": p.report_id.as_deref().map(hex),
        "idBlock": match &p.id_block {
            IdBlockPin::Forbid => json!("forbid"),
            IdBlockPin::Any => json!("any"),
            IdBlockPin::Pinned { id_key_digest, author_key_digest } => json!({"idKeyDigest": hex(id_key_digest), "authorKeyDigest": author_key_digest.as_deref().map(hex)}),
        },
    }))
}

fn hex_list(v: &[Vec<u8>]) -> Vec<String> {
    v.iter().map(|b| hex(b)).collect()
}

fn bit_json(b: Option<Bit>) -> Option<&'static str> {
    b.map(Bit::as_str)
}

fn guest_policy_json(g: &GuestPolicy) -> Value {
    json!({"raw": g.raw.to_string(), "abiMajor": g.abi_major, "abiMinor": g.abi_minor, "smt": g.smt, "migrateMa": g.migrate_ma, "debug": g.debug, "singleSocket": g.single_socket,
        "cxlAllowed": g.cxl_allowed, "memAes256Xts": g.mem_aes256_xts, "raplDisabled": g.rapl_disabled, "ciphertextHidingDram": g.ciphertext_hiding_dram, "pageSwapDisabled": g.page_swap_disabled})
}

fn platform_info_json(p: &PlatformInfo) -> Value {
    json!({"raw": p.raw.to_string(), "smtEnabled": p.smt_enabled, "tsmeEnabled": p.tsme_enabled, "eccEnabled": p.ecc_enabled, "raplDisabled": p.rapl_disabled,
        "ciphertextHidingEnabled": p.ciphertext_hiding_enabled, "aliasCheckComplete": p.alias_check_complete, "iommuWriteSafe": p.iommu_write_safe, "tioEnabled": p.tio_enabled})
}

fn tcb_json(t: &TcbVersion) -> Value {
    json!({"bootloader": t.bootloader, "tee": t.tee, "snp": t.snp, "microcode": t.microcode, "fmc": t.fmc})
}

fn floor_json(t: &TcbFloor) -> Value {
    json!({"bootloader": t.bootloader, "tee": t.tee, "snp": t.snp, "microcode": t.microcode, "fmc": t.fmc})
}

fn floors_json(m: &std::collections::BTreeMap<Product, TcbFloor>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.as_str().to_string(), floor_json(v))).collect())
}

fn fw_json(f: &FirmwareVersion) -> Value {
    json!({"major": f.major, "minor": f.minor, "build": f.build})
}

fn cert_json(c: &CertSummary) -> Value {
    json!({"sha256": hex(&c.sha256), "serial": hex(&c.serial), "subjectCn": c.subject_cn, "notBefore": c.not_before, "notAfter": c.not_after})
}

fn endorsement_key_json(e: &EndorsementKeySummary) -> Value {
    let mut j = cert_json(&e.cert);
    let o = j.as_object_mut().unwrap();
    o.insert("kind".into(), json!(e.kind.as_str()));
    o.insert("hwid".into(), json!(e.hwid.as_deref().map(hex)));
    o.insert("cspId".into(), json!(e.csp_id));
    o.insert("tcb".into(), tcb_json(&e.tcb));
    j
}

fn filter_nulls_deep(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, filter_nulls_deep(v))).collect::<Map<_, _>>()),
        other => other,
    }
}
