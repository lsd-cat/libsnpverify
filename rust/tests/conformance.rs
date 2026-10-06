//! Runs the Tinfoil conformance vectors (vectors/attestation-sev, vectors/quote-sev) through SnpVerifier. Mirrors ts/test/conformance.test.ts.
//! Two policy profiles: baseline for real-hardware fixtures, hardened for synthetic ones (which encode the hardened stance).

mod common;

use common::*;
use serde_json::{json, Map, Value};
use snpverify::*;

// Policies are built in the JSON form (SPEC §5) so that every port runs the vectors through its JSON loader.
fn baseline() -> Value {
    json!({"measurement": "any", "vmpl": "any", "products": ["Milan", "Genoa", "Turin"]})
}

/// Mirrors the "hardened" expectations encoded by the synthetic fixtures (SPEC §3.7.1 defaults + DECIDE-LATER probes).
fn hardened() -> Value {
    merge(
        baseline(),
        json!({
            "allowMaskedChipId": true,
            "minTcb": {"Genoa": {"snp": 14}},
            "minFirmware": {"major": 1, "minor": 55, "build": 21},
            "guestPolicy": {"debug": "forbidden", "migrateMa": "forbidden", "cxlAllowed": "forbidden", "memAes256Xts": "forbidden"},
            "platformInfo": {"tsmeEnabled": "required"},
        }),
    )
}

/// The 27x probes encode the DECIDE-LATER hardened stance that the rest of the synthetic suite does not satisfy.
fn hardened_platform() -> Value {
    json!({"tsmeEnabled": "required", "eccEnabled": "required", "raplDisabled": "required", "ciphertextHidingEnabled": "required", "aliasCheckComplete": "required", "tioEnabled": "required"})
}

fn merge(mut base: Value, over: Value) -> Value {
    for (k, v) in over.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

fn policy_from(j: &Value) -> AppraisalPolicy {
    appraisal_policy_from_value(j).unwrap_or_else(|e| panic!("policy: {e}"))
}

/// Our code -> Tinfoil taxonomy, so vectors that name a code can be asserted.
fn tinfoil_code(e: &AppraisalError) -> String {
    let v = &e.violations[0];
    let field = v.field.as_deref();
    match v.code {
        ErrorCode::ReportTruncated => "REPORT_TRUNCATED",
        ErrorCode::ReportVersionUnsupported => "WRONG_REPORT_VERSION",
        ErrorCode::ReportSignatureInvalid => "REPORT_SIGNATURE_INVALID",
        ErrorCode::CertMalformed | ErrorCode::ChainSignatureInvalid | ErrorCode::ChainNameMismatch | ErrorCode::VcekExtensionInvalid => "VCEK_CHAIN_INVALID",
        ErrorCode::CertExpired => "VCEK_EXPIRED",
        ErrorCode::VcekHwidMismatch => "VCEK_HWID_MISMATCH",
        ErrorCode::VcekTcbMismatch => "VCEK_TCB_MISMATCH",
        ErrorCode::PolicyTcbOutOfDate | ErrorCode::PolicyLaunchTcbOutOfDate => "TCB_OUT_OF_DATE",
        ErrorCode::PolicyMeasurementMismatch => "MEASUREMENT_MISMATCH",
        ErrorCode::PolicyReportDataMismatch => "REPORT_DATA_MISMATCH",
        ErrorCode::PolicyHostDataMismatch => "HOST_DATA_MISMATCH",
        ErrorCode::PolicyGuestPolicy => match field {
            Some("guest_policy.debug") => "GUEST_POLICY_DEBUG_SET",
            Some("guest_policy.migrate_ma") => "GUEST_POLICY_MIGRATE_MA_SET",
            _ => "GUEST_POLICY_RESERVED_BIT_SET",
        },
        ErrorCode::ReportMalformed => {
            if field == Some("guest_policy") {
                "GUEST_POLICY_RESERVED_BIT_SET"
            } else {
                "REPORT_FORMAT_UNSUPPORTED"
            }
        }
        ErrorCode::PolicyIdBlock => {
            if field == Some("author_key_digest") {
                "AUTHOR_KEY_DIGEST_MISMATCH"
            } else {
                "ID_KEY_DIGEST_MISMATCH"
            }
        }
        other => other.as_str(),
    }
    .to_string()
}

fn manifest(dir: &str) -> (i64, Vec<String>) {
    let m = read_text(&format!("{dir}/manifest.yaml"));
    let value_of = |key: &str| m.lines().find_map(|l| l.trim().strip_prefix(key)).map(|v| v.trim().to_string());
    let exit = value_of("exit_code:").unwrap().parse().unwrap();
    let codes = match value_of("rejection_code:") {
        None => vec![],
        Some(line) if line.starts_with('[') => line.split('"').skip(1).step_by(2).map(str::to_string).collect(),
        Some(line) => vec![line.trim_matches('"').to_string()],
    };
    (exit, codes)
}

#[test]
fn attestation_sev() {
    let mut names: Vec<String> = std::fs::read_dir(vectors().join("attestation-sev"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    names.sort();
    assert!(!names.is_empty());
    for name in names {
        let (mut input, x) = fixture(&name);
        let (exit, codes) = manifest(&format!("attestation-sev/{name}"));
        let synthetic = x.get("amd_root_ca_pem").is_some();
        let pol = x.get("policy").cloned().unwrap_or(Value::Object(Default::default()));
        let hex_opt = |k: &str| pol.get(k).and_then(Value::as_str).map(str::to_string);
        let mut j = if synthetic { hardened() } else { baseline() };
        if ["270", "271", "272", "273", "274"].iter().any(|p| name.starts_with(p)) {
            j["platformInfo"] = hardened_platform();
        }
        if let Some(m) = hex_opt("expected_measurement_hex") {
            j["measurement"] = json!([m]);
        }
        if let Some(rd) = hex_opt("expected_report_data_hex") {
            j["reportData"] = json!({"kind": "exact", "value": rd});
        }
        if let Some(hd) = hex_opt("expected_host_data_hex") {
            j["hostData"] = json!(hd);
        }
        let (idk, ak) = (hex_opt("expected_id_key_digest_hex"), hex_opt("expected_author_key_digest_hex"));
        if idk.is_some() || ak.is_some() {
            let mut pin = json!({"idKeyDigest": idk.unwrap_or_else(|| "00".repeat(48))});
            if let Some(ak) = ak {
                pin["authorKeyDigest"] = json!(ak);
            }
            j["idBlock"] = pin;
        }
        let floor_keys = [
            ("min_tcb_bl_spl", "bootloader"),
            ("min_tcb_tee_spl", "tee"),
            ("min_tcb_snp_spl", "snp"),
            ("min_tcb_ucode_spl", "microcode"),
        ];
        if floor_keys.iter().any(|(k, _)| pol.get(k).is_some()) {
            let f: Map<String, Value> = floor_keys.iter().filter_map(|(k, name)| pol.get(k).map(|v| (name.to_string(), v.clone()))).collect();
            j["minTcb"] = json!({"Milan": f, "Genoa": f, "Turin": f});
        }
        let policy = policy_from(&j);
        input.policy = policy;
        let result = verifier_for(&input).appraise(&input);
        if exit == 0 {
            let a = result.unwrap_or_else(|e| panic!("{name}: expected accept, got {:?}", e.violations));
            let expected = json(&format!("attestation-sev/{name}/expected.json"));
            if let Some(want) = expected.pointer("/outputs/measurement/registers/0").and_then(Value::as_str) {
                assert_eq!(from_hex(want), a.identity.measurement, "{name}");
            }
        } else {
            let e = expect_err(result, &name);
            if !codes.is_empty() {
                assert!(codes.contains(&tinfoil_code(&e)), "{name}: code {} ({:?}) not in {codes:?}", tinfoil_code(&e), e.violations[0]);
            }
        }
    }
}

#[test]
fn quote_sev() {
    let mut files: Vec<_> = std::fs::read_dir(vectors().join("quote-sev"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let vec: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let expected_accept = vec["expected"]["accepted"].as_bool().unwrap();
        let doc: Value = serde_json::from_slice(&from_base64(vec["input"]["document_b64"].as_str().unwrap())).unwrap();
        let col = |id: &str| doc["collateral"].as_array().and_then(|c| c.iter().find(|c| c["id"] == id)).map(|c| c["data"].clone());
        let nonempty = |v: Option<&Value>| v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        let vcek_b64 = nonempty(col("vcek").as_ref().and_then(|d| d.get("vcek_der_base64")));
        let chain = col("vcek").and_then(|d| d.get("cert_chain_pem").and_then(Value::as_str).map(pem_to_der)).unwrap_or_default();
        let crl_b64 = nonempty(col("crl").as_ref().and_then(|d| d.get("crl_der_base64")));
        // The v3 stage demands a VCEK, a 2-cert chain and a CRL; the core sees those as structural inputs.
        let (Some(vcek_b64), Some(crl_b64)) = (vcek_b64, crl_b64) else {
            assert!(!expected_accept, "{name}");
            continue;
        };
        if chain.len() != 2 {
            assert!(!expected_accept, "{name}");
            continue;
        }
        let ark = pem_to_der(vec["input"]["amd_root_ca_pem"].as_str().unwrap()).remove(0);
        let input = AppraisalInput {
            evidence: from_base64(doc["cpu_evidence"]["report_base64"].as_str().unwrap()),
            endorsements: Endorsements {
                vcek: from_base64(&vcek_b64),
                ask: Some(chain[0].clone()),
                ark: Some(chain[1].clone()),
                crl: Some(from_base64(&crl_b64)),
            },
            now: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
            policy: policy_from(&merge(baseline(), json!({"requireCrl": true, "minReportVersion": 3}))),
        };
        let result = SnpVerifier::new(RingCrypto, Some(vec![ark])).appraise(&input);
        // This older synthetic happy vector has a v3 CRL issuer without keyUsage.
        // RFC 10007 requires cRLSign, so the hardened verifier must reject it.
        if name == "sev-happy.json" {
            assert_eq!(expect_err(result, &name).violations[0].code, ErrorCode::CrlInvalid, "{name}");
            continue;
        }
        assert_eq!(result.is_ok(), expected_accept, "{name}: {:?}", result.err().map(|e| e.violations));
    }
}
