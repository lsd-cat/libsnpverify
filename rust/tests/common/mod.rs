#![allow(dead_code)]
//! Shared fixtures. Mirrors kotlin/src/test/.../Fixtures.kt.

use std::io::Read;
use std::path::PathBuf;

use serde_json::Value;
use snpverify::*;

pub fn vectors() -> PathBuf {
    PathBuf::from(std::env::var("SNP_VECTORS_DIR").unwrap_or_else(|_| "../vectors".into()))
}

pub fn read(name: &str) -> Vec<u8> {
    std::fs::read(vectors().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

pub fn read_text(name: &str) -> String {
    String::from_utf8(read(name)).unwrap()
}

pub fn json(name: &str) -> Value {
    serde_json::from_slice(&read(name)).unwrap()
}

pub fn gunzip(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b).read_to_end(&mut out).unwrap();
    out
}

pub fn flip(b: &[u8], at: usize) -> Vec<u8> {
    let mut c = b.to_vec();
    c[at] ^= 1;
    c
}

pub fn this_update(crl: &[u8]) -> i64 {
    parse_crl(crl).unwrap().this_update
}

/// An attestation-sev vector as an AppraisalInput with a measurement-any policy.
pub fn fixture(name: &str) -> (AppraisalInput, Value) {
    let x = json(&format!("attestation-sev/{name}/input.json"));
    let str_opt = |k: &str| x.get(k).and_then(Value::as_str).map(str::to_string);
    let input = AppraisalInput {
        evidence: gunzip(&from_base64(x["attestation_doc_b64"].as_str().unwrap())),
        endorsements: Endorsements {
            vcek: from_base64(x["vcek_der_b64"].as_str().unwrap()),
            ask: str_opt("ask_pem").map(|p| pem_to_der(&p).remove(0)),
            ark: str_opt("amd_root_ca_pem").map(|p| pem_to_der(&p).remove(0)),
            crl: None,
        },
        now: x.get("expiration_check_date_unix").and_then(Value::as_i64).unwrap_or(1780272000),
        policy: AppraisalPolicy::new(MeasurementPin::Any),
    };
    (input, x)
}

/// Trusts the input's own ARK when one is supplied, else the embedded roots.
pub fn verifier_for(i: &AppraisalInput) -> SnpVerifier {
    SnpVerifier::new(RingCrypto, i.endorsements.ark.clone().map(|a| vec![a]))
}

pub fn appraise(i: &AppraisalInput) -> std::result::Result<AttestationResult, AppraisalError> {
    verifier_for(i).appraise(i)
}

pub fn expect_err(r: std::result::Result<AttestationResult, AppraisalError>, what: &str) -> AppraisalError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("{what}: expected rejection, got accept"),
    }
}

pub fn expect_ok(r: std::result::Result<AttestationResult, AppraisalError>) -> AttestationResult {
    r.unwrap_or_else(|e| panic!("expected accept: {:?}", e.violations))
}
