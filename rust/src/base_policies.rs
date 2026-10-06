//! Base appraisal policies built from four deployment values. Mirrors ts/src/base-policies.ts.

use std::collections::BTreeMap;

use crate::bytes::is_zero;
use crate::errors::{fail, ErrorCode, Result};
use crate::policy::{AppraisalPolicy, IdBlockPin, MeasurementPin, ReportDataPin, SigningKeyPolicy};
use crate::report::{Product, TcbFloor};

/// Caller-maintained reference values; `report_data` must bind a fresh session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseAppraisalPolicyConfig {
    pub products: Vec<Product>,
    pub measurements: Vec<Vec<u8>>,
    /// Exactly 64 bytes, e.g. SHA-512 of nonce and peer key.
    pub report_data: Vec<u8>,
    /// Explicit component floors for every allowed product.
    pub min_tcb: BTreeMap<Product, TcbFloor>,
}

fn base(config: &BaseAppraisalPolicyConfig) -> Result<AppraisalPolicy> {
    if config.products.is_empty() || !config.products.iter().all(|p| [Product::Milan, Product::Genoa, Product::Turin].contains(p)) {
        fail!(ErrorCode::PolicyInvalid, "base policy requires supported products");
    }
    if config.measurements.is_empty() || !config.measurements.iter().all(|m| m.len() == 48) {
        fail!(ErrorCode::PolicyInvalid, "base policy requires one or more 48-byte measurements");
    }
    if config.report_data.len() != 64 || is_zero(&config.report_data) {
        fail!(ErrorCode::PolicyInvalid, "base policy requires a nonzero, 64-byte report-data binding");
    }
    for product in &config.products {
        let Some(f) = config.min_tcb.get(product) else {
            fail!(ErrorCode::PolicyInvalid, "base policy requires a TCB floor for {product}")
        };
        let mut values = vec![f.bootloader, f.tee, f.snp, f.microcode];
        if *product == Product::Turin {
            values.push(f.fmc);
        }
        if values.iter().any(Option::is_none) {
            fail!(ErrorCode::PolicyInvalid, "base policy requires all TCB component floors for {product}");
        }
    }
    Ok(AppraisalPolicy {
        products: Some(config.products.clone()),
        report_data: Some(ReportDataPin::Exact(config.report_data.clone())),
        min_tcb: Some(config.min_tcb.clone()),
        min_report_version: Some(3),
        require_crl: Some(true),
        vmpl: Some(0),
        id_block: Some(IdBlockPin::Any),
        ..AppraisalPolicy::new(MeasurementPin::Allowlist(config.measurements.clone()))
    })
}

/// Guest-owned endorsement key. CHIP_ID must be present.
pub fn base_vcek_appraisal_policy(config: &BaseAppraisalPolicyConfig) -> Result<AppraisalPolicy> {
    Ok(AppraisalPolicy {
        signing_key: Some(SigningKeyPolicy::Vcek),
        ..base(config)?
    })
}

/// Cloud-provider endorsement key. A signed CSP_ID pin selects the allowed provider.
pub fn base_vlek_appraisal_policy(config: &BaseAppraisalPolicyConfig, csp_ids: &[String]) -> Result<AppraisalPolicy> {
    if csp_ids.is_empty() || csp_ids.iter().any(String::is_empty) {
        fail!(ErrorCode::PolicyInvalid, "base VLEK policy requires one or more CSP_IDs");
    }
    Ok(AppraisalPolicy {
        signing_key: Some(SigningKeyPolicy::Vlek),
        csp_ids: Some(csp_ids.to_vec()),
        ..base(config)?
    })
}
