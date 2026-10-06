//! Bind the endorsement key to the report, then verify the report signature. Mirrors ts/src/bind.ts.

use crate::bytes::{hex, is_zero};
use crate::chain::EndorsementKey;
use crate::crypto::CryptoProvider;
use crate::errors::{fail, ErrorCode, Result};
use crate::products::product_from_cpuid;
use crate::report::{decode_tcb, tcb_equal, Report, SigningKey, TcbVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcbs {
    pub current: TcbVersion,
    pub committed: TcbVersion,
    pub reported: TcbVersion,
    pub launch: TcbVersion,
}

/// The key must derive from exactly REPORTED_TCB, on this chip (unless masked), for the product the CPU reports.
pub fn bind_endorsement(report: &Report, ek: &EndorsementKey) -> Result<Tcbs> {
    if ek.kind != report.signer_info.signing_key {
        fail!(ErrorCode::SignerKindMismatch => "signer_info.signing_key", "report says {}, certificate is a {}", report.signer_info.signing_key, ek.kind);
    }
    let layout = ek.product.info().tcb_layout;
    let tcb = Tcbs {
        current: decode_tcb(report.current_tcb, layout)?,
        committed: decode_tcb(report.committed_tcb, layout)?,
        reported: decode_tcb(report.reported_tcb, layout)?,
        launch: decode_tcb(report.launch_tcb, layout)?,
    };
    if !tcb_equal(&tcb.reported, &ek.tcb) {
        fail!(ErrorCode::VcekTcbMismatch => "reported_tcb", "reported_tcb does not match the {} certificate TCB", ek.kind);
    }
    // A zero CHIP_ID means the host masked it; there is nothing to compare with the HWID.
    if ek.kind == SigningKey::Vcek {
        let hwid = ek.hwid().unwrap_or_default();
        let chip = &report.chip_id()[..hwid.len()];
        if !is_zero(report.chip_id()) && chip != hwid {
            fail!(ErrorCode::VcekHwidMismatch => "chip_id", "chip_id {} != VCEK HWID {}", hex(chip), hex(hwid));
        }
    }
    if let Some(c) = report.cpuid {
        let from_cpu = product_from_cpuid(c.family, c.model);
        if from_cpu != Some(ek.product) {
            let name = from_cpu.map_or("unknown".to_string(), |p| p.to_string());
            fail!(ErrorCode::ProductMismatch => "cpuid_fam_id", "CPUID family 0x{:x} model 0x{:x} is {name}, certificate says {}", c.family, c.model, ek.product);
        }
    }
    Ok(tcb)
}

pub fn verify_report_signature(report: &Report, ek: &EndorsementKey, crypto: &dyn CryptoProvider) -> Result<()> {
    let (r, s) = report.signature_parts();
    if !crypto.verify_ecdsa_p384(ek.cert.spki(), report.signed_bytes(), r, s) {
        fail!(ErrorCode::ReportSignatureInvalid => "signature", "report signature does not verify with the {}", ek.kind);
    }
    Ok(())
}
