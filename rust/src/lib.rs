//! snpverify: AMD SEV-SNP attestation report verification.
//!
//! ```ignore
//! let verifier = SnpVerifier::default();                       // ring crypto, embedded AMD certificates
//! match verifier.appraise(&AppraisalInput { evidence, endorsements: Endorsements { vcek, crl: Some(crl), ..Default::default() }, now, policy }) {
//!     Ok(result) => use_result(result),
//!     Err(e) => show(e.stage, e.violations),
//! }
//! ```
//!
//! Inputs: the report (Evidence), AMD certificates and optional CRL (Endorsements), appraisal time, appraisal policy. No network, no clock. See SPEC.md.

pub mod attestation_result;
pub mod base_policies;
pub mod bind;
pub mod bytes;
pub mod chain;
pub mod crypto;
pub mod der;
pub mod errors;
pub mod policy;
pub mod policy_json;
pub mod products;
pub mod report;
pub mod roots;

pub use attestation_result::{appraisal_policy_to_json, to_json, AttestationResult, CertSummary};
pub use base_policies::{base_vcek_appraisal_policy, base_vlek_appraisal_policy, BaseAppraisalPolicyConfig};
pub use bind::{bind_endorsement, verify_report_signature, Tcbs};
pub use bytes::{from_base64, from_hex, pem_to_der};
pub use chain::{verify_chain, Chain, ChainInput, CrlInfo, EndorsementKey};
pub use crypto::{CryptoProvider, RingCrypto};
pub use der::{parse_certificate, parse_crl, Certificate, Crl, Extension};
pub use errors::{ErrorCode, Result, Stage, Violation};
pub use policy::{
    check_appraisal_policy, resolve_appraisal_policy, AppraisalContext, AppraisalPolicy, Bit, GuestPolicyRules, IdBlockPin, MeasurementPin, PlatformInfoRules, ReportDataPin, ResolvedAppraisalPolicy,
    SigningKeyPolicy,
};
pub use policy_json::{appraisal_policy_from_json, appraisal_policy_from_value};
pub use products::{product_from_cpuid, product_from_name, ProductInfo};
pub use report::{parse_report, FirmwareVersion, GuestPolicy, PlatformInfo, Product, Report, SignerInfo, SigningKey, TcbFloor, TcbLayout, TcbVersion, REPORT_SIZE};
pub use roots::embedded_roots;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Endorsements {
    /// VCEK or VLEK, DER.
    pub vcek: Vec<u8>,
    /// ASK or ASVK, DER; default embedded for the product.
    pub ask: Option<Vec<u8>>,
    /// ARK, DER; default embedded for the product.
    pub ark: Option<Vec<u8>>,
    /// ARK-signed CRL, DER.
    pub crl: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppraisalInput {
    /// The attestation report, exactly 1184 bytes.
    pub evidence: Vec<u8>,
    pub endorsements: Endorsements,
    /// Appraisal time, unix seconds.
    pub now: i64,
    pub policy: AppraisalPolicy,
}

/// The records produced before the failing stage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Partial {
    pub report: Option<Report>,
    pub chain: Option<Chain>,
    pub tcb: Option<Tcbs>,
}

/// The error returned by [`SnpVerifier::appraise`]: the stage that failed and its violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppraisalError {
    pub stage: Stage,
    pub violations: Vec<Violation>,
    pub partial: Box<Partial>,
}

impl fmt::Display for AppraisalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "appraisal failed at stage {}: {}", self.stage, self.violations[0])
    }
}

impl std::error::Error for AppraisalError {}

pub struct SnpVerifier {
    crypto: Box<dyn CryptoProvider>,
    trusted_arks: Option<Vec<Vec<u8>>>,
}

impl Default for SnpVerifier {
    /// `ring` crypto and the embedded AMD roots.
    fn default() -> Self {
        SnpVerifier::new(RingCrypto, None)
    }
}

impl SnpVerifier {
    /// `trusted_arks`: DER ARKs the verifier trusts; the root used must be byte-equal to one. `None`: the embedded ARK of the leaf's product.
    pub fn new(crypto: impl CryptoProvider + 'static, trusted_arks: Option<Vec<Vec<u8>>>) -> Self {
        SnpVerifier {
            crypto: Box::new(crypto),
            trusted_arks,
        }
    }

    pub fn verify_chain(&self, input: &ChainInput) -> Result<Chain> {
        verify_chain(input, self.trusted_arks.as_deref(), self.crypto.as_ref())
    }

    pub fn verify_report_signature(&self, report: &Report, chain: &Chain) -> Result<()> {
        verify_report_signature(report, &chain.leaf, self.crypto.as_ref())
    }

    pub fn appraise(&self, input: &AppraisalInput) -> std::result::Result<AttestationResult, AppraisalError> {
        let failed = |stage: Stage, e: Violation, partial: Partial| AppraisalError {
            stage,
            violations: vec![e],
            partial: Box::new(partial),
        };
        let resolved = resolve_appraisal_policy(&input.policy).map_err(|e| failed(Stage::Policy, e, Partial::default()))?;
        // Parse the report (it checks its length before copying), check endorsement sizes, then every stage copies what it keeps.
        let report = parse_report(&input.evidence).map_err(|e| failed(Stage::Parse, e, Partial::default()))?;
        let e = &input.endorsements;
        chain::check_endorsement_sizes(&e.vcek, e.ask.as_deref(), e.ark.as_deref(), e.crl.as_deref()).map_err(|v| failed(Stage::Chain, v, Partial::default()))?;
        let chain_input = ChainInput {
            leaf: e.vcek.clone(),
            intermediate: e.ask.clone(),
            root: e.ark.clone(),
            crl: e.crl.clone(),
            now: input.now,
        };
        let chain = match self.verify_chain(&chain_input) {
            Ok(c) => c,
            Err(v) => {
                return Err(failed(
                    Stage::Chain,
                    v,
                    Partial {
                        report: Some(report),
                        ..Default::default()
                    },
                ))
            }
        };
        let tcb = match bind_endorsement(&report, &chain.leaf) {
            Ok(t) => t,
            Err(v) => {
                return Err(failed(
                    Stage::Bind,
                    v,
                    Partial {
                        report: Some(report),
                        chain: Some(chain),
                        tcb: None,
                    },
                ))
            }
        };
        if let Err(v) = self.verify_report_signature(&report, &chain) {
            return Err(failed(
                Stage::Signature,
                v,
                Partial {
                    report: Some(report),
                    chain: Some(chain),
                    tcb: Some(tcb),
                },
            ));
        }
        let ctx = AppraisalContext {
            tcb,
            crl_present: chain.crl.is_some(),
            leaf_fingerprint: self.crypto.sha256(chain.leaf.cert.der()),
        };
        let violations = policy::check_resolved_appraisal_policy(&report, &chain.leaf, &ctx, &resolved);
        if !violations.is_empty() {
            return Err(AppraisalError {
                stage: Stage::Policy,
                violations,
                partial: Box::new(Partial {
                    report: Some(report),
                    chain: Some(chain),
                    tcb: Some(tcb),
                }),
            });
        }
        Ok(attestation_result::build_attestation_result(&report, &chain, tcb, resolved, chain_input.now, self.crypto.as_ref()))
    }
}
