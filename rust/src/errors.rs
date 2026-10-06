//! Error codes. The set is shared with the TypeScript and Kotlin ports and is not extended per port.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // parse
    ReportTruncated,
    ReportVersionUnsupported,
    ReportHostRequested,
    ReportMalformed,
    ReportSignatureAlgoUnsupported,
    // chain
    CertMalformed,
    CertAlgoUnsupported,
    ArkUntrusted,
    ChainSignatureInvalid,
    ChainNameMismatch,
    CertNotYetValid,
    CertExpired,
    VcekExtensionInvalid,
    ProductMismatch,
    CrlInvalid,
    CrlExpired,
    CertRevoked,
    // bind
    VcekTcbMismatch,
    VcekHwidMismatch,
    SignerKindMismatch,
    // signature
    ReportSignatureInvalid,
    // policy
    PolicyInvalid,
    PolicyProductNotAllowed,
    PolicySignerNotAllowed,
    PolicyChipIdMasked,
    PolicyChipIdNotAllowed,
    PolicyGuestPolicy,
    PolicyAbiVersion,
    PolicyPlatformInfo,
    PolicyVmpl,
    PolicyGuestSvn,
    PolicyTcbOutOfDate,
    PolicyLaunchTcbOutOfDate,
    PolicyProvisionalFirmware,
    PolicyFirmwareVersion,
    PolicyMitigationVector,
    PolicyMeasurementMismatch,
    PolicyReportDataMismatch,
    PolicyHostDataMismatch,
    PolicyFamilyIdMismatch,
    PolicyImageIdMismatch,
    PolicyReportIdMismatch,
    PolicyIdBlock,
}

impl ErrorCode {
    /// The cross-port name, e.g. "REPORT_TRUNCATED".
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            ReportTruncated => "REPORT_TRUNCATED",
            ReportVersionUnsupported => "REPORT_VERSION_UNSUPPORTED",
            ReportHostRequested => "REPORT_HOST_REQUESTED",
            ReportMalformed => "REPORT_MALFORMED",
            ReportSignatureAlgoUnsupported => "REPORT_SIGNATURE_ALGO_UNSUPPORTED",
            CertMalformed => "CERT_MALFORMED",
            CertAlgoUnsupported => "CERT_ALGO_UNSUPPORTED",
            ArkUntrusted => "ARK_UNTRUSTED",
            ChainSignatureInvalid => "CHAIN_SIGNATURE_INVALID",
            ChainNameMismatch => "CHAIN_NAME_MISMATCH",
            CertNotYetValid => "CERT_NOT_YET_VALID",
            CertExpired => "CERT_EXPIRED",
            VcekExtensionInvalid => "VCEK_EXTENSION_INVALID",
            ProductMismatch => "PRODUCT_MISMATCH",
            CrlInvalid => "CRL_INVALID",
            CrlExpired => "CRL_EXPIRED",
            CertRevoked => "CERT_REVOKED",
            VcekTcbMismatch => "VCEK_TCB_MISMATCH",
            VcekHwidMismatch => "VCEK_HWID_MISMATCH",
            SignerKindMismatch => "SIGNER_KIND_MISMATCH",
            ReportSignatureInvalid => "REPORT_SIGNATURE_INVALID",
            PolicyInvalid => "POLICY_INVALID",
            PolicyProductNotAllowed => "POLICY_PRODUCT_NOT_ALLOWED",
            PolicySignerNotAllowed => "POLICY_SIGNER_NOT_ALLOWED",
            PolicyChipIdMasked => "POLICY_CHIP_ID_MASKED",
            PolicyChipIdNotAllowed => "POLICY_CHIP_ID_NOT_ALLOWED",
            PolicyGuestPolicy => "POLICY_GUEST_POLICY",
            PolicyAbiVersion => "POLICY_ABI_VERSION",
            PolicyPlatformInfo => "POLICY_PLATFORM_INFO",
            PolicyVmpl => "POLICY_VMPL",
            PolicyGuestSvn => "POLICY_GUEST_SVN",
            PolicyTcbOutOfDate => "POLICY_TCB_OUT_OF_DATE",
            PolicyLaunchTcbOutOfDate => "POLICY_LAUNCH_TCB_OUT_OF_DATE",
            PolicyProvisionalFirmware => "POLICY_PROVISIONAL_FIRMWARE",
            PolicyFirmwareVersion => "POLICY_FIRMWARE_VERSION",
            PolicyMitigationVector => "POLICY_MITIGATION_VECTOR",
            PolicyMeasurementMismatch => "POLICY_MEASUREMENT_MISMATCH",
            PolicyReportDataMismatch => "POLICY_REPORT_DATA_MISMATCH",
            PolicyHostDataMismatch => "POLICY_HOST_DATA_MISMATCH",
            PolicyFamilyIdMismatch => "POLICY_FAMILY_ID_MISMATCH",
            PolicyImageIdMismatch => "POLICY_IMAGE_ID_MISMATCH",
            PolicyReportIdMismatch => "POLICY_REPORT_ID_MISMATCH",
            PolicyIdBlock => "POLICY_ID_BLOCK",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Parse,
    Chain,
    Bind,
    Signature,
    Policy,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Parse => "parse",
            Stage::Chain => "chain",
            Stage::Bind => "bind",
            Stage::Signature => "signature",
            Stage::Policy => "policy",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One failed check. `field` is the report or policy field in 56860 snake_case, e.g. "guest_policy.debug".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ErrorCode,
    pub message: String,
    pub field: Option<String>,
}

impl Violation {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Violation {
            code,
            message: message.into(),
            field: None,
        }
    }

    pub fn at(mut self, field: &str) -> Self {
        self.field = Some(field.to_string());
        self
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Violation {}

/// Every stage function returns this: the value, or the first violation.
pub type Result<T> = std::result::Result<T, Violation>;

/// `fail!(code, "message {}", x)` or `fail!(code => "field", "message {}", x)`: return the violation from the current stage.
macro_rules! fail {
    ($code:expr => $field:expr, $($arg:tt)*) => {
        return Err($crate::errors::Violation::new($code, format!($($arg)*)).at($field))
    };
    ($code:expr, $($arg:tt)*) => {
        return Err($crate::errors::Violation::new($code, format!($($arg)*)))
    };
}
pub(crate) use fail;
