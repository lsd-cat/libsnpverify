package snpverify

// Error codes. The set is shared with the TypeScript and Kotlin ports and is not extended per port.
type ErrorCode string

const (
	// parse
	ReportTruncated                ErrorCode = "REPORT_TRUNCATED"
	ReportVersionUnsupported       ErrorCode = "REPORT_VERSION_UNSUPPORTED"
	ReportHostRequested            ErrorCode = "REPORT_HOST_REQUESTED"
	ReportMalformed                ErrorCode = "REPORT_MALFORMED"
	ReportSignatureAlgoUnsupported ErrorCode = "REPORT_SIGNATURE_ALGO_UNSUPPORTED"
	// chain
	CertMalformed         ErrorCode = "CERT_MALFORMED"
	CertAlgoUnsupported   ErrorCode = "CERT_ALGO_UNSUPPORTED"
	ARKUntrusted          ErrorCode = "ARK_UNTRUSTED"
	ChainSignatureInvalid ErrorCode = "CHAIN_SIGNATURE_INVALID"
	ChainNameMismatch     ErrorCode = "CHAIN_NAME_MISMATCH"
	CertNotYetValid       ErrorCode = "CERT_NOT_YET_VALID"
	CertExpired           ErrorCode = "CERT_EXPIRED"
	VCEKExtensionInvalid  ErrorCode = "VCEK_EXTENSION_INVALID"
	ProductMismatch       ErrorCode = "PRODUCT_MISMATCH"
	CRLInvalid            ErrorCode = "CRL_INVALID"
	CRLExpired            ErrorCode = "CRL_EXPIRED"
	CertRevoked           ErrorCode = "CERT_REVOKED"
	// bind
	VCEKTCBMismatch    ErrorCode = "VCEK_TCB_MISMATCH"
	VCEKHWIDMismatch   ErrorCode = "VCEK_HWID_MISMATCH"
	SignerKindMismatch ErrorCode = "SIGNER_KIND_MISMATCH"
	// signature
	ReportSignatureInvalid ErrorCode = "REPORT_SIGNATURE_INVALID"
	// policy
	PolicyInvalid             ErrorCode = "POLICY_INVALID"
	PolicyProductNotAllowed   ErrorCode = "POLICY_PRODUCT_NOT_ALLOWED"
	PolicySignerNotAllowed    ErrorCode = "POLICY_SIGNER_NOT_ALLOWED"
	PolicyChipIDMasked        ErrorCode = "POLICY_CHIP_ID_MASKED"
	PolicyChipIDNotAllowed    ErrorCode = "POLICY_CHIP_ID_NOT_ALLOWED"
	PolicyGuestPolicy         ErrorCode = "POLICY_GUEST_POLICY"
	PolicyABIVersion          ErrorCode = "POLICY_ABI_VERSION"
	PolicyPlatformInfo        ErrorCode = "POLICY_PLATFORM_INFO"
	PolicyVMPL                ErrorCode = "POLICY_VMPL"
	PolicyGuestSVN            ErrorCode = "POLICY_GUEST_SVN"
	PolicyTCBOutOfDate        ErrorCode = "POLICY_TCB_OUT_OF_DATE"
	PolicyLaunchTCBOutOfDate  ErrorCode = "POLICY_LAUNCH_TCB_OUT_OF_DATE"
	PolicyProvisionalFirmware ErrorCode = "POLICY_PROVISIONAL_FIRMWARE"
	PolicyFirmwareVersion     ErrorCode = "POLICY_FIRMWARE_VERSION"
	PolicyMitigationVector    ErrorCode = "POLICY_MITIGATION_VECTOR"
	PolicyMeasurementMismatch ErrorCode = "POLICY_MEASUREMENT_MISMATCH"
	PolicyReportDataMismatch  ErrorCode = "POLICY_REPORT_DATA_MISMATCH"
	PolicyHostDataMismatch    ErrorCode = "POLICY_HOST_DATA_MISMATCH"
	PolicyFamilyIDMismatch    ErrorCode = "POLICY_FAMILY_ID_MISMATCH"
	PolicyImageIDMismatch     ErrorCode = "POLICY_IMAGE_ID_MISMATCH"
	PolicyReportIDMismatch    ErrorCode = "POLICY_REPORT_ID_MISMATCH"
	PolicyIDBlock             ErrorCode = "POLICY_ID_BLOCK"
)

type Stage string

const (
	StageParse     Stage = "parse"
	StageChain     Stage = "chain"
	StageBind      Stage = "bind"
	StageSignature Stage = "signature"
	StagePolicy    Stage = "policy"
)

// Violation is one failed check. Field is the report or policy field in 56860 snake_case, e.g. "guest_policy.debug"; empty when none applies.
// Every error returned by a stage function is a *Violation.
type Violation struct {
	Code    ErrorCode
	Message string
	Field   string
}

func (v *Violation) Error() string { return string(v.Code) + ": " + v.Message }

// fail aborts the current stage. Internal: the panic is converted to an error at the stage boundary by stage().
func fail(code ErrorCode, message string, field ...string) {
	v := &Violation{Code: code, Message: message}
	if len(field) > 0 {
		v.Field = field[0]
	}
	panic(v)
}

// stage runs fn; a fail() becomes the returned error, anything else (a bug) propagates.
func stage[T any](fn func() T) (out T, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, ok := r.(*Violation)
			if !ok {
				panic(r)
			}
			err = v
		}
	}()
	return fn(), nil
}
