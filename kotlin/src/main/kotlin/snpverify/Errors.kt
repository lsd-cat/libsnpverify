package snpverify

/** Error codes. The set is shared with the TypeScript port and is not extended per port. */
enum class ErrorCode {
    // parse
    REPORT_TRUNCATED,
    REPORT_VERSION_UNSUPPORTED,
    REPORT_HOST_REQUESTED,
    REPORT_MALFORMED,
    REPORT_SIGNATURE_ALGO_UNSUPPORTED,

    // chain
    CERT_MALFORMED,
    CERT_ALGO_UNSUPPORTED,
    ARK_UNTRUSTED,
    CHAIN_SIGNATURE_INVALID,
    CHAIN_NAME_MISMATCH,
    CERT_NOT_YET_VALID,
    CERT_EXPIRED,
    VCEK_EXTENSION_INVALID,
    PRODUCT_MISMATCH,
    CRL_INVALID,
    CRL_EXPIRED,
    CERT_REVOKED,

    // bind
    VCEK_TCB_MISMATCH,
    VCEK_HWID_MISMATCH,
    SIGNER_KIND_MISMATCH,

    // signature
    REPORT_SIGNATURE_INVALID,

    // policy
    POLICY_INVALID,
    POLICY_PRODUCT_NOT_ALLOWED,
    POLICY_SIGNER_NOT_ALLOWED,
    POLICY_CHIP_ID_MASKED,
    POLICY_CHIP_ID_NOT_ALLOWED,
    POLICY_GUEST_POLICY,
    POLICY_ABI_VERSION,
    POLICY_PLATFORM_INFO,
    POLICY_VMPL,
    POLICY_GUEST_SVN,
    POLICY_TCB_OUT_OF_DATE,
    POLICY_LAUNCH_TCB_OUT_OF_DATE,
    POLICY_PROVISIONAL_FIRMWARE,
    POLICY_FIRMWARE_VERSION,
    POLICY_MITIGATION_VECTOR,
    POLICY_MEASUREMENT_MISMATCH,
    POLICY_REPORT_DATA_MISMATCH,
    POLICY_HOST_DATA_MISMATCH,
    POLICY_FAMILY_ID_MISMATCH,
    POLICY_IMAGE_ID_MISMATCH,
    POLICY_REPORT_ID_MISMATCH,
    POLICY_ID_BLOCK,
}

enum class Stage { PARSE, CHAIN, BIND, SIGNATURE, POLICY }

/** `field` is the report or policy field in 56860 snake_case, e.g. "guest_policy.debug". */
data class Violation(val code: ErrorCode, val message: String, val field: String? = null)

sealed interface Result<out T> {
    data class Ok<T>(val value: T) : Result<T>
    data class Err(val error: Violation) : Result<Nothing>
}

/** Internal: thrown inside a stage, converted to Result.Err at the stage boundary by [stage]. */
internal class Fail(val violation: Violation) : Exception("${violation.code}: ${violation.message}")

internal fun fail(code: ErrorCode, message: String, field: String? = null): Nothing = throw Fail(Violation(code, message, field))

internal inline fun <T> stage(block: () -> T): Result<T> = try {
    Result.Ok(block())
} catch (e: Fail) {
    Result.Err(e.violation)
}
