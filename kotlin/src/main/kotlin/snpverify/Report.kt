package snpverify

// ATTESTATION_REPORT parsing (AMD 56860), report versions 2 to 5. Mirrors ts/src/report.ts.

const val REPORT_SIZE = 0x4a0
const val SIGNED_SIZE = 0x2a0

enum class Product { Milan, Genoa, Turin, Venice }
enum class TcbLayout { V0, V1, V2 }
enum class SigningKey { VCEK, VLEK }

data class TcbVersion(val bootloader: Int, val tee: Int, val snp: Int, val microcode: Int, val fmc: Int? = null)

/** Partial floor: null components are not constrained. */
data class TcbFloor(val bootloader: Int? = null, val tee: Int? = null, val snp: Int? = null, val microcode: Int? = null, val fmc: Int? = null)

data class GuestPolicy(
    val raw: ULong,
    val abiMajor: Int,
    val abiMinor: Int,
    val smt: Boolean,
    val migrateMa: Boolean,
    val debug: Boolean,
    val singleSocket: Boolean,
    val cxlAllowed: Boolean,
    val memAes256Xts: Boolean,
    val raplDisabled: Boolean,
    val ciphertextHidingDram: Boolean,
    val pageSwapDisabled: Boolean,
)

data class PlatformInfo(
    val raw: ULong,
    val smtEnabled: Boolean,
    val tsmeEnabled: Boolean,
    val eccEnabled: Boolean,
    val raplDisabled: Boolean,
    val ciphertextHidingEnabled: Boolean,
    val aliasCheckComplete: Boolean,
    val iommuWriteSafe: Boolean,
    val tioEnabled: Boolean,
)

data class SignerInfo(val signingKey: SigningKey, val maskChipKey: Boolean, val authorKeyEnabled: Boolean)
data class FirmwareVersion(val major: Int, val minor: Int, val build: Int)
data class Cpuid(val family: Int, val model: Int, val stepping: Int)
data class EcdsaSignature(val r: ByteArray, val s: ByteArray)

/** Immutable: owns a private copy of the report; byte-valued properties return fresh copies. */
class Report internal constructor(
    bytes: ByteArray,
    val version: Int,
    val guestSvn: Long,
    val policy: GuestPolicy,
    val vmpl: Int,
    val currentTcb: ULong,
    val platformInfo: PlatformInfo,
    val signerInfo: SignerInfo,
    val reportedTcb: ULong,
    val cpuid: Cpuid?,
    val committedTcb: ULong,
    val currentVersion: FirmwareVersion,
    val committedVersion: FirmwareVersion,
    val launchTcb: ULong,
    val launchMitVector: ULong?,
    val currentMitVector: ULong?,
    signature: EcdsaSignature,
) {
    private val bytes = bytes.copyOf()
    private val sigR = signature.r.copyOf()
    private val sigS = signature.s.copyOf()
    val raw: ByteArray get() = bytes.copyOf()
    val familyId: ByteArray get() = bytes.copyOfRange(0x10, 0x20)
    val imageId: ByteArray get() = bytes.copyOfRange(0x20, 0x30)
    val reportData: ByteArray get() = bytes.copyOfRange(0x50, 0x90)
    val measurement: ByteArray get() = bytes.copyOfRange(0x90, 0xc0)
    val hostData: ByteArray get() = bytes.copyOfRange(0xc0, 0xe0)
    val idKeyDigest: ByteArray get() = bytes.copyOfRange(0xe0, 0x110)
    val authorKeyDigest: ByteArray get() = bytes.copyOfRange(0x110, 0x140)
    val reportId: ByteArray get() = bytes.copyOfRange(0x140, 0x160)
    val reportIdMa: ByteArray get() = bytes.copyOfRange(0x160, 0x180)
    val chipId: ByteArray get() = bytes.copyOfRange(0x1a0, 0x1e0)
    val signature: EcdsaSignature get() = EcdsaSignature(sigR.copyOf(), sigS.copyOf())
    val signedBytes: ByteArray get() = bytes.copyOfRange(0, SIGNED_SIZE)
}

private fun mbz(b: ByteArray, s: Int, e: Int) {
    if (!b.isZero(s, e)) fail(ErrorCode.REPORT_MALFORMED, "reserved bytes 0x${s.toString(16)}..0x${e.toString(16)} not zero")
}
private fun ULong.bit(n: Int): Boolean = (this shr n) and 1UL == 1UL

internal fun decodeGuestPolicy(raw: ULong): GuestPolicy {
    if (!raw.bit(17)) fail(ErrorCode.REPORT_MALFORMED, "guest_policy bit 17 must be 1", "guest_policy")
    if (raw shr 26 != 0UL) fail(ErrorCode.REPORT_MALFORMED, "guest_policy bits 63:26 must be 0", "guest_policy")
    return GuestPolicy(
        raw, abiMajor = ((raw shr 8) and 0xffUL).toInt(), abiMinor = (raw and 0xffUL).toInt(), smt = raw.bit(16), migrateMa = raw.bit(18), debug = raw.bit(19),
        singleSocket = raw.bit(20), cxlAllowed = raw.bit(21), memAes256Xts = raw.bit(22), raplDisabled = raw.bit(23), ciphertextHidingDram = raw.bit(24), pageSwapDisabled = raw.bit(25)
    )
}

/** Bits this library knows. Unknown set bits are a policy matter (Policy.platformInfo.allowUnknownBits). */
internal const val KNOWN_PLATFORM_INFO_BITS: ULong = 0xffUL

internal fun decodePlatformInfo(raw: ULong) = PlatformInfo(raw, raw.bit(0), raw.bit(1), raw.bit(2), raw.bit(3), raw.bit(4), raw.bit(5), raw.bit(6), raw.bit(7))

internal fun decodeSignerInfo(raw: Long): SignerInfo {
    if (raw ushr 5 != 0L) fail(ErrorCode.REPORT_MALFORMED, "signer_info bits 31:5 must be 0", "signer_info")
    val key = ((raw ushr 2) and 7).toInt()
    if (key != 0 && key != 1) fail(ErrorCode.REPORT_MALFORMED, "signer_info.signing_key $key is not VCEK or VLEK", "signer_info.signing_key")
    return SignerInfo(if (key == 0) SigningKey.VCEK else SigningKey.VLEK, raw and 2L != 0L, raw and 1L != 0L)
}

internal fun decodeTcb(raw: ULong, layout: TcbLayout): TcbVersion {
    fun byte(n: Int) = ((raw shr (8 * n)) and 0xffUL).toInt()
    return when (layout) {
        TcbLayout.V0 -> {
            if (raw and 0x0000ffffffff0000UL != 0UL) fail(ErrorCode.REPORT_MALFORMED, "TCB reserved bytes 2..5 not zero")
            TcbVersion(byte(0), byte(1), byte(6), byte(7))
        }
        TcbLayout.V1 -> {
            if (raw and 0x00ffffff00000000UL != 0UL) fail(ErrorCode.REPORT_MALFORMED, "Turin TCB reserved bytes 4..6 not zero")
            TcbVersion(byte(1), byte(2), byte(3), byte(7), fmc = byte(0))
        }
        TcbLayout.V2 -> fail(ErrorCode.REPORT_MALFORMED, "Venice TCB layout not supported yet")
    }
}

internal fun tcbAtLeast(a: TcbVersion, min: TcbFloor): Boolean = (min.bootloader == null || a.bootloader >= min.bootloader) &&
    (min.tee == null || a.tee >= min.tee) &&
    (min.snp == null || a.snp >= min.snp) &&
    (min.microcode == null || a.microcode >= min.microcode) &&
    (min.fmc == null || (a.fmc ?: 0) >= min.fmc)

internal fun tcbAtLeast(a: TcbVersion, b: TcbVersion): Boolean = tcbAtLeast(a, TcbFloor(b.bootloader, b.tee, b.snp, b.microcode, b.fmc))
internal fun tcbEqual(a: TcbVersion, b: TcbVersion): Boolean = a.bootloader == b.bootloader && a.tee == b.tee && a.snp == b.snp && a.microcode == b.microcode && (a.fmc ?: 0) == (b.fmc ?: 0)

private fun le72ToBe48(b: ByteArray, off: Int, what: String): ByteArray {
    if (!b.isZero(off + 48, off + 72)) fail(ErrorCode.REPORT_MALFORMED, "signature $what exceeds 384 bits", "signature")
    return ByteArray(48) { b[off + 47 - it] }
}

fun parseReport(data: ByteArray): Result<Report> = stage {
    if (data.size != REPORT_SIZE) fail(ErrorCode.REPORT_TRUNCATED, "report is ${data.size} bytes, want $REPORT_SIZE")
    val version = data.u32le(0x00).toInt()
    if (version < 2 || version > 5) fail(ErrorCode.REPORT_VERSION_UNSUPPORTED, "report version $version", "version")
    val vmpl = data.u32le(0x30)
    if (vmpl == 0xffffffffL) fail(ErrorCode.REPORT_HOST_REQUESTED, "report was requested by the host (VMPL=0xFFFFFFFF), not by the guest", "vmpl")
    if (vmpl > 3) fail(ErrorCode.REPORT_MALFORMED, "vmpl $vmpl out of range 0..3", "vmpl")
    val signatureAlgo = data.u32le(0x34)
    if (signatureAlgo != 1L) fail(ErrorCode.REPORT_SIGNATURE_ALGO_UNSUPPORTED, "signature_algo $signatureAlgo", "signature_algo")
    mbz(data, 0x4c, 0x50)
    mbz(data, if (version >= 3) 0x18b else 0x188, 0x1a0)
    mbz(data, 0x1eb, 0x1ec)
    mbz(data, 0x1ef, 0x1f0)
    if (version < 5) mbz(data, 0x1f8, 0x208)
    mbz(data, 0x208, SIGNED_SIZE)
    mbz(data, SIGNED_SIZE + 144, REPORT_SIZE)
    Report(
        bytes = data, version = version, guestSvn = data.u32le(0x04), policy = decodeGuestPolicy(data.u64le(0x08)), vmpl = vmpl.toInt(), currentTcb = data.u64le(0x38),
        platformInfo = decodePlatformInfo(data.u64le(0x40)), signerInfo = decodeSignerInfo(data.u32le(0x48)),
        reportedTcb = data.u64le(0x180), cpuid = if (version >= 3) Cpuid(data.u8(0x188), data.u8(0x189), data.u8(0x18a)) else null, committedTcb = data.u64le(0x1e0),
        currentVersion = FirmwareVersion(build = data.u8(0x1e8), minor = data.u8(0x1e9), major = data.u8(0x1ea)),
        committedVersion = FirmwareVersion(build = data.u8(0x1ec), minor = data.u8(0x1ed), major = data.u8(0x1ee)),
        launchTcb = data.u64le(0x1f0),
        launchMitVector = if (version >= 5) data.u64le(0x1f8) else null, currentMitVector = if (version >= 5) data.u64le(0x200) else null,
        signature = EcdsaSignature(le72ToBe48(data, SIGNED_SIZE, "r"), le72ToBe48(data, SIGNED_SIZE + 72, "s")),
    )
}
