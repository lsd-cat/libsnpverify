package cat.lsd.snpverify

// Policy definition, defaults and checks. checkPolicy returns all violations. Mirrors ts/src/policy.ts.

enum class Bit { REQUIRED, FORBIDDEN, ANY }

sealed interface ReportDataPin {
    data class Exact(val value: ByteArray) : ReportDataPin
    data class Prefix(val value: ByteArray) : ReportDataPin
    data object Any : ReportDataPin
}

sealed interface IdBlockPin {
    data object Forbid : IdBlockPin
    data object Any : IdBlockPin
    data class Pinned(val idKeyDigest: ByteArray, val authorKeyDigest: ByteArray? = null) : IdBlockPin
}

sealed interface MeasurementPin {
    data class Allowlist(val values: List<ByteArray>) : MeasurementPin
    data object Any : MeasurementPin
}

enum class SigningKeyPolicy { VCEK, VLEK, ANY }

data class GuestPolicyRules(
    val debug: Bit? = null,
    val migrateMa: Bit? = null,
    val smt: Bit? = null,
    val singleSocket: Bit? = null,
    val cxlAllowed: Bit? = null,
    val memAes256Xts: Bit? = null,
    val raplDisabled: Bit? = null,
    val ciphertextHidingDram: Bit? = null,
    val pageSwapDisabled: Bit? = null,
    val minAbi: Pair<Int, Int>? = null,
)

data class PlatformInfoRules(
    val smtEnabled: Bit? = null,
    val tsmeEnabled: Bit? = null,
    val eccEnabled: Bit? = null,
    val raplDisabled: Bit? = null,
    val ciphertextHidingEnabled: Bit? = null,
    val aliasCheckComplete: Bit? = null,
    val iommuWriteSafe: Bit? = null,
    val tioEnabled: Bit? = null,
    val allowUnknownBits: Boolean? = null,
)

/** Null means "use the default" (SPEC §5). `measurement` is required. */
data class Policy(
    val measurement: MeasurementPin,
    val products: List<Product>? = null,
    val signingKey: SigningKeyPolicy? = null,
    val allowMaskedChipId: Boolean? = null,
    val chipIds: List<ByteArray>? = null,
    val endorsementKeyFingerprints: List<ByteArray>? = null,
    val cspIds: List<String>? = null,
    val requireCrl: Boolean? = null,
    val guestPolicy: GuestPolicyRules? = null,
    val platformInfo: PlatformInfoRules? = null,
    val vmpl: Int? = null, // null = default 0; use vmplAny = true to skip
    val vmplAny: Boolean = false,
    val minReportVersion: Int? = null,
    val minGuestSvn: Long? = null,
    val minTcb: Map<Product, TcbFloor>? = null,
    val minLaunchTcb: Map<Product, TcbFloor>? = null,
    val minFirmware: FirmwareVersion? = null,
    val allowProvisionalFirmware: Boolean? = null,
    val minLaunchMitVector: ULong? = null,
    val minCurrentMitVector: ULong? = null,
    val reportData: ReportDataPin? = null,
    val hostData: ByteArray? = null,
    val familyId: ByteArray? = null,
    val imageId: ByteArray? = null,
    val reportId: ByteArray? = null,
    val idBlock: IdBlockPin? = null,
)

/** Policy with defaults filled in; recorded in the result as policyApplied. */
data class ResolvedPolicy(
    val products: List<Product>,
    val signingKey: SigningKeyPolicy,
    val allowMaskedChipId: Boolean,
    val chipIds: List<ByteArray>?,
    val endorsementKeyFingerprints: List<ByteArray>?,
    val cspIds: List<String>?,
    val requireCrl: Boolean,
    val guestPolicy: GuestPolicyRules,
    val platformInfo: PlatformInfoRules,
    val vmpl: Int?,
    val minReportVersion: Int,
    val minGuestSvn: Long,
    val minTcb: Map<Product, TcbFloor>,
    val minLaunchTcb: Map<Product, TcbFloor>,
    val minFirmware: FirmwareVersion,
    val allowProvisionalFirmware: Boolean,
    val minLaunchMitVector: ULong?,
    val minCurrentMitVector: ULong?,
    val measurement: MeasurementPin,
    val reportData: ReportDataPin,
    val hostData: ByteArray?,
    val familyId: ByteArray?,
    val imageId: ByteArray?,
    val reportId: ByteArray?,
    val idBlock: IdBlockPin,
)

private class Invalid(msg: String) : Exception(msg)
private fun need(cond: Boolean, msg: String) {
    if (!cond) throw Invalid(msg)
}
private fun len(v: ByteArray?, n: Int, what: String) = need(v == null || v.size == n, "policy.$what must be $n bytes")

/** Fill defaults and validate shapes. Returns Result.Err(POLICY_INVALID) on a malformed policy. */
fun resolvePolicy(p: Policy): Result<ResolvedPolicy> = try {
    (p.measurement as? MeasurementPin.Allowlist)?.let {
        need(it.values.isNotEmpty(), "policy.measurement must be a nonempty allowlist or Any");
        it.values.forEach { m -> len(m, 48, "measurement[]") }
    }
    when (val rd = p.reportData) {
        is ReportDataPin.Exact -> len(rd.value, 64, "reportData.value")
        is ReportDataPin.Prefix -> need(rd.value.size in 1..64, "policy.reportData.value must be 1..64 bytes")
        else -> {}
    }
    len(p.hostData, 32, "hostData");
    len(p.familyId, 16, "familyId");
    len(p.imageId, 16, "imageId");
    len(p.reportId, 32, "reportId")
    p.chipIds?.forEach { len(it, 64, "chipIds[]") }
    p.endorsementKeyFingerprints?.forEach { len(it, 32, "endorsementKeyFingerprints[]") }
    (p.idBlock as? IdBlockPin.Pinned)?.let {
        len(it.idKeyDigest, 48, "idBlock.idKeyDigest");
        len(it.authorKeyDigest, 48, "idBlock.authorKeyDigest")
    }
    p.vmpl?.let { need(it in 0..3, "policy.vmpl must be 0..3") }
    p.cspIds?.let { need(it.isNotEmpty() && it.all(String::isNotEmpty), "policy.cspIds must be nonempty strings") }
    p.products?.let { need(it.isNotEmpty(), "policy.products must be nonempty") }
    p.minReportVersion?.let { need(it in 2..5, "policy.minReportVersion must be 2..5") }
    p.minGuestSvn?.let { need(it in 0..0xffffffffL, "policy.minGuestSvn must be uint32") }
    p.guestPolicy?.minAbi?.let { need(it.first in 0..255 && it.second in 0..255, "policy.guestPolicy.minAbi must be byte values") }
    for ((name, table) in listOf("minTcb" to p.minTcb, "minLaunchTcb" to p.minLaunchTcb)) {
        table?.forEach { (product, floor) ->
            for ((part, value) in listOf("bootloader" to floor.bootloader, "tee" to floor.tee, "snp" to floor.snp, "microcode" to floor.microcode, "fmc" to floor.fmc)) {
                value?.let { need(it in 0..255, "policy.$name.$product.$part must be byte value") }
            }
        }
    }
    p.minFirmware?.let { need(it.major in 0..255 && it.minor in 0..255 && it.build in 0..255, "policy.minFirmware must be byte values") }
    val minTcb = p.minTcb ?: emptyMap()
    val g = p.guestPolicy ?: GuestPolicyRules()
    Result.Ok(
        ResolvedPolicy(
            products = p.products ?: listOf(Product.Genoa, Product.Turin),
            signingKey = p.signingKey ?: SigningKeyPolicy.VCEK,
            allowMaskedChipId = p.allowMaskedChipId ?: false,
            chipIds = p.chipIds?.map { it.copyOf() }, endorsementKeyFingerprints = p.endorsementKeyFingerprints?.map { it.copyOf() }, cspIds = p.cspIds?.toList(),
            requireCrl = p.requireCrl ?: false,
            guestPolicy = g.copy(debug = g.debug ?: Bit.FORBIDDEN, migrateMa = g.migrateMa ?: Bit.FORBIDDEN, cxlAllowed = g.cxlAllowed ?: Bit.FORBIDDEN, memAes256Xts = g.memAes256Xts ?: Bit.ANY),
            platformInfo = (p.platformInfo ?: PlatformInfoRules()).let { it.copy(allowUnknownBits = it.allowUnknownBits ?: false) },
            vmpl = if (p.vmplAny) null else (p.vmpl ?: 0),
            minReportVersion = p.minReportVersion ?: 2,
            minGuestSvn = p.minGuestSvn ?: 0,
            minTcb = minTcb, minLaunchTcb = p.minLaunchTcb ?: minTcb,
            minFirmware = p.minFirmware ?: FirmwareVersion(0, 0, 0),
            allowProvisionalFirmware = p.allowProvisionalFirmware ?: false,
            minLaunchMitVector = p.minLaunchMitVector, minCurrentMitVector = p.minCurrentMitVector,
            measurement = when (val m = p.measurement) {
                is MeasurementPin.Allowlist -> MeasurementPin.Allowlist(m.values.map { it.copyOf() });
                MeasurementPin.Any -> m
            },
            reportData = when (val d = p.reportData) {
                is ReportDataPin.Exact -> ReportDataPin.Exact(d.value.copyOf());
                is ReportDataPin.Prefix -> ReportDataPin.Prefix(d.value.copyOf());
                else -> ReportDataPin.Any
            },
            hostData = p.hostData?.copyOf(), familyId = p.familyId?.copyOf(), imageId = p.imageId?.copyOf(), reportId = p.reportId?.copyOf(),
            idBlock = when (val b = p.idBlock) {
                is IdBlockPin.Pinned -> IdBlockPin.Pinned(b.idKeyDigest.copyOf(), b.authorKeyDigest?.copyOf());
                null -> IdBlockPin.Forbid;
                else -> b
            },
        )
    )
} catch (e: Invalid) {
    Result.Err(Violation(ErrorCode.POLICY_INVALID, e.message ?: "invalid policy"))
}

data class PolicyContext(val tcb: Tcbs, val crlPresent: Boolean, val leafFingerprint: ByteArray)

/** Check a signature-verified report against the policy. Empty list = satisfied. */
fun checkPolicy(report: Report, ek: EndorsementKey, ctx: PolicyContext, policy: Policy): List<Violation> {
    val p = when (val r = resolvePolicy(policy)) {
        is Result.Err -> return listOf(r.error);
        is Result.Ok -> r.value
    }
    return checkResolvedPolicy(report, ek, ctx, p)
}

internal fun checkResolvedPolicy(report: Report, ek: EndorsementKey, ctx: PolicyContext, p: ResolvedPolicy): List<Violation> {
    val v = ArrayList<Violation>()
    fun bad(code: ErrorCode, message: String, field: String? = null) {
        v.add(Violation(code, message, field))
    }
    fun bit(code: ErrorCode, field: String, want: Bit?, got: Boolean) {
        if (want == Bit.REQUIRED && !got) bad(code, "$field is required but not set", field)
        if (want == Bit.FORBIDDEN && got) bad(code, "$field is set but forbidden", field)
    }
    fun pin(code: ErrorCode, field: String, want: ByteArray?, got: ByteArray) {
        if (want != null && !want.contentEquals(got)) bad(code, "$field ${got.hex()} != expected ${want.hex()}", field)
    }

    if (ek.product !in p.products) bad(ErrorCode.POLICY_PRODUCT_NOT_ALLOWED, "product ${ek.product} not in ${p.products}")
    if (p.signingKey != SigningKeyPolicy.ANY && ek.kind.name != p.signingKey.name) bad(ErrorCode.POLICY_SIGNER_NOT_ALLOWED, "signed by ${ek.kind}, policy requires ${p.signingKey}", "signer_info.signing_key")
    if (ek.kind == SigningKey.VCEK && report.chipId.isZero() && !p.allowMaskedChipId) bad(ErrorCode.POLICY_CHIP_ID_MASKED, "CHIP_ID is masked; chip identity is not in the report", "chip_id") // VLEK reports carry no CHIP_ID by design
    p.chipIds?.let { ids -> if (ids.none { it.contentEquals(report.chipId) }) bad(ErrorCode.POLICY_CHIP_ID_NOT_ALLOWED, "chip_id ${report.chipId.hex()} not in allowlist", "chip_id") }
    p.endorsementKeyFingerprints?.let { fps -> if (fps.none { it.contentEquals(ctx.leafFingerprint) }) bad(ErrorCode.POLICY_CHIP_ID_NOT_ALLOWED, "${ek.kind} fingerprint ${ctx.leafFingerprint.hex()} not in allowlist") }
    p.cspIds?.let { ids -> if (ek.kind != SigningKey.VLEK || ek.cspId == null || ek.cspId !in ids) bad(ErrorCode.POLICY_SIGNER_NOT_ALLOWED, "VLEK CSP_ID is not in the allowed list", "endorsement_key.csp_id") }
    if (p.requireCrl && !ctx.crlPresent) bad(ErrorCode.POLICY_INVALID, "policy requires a CRL but none was supplied")

    val gp = report.policy;
    val g = p.guestPolicy
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.debug", g.debug, gp.debug)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.migrate_ma", g.migrateMa, gp.migrateMa)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.smt", g.smt, gp.smt)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.single_socket", g.singleSocket, gp.singleSocket)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.cxl_allow", g.cxlAllowed, gp.cxlAllowed)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.mem_aes_256_xts", g.memAes256Xts, gp.memAes256Xts)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.rapl_dis", g.raplDisabled, gp.raplDisabled)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.ciphertext_hiding_dram", g.ciphertextHidingDram, gp.ciphertextHidingDram)
    bit(ErrorCode.POLICY_GUEST_POLICY, "guest_policy.page_swap_disable", g.pageSwapDisabled, gp.pageSwapDisabled)
    g.minAbi?.let { (maj, min) -> if (gp.abiMajor < maj || (gp.abiMajor == maj && gp.abiMinor < min)) bad(ErrorCode.POLICY_ABI_VERSION, "guest_policy ABI ${gp.abiMajor}.${gp.abiMinor} < $maj.$min", "guest_policy.abi_major") }

    val pi = report.platformInfo;
    val q = p.platformInfo
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.smt_en", q.smtEnabled, pi.smtEnabled)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.tsme_en", q.tsmeEnabled, pi.tsmeEnabled)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.ecc_en", q.eccEnabled, pi.eccEnabled)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.rapl_dis", q.raplDisabled, pi.raplDisabled)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.ciphertext_hiding_dram_en", q.ciphertextHidingEnabled, pi.ciphertextHidingEnabled)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.alias_check_complete", q.aliasCheckComplete, pi.aliasCheckComplete)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.iommu_write_safe", q.iommuWriteSafe, pi.iommuWriteSafe)
    bit(ErrorCode.POLICY_PLATFORM_INFO, "platform_info.tio_en", q.tioEnabled, pi.tioEnabled)
    if (q.allowUnknownBits != true && (pi.raw and KNOWN_PLATFORM_INFO_BITS.inv()) != 0UL) bad(ErrorCode.POLICY_PLATFORM_INFO, "platform_info has unknown bits: 0x${pi.raw.toString(16)}", "platform_info")

    if (report.version < p.minReportVersion) bad(ErrorCode.POLICY_INVALID, "report version ${report.version} < required ${p.minReportVersion}", "version")
    if (p.vmpl != null && report.vmpl != p.vmpl) bad(ErrorCode.POLICY_VMPL, "vmpl ${report.vmpl} != ${p.vmpl}", "vmpl")
    if (report.guestSvn < p.minGuestSvn) bad(ErrorCode.POLICY_GUEST_SVN, "guest_svn ${report.guestSvn} < ${p.minGuestSvn}", "guest_svn")

    val floor = p.minTcb[ek.product] ?: TcbFloor();
    val launchFloor = p.minLaunchTcb[ek.product] ?: TcbFloor()
    for ((name, t) in listOf("current" to ctx.tcb.current, "committed" to ctx.tcb.committed, "reported" to ctx.tcb.reported)) {
        if (!tcbAtLeast(t, floor)) bad(ErrorCode.POLICY_TCB_OUT_OF_DATE, "${name}_tcb ${fmtTcb(t)} below minimum ${fmtFloor(floor)}", "${name}_tcb")
    }
    if (!tcbAtLeast(ctx.tcb.launch, launchFloor)) bad(ErrorCode.POLICY_LAUNCH_TCB_OUT_OF_DATE, "launch_tcb ${fmtTcb(ctx.tcb.launch)} below minimum ${fmtFloor(launchFloor)}", "launch_tcb")
    if (!tcbAtLeast(ctx.tcb.current, ek.tcb)) bad(ErrorCode.POLICY_TCB_OUT_OF_DATE, "current_tcb ${fmtTcb(ctx.tcb.current)} below the endorsement key TCB ${fmtTcb(ek.tcb)}", "current_tcb")

    for ((name, fw) in listOf("current" to report.currentVersion, "committed" to report.committedVersion)) {
        if (!fwAtLeast(fw, p.minFirmware)) bad(ErrorCode.POLICY_FIRMWARE_VERSION, "$name firmware ${fw.major}.${fw.minor}.${fw.build} below minimum", "${name}_build")
    }
    if (!p.allowProvisionalFirmware && (report.currentVersion != report.committedVersion || report.currentTcb != report.committedTcb)) {
        bad(ErrorCode.POLICY_PROVISIONAL_FIRMWARE, "committed firmware/TCB differs from current (uncommitted update; rollback possible)", "committed_tcb")
    }
    p.minLaunchMitVector?.let { if (((report.launchMitVector ?: 0UL) and it) != it) bad(ErrorCode.POLICY_MITIGATION_VECTOR, "launch_mit_vector lacks required bits", "launch_mit_vector") }
    p.minCurrentMitVector?.let { if (((report.currentMitVector ?: 0UL) and it) != it) bad(ErrorCode.POLICY_MITIGATION_VECTOR, "current_mit_vector lacks required bits", "current_mit_vector") }

    (p.measurement as? MeasurementPin.Allowlist)?.let { m -> if (m.values.none { it.contentEquals(report.measurement) }) bad(ErrorCode.POLICY_MEASUREMENT_MISMATCH, "measurement ${report.measurement.hex()} not in allowlist", "measurement") }
    when (val rd = p.reportData) {
        is ReportDataPin.Exact -> pin(ErrorCode.POLICY_REPORT_DATA_MISMATCH, "report_data", rd.value, report.reportData)
        is ReportDataPin.Prefix -> if (!rd.value.contentEquals(report.reportData.copyOfRange(0, rd.value.size))) bad(ErrorCode.POLICY_REPORT_DATA_MISMATCH, "report_data does not start with ${rd.value.hex()}", "report_data")
        ReportDataPin.Any -> {}
    }
    pin(ErrorCode.POLICY_HOST_DATA_MISMATCH, "host_data", p.hostData, report.hostData)
    pin(ErrorCode.POLICY_FAMILY_ID_MISMATCH, "family_id", p.familyId, report.familyId)
    pin(ErrorCode.POLICY_IMAGE_ID_MISMATCH, "image_id", p.imageId, report.imageId)
    pin(ErrorCode.POLICY_REPORT_ID_MISMATCH, "report_id", p.reportId, report.reportId)
    when (val ib = p.idBlock) {
        IdBlockPin.Forbid -> {
            if (report.signerInfo.authorKeyEnabled) bad(ErrorCode.POLICY_ID_BLOCK, "author_key_en set but ID block forbidden", "signer_info.author_key_en")
            if (!report.idKeyDigest.isZero()) bad(ErrorCode.POLICY_ID_BLOCK, "id_key_digest nonzero but ID block forbidden", "id_key_digest")
            if (!report.authorKeyDigest.isZero()) bad(ErrorCode.POLICY_ID_BLOCK, "author_key_digest nonzero but ID block forbidden", "author_key_digest")
        }
        is IdBlockPin.Pinned -> {
            pin(ErrorCode.POLICY_ID_BLOCK, "id_key_digest", ib.idKeyDigest, report.idKeyDigest)
            ib.authorKeyDigest?.let { ak ->
                val wantAuthor = !ak.isZero() // all-zero pin means "no author key"
                if (report.signerInfo.authorKeyEnabled != wantAuthor) bad(ErrorCode.POLICY_ID_BLOCK, "author_key_en is ${if (report.signerInfo.authorKeyEnabled) 1 else 0}, pinned author_key_digest implies ${if (wantAuthor) 1 else 0}", "author_key_digest")
                pin(ErrorCode.POLICY_ID_BLOCK, "author_key_digest", ak, report.authorKeyDigest)
            }
        }
        IdBlockPin.Any -> {}
    }
    return v
}

private fun fwAtLeast(fw: FirmwareVersion, min: FirmwareVersion): Boolean {
    val a = listOf(fw.major, fw.minor, fw.build);
    val b = listOf(min.major, min.minor, min.build)
    for (i in 0..2) {
        if (a[i] > b[i]) return true
        if (a[i] < b[i]) return false
    }
    return true
}

private fun fmtTcb(t: TcbVersion) = "bl=${t.bootloader} tee=${t.tee} snp=${t.snp} ucode=${t.microcode}" + (t.fmc?.let { " fmc=$it" } ?: "")
private fun fmtFloor(t: TcbFloor) = "bl=${t.bootloader ?: "*"} tee=${t.tee ?: "*"} snp=${t.snp ?: "*"} ucode=${t.microcode ?: "*"}" + (t.fmc?.let { " fmc=$it" } ?: "")
