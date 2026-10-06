package cat.lsd.snpverify

// JSON form of the appraisal policy: the shape toJson() renders as appraisalPolicy, read back. Mirrors ts/src/policy-json.ts.
// Bytes are lowercase hex, 64-bit values decimal strings, enumerations strings; a "$comment" key in any object is ignored.
// The checks run in the same order as the TypeScript port, so the same document yields the same POLICY_INVALID message.
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener
import java.math.BigDecimal
import java.math.BigInteger

private val POLICY_KEYS = setOf(
    "measurement", "products", "signingKey", "allowMaskedChipId", "chipIds", "endorsementKeyFingerprints", "cspIds", "requireCrl",
    "guestPolicy", "platformInfo", "vmpl", "minReportVersion", "minGuestSvn", "minTcb", "minLaunchTcb", "minFirmware", "allowProvisionalFirmware",
    "minLaunchMitVector", "minCurrentMitVector", "reportData", "hostData", "familyId", "imageId", "reportId", "idBlock",
)
private val GUEST_POLICY_KEYS = setOf("debug", "migrateMa", "smt", "singleSocket", "cxlAllowed", "memAes256Xts", "raplDisabled", "ciphertextHidingDram", "pageSwapDisabled", "minAbi")
private val PLATFORM_INFO_KEYS = setOf("smtEnabled", "tsmeEnabled", "eccEnabled", "raplDisabled", "ciphertextHidingEnabled", "aliasCheckComplete", "iommuWriteSafe", "tioEnabled", "allowUnknownBits")
private val FLOOR_KEYS = setOf("bootloader", "tee", "snp", "microcode", "fmc")
private const val COMMENT = "\$comment"

/**
 * Parse the JSON form from text. A malformed document yields POLICY_INVALID. org.json accepts a superset of JSON
 * (unquoted keys, single quotes, comments) and, on the JVM, rejects duplicate keys; valid JSON without duplicate keys
 * behaves as in the other ports.
 */
fun appraisalPolicyFromJson(json: String): Result<AppraisalPolicy> {
    val tokener = JSONTokener(json)
    val value = try {
        tokener.nextValue().also { if (tokener.nextClean() != 0.toChar()) throw JSONException("trailing content") }
    } catch (e: JSONException) {
        null
    }
    if (value !is JSONObject && value !is JSONArray) return Result.Err(Violation(ErrorCode.POLICY_INVALID, "policy is not valid JSON"))
    return fromJsonValue(value)
}

/** Parse the JSON form from an already-parsed object. */
fun appraisalPolicyFromJson(json: JSONObject): Result<AppraisalPolicy> = fromJsonValue(json)

private fun fromJsonValue(v: Any?): Result<AppraisalPolicy> = try {
    Result.Ok(parse(v))
} catch (e: Invalid) {
    Result.Err(Violation(ErrorCode.POLICY_INVALID, e.message ?: "invalid policy"))
}

private fun obj(v: Any?, path: String): JSONObject = v as? JSONObject ?: throw Invalid("$path must be an object")
private fun keys(o: JSONObject, path: String, allowed: Set<String>) = need(o.keys().asSequence().all { it == COMMENT || it in allowed }, "$path has unknown fields")
private fun bool(o: JSONObject, key: String, path: String): Boolean? = if (!o.has(key)) null else (o.opt(key) as? Boolean ?: throw Invalid("$path must be boolean"))

private fun integral(v: Any?): Long? = when (v) {
    is Int -> v.toLong()
    is Long -> v
    is Double -> if (v.isFinite() && v == Math.floor(v) && Math.abs(v) < 9.0e18) v.toLong() else null
    is BigInteger -> if (v.bitLength() < 63) v.toLong() else null
    is BigDecimal -> try {
        v.longValueExact()
    } catch (e: ArithmeticException) {
        null
    }
    else -> null
}

private fun uint(v: Any?, max: Long, path: String): Long {
    val n = integral(v)
    need(n != null && n in 0..max, "$path must be an integer in 0..$max")
    return n!!
}

private fun isHexString(v: Any?) = v is String && v.length % 2 == 0 && v.all { it in "0123456789abcdefABCDEF" }
private fun hexSyntax(v: Any?, path: String) = need(isHexString(v), "$path must be a hex string")
private fun hexListSyntax(v: Any?, path: String) {
    if (v is JSONArray) for (i in 0 until v.length()) hexSyntax(v.opt(i), "$path[]")
}

/** Mirrors the conversion pass of the TypeScript port, which runs before its shape validation. */
private fun checkHexSyntax(p: JSONObject) {
    if (p.opt("measurement") != "any") hexListSyntax(p.opt("measurement"), "policy.measurement")
    hexListSyntax(p.opt("chipIds"), "policy.chipIds")
    hexListSyntax(p.opt("endorsementKeyFingerprints"), "policy.endorsementKeyFingerprints")
    (p.opt("reportData") as? JSONObject)?.let { rd -> if (rd.has("value")) hexSyntax(rd.opt("value"), "policy.reportData.value") }
    for (k in listOf("hostData", "familyId", "imageId", "reportId")) if (p.has(k)) hexSyntax(p.opt(k), "policy.$k")
    (p.opt("idBlock") as? JSONObject)?.let { ib -> for (k in listOf("idKeyDigest", "authorKeyDigest")) if (ib.has(k)) hexSyntax(ib.opt(k), "policy.idBlock.$k") }
    for (k in listOf("minLaunchMitVector", "minCurrentMitVector")) {
        if (p.has(k)) {
            val s = p.opt(k)
            need(s is String && s.isNotEmpty() && s.all { it in '0'..'9' }, "policy.$k must be uint64")
        }
    }
}

/** Decodes a value already checked by [checkHexSyntax]; null when absent. */
private fun hexLen(v: Any?, n: Int, path: String): ByteArray? = v?.let {
    val b = fromHex(it as String)
    need(b.size == n, "$path must be $n bytes")
    b
}

private fun hexList(a: JSONArray, n: Int, path: String): List<ByteArray> = (0 until a.length()).map { hexLen(a.opt(it), n, path)!! }

private fun bit(o: JSONObject, key: String, path: String): Bit? = if (!o.has(key)) {
    null
} else {
    when (o.opt(key)) {
        "required" -> Bit.REQUIRED
        "forbidden" -> Bit.FORBIDDEN
        "any" -> Bit.ANY
        else -> throw Invalid("$path.$key is not a Bit")
    }
}

private fun floors(v: Any?, path: String): Map<Product, TcbFloor> {
    val o = obj(v, path)
    keys(o, path, Product.entries.map { it.name }.toSet())
    val out = LinkedHashMap<Product, TcbFloor>()
    for (product in Product.entries) {
        if (!o.has(product.name)) continue
        val fpath = "$path.$product"
        val fo = obj(o.opt(product.name), fpath)
        keys(fo, fpath, FLOOR_KEYS)
        fun component(key: String): Int? = if (fo.has(key)) uint(fo.opt(key), 255, "$fpath.$key").toInt() else null
        out[product] = TcbFloor(component("bootloader"), component("tee"), component("snp"), component("microcode"), component("fmc"))
    }
    return out
}

private fun parse(v: Any?): AppraisalPolicy {
    val p = obj(v, "policy")
    checkHexSyntax(p)
    keys(p, "policy", POLICY_KEYS)

    need(p.has("measurement"), "policy.measurement is required: an allowlist or the explicit string \"any\"")
    val m = p.opt("measurement")
    val measurement = if (m == "any") {
        MeasurementPin.Any
    } else {
        need(m is JSONArray && m.length() > 0, "policy.measurement must be a nonempty array or \"any\"")
        MeasurementPin.Allowlist(hexList(m as JSONArray, 48, "policy.measurement[]"))
    }
    var reportData: ReportDataPin? = null
    if (p.has("reportData")) {
        val o = obj(p.opt("reportData"), "policy.reportData")
        val kind = o.opt("kind")
        need(kind == "any" || kind == "exact" || kind == "prefix", "policy.reportData.kind is invalid")
        reportData = if (kind == "any") {
            keys(o, "policy.reportData", setOf("kind"))
            ReportDataPin.Any
        } else {
            keys(o, "policy.reportData", setOf("kind", "value"))
            val value = (o.opt("value") as? String)?.let { fromHex(it) }
            need(value != null && value.size in 1..64, "policy.reportData.value must be 1..64 bytes")
            if (kind == "exact") {
                need(value!!.size == 64, "policy.reportData.value must be 64 bytes")
                ReportDataPin.Exact(value)
            } else {
                ReportDataPin.Prefix(value!!)
            }
        }
    }
    val hostData = hexLen(p.opt("hostData"), 32, "policy.hostData")
    val familyId = hexLen(p.opt("familyId"), 16, "policy.familyId")
    val imageId = hexLen(p.opt("imageId"), 16, "policy.imageId")
    val reportId = hexLen(p.opt("reportId"), 32, "policy.reportId")
    var products: List<Product>? = null
    if (p.has("products")) {
        val a = p.opt("products") as? JSONArray
        val list = a?.let { arr -> (0 until arr.length()).map { i -> Product.entries.find { it.name == arr.opt(i) } } }
        need(list != null && list.isNotEmpty() && list.all { it != null }, "policy.products must be a nonempty Product list")
        products = list!!.map { it!! }
    }
    var signingKey: SigningKeyPolicy? = null
    if (p.has("signingKey")) {
        signingKey = when (p.opt("signingKey")) {
            "VCEK" -> SigningKeyPolicy.VCEK
            "VLEK" -> SigningKeyPolicy.VLEK
            "any" -> SigningKeyPolicy.ANY
            else -> throw Invalid("policy.signingKey is invalid")
        }
    }
    val allowMaskedChipId = bool(p, "allowMaskedChipId", "policy.allowMaskedChipId")
    val requireCrl = bool(p, "requireCrl", "policy.requireCrl")
    val allowProvisionalFirmware = bool(p, "allowProvisionalFirmware", "policy.allowProvisionalFirmware")
    if (p.has("chipIds")) need(p.opt("chipIds") is JSONArray, "policy.chipIds must be an array")
    if (p.has("endorsementKeyFingerprints")) need(p.opt("endorsementKeyFingerprints") is JSONArray, "policy.endorsementKeyFingerprints must be an array")
    val chipIds = (p.opt("chipIds") as? JSONArray)?.let { hexList(it, 64, "policy.chipIds[]") }
    val fingerprints = (p.opt("endorsementKeyFingerprints") as? JSONArray)?.let { hexList(it, 32, "policy.endorsementKeyFingerprints[]") }
    var cspIds: List<String>? = null
    if (p.has("cspIds")) {
        val a = p.opt("cspIds") as? JSONArray
        val list = a?.let { arr -> (0 until arr.length()).map { arr.opt(it) as? String } }
        need(list != null && list.isNotEmpty() && list.all { !it.isNullOrEmpty() }, "policy.cspIds must be nonempty strings")
        cspIds = list!!.map { it!! }
    }
    var idBlock: IdBlockPin? = null
    if (p.has("idBlock")) {
        val v = p.opt("idBlock")
        need(v == "forbid" || v == "any" || v is JSONObject, "policy.idBlock is invalid")
        idBlock = when (v) {
            "forbid" -> IdBlockPin.Forbid
            "any" -> IdBlockPin.Any
            else -> {
                val o = v as JSONObject
                keys(o, "policy.idBlock", setOf("idKeyDigest", "authorKeyDigest"))
                need(o.has("idKeyDigest"), "policy.idBlock.idKeyDigest is required")
                IdBlockPin.Pinned(hexLen(o.opt("idKeyDigest"), 48, "policy.idBlock.idKeyDigest")!!, hexLen(o.opt("authorKeyDigest"), 48, "policy.idBlock.authorKeyDigest"))
            }
        }
    }
    var guestPolicy: GuestPolicyRules? = null
    if (p.has("guestPolicy")) {
        val o = obj(p.opt("guestPolicy"), "policy.guestPolicy")
        keys(o, "policy.guestPolicy", GUEST_POLICY_KEYS)
        fun b(key: String) = bit(o, key, "policy.guestPolicy")
        var minAbi: Pair<Int, Int>? = null
        if (o.has("minAbi")) {
            val ao = obj(o.opt("minAbi"), "policy.guestPolicy.minAbi")
            keys(ao, "policy.guestPolicy.minAbi", setOf("major", "minor"))
            need(ao.has("major") && ao.has("minor"), "policy.guestPolicy.minAbi requires major and minor")
            minAbi = Pair(uint(ao.opt("major"), 255, "policy.guestPolicy.minAbi.major").toInt(), uint(ao.opt("minor"), 255, "policy.guestPolicy.minAbi.minor").toInt())
        }
        guestPolicy = GuestPolicyRules(b("debug"), b("migrateMa"), b("smt"), b("singleSocket"), b("cxlAllowed"), b("memAes256Xts"), b("raplDisabled"), b("ciphertextHidingDram"), b("pageSwapDisabled"), minAbi)
    }
    var platformInfo: PlatformInfoRules? = null
    if (p.has("platformInfo")) {
        val o = obj(p.opt("platformInfo"), "policy.platformInfo")
        keys(o, "policy.platformInfo", PLATFORM_INFO_KEYS)
        fun b(key: String) = bit(o, key, "policy.platformInfo")
        platformInfo = PlatformInfoRules(
            b("smtEnabled"), b("tsmeEnabled"), b("eccEnabled"), b("raplDisabled"), b("ciphertextHidingEnabled"), b("aliasCheckComplete"), b("iommuWriteSafe"), b("tioEnabled"),
            bool(o, "allowUnknownBits", "policy.platformInfo.allowUnknownBits"),
        )
    }
    var vmpl: Int? = null
    var vmplAny = false
    if (p.has("vmpl")) {
        val v = p.opt("vmpl")
        if (v is Number) {
            val n = integral(v)
            need(n != null && n in 0..3, "policy.vmpl must be 0..3")
            vmpl = n!!.toInt()
        } else {
            need(v == "any", "policy.vmpl must be 0..3 or any")
            vmplAny = true
        }
    }
    var minReportVersion: Int? = null
    if (p.has("minReportVersion")) {
        val n = integral(p.opt("minReportVersion"))
        need(n != null && n in 2..5, "policy.minReportVersion must be 2..5")
        minReportVersion = n!!.toInt()
    }
    val minGuestSvn = if (p.has("minGuestSvn")) uint(p.opt("minGuestSvn"), 0xffffffffL, "policy.minGuestSvn") else null
    val minTcb = if (p.has("minTcb")) floors(p.opt("minTcb"), "policy.minTcb") else null
    val minLaunchTcb = if (p.has("minLaunchTcb")) floors(p.opt("minLaunchTcb"), "policy.minLaunchTcb") else null
    var minFirmware: FirmwareVersion? = null
    if (p.has("minFirmware")) {
        val o = obj(p.opt("minFirmware"), "policy.minFirmware")
        keys(o, "policy.minFirmware", setOf("major", "minor", "build"))
        fun component(key: String): Int = if (o.has(key)) uint(o.opt(key), 255, "policy.minFirmware.$key").toInt() else 0
        minFirmware = FirmwareVersion(component("major"), component("minor"), component("build"))
    }
    fun u64(key: String): ULong? = if (p.has(key)) (p.opt(key) as String).toULongOrNull() ?: throw Invalid("policy.$key must be uint64") else null
    return AppraisalPolicy(
        measurement = measurement, products = products, signingKey = signingKey, allowMaskedChipId = allowMaskedChipId, chipIds = chipIds,
        endorsementKeyFingerprints = fingerprints, cspIds = cspIds, requireCrl = requireCrl, guestPolicy = guestPolicy, platformInfo = platformInfo,
        vmpl = vmpl, vmplAny = vmplAny, minReportVersion = minReportVersion, minGuestSvn = minGuestSvn, minTcb = minTcb, minLaunchTcb = minLaunchTcb,
        minFirmware = minFirmware, allowProvisionalFirmware = allowProvisionalFirmware, minLaunchMitVector = u64("minLaunchMitVector"), minCurrentMitVector = u64("minCurrentMitVector"),
        reportData = reportData, hostData = hostData, familyId = familyId, imageId = imageId, reportId = reportId, idBlock = idBlock,
    )
}
