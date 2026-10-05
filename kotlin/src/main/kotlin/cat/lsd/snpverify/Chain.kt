package cat.lsd.snpverify

// AMD endorsement chain: ARK (pinned) -> ASK/ASVK -> VCEK/VLEK. VCEK extension parsing (57230). Optional CRL. Mirrors ts/src/chain.ts.

private object Kds {
    const val structVersion = "1.3.6.1.4.1.3704.1.1";
    const val productName = "1.3.6.1.4.1.3704.1.2"
    const val bl = "1.3.6.1.4.1.3704.1.3.1";
    const val tee = "1.3.6.1.4.1.3704.1.3.2";
    const val snp = "1.3.6.1.4.1.3704.1.3.3";
    const val spl4 = "1.3.6.1.4.1.3704.1.3.4"
    const val spl5 = "1.3.6.1.4.1.3704.1.3.5";
    const val spl6 = "1.3.6.1.4.1.3704.1.3.6";
    const val spl7 = "1.3.6.1.4.1.3704.1.3.7";
    const val ucode = "1.3.6.1.4.1.3704.1.3.8"
    const val fmc = "1.3.6.1.4.1.3704.1.3.9";
    const val hwid = "1.3.6.1.4.1.3704.1.4";
    const val cspId = "1.3.6.1.4.1.3704.1.5"
}

class EndorsementKey internal constructor(val kind: SigningKey, val product: Product, val productName: String, hwid: ByteArray?, val cspId: String?, val tcb: TcbVersion, val cert: Certificate) {
    private val hwidBytes = hwid?.copyOf()

    /** VCEK: 64 (Milan/Genoa) or 8 (Turin) bytes; copy on every access. */
    val hwid: ByteArray? get() = hwidBytes?.copyOf()
}

data class ChainInput(val leaf: ByteArray, val intermediate: ByteArray? = null, val root: ByteArray? = null, val crl: ByteArray? = null, val now: Long)
data class CrlInfo(val thisUpdate: Long, val nextUpdate: Long?, val revokedCount: Int)
class Chain(val leaf: EndorsementKey, val intermediate: Certificate, val root: Certificate, val crl: CrlInfo?)

private fun extInt(cert: Certificate, oid: String, what: String): Int {
    val e = cert.extensions[oid] ?: fail(ErrorCode.VCEK_EXTENSION_INVALID, "missing $what extension")
    val t = readTlv(e.value, 0)
    if (t.end != e.value.size) fail(ErrorCode.VCEK_EXTENSION_INVALID, "$what: trailing bytes")
    val v = smallInt(e.value, t, what)
    if (v > 255) fail(ErrorCode.VCEK_EXTENSION_INVALID, "$what out of range")
    return v.toInt()
}

private fun extString(cert: Certificate, oid: String, what: String): String? {
    val e = cert.extensions[oid] ?: return null
    val t = readTlv(e.value, 0)
    if (t.tag != Tag.IA5 && t.tag != Tag.UTF8 && t.tag != Tag.PRINTABLE) fail(ErrorCode.VCEK_EXTENSION_INVALID, "$what: not a string")
    val value = content(e.value, t)
    if (value.size > 4096 || value.any { it.toInt() and 0xff > 0x7f }) fail(ErrorCode.VCEK_EXTENSION_INVALID, "$what: invalid ASCII")
    return String(value, Charsets.US_ASCII)
}

/** Parse the AMD extensions of a VCEK/VLEK. KDS emits HWID either raw or wrapped in an OCTET STRING. */
internal fun parseEndorsementKey(cert: Certificate): EndorsementKey {
    val productName = extString(cert, Kds.productName, "productName") ?: fail(ErrorCode.VCEK_EXTENSION_INVALID, "missing productName extension")
    val product = productFromName(productName) ?: fail(ErrorCode.VCEK_EXTENSION_INVALID, "unknown product \"$productName\"")
    val info = PRODUCTS.getValue(product)
    val structVersion = extInt(cert, Kds.structVersion, "structVersion")
    if (structVersion != info.structVersion) fail(ErrorCode.VCEK_EXTENSION_INVALID, "structVersion $structVersion does not match $product")

    val hwidExt = cert.extensions[Kds.hwid]
    val cspId = extString(cert, Kds.cspId, "cspId")
    if (hwidExt != null && cspId != null) fail(ErrorCode.VCEK_EXTENSION_INVALID, "certificate has both HWID and CSP_ID")
    if (hwidExt == null && cspId == null) fail(ErrorCode.VCEK_EXTENSION_INVALID, "certificate has neither HWID (VCEK) nor CSP_ID (VLEK)")
    var hwid: ByteArray? = null
    if (hwidExt != null) {
        var h = hwidExt.value
        if (h.size != info.hwidLength && h.u8(0) == Tag.OCTET_STRING) h = content(h, expect(readTlv(h, 0), Tag.OCTET_STRING, "HWID"))
        if (h.size != info.hwidLength) fail(ErrorCode.VCEK_EXTENSION_INVALID, "HWID is ${h.size} bytes, want ${info.hwidLength}")
        hwid = h
    }

    var tcb = TcbVersion(extInt(cert, Kds.bl, "blSPL"), extInt(cert, Kds.tee, "teeSPL"), extInt(cert, Kds.snp, "snpSPL"), extInt(cert, Kds.ucode, "ucodeSPL"))
    for ((oid, what) in listOf(Kds.spl5 to "spl5", Kds.spl6 to "spl6", Kds.spl7 to "spl7")) if (extInt(cert, oid, what) != 0) fail(ErrorCode.VCEK_EXTENSION_INVALID, "$what must be 0")
    if (info.tcbLayout == TcbLayout.V0) {
        if (cert.extensions.containsKey(Kds.fmc)) fail(ErrorCode.VCEK_EXTENSION_INVALID, "fmcSPL not valid for this product")
        if (extInt(cert, Kds.spl4, "spl4") != 0) fail(ErrorCode.VCEK_EXTENSION_INVALID, "spl4 must be 0")
    } else {
        if (cert.extensions.containsKey(Kds.spl4)) fail(ErrorCode.VCEK_EXTENSION_INVALID, "spl4 not valid for this product")
        tcb = tcb.copy(fmc = extInt(cert, Kds.fmc, "fmcSPL"))
    }
    val kind = if (hwid != null) SigningKey.VCEK else SigningKey.VLEK
    if (!cert.subjectCN.startsWith("SEV-$kind")) fail(ErrorCode.VCEK_EXTENSION_INVALID, "leaf CN \"${cert.subjectCN}\" is not SEV-$kind")
    return EndorsementKey(kind, product, productName, hwid, cspId, tcb, cert)
}

private fun checkValidity(cert: Certificate, now: Long, what: String) {
    if (now < cert.notBefore) fail(ErrorCode.CERT_NOT_YET_VALID, "$what not valid before ${java.time.Instant.ofEpochSecond(cert.notBefore)}")
    if (now > cert.notAfter) fail(ErrorCode.CERT_EXPIRED, "$what expired at ${java.time.Instant.ofEpochSecond(cert.notAfter)}")
}

private fun checkCertificatePurpose(cert: Certificate, ca: Boolean) {
    for (e in cert.extensions.values) {
        if (e.critical && e.oid != "2.5.29.19" && e.oid != "2.5.29.15") {
            fail(ErrorCode.CERT_MALFORMED, "unsupported critical certificate extension ${e.oid}")
        }
    }
    val bc = cert.extensions["2.5.29.19"]
    if (ca && bc == null) fail(ErrorCode.CERT_MALFORMED, "CA certificate lacks basicConstraints")
    if (bc != null) {
        val t = expect(readTlv(bc.value, 0), Tag.SEQUENCE, "basicConstraints")
        if (t.end != bc.value.size) fail(ErrorCode.CERT_MALFORMED, "basicConstraints trailing bytes")
        val fields = children(bc.value, t)
        val isCa = fields.firstOrNull()?.tag == Tag.BOOLEAN && content(bc.value, fields[0]).contentEquals(byteArrayOf(0xff.toByte()))
        if (ca != isCa) fail(ErrorCode.CERT_MALFORMED, "basicConstraints CA=$isCa is wrong for ${if (ca) "issuer" else "leaf"}")
    }
    val ku = keyUsageBits(cert)
    if (ku != null && ku and (if (ca) 0x04 else 0x80) == 0) fail(ErrorCode.CERT_MALFORMED, "keyUsage does not permit ${if (ca) "certificate signing" else "digital signing"}")
}

/** First keyUsage byte, or null when the extension is absent. */
private fun keyUsageBits(cert: Certificate): Int? {
    val e = cert.extensions["2.5.29.15"] ?: return null
    val value = e.value
    val t = expect(readTlv(value, 0), Tag.BIT_STRING, "keyUsage")
    if (t.end != value.size || t.end - t.start < 2) fail(ErrorCode.CERT_MALFORMED, "invalid keyUsage")
    return value.u8(t.start + 1)
}

private fun signedBy(crypto: CryptoProvider, alg: SignatureAlgorithm, signature: ByteArray, tbs: ByteArray, issuer: Certificate): Boolean {
    val pss = alg.pss
    if (alg.oid != Oid.rsassaPss || pss == null) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "signature algorithm ${alg.oid}")
    if (pss.hash != "SHA-384" || pss.saltLength != 48) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "RSASSA-PSS must use SHA-384 with salt length 48")
    if (issuer.spkiAlgorithm != Oid.rsaEncryption) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "issuer key is not RSA")
    return crypto.verifyRsaPss(issuer.spki, tbs, signature, 48)
}

/** Verify the chain. `trustedRoots` must contain a DER byte-equal to the root used (default: embedded ARK of the leaf's product). */
fun verifyChain(callerInput: ChainInput, trustedRoots: List<ByteArray>?, crypto: CryptoProvider): Result<Chain> = stage {
    // Check sizes, then copy every input at entry.
    checkCollateralSizes(callerInput.leaf, callerInput.intermediate, callerInput.root, callerInput.crl)
    val input = ChainInput(callerInput.leaf.copyOf(), callerInput.intermediate?.copyOf(), callerInput.root?.copyOf(), callerInput.crl?.copyOf(), callerInput.now)
    val trustedRoots = trustedRoots?.map { it.copyOf() }
    val leafCert = parseCertificate(input.leaf)
    val leaf = parseEndorsementKey(leafCert)
    val defaults = embeddedRoots(leaf.product)
    val rootDer = input.root ?: defaults?.ark ?: fail(ErrorCode.ARK_UNTRUSTED, "no embedded root for ${leaf.product}; pass one")
    val interDer = input.intermediate ?: defaults?.ask ?: fail(ErrorCode.CERT_MALFORMED, "no embedded intermediate for ${leaf.product}; pass one")
    val trusted = trustedRoots ?: listOfNotNull(defaults?.ark)
    if (trusted.none { it.contentEquals(rootDer) }) fail(ErrorCode.ARK_UNTRUSTED, "root certificate is not a trusted ARK")
    val root = parseCertificate(rootDer)
    val intermediate = parseCertificate(interDer)

    val p = leaf.product
    if (!root.subjectCN.endsWith("-$p")) fail(ErrorCode.PRODUCT_MISMATCH, "ARK \"${root.subjectCN}\" is not for $p")
    if (!intermediate.subjectCN.endsWith("-$p")) fail(ErrorCode.PRODUCT_MISMATCH, "intermediate \"${intermediate.subjectCN}\" is not for $p")
    if ((leaf.kind == SigningKey.VLEK) != intermediate.subjectCN.startsWith("SEV-VLEK")) fail(ErrorCode.PRODUCT_MISMATCH, "${leaf.kind} must be issued by ${if (leaf.kind == SigningKey.VLEK) "an ASVK" else "an ASK"}")

    for ((c, what) in listOf(root to "ARK", intermediate to "ASK", leafCert to leaf.kind.name)) {
        if (c.subjectName.o != "Advanced Micro Devices" || c.subjectName.ou != "Engineering") fail(ErrorCode.CHAIN_NAME_MISMATCH, "$what subject is not AMD Engineering")
    }
    if (!leafCert.issuer.contentEquals(intermediate.subject)) fail(ErrorCode.CHAIN_NAME_MISMATCH, "leaf issuer != intermediate subject")
    if (!intermediate.issuer.contentEquals(root.subject)) fail(ErrorCode.CHAIN_NAME_MISMATCH, "intermediate issuer != root subject")
    if (!root.issuer.contentEquals(root.subject)) fail(ErrorCode.CHAIN_NAME_MISMATCH, "root is not self-issued")

    checkValidity(root, input.now, "ARK")
    checkValidity(intermediate, input.now, "ASK")
    checkValidity(leafCert, input.now, leaf.kind.name)
    checkCertificatePurpose(root, true)
    checkCertificatePurpose(intermediate, true)
    checkCertificatePurpose(leafCert, false)
    if (leafCert.spkiAlgorithm != Oid.ecPublicKey || leafCert.spkiCurve != Oid.p384) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "${leaf.kind} key is not EC P-384")

    if (!signedBy(crypto, root.signatureAlgorithm, root.signature, root.tbs, root)) fail(ErrorCode.CHAIN_SIGNATURE_INVALID, "ARK self-signature invalid")
    if (!signedBy(crypto, intermediate.signatureAlgorithm, intermediate.signature, intermediate.tbs, root)) fail(ErrorCode.CHAIN_SIGNATURE_INVALID, "ASK not signed by ARK")
    if (!signedBy(crypto, leafCert.signatureAlgorithm, leafCert.signature, leafCert.tbs, intermediate)) fail(ErrorCode.CHAIN_SIGNATURE_INVALID, "${leaf.kind} not signed by ASK")

    val crl = input.crl?.let { checkCrl(it, root, intermediate, input.now, crypto) }
    Chain(leaf, intermediate, root, crl)
}

/** Size caps, checked before any copy or parse. */
internal fun checkCollateralSizes(leaf: ByteArray?, intermediate: ByteArray?, root: ByteArray?, crl: ByteArray?) {
    for ((what, b) in listOf("leaf" to leaf, "intermediate" to intermediate, "root" to root)) {
        if (b != null && b.size > MAX_CERT_BYTES) fail(ErrorCode.CERT_MALFORMED, "$what certificate is ${b.size} bytes, limit $MAX_CERT_BYTES")
    }
    if (crl != null && crl.size > MAX_CRL_BYTES) fail(ErrorCode.CRL_INVALID, "CRL is ${crl.size} bytes, limit $MAX_CRL_BYTES")
}

/** KDS CRLs are ARK-signed and list revoked ASK/ASVK serials. VCEKs (serial 0) are never revoked; TCB supersedes them. */
internal fun checkCrl(crlDer: ByteArray, root: Certificate, intermediate: Certificate, now: Long, crypto: CryptoProvider): CrlInfo {
    val crl = parseCrl(crlDer)
    if (crl.nextUpdate == null) fail(ErrorCode.CRL_INVALID, "CRL has no nextUpdate")
    if (crl.extensions.containsKey("2.5.29.27")) fail(ErrorCode.CRL_INVALID, "delta CRL requires a base CRL")
    for (ext in crl.extensions.values) if (ext.critical) fail(ErrorCode.CRL_INVALID, "unsupported critical CRL extension ${ext.oid}")
    val ku = keyUsageBits(root) ?: fail(ErrorCode.CRL_INVALID, "CRL issuer lacks keyUsage")
    if (ku and 0x02 == 0) fail(ErrorCode.CRL_INVALID, "CRL issuer keyUsage does not permit CRL signing")
    if (!crl.issuer.contentEquals(root.subject)) fail(ErrorCode.CRL_INVALID, "CRL issuer is not the ARK")
    if (!signedBy(crypto, crl.signatureAlgorithm, crl.signature, crl.tbs, root)) fail(ErrorCode.CRL_INVALID, "CRL signature invalid")
    if (now < crl.thisUpdate) fail(ErrorCode.CRL_INVALID, "CRL thisUpdate is in the future")
    if (now > crl.nextUpdate) fail(ErrorCode.CRL_EXPIRED, "CRL nextUpdate ${java.time.Instant.ofEpochSecond(crl.nextUpdate)} passed")
    for (serial in crl.revokedSerials) {
        if (serial.contentEquals(intermediate.serial)) fail(ErrorCode.CERT_REVOKED, "intermediate serial ${serial.hex()} is revoked")
        if (serial.contentEquals(root.serial)) fail(ErrorCode.CERT_REVOKED, "root serial ${serial.hex()} is revoked")
    }
    return CrlInfo(crl.thisUpdate, crl.nextUpdate, crl.revokedSerials.size)
}
