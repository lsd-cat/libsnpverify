package cat.lsd.snpverify

// DER reader and X.509 certificate / CRL parser for AMD's ARK, ASK, VCEK, VLEK certificates and KDS CRLs. Mirrors ts/src/der.ts.

internal data class Tlv(val tag: Int, val start: Int, val end: Int, val at: Int)

internal object Tag {
    const val BOOLEAN = 0x01;
    const val INTEGER = 0x02;
    const val BIT_STRING = 0x03;
    const val OCTET_STRING = 0x04;
    const val OID = 0x06
    const val UTF8 = 0x0c;
    const val SEQUENCE = 0x30;
    const val PRINTABLE = 0x13;
    const val IA5 = 0x16;
    const val UTCTIME = 0x17;
    const val GENTIME = 0x18
    const val CTX0 = 0xa0;
    const val CTX1 = 0xa1;
    const val CTX2 = 0xa2;
    const val CTX3 = 0xa3
}

internal object Oid {
    const val rsaEncryption = "1.2.840.113549.1.1.1";
    const val rsassaPss = "1.2.840.113549.1.1.10";
    const val ecPublicKey = "1.2.840.10045.2.1"
    const val p384 = "1.3.132.0.34";
    const val sha256 = "2.16.840.1.101.3.4.2.1";
    const val sha384 = "2.16.840.1.101.3.4.2.2";
    const val sha512 = "2.16.840.1.101.3.4.2.3"
    const val mgf1 = "1.2.840.113549.1.1.8";
    const val cn = "2.5.4.3";
    const val o = "2.5.4.10";
    const val ou = "2.5.4.11"
}

internal fun readTlv(b: ByteArray, at: Int, limit: Int = b.size): Tlv {
    if (at + 2 > limit) fail(ErrorCode.CERT_MALFORMED, "DER: truncated header")
    val tag = b.u8(at)
    if (tag and 0x1f == 0x1f) fail(ErrorCode.CERT_MALFORMED, "DER: multi-byte tags unsupported")
    var i = at + 1
    var len = b.u8(i++)
    if (len == 0x80) fail(ErrorCode.CERT_MALFORMED, "DER: indefinite length")
    if (len and 0x80 != 0) {
        val n = len and 0x7f
        if (n == 0 || n > 4 || i + n > limit) fail(ErrorCode.CERT_MALFORMED, "DER: bad length")
        len = 0
        repeat(n) { len = len * 256 + b.u8(i++) }
        if (len < 0x80 && n == 1) fail(ErrorCode.CERT_MALFORMED, "DER: non-minimal length")
    }
    if (len < 0 || i + len > limit) fail(ErrorCode.CERT_MALFORMED, "DER: content exceeds bounds")
    return Tlv(tag, i, i + len, at)
}

internal fun children(b: ByteArray, t: Tlv): List<Tlv> {
    val out = ArrayList<Tlv>()
    var o = t.start
    while (o < t.end) {
        val c = readTlv(b, o, t.end)
        out.add(c)
        o = c.end
    }
    return out
}

internal fun expect(t: Tlv, tag: Int, what: String): Tlv {
    if (t.tag != tag) fail(ErrorCode.CERT_MALFORMED, "DER: $what: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}")
    return t
}
internal fun raw(b: ByteArray, t: Tlv): ByteArray = b.copyOfRange(t.at, t.end)
internal fun content(b: ByteArray, t: Tlv): ByteArray = b.copyOfRange(t.start, t.end)

internal fun oidToString(b: ByteArray, t: Tlv): String {
    expect(t, Tag.OID, "OID")
    val c = content(b, t)
    if (c.isEmpty()) fail(ErrorCode.CERT_MALFORMED, "DER: empty OID")
    val parts = ArrayList<Long>()
    var v = 0L
    for (x in c) {
        v = v * 128 + (x.toInt() and 0x7f)
        if (x.toInt() and 0x80 == 0) {
            if (parts.isEmpty()) {
                val first = minOf(2L, v / 40);
                parts.add(first);
                parts.add(v - 40 * first)
            } else {
                parts.add(v)
            }
            v = 0
        }
    }
    return parts.joinToString(".")
}

/** Small non-negative INTEGER. */
internal fun smallInt(b: ByteArray, t: Tlv, what: String): Long {
    expect(t, Tag.INTEGER, what)
    val c = content(b, t)
    if (c.isEmpty() || c.size > 6) fail(ErrorCode.CERT_MALFORMED, "DER: $what: bad integer length")
    if (c[0].toInt() and 0x80 != 0) fail(ErrorCode.CERT_MALFORMED, "DER: $what: negative integer")
    var v = 0L;
    for (x in c) v = v * 256 + (x.toInt() and 0xff);
    return v
}

private fun parseTime(b: ByteArray, t: Tlv): Long {
    val s = String(content(b, t), Charsets.US_ASCII)
    val yearDigits = when (t.tag) {
        Tag.UTCTIME -> 2;
        Tag.GENTIME -> 4;
        else -> fail(ErrorCode.CERT_MALFORMED, "bad time tag")
    }
    val m = Regex("^(\\d{$yearDigits})(\\d{10})Z$").find(s) ?: fail(ErrorCode.CERT_MALFORMED, "bad time $s")
    var year = m.groupValues[1].toInt()
    if (yearDigits == 2) year += if (year >= 50) 1900 else 2000
    val rest = m.groupValues[2]
    val mo = rest.substring(0, 2).toInt()
    val d = rest.substring(2, 4).toInt()
    val h = rest.substring(4, 6).toInt()
    val mi = rest.substring(6, 8).toInt()
    val sec = rest.substring(8, 10).toInt()
    return java.time.LocalDateTime.of(year, mo, d, h, mi, sec).toEpochSecond(java.time.ZoneOffset.UTC)
}

/** Immutable: `value` returns a fresh copy on every access. */
class Extension internal constructor(val oid: String, val critical: Boolean, value: ByteArray) {
    private val bytes = value.copyOf()
    val value: ByteArray get() = bytes.copyOf()
}
data class PssParams(val hash: String, val saltLength: Int)
data class SignatureAlgorithm(val oid: String, val pss: PssParams?)
data class Name(val cn: String, val o: String, val ou: String)

/** Immutable: owns a private copy of the DER; byte-valued properties return fresh copies. */
class Certificate internal constructor(
    der: ByteArray,
    private val tbsRange: IntRange,
    serial: ByteArray,
    private val issuerRange: IntRange,
    private val subjectRange: IntRange,
    val subjectName: Name,
    val notBefore: Long,
    val notAfter: Long,
    private val spkiRange: IntRange,
    val spkiAlgorithm: String,
    val spkiCurve: String?,
    val signatureAlgorithm: SignatureAlgorithm,
    signature: ByteArray,
    val extensions: Map<String, Extension>,
) {
    private val bytes = der.copyOf()
    private val serialBytes = serial.copyOf()
    private val signatureBytes = signature.copyOf()
    val der: ByteArray get() = bytes.copyOf()
    val tbs: ByteArray get() = bytes.copyOfRange(tbsRange.first, tbsRange.last + 1)
    val serial: ByteArray get() = serialBytes.copyOf()
    val issuer: ByteArray get() = bytes.copyOfRange(issuerRange.first, issuerRange.last + 1)
    val subject: ByteArray get() = bytes.copyOfRange(subjectRange.first, subjectRange.last + 1)
    val spki: ByteArray get() = bytes.copyOfRange(spkiRange.first, spkiRange.last + 1)
    val signature: ByteArray get() = signatureBytes.copyOf()
    val subjectCN: String get() = subjectName.cn
}

/** Immutable: owns private copies; byte-valued properties return fresh copies. */
class Crl internal constructor(
    der: ByteArray,
    tbs: ByteArray,
    issuer: ByteArray,
    val thisUpdate: Long,
    val nextUpdate: Long?,
    revokedSerials: List<ByteArray>,
    val extensions: Map<String, Extension>,
    val signatureAlgorithm: SignatureAlgorithm,
    signature: ByteArray
) {
    private val derBytes = der.copyOf();
    private val tbsBytes = tbs.copyOf();
    private val issuerBytes = issuer.copyOf();
    private val signatureBytes = signature.copyOf()
    private val serials = revokedSerials.map { it.copyOf() }
    val der: ByteArray get() = derBytes.copyOf()
    val tbs: ByteArray get() = tbsBytes.copyOf()
    val issuer: ByteArray get() = issuerBytes.copyOf()
    val signature: ByteArray get() = signatureBytes.copyOf()
    val revokedSerials: List<ByteArray> get() = serials.map { it.copyOf() }
}

private fun hashName(oid: String): String = when (oid) {
    Oid.sha256 -> "SHA-256";
    Oid.sha384 -> "SHA-384";
    Oid.sha512 -> "SHA-512"
    else -> fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "unsupported hash OID $oid")
}

private fun parseSigAlg(b: ByteArray, t: Tlv): SignatureAlgorithm {
    expect(t, Tag.SEQUENCE, "AlgorithmIdentifier")
    val kids = children(b, t)
    val oid = oidToString(b, kids[0])
    if (oid != Oid.rsassaPss) return SignatureAlgorithm(oid, null)
    val params = kids.getOrNull(1) ?: fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "RSASSA-PSS without parameters")
    var hash: String? = null;
    var saltLength = 20;
    var mgfHash = ""
    for (p in children(b, params)) {
        val inner = children(b, p)[0]
        when (p.tag) {
            Tag.CTX0 -> hash = hashName(oidToString(b, children(b, inner)[0]))
            Tag.CTX1 -> {
                val (mgfOid, mgfParams) = children(b, inner)
                if (oidToString(b, mgfOid) != Oid.mgf1) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "PSS MGF is not MGF1")
                mgfHash = hashName(oidToString(b, children(b, mgfParams)[0]))
            }
            Tag.CTX2 -> saltLength = smallInt(b, inner, "saltLength").toInt()
            Tag.CTX3 -> if (smallInt(b, inner, "trailerField") != 1L) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "PSS trailerField")
        }
    }
    val h = hash ?: fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "PSS without explicit hash (SHA-1 default) is not accepted")
    if (mgfHash != h) fail(ErrorCode.CERT_ALGO_UNSUPPORTED, "PSS MGF1 must explicitly use the message hash")
    return SignatureAlgorithm(oid, PssParams(h, saltLength))
}

private fun parseName(b: ByteArray, name: Tlv): Name {
    var cn = "";
    var o = "";
    var ou = ""
    for (rdn in children(b, name)) {
        for (atv in children(b, rdn)) {
            val (oidT, v) = children(b, atv)
            if (v.end - v.start > 4096) fail(ErrorCode.CERT_MALFORMED, "DN attribute too long")
            val str = String(content(b, v), Charsets.UTF_8)
            when (oidToString(b, oidT)) {
                Oid.cn -> cn = str;
                Oid.o -> o = str;
                Oid.ou -> ou = str
            }
        }
    }
    return Name(cn, o, ou)
}

private fun bitStringContent(b: ByteArray, t: Tlv): ByteArray {
    expect(t, Tag.BIT_STRING, "BIT STRING")
    if (b[t.start].toInt() != 0) fail(ErrorCode.CERT_MALFORMED, "BIT STRING with unused bits")
    return b.copyOfRange(t.start + 1, t.end)
}

private fun parseExtensions(b: ByteArray, extsSeq: Tlv): Map<String, Extension> {
    val map = LinkedHashMap<String, Extension>()
    for (ext in children(b, expect(extsSeq, Tag.SEQUENCE, "Extensions"))) {
        val parts = children(b, ext)
        val oid = oidToString(b, parts[0])
        var critical = false;
        var i = 1
        if (parts[i].tag == Tag.BOOLEAN) {
            critical = content(b, parts[i])[0].toInt() != 0;
            i++
        }
        val value = content(b, expect(parts[i], Tag.OCTET_STRING, "extnValue"))
        if (map.containsKey(oid)) fail(ErrorCode.CERT_MALFORMED, "duplicate extension $oid")
        map[oid] = Extension(oid, critical, value)
    }
    return map
}

/** Input size caps. AMD certificates are about 2 KiB, CRLs a few hundred bytes. */
const val MAX_CERT_BYTES = 16 * 1024
const val MAX_CRL_BYTES = 1024 * 1024

fun parseCertificate(der: ByteArray): Certificate = try {
    if (der.size > MAX_CERT_BYTES) fail(ErrorCode.CERT_MALFORMED, "certificate is ${der.size} bytes, limit $MAX_CERT_BYTES")
    val cert = readTlv(der, 0)
    expect(cert, Tag.SEQUENCE, "Certificate")
    if (cert.end != der.size) fail(ErrorCode.CERT_MALFORMED, "trailing bytes after certificate")
    val top = children(der, cert)
    if (top.size < 3) fail(ErrorCode.CERT_MALFORMED, "Certificate: missing fields")
    val (tbsT, sigAlgT, sigValT) = top
    expect(tbsT, Tag.SEQUENCE, "TBSCertificate")
    val f = children(der, tbsT)
    if (f.isEmpty() || f[0].tag != Tag.CTX0 || smallInt(der, children(der, f[0])[0], "version") != 2L) fail(ErrorCode.CERT_MALFORMED, "not X.509 v3")
    if (f.size < 7) fail(ErrorCode.CERT_MALFORMED, "TBSCertificate: missing fields")
    val serialT = f[1];
    val tbsSigAlgT = f[2];
    val issuerT = f[3];
    val validityT = f[4];
    val subjectT = f[5];
    val spkiT = f[6]
    val (nbT, naT) = children(der, expect(validityT, Tag.SEQUENCE, "Validity"))
    val spkiKids = children(der, expect(spkiT, Tag.SEQUENCE, "SPKI"))
    val spkiAlgKids = children(der, expect(spkiKids[0], Tag.SEQUENCE, "SPKI alg"))
    val spkiAlgorithm = oidToString(der, spkiAlgKids[0])
    val spkiCurve = if (spkiAlgorithm == Oid.ecPublicKey && spkiAlgKids.getOrNull(1)?.tag == Tag.OID) oidToString(der, spkiAlgKids[1]) else null
    val extT = f.drop(7).find { it.tag == Tag.CTX3 }
    val sigAlg = parseSigAlg(der, sigAlgT)
    val tbsSigAlg = parseSigAlg(der, tbsSigAlgT)
    if (sigAlg != tbsSigAlg) fail(ErrorCode.CERT_MALFORMED, "signatureAlgorithm mismatch between TBS and outer")
    Certificate(
        der = der, tbsRange = tbsT.at until tbsT.end, serial = content(der, expect(serialT, Tag.INTEGER, "serialNumber")),
        issuerRange = issuerT.at until issuerT.end, subjectRange = subjectT.at until subjectT.end,
        subjectName = parseName(der, subjectT),
        notBefore = parseTime(der, nbT), notAfter = parseTime(der, naT),
        spkiRange = spkiT.at until spkiT.end, spkiAlgorithm = spkiAlgorithm, spkiCurve = spkiCurve,
        signatureAlgorithm = sigAlg, signature = bitStringContent(der, sigValT),
        extensions = java.util.Collections.unmodifiableMap(if (extT != null) parseExtensions(der, children(der, extT)[0]) else emptyMap()),
    )
} catch (e: IndexOutOfBoundsException) {
    fail(ErrorCode.CERT_MALFORMED, "malformed certificate structure")
} catch (e: java.time.DateTimeException) {
    fail(ErrorCode.CERT_MALFORMED, "invalid certificate time")
}

fun parseCrl(der: ByteArray): Crl = try {
    if (der.size > MAX_CRL_BYTES) fail(ErrorCode.CRL_INVALID, "CRL is ${der.size} bytes, limit $MAX_CRL_BYTES")
    val crl = readTlv(der, 0)
    expect(crl, Tag.SEQUENCE, "CertificateList")
    if (crl.end != der.size) fail(ErrorCode.CRL_INVALID, "trailing bytes after CRL")
    val top = children(der, crl)
    if (top.size < 3) fail(ErrorCode.CRL_INVALID, "CRL: missing fields")
    val (tbsT, sigAlgT, sigValT) = top
    val f = children(der, expect(tbsT, Tag.SEQUENCE, "TBSCertList"))
    val i = if (f[0].tag == Tag.INTEGER) 1 else 0
    val issuerT = f.getOrNull(i + 1)
    val thisUpdateT = f.getOrNull(i + 2)
    if (issuerT == null || thisUpdateT == null) fail(ErrorCode.CRL_INVALID, "TBSCertList: missing fields")
    var j = i + 3
    var nextUpdate: Long? = null
    if (j < f.size && (f[j].tag == Tag.UTCTIME || f[j].tag == Tag.GENTIME)) {
        nextUpdate = parseTime(der, f[j]);
        j++
    }
    val revoked = ArrayList<ByteArray>()
    if (j < f.size && f[j].tag == Tag.SEQUENCE) {
        for (entry in children(der, f[j])) revoked.add(content(der, expect(children(der, entry)[0], Tag.INTEGER, "revoked serial")))
        j++
    }
    val extensions = if (j < f.size && f[j].tag == Tag.CTX0) parseExtensions(der, children(der, f[j++])[0]) else emptyMap()
    if (j != f.size) fail(ErrorCode.CRL_INVALID, "unexpected CRL fields")
    val sigAlg = parseSigAlg(der, sigAlgT)
    if (sigAlg != parseSigAlg(der, f[i])) fail(ErrorCode.CRL_INVALID, "signatureAlgorithm mismatch between TBS and outer")
    Crl(der, raw(der, tbsT), raw(der, issuerT), parseTime(der, thisUpdateT), nextUpdate, revoked, java.util.Collections.unmodifiableMap(extensions), sigAlg, bitStringContent(der, sigValT))
} catch (e: Fail) {
    if (e.violation.code == ErrorCode.CERT_MALFORMED) fail(ErrorCode.CRL_INVALID, e.violation.message)
    throw e
} catch (e: IndexOutOfBoundsException) {
    fail(ErrorCode.CRL_INVALID, "malformed CRL structure")
} catch (e: java.time.DateTimeException) {
    fail(ErrorCode.CRL_INVALID, "invalid CRL time")
}
