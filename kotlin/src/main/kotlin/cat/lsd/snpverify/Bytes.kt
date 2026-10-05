package cat.lsd.snpverify

import java.util.Base64

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

fun fromHex(s: String): ByteArray {
    require(s.length % 2 == 0 && s.all { it in "0123456789abcdefABCDEF" }) { "invalid hex" }
    return ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

fun fromBase64(s: String): ByteArray = Base64.getMimeDecoder().decode(s)

/** Extract all DER blobs from a PEM string, in order. Tolerates trailing whitespace. */
fun pemToDer(pem: String): List<ByteArray> = Regex("-----BEGIN [^-]+-----([^-]+)-----END [^-]+-----").findAll(pem).map { fromBase64(it.groupValues[1]) }.toList()

internal fun ByteArray.isZero(start: Int = 0, end: Int = size): Boolean {
    for (i in start until end) if (this[i].toInt() != 0) return false
    return true
}
internal fun ByteArray.u8(off: Int): Int = this[off].toInt() and 0xff
internal fun ByteArray.u32le(off: Int): Long = (u8(off).toLong()) or (u8(off + 1).toLong() shl 8) or (u8(off + 2).toLong() shl 16) or (u8(off + 3).toLong() shl 24)
internal fun ByteArray.u64le(off: Int): ULong {
    var v = 0UL
    for (i in 7 downTo 0) v = (v shl 8) or u8(off + i).toULong()
    return v
}
