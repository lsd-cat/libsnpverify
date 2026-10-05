package cat.lsd.snpverify

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Provider
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec

/** Crypto provider interface. */
interface CryptoProvider {
    /** RSASSA-PSS with SHA-384 and MGF1-SHA-384 over `msg`, public key as SPKI DER. */
    fun verifyRsaPss(spki: ByteArray, msg: ByteArray, sig: ByteArray, saltLength: Int): Boolean

    /** ECDSA P-384 with SHA-384, r and s as 48-byte big-endian integers, public key as SPKI DER. */
    fun verifyEcdsaP384(spki: ByteArray, msg: ByteArray, r: ByteArray, s: ByteArray): Boolean
    fun sha256(data: ByteArray): ByteArray
}

/** JCA-backed provider. `null` uses the platform default (Android built-ins); pass `BouncyCastleProvider()` or any JCA provider to override. */
class JcaCryptoProvider(private val provider: Provider? = null) : CryptoProvider {
    private fun sig(alg: String): Signature = if (provider != null) Signature.getInstance(alg, provider) else Signature.getInstance(alg)
    private fun kf(alg: String): KeyFactory = if (provider != null) KeyFactory.getInstance(alg, provider) else KeyFactory.getInstance(alg)

    override fun verifyRsaPss(spki: ByteArray, msg: ByteArray, sig: ByteArray, saltLength: Int): Boolean = try {
        val key = kf("RSA").generatePublic(X509EncodedKeySpec(spki)) as RSAPublicKey
        if (key.modulus.bitLength() < 4096) return false
        val s = sig("RSASSA-PSS")
        s.setParameter(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, saltLength, 1))
        s.initVerify(key);
        s.update(msg);
        s.verify(sig)
    } catch (e: java.security.GeneralSecurityException) {
        false
    }

    override fun verifyEcdsaP384(spki: ByteArray, msg: ByteArray, r: ByteArray, s: ByteArray): Boolean = try {
        val key = kf("EC").generatePublic(X509EncodedKeySpec(spki)) as ECPublicKey
        if (key.params.curve.field.fieldSize != 384) return false
        val v = sig("SHA384withECDSA")
        v.initVerify(key);
        v.update(msg);
        v.verify(derSignature(r, s))
    } catch (e: java.security.GeneralSecurityException) {
        false
    }

    override fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** JCA wants SEQUENCE { INTEGER r, INTEGER s }. */
    private fun derSignature(r: ByteArray, s: ByteArray): ByteArray {
        fun int(x: ByteArray): ByteArray {
            val m = BigInteger(1, x).toByteArray();
            return byteArrayOf(0x02, m.size.toByte()) + m
        }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
