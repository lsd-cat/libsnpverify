package cat.lsd.snpverify

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.util.zip.GZIPInputStream

object Fixtures {
    val vectors: File = File(System.getProperty("vectors.dir") ?: "../vectors")
    fun json(f: File): JsonObject = JsonParser.parseString(f.readText()).asJsonObject
    fun gunzip(b: ByteArray): ByteArray = GZIPInputStream(b.inputStream()).readBytes()
}

/** Copy with the Evidence, one Endorsement, the time or the policy replaced. */
fun AppraisalInput.with(
    evidence: ByteArray = this.evidence,
    vcek: ByteArray = endorsements.vcek,
    ask: ByteArray? = endorsements.ask,
    ark: ByteArray? = endorsements.ark,
    crl: ByteArray? = endorsements.crl,
    now: Long = this.now,
    policy: AppraisalPolicy = this.policy,
) = AppraisalInput(evidence, Endorsements(vcek, ask, ark, crl), now, policy)
