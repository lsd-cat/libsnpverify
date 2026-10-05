package cat.lsd.snpverify

// Cross-port violation vector: the cases in ts/test/violations.test.ts, compared against vectors/expected-violations.json.
import com.google.gson.Gson
import com.google.gson.JsonParser
import kotlin.test.Test
import kotlin.test.assertEquals

class ViolationsTest {
    private val input = Fixtures.json(Fixtures.vectors.resolve("attestation-sev/200-real-sev-snp-happy/input.json"))
    private val report = Fixtures.gunzip(fromBase64(input["attestation_doc_b64"].asString))
    private val vcek = fromBase64(input["vcek_der_b64"].asString)
    private val crl = Fixtures.vectors.resolve("kds/Genoa.crl").readBytes()
    private val chain = pemToDer(Fixtures.vectors.resolve("kds/Genoa.cert_chain.pem").readText())
    private val now = parseCrl(crl).thisUpdate + 60
    private val policy = Policy(MeasurementPin.Allowlist(listOf(report.copyOfRange(0x90, 0xc0))), products = listOf(Product.Genoa), requireCrl = true)
    private val base = VerifyInput(report, vcek, ask = chain[0], ark = chain[1], crl = crl, now = now, policy = policy)
    private fun flip(b: ByteArray, at: Int) = b.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }

    private val cases: Map<String, VerifyInput> = linkedMapOf(
        "flipped-signature" to base.copy(report = flip(report, 0x2a0)),
        "flipped-reported-tcb" to base.copy(report = flip(report, 0x180)),
        "flipped-chip-id" to base.copy(report = flip(report, 0x1a0)),
        "trailing-byte" to base.copy(report = report + 0),
        "version-6" to base.copy(report = report.copyOf().also { it[0] = 6 }),
        "host-requested" to base.copy(report = report.copyOf().also { it.fill(0xff.toByte(), 0x30, 0x34) }),
        "reserved-byte" to base.copy(report = flip(report, 0x4c)),
        "flipped-vcek" to base.copy(vcek = flip(vcek, vcek.size - 1)),
        "untrusted-root" to base.copy(ark = chain[0], ask = chain[1]),
        "expired" to base.copy(now = 2100000000L),
        "not-yet-valid" to base.copy(now = 1600000000L),
        "flipped-crl" to base.copy(crl = flip(crl, crl.size - 1)),
        "crl-absent" to base.copy(crl = null),
        "measurement-mismatch" to base.copy(policy = policy.copy(measurement = MeasurementPin.Allowlist(listOf(ByteArray(48))))),
        "report-data-prefix-mismatch" to base.copy(policy = policy.copy(reportData = ReportDataPin.Prefix(ByteArray(32)))),
        "chip-id-not-allowed" to base.copy(policy = policy.copy(chipIds = listOf(ByteArray(64)))),
        "product-not-allowed" to base.copy(policy = policy.copy(products = listOf(Product.Turin))),
        "several-policy-violations" to base.copy(policy = policy.copy(vmpl = 1, minGuestSvn = 5, guestPolicy = GuestPolicyRules(smt = Bit.FORBIDDEN))),
        "tcb-floor" to base.copy(policy = policy.copy(minTcb = mapOf(Product.Genoa to TcbFloor(snp = 24)))),
        "oversized-vcek" to base.copy(vcek = ByteArray(16 * 1024 + 1).also { vcek.copyInto(it) }),
    )

    @Test fun matchesCrossPortViolationVector() {
        val v = SnpVerifier(JcaCryptoProvider())
        val actual = cases.mapValues { (name, i) ->
            val r = v.verify(i) as? VerifyResult.Err ?: error("$name: expected rejection")
            mapOf("stage" to r.stage.name.lowercase(), "violations" to r.violations.map { x -> mapOf("code" to x.code.name, "message" to x.message, "field" to x.field) })
        }
        val expected = JsonParser.parseString(Fixtures.vectors.resolve("expected-violations.json").readText())
        assertEquals(expected, Gson().toJsonTree(actual))
    }
}
