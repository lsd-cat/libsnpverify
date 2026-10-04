package snpverify

// Mutation and API tests on the real Genoa fixture and the KDS CRL snapshot. Mirrors ts/test/mutation.test.ts.
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MutationTest {
    private val input = Fixtures.json(Fixtures.vectors.resolve("attestation-sev/200-real-sev-snp-happy/input.json"))
    private val report = Fixtures.gunzip(fromBase64(input["attestation_doc_b64"].asString))
    private val vcek = fromBase64(input["vcek_der_b64"].asString)
    private val crl = Fixtures.vectors.resolve("kds/Genoa.crl").readBytes()
    private val chain = pemToDer(Fixtures.vectors.resolve("kds/Genoa.cert_chain.pem").readText())
    private val now = parseCrl(crl).thisUpdate + 60
    private val policy = Policy(MeasurementPin.Allowlist(listOf(report.copyOfRange(0x90, 0xc0))), products = listOf(Product.Genoa), requireCrl = true)
    private val base = VerifyInput(report, vcek, crl = crl, now = now, policy = policy)
    private val v = SnpVerifier(JcaCryptoProvider())

    private fun flip(b: ByteArray, at: Int) = b.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }
    private fun expectFail(i: VerifyInput, stage: Stage, code: ErrorCode, what: String, verifier: SnpVerifier = v) {
        val r = verifier.verify(i)
        assertTrue(r is VerifyResult.Err, "$what: expected rejection")
        assertEquals(stage, r.stage, "$what: stage")
        assertEquals(code, r.violations[0].code, "$what: ${r.violations}")
    }
    private fun ok(i: VerifyInput, verifier: SnpVerifier = v): Attestation = (verifier.verify(i) as? VerifyResult.Ok ?: error("expected accept: ${(verifier.verify(i) as VerifyResult.Err).violations}")).attestation

    @Test fun realGenoaVerifies() {
        val a = ok(base.copy(ask = chain[0], ark = chain[1]))
        assertEquals(Product.Genoa, a.platform.product)
        assertEquals(3, a.evidence.reportVersion)
        assertEquals(TcbVersion(10, 0, 23, 84), a.platform.tcb.reported)
        assertEquals(a.platform.tcb.reported, a.evidence.endorsementKey.tcb)
        assertTrue(a.evidence.crl != null && a.evidence.crl.revokedCount >= 0)
        assertEquals(32, a.evidence.reportSha256.size)
        assertEquals(0, a.policyApplied.vmpl)
        assertEquals(now, a.verifiedAt)
        val j = toJson(a)
        val identity = j["identity"] as Map<*, *>
        assertEquals(128, (identity["chipId"] as String).length)
    }

    @Test fun embeddedRootsEqualKdsSnapshot() {
        ok(base)
    }

    @Test fun bouncyCastleProvider() {
        ok(base, SnpVerifier(JcaCryptoProvider(BouncyCastleProvider())));
        expectFail(base.copy(report = flip(report, 0x2a0)), Stage.SIGNATURE, ErrorCode.REPORT_SIGNATURE_INVALID, "bc sig", SnpVerifier(JcaCryptoProvider(BouncyCastleProvider())))
    }

    @Test fun flippedSignature() = expectFail(base.copy(report = flip(report, 0x2a0)), Stage.SIGNATURE, ErrorCode.REPORT_SIGNATURE_INVALID, "sig")

    @Test fun flippedMeasurement() = expectFail(base.copy(report = flip(report, 0x90)), Stage.SIGNATURE, ErrorCode.REPORT_SIGNATURE_INVALID, "measurement")

    @Test fun flippedReportedTcb() = expectFail(base.copy(report = flip(report, 0x180)), Stage.BIND, ErrorCode.VCEK_TCB_MISMATCH, "tcb")

    @Test fun flippedChipId() = expectFail(base.copy(report = flip(report, 0x1a0)), Stage.BIND, ErrorCode.VCEK_HWID_MISMATCH, "chip")

    @Test fun trailingByte() = expectFail(base.copy(report = report + 0), Stage.PARSE, ErrorCode.REPORT_TRUNCATED, "trailing")

    @Test fun version6() = expectFail(base.copy(report = report.copyOf().also { it[0] = 6 }), Stage.PARSE, ErrorCode.REPORT_VERSION_UNSUPPORTED, "v6")

    @Test fun hostRequested() = expectFail(base.copy(report = report.copyOf().also { it.fill(0xff.toByte(), 0x30, 0x34) }), Stage.PARSE, ErrorCode.REPORT_HOST_REQUESTED, "host")

    @Test fun reservedByteSet() = expectFail(base.copy(report = flip(report, 0x4c)), Stage.PARSE, ErrorCode.REPORT_MALFORMED, "mbz")

    @Test fun flippedVcek() = expectFail(base.copy(vcek = flip(vcek, vcek.size - 1)), Stage.CHAIN, ErrorCode.CHAIN_SIGNATURE_INVALID, "vcek")

    @Test fun untrustedRoot() = expectFail(base.copy(ark = chain[0], ask = chain[1]), Stage.CHAIN, ErrorCode.ARK_UNTRUSTED, "swap")

    @Test fun expired() = expectFail(base.copy(now = 2100000000L), Stage.CHAIN, ErrorCode.CERT_EXPIRED, "expired")

    @Test fun notYetValid() = expectFail(base.copy(now = 1600000000L), Stage.CHAIN, ErrorCode.CERT_NOT_YET_VALID, "early")

    @Test fun flippedCrl() = expectFail(base.copy(crl = flip(crl, crl.size - 1)), Stage.CHAIN, ErrorCode.CRL_INVALID, "crl")

    @Test fun crlRequiredButAbsent() = expectFail(base.copy(crl = null), Stage.POLICY, ErrorCode.POLICY_INVALID, "nocrl")

    @Test fun measurementMismatch() = expectFail(base.copy(policy = policy.copy(measurement = MeasurementPin.Allowlist(listOf(ByteArray(48))))), Stage.POLICY, ErrorCode.POLICY_MEASUREMENT_MISMATCH, "meas")

    @Test fun reportDataPrefix() {
        ok(base.copy(policy = policy.copy(reportData = ReportDataPin.Prefix(report.copyOfRange(0x50, 0x70)))))
        expectFail(base.copy(policy = policy.copy(reportData = ReportDataPin.Prefix(ByteArray(32)))), Stage.POLICY, ErrorCode.POLICY_REPORT_DATA_MISMATCH, "prefix")
    }

    @Test fun chipIdAllowlist() {
        ok(base.copy(policy = policy.copy(chipIds = listOf(report.copyOfRange(0x1a0, 0x1e0)))))
        expectFail(base.copy(policy = policy.copy(chipIds = listOf(ByteArray(64)))), Stage.POLICY, ErrorCode.POLICY_CHIP_ID_NOT_ALLOWED, "chipIds")
    }

    @Test fun reportIdAndProduct() {
        ok(base.copy(policy = policy.copy(reportId = report.copyOfRange(0x140, 0x160))))
        expectFail(base.copy(policy = policy.copy(products = listOf(Product.Turin))), Stage.POLICY, ErrorCode.POLICY_PRODUCT_NOT_ALLOWED, "product")
    }

    @Test fun allViolationsReported() {
        val r = v.verify(base.copy(policy = policy.copy(vmpl = 1, minGuestSvn = 5, guestPolicy = GuestPolicyRules(smt = Bit.FORBIDDEN)))) as VerifyResult.Err
        assertEquals(Stage.POLICY, r.stage)
        assertEquals(listOf(ErrorCode.POLICY_GUEST_POLICY, ErrorCode.POLICY_GUEST_SVN, ErrorCode.POLICY_VMPL), r.violations.map { it.code }.sortedBy { it.name })
    }

    @Test fun malformedPolicy() {
        val r = v.verify(base.copy(policy = Policy(MeasurementPin.Allowlist(listOf(ByteArray(47)))))) as VerifyResult.Err
        assertEquals(ErrorCode.POLICY_INVALID, r.violations[0].code)
    }

    @Test fun tcbFloorPerProduct() {
        ok(base.copy(policy = policy.copy(minTcb = mapOf(Product.Genoa to TcbFloor(snp = 23, microcode = 84)))))
        expectFail(base.copy(policy = policy.copy(minTcb = mapOf(Product.Genoa to TcbFloor(snp = 24)))), Stage.POLICY, ErrorCode.POLICY_TCB_OUT_OF_DATE, "floor")
    }
}

class GoldenTest {
    @Test fun matchesCrossPortGolden() {
        val input = Fixtures.json(Fixtures.vectors.resolve("attestation-sev/200-real-sev-snp-happy/input.json"))
        val report = Fixtures.gunzip(fromBase64(input["attestation_doc_b64"].asString))
        val crl = Fixtures.vectors.resolve("kds/Genoa.crl").readBytes()
        val chain = pemToDer(Fixtures.vectors.resolve("kds/Genoa.cert_chain.pem").readText())
        val r = SnpVerifier(JcaCryptoProvider()).verify(
            VerifyInput(
                report,
                fromBase64(input["vcek_der_b64"].asString),
                ask = chain[0],
                ark = chain[1],
                crl = crl,
                now = parseCrl(crl).thisUpdate + 60,
                policy = Policy(
                    MeasurementPin.Allowlist(listOf(report.copyOfRange(0x90, 0xc0))),
                    products = listOf(Product.Genoa),
                    requireCrl = true,
                    reportData = ReportDataPin.Prefix(report.copyOfRange(0x50, 0x60)),
                    minTcb = mapOf(Product.Genoa to TcbFloor(snp = 20))
                )
            )
        )
        val ours = com.google.gson.Gson().toJsonTree(toJson((r as VerifyResult.Ok).attestation))
        val golden = com.google.gson.JsonParser.parseString(Fixtures.vectors.resolve("golden/real-genoa.json").readText())
        assertEquals(golden, ours)
    }
}

class ImmutabilityTest {
    private val input = Fixtures.json(Fixtures.vectors.resolve("attestation-sev/200-real-sev-snp-happy/input.json"))
    private val report = Fixtures.gunzip(fromBase64(input["attestation_doc_b64"].asString))
    private val vcek = fromBase64(input["vcek_der_b64"].asString)
    private val crl = Fixtures.vectors.resolve("kds/Genoa.crl").readBytes()
    private val chain = pemToDer(Fixtures.vectors.resolve("kds/Genoa.cert_chain.pem").readText())
    private val now = parseCrl(crl).thisUpdate + 60
    private val v = SnpVerifier(JcaCryptoProvider())

    @Test fun parsedRecordsCannotBeAlteredBetweenStages() {
        val rep = (parseReport(report) as Result.Ok).value
        rep.measurement[0] = (rep.measurement[0].toInt() xor 1).toByte() // mutate a returned copy
        assertTrue(rep.measurement.contentEquals(report.copyOfRange(0x90, 0xc0)))
        val ch = (v.verifyChain(ChainInput(vcek, chain[0], chain[1], crl, now)) as Result.Ok).value
        ch.leaf.cert.spki[30] = (ch.leaf.cert.spki[30].toInt() xor 1).toByte() // returned copy
        ch.leaf.hwid!![0] = (ch.leaf.hwid!![0].toInt() xor 1).toByte()
        assertTrue(v.verifyReportSignature(rep, ch) is Result.Ok)
        assertTrue(bindEndorsement(rep, ch.leaf) is Result.Ok)
    }

    @Test fun extensionsAndCrlSerialsDoNotAliasCallerMemory() {
        val myArk = chain[1].copyOf();
        val myCrl = crl.copyOf()
        val cert = parseCertificate(myArk);
        val parsed = parseCrl(myCrl)
        val ku = cert.extensions.getValue("2.5.29.15").value
        myArk.fill(0);
        myCrl.fill(0) // caller mutates its own buffers after parsing
        cert.extensions.getValue("2.5.29.15").value[0] = 0 // and a returned copy
        assertTrue(cert.extensions.getValue("2.5.29.15").value.contentEquals(ku))
        val n = parsed.revokedSerials.size
        if (n > 0) parsed.revokedSerials[0][0] = (parsed.revokedSerials[0][0].toInt() xor 1).toByte()
        assertEquals(n, parsed.revokedSerials.size)
        assertTrue(v.verifyChain(ChainInput(vcek, chain[0], chain[1], crl, now)) is Result.Ok)
    }

    @Test fun extensionMapIsReadOnly() {
        val cert = parseCertificate(chain[1])
        assertTrue(runCatching { (cert.extensions as MutableMap<String, Extension>).remove("2.5.29.15") }.isFailure)
        assertTrue(runCatching { (parseCrl(crl).extensions as MutableMap<String, Extension>).clear() }.isFailure)
    }

    @Test fun oversizedCollateralRejected() {
        val policy = Policy(MeasurementPin.Any, products = listOf(Product.Genoa))
        val big = ByteArray(16 * 1024 + 1).also { vcek.copyInto(it) }
        val r1 = v.verify(VerifyInput(report, big, crl = crl, now = now, policy = policy)) as VerifyResult.Err
        assertEquals(ErrorCode.CERT_MALFORMED, r1.violations[0].code)
        val bigCrl = ByteArray(1024 * 1024 + 1).also { crl.copyInto(it) }
        val r2 = v.verify(VerifyInput(report, vcek, crl = bigCrl, now = now, policy = policy)) as VerifyResult.Err
        assertEquals(ErrorCode.CRL_INVALID, r2.violations[0].code)
    }
}
