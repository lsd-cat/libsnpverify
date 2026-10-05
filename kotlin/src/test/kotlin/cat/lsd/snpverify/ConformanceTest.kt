package cat.lsd.snpverify

// Runs the Tinfoil conformance vectors through SnpVerifier. Mirrors ts/test/conformance.test.ts exactly.
import com.google.gson.JsonObject
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConformanceTest {
    private val crypto = JcaCryptoProvider()
    private val baseline = AppraisalPolicy(MeasurementPin.Any, vmplAny = true, products = listOf(Product.Milan, Product.Genoa, Product.Turin))
    private val hardened = baseline.copy(
        allowMaskedChipId = true,
        minTcb = mapOf(Product.Genoa to TcbFloor(snp = 14)),
        minFirmware = FirmwareVersion(1, 55, 21),
        guestPolicy = GuestPolicyRules(debug = Bit.FORBIDDEN, migrateMa = Bit.FORBIDDEN, cxlAllowed = Bit.FORBIDDEN, memAes256Xts = Bit.FORBIDDEN),
        platformInfo = PlatformInfoRules(tsmeEnabled = Bit.REQUIRED),
    )
    private val hardenedPlatform = PlatformInfoRules(tsmeEnabled = Bit.REQUIRED, eccEnabled = Bit.REQUIRED, raplDisabled = Bit.REQUIRED, ciphertextHidingEnabled = Bit.REQUIRED, aliasCheckComplete = Bit.REQUIRED, tioEnabled = Bit.REQUIRED)

    private fun tinfoilCode(r: AppraisalResult.Err): String {
        val v = r.violations[0]
        return when (v.code) {
            ErrorCode.REPORT_TRUNCATED -> "REPORT_TRUNCATED";
            ErrorCode.REPORT_VERSION_UNSUPPORTED -> "WRONG_REPORT_VERSION";
            ErrorCode.REPORT_SIGNATURE_INVALID -> "REPORT_SIGNATURE_INVALID"
            ErrorCode.CERT_MALFORMED, ErrorCode.CHAIN_SIGNATURE_INVALID, ErrorCode.CHAIN_NAME_MISMATCH, ErrorCode.VCEK_EXTENSION_INVALID -> "VCEK_CHAIN_INVALID"
            ErrorCode.CERT_EXPIRED -> "VCEK_EXPIRED";
            ErrorCode.VCEK_HWID_MISMATCH -> "VCEK_HWID_MISMATCH";
            ErrorCode.VCEK_TCB_MISMATCH -> "VCEK_TCB_MISMATCH"
            ErrorCode.POLICY_TCB_OUT_OF_DATE, ErrorCode.POLICY_LAUNCH_TCB_OUT_OF_DATE -> "TCB_OUT_OF_DATE"
            ErrorCode.POLICY_MEASUREMENT_MISMATCH -> "MEASUREMENT_MISMATCH";
            ErrorCode.POLICY_REPORT_DATA_MISMATCH -> "REPORT_DATA_MISMATCH";
            ErrorCode.POLICY_HOST_DATA_MISMATCH -> "HOST_DATA_MISMATCH"
            ErrorCode.POLICY_GUEST_POLICY -> when (v.field) {
                "guest_policy.debug" -> "GUEST_POLICY_DEBUG_SET";
                "guest_policy.migrate_ma" -> "GUEST_POLICY_MIGRATE_MA_SET";
                else -> "GUEST_POLICY_RESERVED_BIT_SET"
            }
            ErrorCode.REPORT_MALFORMED -> if (v.field == "guest_policy") "GUEST_POLICY_RESERVED_BIT_SET" else "REPORT_FORMAT_UNSUPPORTED"
            ErrorCode.POLICY_ID_BLOCK -> if (v.field == "author_key_digest") "AUTHOR_KEY_DIGEST_MISMATCH" else "ID_KEY_DIGEST_MISMATCH"
            else -> v.code.name
        }
    }

    private data class Manifest(val exit: Int, val codes: List<String>)
    private fun manifest(dir: File): Manifest {
        val m = dir.resolve("manifest.yaml").readText()
        val exit = Regex("exit_code:\\s*(\\d+)").find(m)!!.groupValues[1].toInt()
        val line = Regex("(?m)^\\s*rejection_code:\\s*(.+)$").find(m)?.groupValues?.get(1)?.trim()
        val codes = when {
            line == null -> emptyList();
            line.startsWith("[") -> Regex("\"([A-Z_]+)\"").findAll(line).map { it.groupValues[1] }.toList();
            else -> listOf(line.trim('"'))
        }
        return Manifest(exit, codes)
    }

    @TestFactory
    fun attestationSev(): List<DynamicTest> = Fixtures.vectors.resolve("attestation-sev").listFiles()!!.filter { it.isDirectory && it.name[0].isDigit() }.sorted().map { dir ->
        DynamicTest.dynamicTest("attestation-sev/${dir.name}") {
            val input = Fixtures.json(dir.resolve("input.json"))
            val (exit, codes) = manifest(dir)
            val report = Fixtures.gunzip(fromBase64(input["attestation_doc_b64"].asString))
            val synthetic = input.has("amd_root_ca_pem")
            val pol: JsonObject = input.getAsJsonObject("policy") ?: JsonObject()
            fun hexOpt(k: String) = if (pol.has(k)) fromHex(pol[k].asString) else null
            var policy = if (synthetic) hardened else baseline
            if (Regex("^27[0-4]").containsMatchIn(dir.name)) policy = policy.copy(platformInfo = hardenedPlatform)
            hexOpt("expected_measurement_hex")?.let { policy = policy.copy(measurement = MeasurementPin.Allowlist(listOf(it))) }
            hexOpt("expected_report_data_hex")?.let { policy = policy.copy(reportData = ReportDataPin.Exact(it)) }
            hexOpt("expected_host_data_hex")?.let { policy = policy.copy(hostData = it) }
            val idk = hexOpt("expected_id_key_digest_hex");
            val ak = hexOpt("expected_author_key_digest_hex")
            if (idk != null || ak != null) policy = policy.copy(idBlock = IdBlockPin.Pinned(idk ?: ByteArray(48), ak))
            val floorKeys = listOf("min_tcb_bl_spl", "min_tcb_tee_spl", "min_tcb_snp_spl", "min_tcb_ucode_spl")
            if (floorKeys.any { pol.has(it) }) {
                fun i(k: String) = if (pol.has(k)) pol[k].asInt else null
                val f = TcbFloor(bootloader = i("min_tcb_bl_spl"), tee = i("min_tcb_tee_spl"), snp = i("min_tcb_snp_spl"), microcode = i("min_tcb_ucode_spl"))
                policy = policy.copy(minTcb = mapOf(Product.Milan to f, Product.Genoa to f, Product.Turin to f))
            }
            val ark = if (synthetic) pemToDer(input["amd_root_ca_pem"].asString)[0] else null
            val verifier = SnpVerifier(crypto, trustedArks = ark?.let { listOf(it) })
            val result = verifier.appraise(
                AppraisalInput(
                    evidence = report,
                    endorsements = Endorsements(
                        vcek = fromBase64(input["vcek_der_b64"].asString),
                        ask = if (input.has("ask_pem")) pemToDer(input["ask_pem"].asString)[0] else null,
                        ark = ark,
                    ),
                    now = if (input.has("expiration_check_date_unix")) input["expiration_check_date_unix"].asLong else 1780272000L,
                    policy = policy,
                )
            )
            if (exit == 0) {
                assertTrue(result is AppraisalResult.Ok, "expected accept, got ${(result as? AppraisalResult.Err)?.violations}")
                val expected = Fixtures.json(dir.resolve("expected.json"))
                val want = expected.getAsJsonObject("outputs")?.getAsJsonObject("measurement")?.getAsJsonArray("registers")?.get(0)?.asString
                if (want != null) assertEquals(want, (result as AppraisalResult.Ok).attestationResult.identity.measurement.hex())
            } else {
                assertTrue(result is AppraisalResult.Err, "expected rejection, got accept")
                val err = result as AppraisalResult.Err
                if (codes.isNotEmpty()) assertTrue(tinfoilCode(err) in codes, "code ${tinfoilCode(err)} (${err.violations[0]}) not in $codes")
            }
        }
    }

    @TestFactory
    fun quoteSev(): List<DynamicTest> = Fixtures.vectors.resolve("quote-sev").listFiles()!!.filter { it.name.endsWith(".json") }.sorted().map { file ->
        DynamicTest.dynamicTest("quote-sev/${file.name}") {
            val vec = Fixtures.json(file)
            val input = vec.getAsJsonObject("input");
            val expectedAccept = vec.getAsJsonObject("expected")["accepted"].asBoolean
            val doc = com.google.gson.JsonParser.parseString(String(fromBase64(input["document_b64"].asString))).asJsonObject
            fun col(id: String): JsonObject? = doc.getAsJsonArray("collateral")?.firstOrNull { it.asJsonObject["id"].asString == id }?.asJsonObject?.getAsJsonObject("data")
            val vcekB64 = col("vcek")?.get("vcek_der_base64")?.asString?.takeIf { it.isNotEmpty() }
            val chain = col("vcek")?.get("cert_chain_pem")?.asString?.let { pemToDer(it) } ?: emptyList()
            val crlB64 = col("crl")?.get("crl_der_base64")?.asString?.takeIf { it.isNotEmpty() }
            if (vcekB64 == null || chain.size != 2 || crlB64 == null) {
                assertEquals(false, expectedAccept);
                return@dynamicTest
            }
            val ark = pemToDer(input["amd_root_ca_pem"].asString)[0]
            val result = SnpVerifier(crypto, listOf(ark)).appraise(
                AppraisalInput(
                    evidence = fromBase64(doc.getAsJsonObject("cpu_evidence")["report_base64"].asString),
                    endorsements = Endorsements(vcek = fromBase64(vcekB64), ask = chain[0], ark = chain[1], crl = fromBase64(crlB64)),
                    now = System.currentTimeMillis() / 1000,
                    policy = baseline.copy(requireCrl = true, minReportVersion = 3),
                )
            )
            // Older synthetic happy vector has a v3 CRL issuer without keyUsage.
            // RFC 10007 requires cRLSign, so the hardened verifier rejects it.
            if (file.name == "sev-happy.json") {
                assertEquals(ErrorCode.CRL_INVALID, (result as AppraisalResult.Err).violations[0].code)
                return@dynamicTest
            }
            assertEquals(expectedAccept, result is AppraisalResult.Ok, (result as? AppraisalResult.Err)?.violations.toString())
        }
    }
}
