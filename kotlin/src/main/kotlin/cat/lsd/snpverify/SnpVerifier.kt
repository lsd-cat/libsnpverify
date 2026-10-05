package cat.lsd.snpverify

// snpverify: AMD SEV-SNP attestation report verification.
//
//   val verifier = SnpVerifier(JcaCryptoProvider())
//   when (val r = verifier.verify(VerifyInput(report, vcek, crl = crl, now = now, policy = Policy(MeasurementPin.Allowlist(listOf(m)))))) {
//       is VerifyResult.Ok -> use(r.attestation)
//       is VerifyResult.Err -> show(r.violations)
//   }
// Inputs: report bytes, AMD certificates, optional CRL, verification time, policy. No network, no clock. See SPEC.md.

data class VerifyInput(
    val report: ByteArray,
    val vcek: ByteArray,
    val ask: ByteArray? = null,
    val ark: ByteArray? = null,
    val crl: ByteArray? = null,
    val now: Long,
    val policy: Policy,
)

data class Partial(val report: Report? = null, val chain: Chain? = null, val tcb: Tcbs? = null)

sealed interface VerifyResult {
    data class Ok(val attestation: Attestation) : VerifyResult
    data class Err(val stage: Stage, val violations: List<Violation>, val partial: Partial? = null) : VerifyResult
}

class SnpVerifier(private val crypto: CryptoProvider, trustedArks: List<ByteArray>? = null) {
    private val trustedArks = trustedArks?.map { it.copyOf() }

    fun verifyChain(input: ChainInput): Result<Chain> = verifyChain(input, trustedArks, crypto)
    fun verifyReportSignature(report: Report, chain: Chain): Result<Unit> = verifyReportSignature(report, chain.leaf, crypto)

    fun verify(input: VerifyInput): VerifyResult {
        val resolved = when (val r = resolvePolicy(input.policy)) {
            is Result.Err -> return VerifyResult.Err(Stage.POLICY, listOf(r.error));
            is Result.Ok -> r.value
        }
        // Parse the report (it checks its length before copying), check collateral sizes, then copy every input.
        val report = when (val r = parseReport(input.report)) {
            is Result.Err -> return VerifyResult.Err(Stage.PARSE, listOf(r.error));
            is Result.Ok -> r.value
        }
        when (val s = stage { checkCollateralSizes(input.vcek, input.ask, input.ark, input.crl) }) {
            is Result.Err -> return VerifyResult.Err(Stage.CHAIN, listOf(s.error));
            is Result.Ok -> {}
        }
        val chainInput = ChainInput(input.vcek.copyOf(), input.ask?.copyOf(), input.ark?.copyOf(), input.crl?.copyOf(), input.now)
        val chain = when (val r = verifyChain(chainInput)) {
            is Result.Err -> return VerifyResult.Err(Stage.CHAIN, listOf(r.error), Partial(report));
            is Result.Ok -> r.value
        }
        val tcb = when (val r = bindEndorsement(report, chain.leaf)) {
            is Result.Err -> return VerifyResult.Err(Stage.BIND, listOf(r.error), Partial(report, chain));
            is Result.Ok -> r.value
        }
        when (val r = verifyReportSignature(report, chain)) {
            is Result.Err -> return VerifyResult.Err(Stage.SIGNATURE, listOf(r.error), Partial(report, chain, tcb));
            is Result.Ok -> {}
        }
        val violations = checkResolvedPolicy(report, chain.leaf, PolicyContext(tcb, chain.crl != null, crypto.sha256(chain.leaf.cert.der)), resolved)
        if (violations.isNotEmpty()) return VerifyResult.Err(Stage.POLICY, violations, Partial(report, chain, tcb))
        return VerifyResult.Ok(buildAttestation(report, chain, tcb, resolved, input.now, crypto))
    }
}
