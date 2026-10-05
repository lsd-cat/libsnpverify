package cat.lsd.snpverify

// snpverify: AMD SEV-SNP attestation report verification.
//
//   val verifier = SnpVerifier(JcaCryptoProvider())
//   when (val r = verifier.appraise(AppraisalInput(report, Endorsements(vcek, crl = crl), now, AppraisalPolicy(MeasurementPin.Allowlist(listOf(m)))))) {
//       is AppraisalResult.Ok -> use(r.attestationResult)
//       is AppraisalResult.Err -> show(r.violations)
//   }
// Inputs: the report (Evidence), AMD certificates and optional CRL (Endorsements), appraisal time, appraisal policy. No network, no clock. See SPEC.md.

data class Endorsements(
    val vcek: ByteArray,
    val ask: ByteArray? = null,
    val ark: ByteArray? = null,
    val crl: ByteArray? = null,
)

data class AppraisalInput(
    val evidence: ByteArray,
    val endorsements: Endorsements,
    val now: Long,
    val policy: AppraisalPolicy,
)

data class Partial(val report: Report? = null, val chain: Chain? = null, val tcb: Tcbs? = null)

sealed interface AppraisalResult {
    data class Ok(val attestationResult: AttestationResult) : AppraisalResult
    data class Err(val stage: Stage, val violations: List<Violation>, val partial: Partial? = null) : AppraisalResult
}

class SnpVerifier(private val crypto: CryptoProvider, trustedArks: List<ByteArray>? = null) {
    private val trustedArks = trustedArks?.map { it.copyOf() }

    fun verifyChain(input: ChainInput): Result<Chain> = verifyChain(input, trustedArks, crypto)
    fun verifyReportSignature(report: Report, chain: Chain): Result<Unit> = verifyReportSignature(report, chain.leaf, crypto)

    fun appraise(input: AppraisalInput): AppraisalResult {
        val resolved = when (val r = resolveAppraisalPolicy(input.policy)) {
            is Result.Err -> return AppraisalResult.Err(Stage.POLICY, listOf(r.error));
            is Result.Ok -> r.value
        }
        // Parse the report (it checks its length before copying), check endorsement sizes, then copy every input.
        val report = when (val r = parseReport(input.evidence)) {
            is Result.Err -> return AppraisalResult.Err(Stage.PARSE, listOf(r.error));
            is Result.Ok -> r.value
        }
        val e = input.endorsements
        when (val s = stage { checkEndorsementSizes(e.vcek, e.ask, e.ark, e.crl) }) {
            is Result.Err -> return AppraisalResult.Err(Stage.CHAIN, listOf(s.error));
            is Result.Ok -> {}
        }
        val chainInput = ChainInput(e.vcek.copyOf(), e.ask?.copyOf(), e.ark?.copyOf(), e.crl?.copyOf(), input.now)
        val chain = when (val r = verifyChain(chainInput)) {
            is Result.Err -> return AppraisalResult.Err(Stage.CHAIN, listOf(r.error), Partial(report));
            is Result.Ok -> r.value
        }
        val tcb = when (val r = bindEndorsement(report, chain.leaf)) {
            is Result.Err -> return AppraisalResult.Err(Stage.BIND, listOf(r.error), Partial(report, chain));
            is Result.Ok -> r.value
        }
        when (val r = verifyReportSignature(report, chain)) {
            is Result.Err -> return AppraisalResult.Err(Stage.SIGNATURE, listOf(r.error), Partial(report, chain, tcb));
            is Result.Ok -> {}
        }
        val violations = checkResolvedAppraisalPolicy(report, chain.leaf, AppraisalContext(tcb, chain.crl != null, crypto.sha256(chain.leaf.cert.der)), resolved)
        if (violations.isNotEmpty()) return AppraisalResult.Err(Stage.POLICY, violations, Partial(report, chain, tcb))
        return AppraisalResult.Ok(buildAttestationResult(report, chain, tcb, resolved, input.now, crypto))
    }
}
