package snpverify

// Bind the endorsement key to the report, then verify the report signature. Mirrors ts/src/bind.ts.
data class Tcbs(val current: TcbVersion, val committed: TcbVersion, val reported: TcbVersion, val launch: TcbVersion)

fun bindEndorsement(report: Report, ek: EndorsementKey): Result<Tcbs> = stage {
    if (ek.kind != report.signerInfo.signingKey) fail(ErrorCode.SIGNER_KIND_MISMATCH, "report says ${report.signerInfo.signingKey}, certificate is a ${ek.kind}", "signer_info.signing_key")
    val layout = PRODUCTS.getValue(ek.product).tcbLayout
    val tcb = Tcbs(decodeTcb(report.currentTcb, layout), decodeTcb(report.committedTcb, layout), decodeTcb(report.reportedTcb, layout), decodeTcb(report.launchTcb, layout))
    if (!tcbEqual(tcb.reported, ek.tcb)) fail(ErrorCode.VCEK_TCB_MISMATCH, "reported_tcb does not match the ${ek.kind} certificate TCB", "reported_tcb")
    if (ek.kind == SigningKey.VCEK) {
        val hwid = ek.hwid!!
        val chip = report.chipId.copyOfRange(0, hwid.size)
        if (!report.chipId.isZero() && !chip.contentEquals(hwid)) fail(ErrorCode.VCEK_HWID_MISMATCH, "chip_id ${chip.hex()} != VCEK HWID ${hwid.hex()}", "chip_id")
    }
    report.cpuid?.let { c ->
        val fromCpu = productFromCpuid(c.family, c.model)
        if (fromCpu != ek.product) fail(ErrorCode.PRODUCT_MISMATCH, "CPUID family 0x${c.family.toString(16)} model 0x${c.model.toString(16)} is ${fromCpu ?: "unknown"}, certificate says ${ek.product}", "cpuid_fam_id")
    }
    tcb
}

fun verifyReportSignature(report: Report, ek: EndorsementKey, crypto: CryptoProvider): Result<Unit> = stage {
    if (!crypto.verifyEcdsaP384(ek.cert.spki, report.signedBytes, report.signature.r, report.signature.s)) fail(ErrorCode.REPORT_SIGNATURE_INVALID, "report signature does not verify with the ${ek.kind}", "signature")
}
