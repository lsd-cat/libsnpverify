package snpverify

// The result record (SPEC §6) and its JSON-shaped projection. Mirrors ts/src/attestation.ts.

data class CertSummary(val sha256: ByteArray, val serial: ByteArray, val subjectCn: String, val notBefore: Long, val notAfter: Long)
data class EndorsementKeySummary(val cert: CertSummary, val kind: SigningKey, val hwid: ByteArray?, val cspId: String?, val tcb: TcbVersion)

data class Identity(
    val chipId: ByteArray,
    val reportId: ByteArray,
    val reportIdMa: ByteArray,
    val measurement: ByteArray,
    val hostData: ByteArray,
    val reportData: ByteArray,
    val familyId: ByteArray,
    val imageId: ByteArray,
    val guestSvn: Long,
    val vmpl: Int
)
data class Platform(
    val product: Product,
    val productName: String,
    val cpuid: Cpuid?,
    val guestPolicy: GuestPolicy,
    val platformInfo: PlatformInfo,
    val tcb: Tcbs,
    val firmwareCurrent: FirmwareVersion,
    val firmwareCommitted: FirmwareVersion,
    val launchMitVector: ULong?,
    val currentMitVector: ULong?,
    val signer: SignerInfo,
    val idKeyDigest: ByteArray,
    val authorKeyDigest: ByteArray
)
data class Evidence(
    val reportVersion: Int,
    val reportSha256: ByteArray,
    val signature: EcdsaSignature,
    val endorsementKey: EndorsementKeySummary,
    val ask: CertSummary,
    val ark: CertSummary,
    val crl: CrlInfo?
)
data class Attestation(val identity: Identity, val platform: Platform, val evidence: Evidence, val policyApplied: ResolvedPolicy, val verifiedAt: Long)

internal fun buildAttestation(report: Report, chain: Chain, tcb: Tcbs, policy: ResolvedPolicy, now: Long, crypto: CryptoProvider): Attestation {
    fun sum(c: Certificate) = CertSummary(crypto.sha256(c.der), c.serial, c.subjectCN, c.notBefore, c.notAfter)
    val ek = chain.leaf
    return Attestation(
        identity = Identity(report.chipId, report.reportId, report.reportIdMa, report.measurement, report.hostData, report.reportData, report.familyId, report.imageId, report.guestSvn, report.vmpl),
        platform = Platform(
            ek.product, ek.productName, report.cpuid, report.policy, report.platformInfo, tcb, report.currentVersion, report.committedVersion,
            report.launchMitVector, report.currentMitVector, report.signerInfo, report.idKeyDigest, report.authorKeyDigest
        ),
        evidence = Evidence(report.version, crypto.sha256(report.raw), report.signature, EndorsementKeySummary(sum(ek.cert), ek.kind, ek.hwid, ek.cspId, ek.tcb), sum(chain.intermediate), sum(chain.root), chain.crl),
        policyApplied = policy,
        verifiedAt = now,
    )
}

/** JSON-shaped projection: bytes as lowercase hex, unsigned 64-bit as decimal strings, enums as names. Same keys as the TS port. */
fun toJson(a: Attestation): Map<String, Any?> = mapOf(
    "identity" to mapOf(
        "chipId" to a.identity.chipId.hex(),
        "reportId" to a.identity.reportId.hex(),
        "reportIdMa" to a.identity.reportIdMa.hex(),
        "measurement" to a.identity.measurement.hex(),
        "hostData" to a.identity.hostData.hex(),
        "reportData" to a.identity.reportData.hex(),
        "familyId" to a.identity.familyId.hex(),
        "imageId" to a.identity.imageId.hex(),
        "guestSvn" to a.identity.guestSvn,
        "vmpl" to a.identity.vmpl,
    ),
    "platform" to mapOf(
        "product" to a.platform.product.name,
        "productName" to a.platform.productName,
        "cpuid" to a.platform.cpuid?.let { mapOf("family" to it.family, "model" to it.model, "stepping" to it.stepping) },
        "guestPolicy" to a.platform.guestPolicy.let { g ->
            mapOf(
                "raw" to g.raw.toString(),
                "abiMajor" to g.abiMajor,
                "abiMinor" to g.abiMinor,
                "smt" to g.smt,
                "migrateMa" to g.migrateMa,
                "debug" to g.debug,
                "singleSocket" to g.singleSocket,
                "cxlAllowed" to g.cxlAllowed,
                "memAes256Xts" to g.memAes256Xts,
                "raplDisabled" to g.raplDisabled,
                "ciphertextHidingDram" to g.ciphertextHidingDram,
                "pageSwapDisabled" to g.pageSwapDisabled,
            )
        },
        "platformInfo" to a.platform.platformInfo.let { p ->
            mapOf(
                "raw" to p.raw.toString(),
                "smtEnabled" to p.smtEnabled,
                "tsmeEnabled" to p.tsmeEnabled,
                "eccEnabled" to p.eccEnabled,
                "raplDisabled" to p.raplDisabled,
                "ciphertextHidingEnabled" to p.ciphertextHidingEnabled,
                "aliasCheckComplete" to p.aliasCheckComplete,
                "iommuWriteSafe" to p.iommuWriteSafe,
                "tioEnabled" to p.tioEnabled,
            )
        },
        "tcb" to mapOf(
            "current" to tcbJson(a.platform.tcb.current),
            "committed" to tcbJson(a.platform.tcb.committed),
            "reported" to tcbJson(a.platform.tcb.reported),
            "launch" to tcbJson(a.platform.tcb.launch),
        ),
        "firmware" to mapOf("current" to fwJson(a.platform.firmwareCurrent), "committed" to fwJson(a.platform.firmwareCommitted)),
        "mitVectors" to a.platform.launchMitVector?.let { mapOf("launch" to it.toString(), "current" to a.platform.currentMitVector.toString()) },
        "signer" to mapOf(
            "signingKey" to a.platform.signer.signingKey.name,
            "maskChipKey" to a.platform.signer.maskChipKey,
            "authorKeyEnabled" to a.platform.signer.authorKeyEnabled,
        ),
        "idKeyDigest" to a.platform.idKeyDigest.hex(),
        "authorKeyDigest" to a.platform.authorKeyDigest.hex(),
    ),
    "evidence" to mapOf(
        "reportVersion" to a.evidence.reportVersion,
        "reportSha256" to a.evidence.reportSha256.hex(),
        "signature" to mapOf("r" to a.evidence.signature.r.hex(), "s" to a.evidence.signature.s.hex()),
        "endorsementKey" to (
            certJson(a.evidence.endorsementKey.cert) + mapOf(
                "kind" to a.evidence.endorsementKey.kind.name,
                "hwid" to a.evidence.endorsementKey.hwid?.hex(),
                "cspId" to a.evidence.endorsementKey.cspId,
                "tcb" to tcbJson(a.evidence.endorsementKey.tcb),
            )
            ),
        "ask" to certJson(a.evidence.ask),
        "ark" to certJson(a.evidence.ark),
        "crl" to a.evidence.crl?.let { mapOf("thisUpdate" to it.thisUpdate, "nextUpdate" to it.nextUpdate, "revokedCount" to it.revokedCount) },
    ),
    "policyApplied" to a.policyApplied.let { p ->
        mapOf(
            "products" to p.products.map { it.name },
            "signingKey" to (if (p.signingKey == SigningKeyPolicy.ANY) "any" else p.signingKey.name),
            "allowMaskedChipId" to p.allowMaskedChipId,
            "chipIds" to p.chipIds?.map { it.hex() },
            "endorsementKeyFingerprints" to p.endorsementKeyFingerprints?.map { it.hex() },
            "cspIds" to p.cspIds,
            "requireCrl" to p.requireCrl,
            "guestPolicy" to p.guestPolicy.let { g ->
                mapOf(
                    "debug" to bitJson(g.debug),
                    "migrateMa" to bitJson(g.migrateMa),
                    "smt" to bitJson(g.smt),
                    "singleSocket" to bitJson(g.singleSocket),
                    "cxlAllowed" to bitJson(g.cxlAllowed),
                    "memAes256Xts" to bitJson(g.memAes256Xts),
                    "raplDisabled" to bitJson(g.raplDisabled),
                    "ciphertextHidingDram" to bitJson(g.ciphertextHidingDram),
                    "pageSwapDisabled" to bitJson(g.pageSwapDisabled),
                    "minAbi" to g.minAbi?.let { mapOf("major" to it.first, "minor" to it.second) },
                )
            },
            "platformInfo" to p.platformInfo.let { q ->
                mapOf(
                    "smtEnabled" to bitJson(q.smtEnabled),
                    "tsmeEnabled" to bitJson(q.tsmeEnabled),
                    "eccEnabled" to bitJson(q.eccEnabled),
                    "raplDisabled" to bitJson(q.raplDisabled),
                    "ciphertextHidingEnabled" to bitJson(q.ciphertextHidingEnabled),
                    "aliasCheckComplete" to bitJson(q.aliasCheckComplete),
                    "iommuWriteSafe" to bitJson(q.iommuWriteSafe),
                    "tioEnabled" to bitJson(q.tioEnabled),
                    "allowUnknownBits" to q.allowUnknownBits,
                )
            },
            "vmpl" to (p.vmpl ?: "any"),
            "minReportVersion" to p.minReportVersion,
            "minGuestSvn" to p.minGuestSvn,
            "minTcb" to p.minTcb.entries.associate { (k, v) -> k.name to floorJson(v) },
            "minLaunchTcb" to p.minLaunchTcb.entries.associate { (k, v) -> k.name to floorJson(v) },
            "minFirmware" to fwJson(p.minFirmware),
            "allowProvisionalFirmware" to p.allowProvisionalFirmware,
            "minLaunchMitVector" to p.minLaunchMitVector?.toString(),
            "minCurrentMitVector" to p.minCurrentMitVector?.toString(),
            "measurement" to when (val m = p.measurement) {
                is MeasurementPin.Allowlist -> m.values.map { it.hex() };
                MeasurementPin.Any -> "any"
            },
            "reportData" to when (val r = p.reportData) {
                is ReportDataPin.Exact -> mapOf("kind" to "exact", "value" to r.value.hex())
                is ReportDataPin.Prefix -> mapOf("kind" to "prefix", "value" to r.value.hex())
                ReportDataPin.Any -> mapOf("kind" to "any")
            },
            "hostData" to p.hostData?.hex(),
            "familyId" to p.familyId?.hex(),
            "imageId" to p.imageId?.hex(),
            "reportId" to p.reportId?.hex(),
            "idBlock" to when (val i = p.idBlock) {
                IdBlockPin.Forbid -> "forbid"
                IdBlockPin.Any -> "any"
                is IdBlockPin.Pinned -> mapOf("idKeyDigest" to i.idKeyDigest.hex(), "authorKeyDigest" to i.authorKeyDigest?.hex())
            },
        )
    },
    "verifiedAt" to a.verifiedAt,
).filterNullsDeep()

private fun bitJson(b: Bit?) = b?.name?.lowercase()
private fun tcbJson(t: TcbVersion) = mapOf("bootloader" to t.bootloader, "tee" to t.tee, "snp" to t.snp, "microcode" to t.microcode, "fmc" to t.fmc)
private fun floorJson(t: TcbFloor) = mapOf("bootloader" to t.bootloader, "tee" to t.tee, "snp" to t.snp, "microcode" to t.microcode, "fmc" to t.fmc)
private fun fwJson(f: FirmwareVersion) = mapOf("major" to f.major, "minor" to f.minor, "build" to f.build)
private fun certJson(c: CertSummary) = mapOf("sha256" to c.sha256.hex(), "serial" to c.serial.hex(), "subjectCn" to c.subjectCn, "notBefore" to c.notBefore, "notAfter" to c.notAfter)

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.filterNullsDeep(): Map<String, Any?> = entries.filter { it.value != null }.associate { (k, v) -> k to (if (v is Map<*, *>) (v as Map<String, Any?>).filterNullsDeep() else v) }
