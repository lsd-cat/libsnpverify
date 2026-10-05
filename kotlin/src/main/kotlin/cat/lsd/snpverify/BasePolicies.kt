package cat.lsd.snpverify

/** Caller-maintained reference values; reportData must bind a fresh session. */
data class BaseAppraisalPolicyConfig(
    val products: List<Product>,
    val measurements: List<ByteArray>,
    val reportData: ByteArray, // exactly 64 bytes, e.g. SHA-512 of nonce and peer key
    val minTcb: Map<Product, TcbFloor>,
)

private fun base(config: BaseAppraisalPolicyConfig): AppraisalPolicy {
    require(config.products.isNotEmpty() && config.products.all { it in listOf(Product.Milan, Product.Genoa, Product.Turin) }) { "base policy requires supported products" }
    require(config.measurements.isNotEmpty() && config.measurements.all { it.size == 48 }) { "base policy requires one or more 48-byte measurements" }
    require(config.reportData.size == 64 && !config.reportData.isZero()) { "base policy requires a nonzero, 64-byte report-data binding" }
    for (product in config.products) {
        val f = config.minTcb[product] ?: error("base policy requires a TCB floor for $product")
        val values = listOf(f.bootloader, f.tee, f.snp, f.microcode) + if (product == Product.Turin) listOf(f.fmc) else emptyList()
        require(values.all { it != null && it in 0..255 }) { "base policy requires all TCB component floors for $product" }
    }
    return AppraisalPolicy(
        measurement = MeasurementPin.Allowlist(config.measurements.map { it.copyOf() }),
        products = config.products.toList(),
        reportData = ReportDataPin.Exact(config.reportData.copyOf()),
        minTcb = config.minTcb.toMap(),
        minReportVersion = 3,
        requireCrl = true,
        vmpl = 0,
        idBlock = IdBlockPin.Any,
    )
}

/** Guest-owned endorsement key. CHIP_ID must be present. */
fun baseVcekAppraisalPolicy(config: BaseAppraisalPolicyConfig): AppraisalPolicy = base(config).copy(signingKey = SigningKeyPolicy.VCEK)

/** Cloud-provider endorsement key. A signed CSP_ID pin selects the allowed provider. */
fun baseVlekAppraisalPolicy(config: BaseAppraisalPolicyConfig, cspIds: List<String>): AppraisalPolicy {
    require(cspIds.isNotEmpty() && cspIds.all { it.isNotEmpty() }) { "base VLEK policy requires one or more CSP_IDs" }
    return base(config).copy(signingKey = SigningKeyPolicy.VLEK, cspIds = cspIds.toList())
}
