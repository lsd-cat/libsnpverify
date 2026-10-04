package snpverify

// The product table. Mirrors ts/src/products.ts.
data class CpuidRange(val family: Int, val modelMin: Int, val modelMax: Int)
data class ProductInfo(val tcbLayout: TcbLayout, val hwidLength: Int, val structVersion: Int, val cpuid: List<CpuidRange>)

val PRODUCTS: Map<Product, ProductInfo> = mapOf(
    Product.Milan to ProductInfo(TcbLayout.V0, 64, 0, listOf(CpuidRange(0x19, 0x00, 0x0f))),
    Product.Genoa to ProductInfo(TcbLayout.V0, 64, 0, listOf(CpuidRange(0x19, 0x10, 0x1f), CpuidRange(0x19, 0xa0, 0xaf))), // Bergamo/Siena
    Product.Turin to ProductInfo(TcbLayout.V1, 8, 1, listOf(CpuidRange(0x1a, 0x00, 0x1f))),
    // Venice: TCB layout V2 and roots pending; reports are rejected.
    Product.Venice to ProductInfo(TcbLayout.V2, 8, 1, listOf(CpuidRange(0x1a, 0x50, 0x5f))),
)

fun productFromName(name: String): Product? {
    val line = name.substringBefore('-')
    if (line == "Siena" || line == "Bergamo") return Product.Genoa
    return Product.entries.find { it.name == line }
}

fun productFromCpuid(family: Int, model: Int): Product? = PRODUCTS.entries.find { (_, info) -> info.cpuid.any { it.family == family && model in it.modelMin..it.modelMax } }?.key
