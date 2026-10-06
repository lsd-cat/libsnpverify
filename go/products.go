package snpverify

import "strings"

// The product table. A new CPU generation is a row here, its roots, and a TCB layout if the bytes differ. Mirrors ts/src/products.ts.

type CPUIDRange struct{ Family, ModelMin, ModelMax int }

type ProductInfo struct {
	TCBLayout TCBLayout
	// HWIDLength is the length of the HWID extension in VCEK certificates.
	HWIDLength int
	// StructVersion expected in the VCEK extensions (KDS spec 57230).
	StructVersion int
	// CPUID (family, model range) values that report this product (report version >= 3).
	CPUID []CPUIDRange
}

var Products = map[Product]ProductInfo{
	Milan: {TCBLayoutV0, 64, 0, []CPUIDRange{{0x19, 0x00, 0x0f}}},
	Genoa: {TCBLayoutV0, 64, 0, []CPUIDRange{{0x19, 0x10, 0x1f}, {0x19, 0xa0, 0xaf}}}, // Bergamo/Siena
	Turin: {TCBLayoutV1, 8, 1, []CPUIDRange{{0x1a, 0x00, 0x1f}}},
	// Venice: TCB layout v2 and roots pending; reports are rejected.
	Venice: {TCBLayoutV2, 8, 1, []CPUIDRange{{0x1a, 0x50, 0x5f}}},
}

// ProductFromName names the product of a VCEK productName extension ("Genoa-B2", "Siena", "Turin-B1").
func ProductFromName(name string) (Product, bool) {
	line, _, _ := strings.Cut(name, "-")
	if line == "Siena" || line == "Bergamo" {
		return Genoa, true
	}
	_, ok := Products[Product(line)]
	return Product(line), ok
}

func ProductFromCPUID(family, model int) (Product, bool) {
	for p, info := range Products {
		for _, c := range info.CPUID {
			if c.Family == family && model >= c.ModelMin && model <= c.ModelMax {
				return p, true
			}
		}
	}
	return "", false
}
