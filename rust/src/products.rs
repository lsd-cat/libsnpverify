//! The product table. A new CPU generation is a row here, its roots, and a TCB layout if the bytes differ. Mirrors ts/src/products.ts.

use crate::report::{Product, TcbLayout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidRange {
    pub family: u8,
    pub model_min: u8,
    pub model_max: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductInfo {
    pub tcb_layout: TcbLayout,
    /// Length of the HWID extension in VCEK certificates.
    pub hwid_length: usize,
    /// structVersion expected in the VCEK extensions (KDS spec 57230).
    pub struct_version: u64,
    /// CPUID (family, model range) values that report this product (report version >= 3).
    pub cpuid: &'static [CpuidRange],
}

const fn range(family: u8, model_min: u8, model_max: u8) -> CpuidRange {
    CpuidRange { family, model_min, model_max }
}

const MILAN: ProductInfo = ProductInfo {
    tcb_layout: TcbLayout::V0,
    hwid_length: 64,
    struct_version: 0,
    cpuid: &[range(0x19, 0x00, 0x0f)],
};
const GENOA: ProductInfo = ProductInfo {
    tcb_layout: TcbLayout::V0,
    hwid_length: 64,
    struct_version: 0,
    cpuid: &[range(0x19, 0x10, 0x1f), range(0x19, 0xa0, 0xaf)],
}; // Bergamo/Siena
const TURIN: ProductInfo = ProductInfo {
    tcb_layout: TcbLayout::V1,
    hwid_length: 8,
    struct_version: 1,
    cpuid: &[range(0x1a, 0x00, 0x1f)],
};
// Venice: TCB layout V2 and roots pending; reports are rejected.
const VENICE: ProductInfo = ProductInfo {
    tcb_layout: TcbLayout::V2,
    hwid_length: 8,
    struct_version: 1,
    cpuid: &[range(0x1a, 0x50, 0x5f)],
};

impl Product {
    pub const ALL: [Product; 4] = [Product::Milan, Product::Genoa, Product::Turin, Product::Venice];

    pub fn info(self) -> &'static ProductInfo {
        match self {
            Product::Milan => &MILAN,
            Product::Genoa => &GENOA,
            Product::Turin => &TURIN,
            Product::Venice => &VENICE,
        }
    }
}

/// Product named by a VCEK productName extension ("Genoa-B2", "Siena", "Turin-B1").
pub fn product_from_name(name: &str) -> Option<Product> {
    let line = name.split('-').next().unwrap_or("");
    if line == "Siena" || line == "Bergamo" {
        return Some(Product::Genoa);
    }
    Product::ALL.into_iter().find(|p| p.as_str() == line)
}

pub fn product_from_cpuid(family: u8, model: u8) -> Option<Product> {
    Product::ALL
        .into_iter()
        .find(|p| p.info().cpuid.iter().any(|c| c.family == family && (c.model_min..=c.model_max).contains(&model)))
}
