//! ATTESTATION_REPORT parsing (AMD 56860), report versions 2 to 5. Mirrors ts/src/report.ts.
//! TCBs stay raw; `decode_tcb` takes the product layout established by the chain stage.

use std::fmt;

use crate::bytes::{is_zero, u32le, u64le};
use crate::errors::{fail, ErrorCode, Result};

pub const REPORT_SIZE: usize = 0x4a0;
pub const SIGNED_SIZE: usize = 0x2a0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
    Venice,
}

impl Product {
    pub fn as_str(self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
            Product::Turin => "Turin",
            Product::Venice => "Venice",
        }
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbLayout {
    V0,
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningKey {
    Vcek,
    Vlek,
}

impl SigningKey {
    pub fn as_str(self) -> &'static str {
        match self {
            SigningKey::Vcek => "VCEK",
            SigningKey::Vlek => "VLEK",
        }
    }
}

impl fmt::Display for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcbVersion {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    pub fmc: Option<u8>,
}

/// Partial floor: `None` components are not constrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcbFloor {
    pub bootloader: Option<u8>,
    pub tee: Option<u8>,
    pub snp: Option<u8>,
    pub microcode: Option<u8>,
    pub fmc: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPolicy {
    pub raw: u64,
    pub abi_major: u8,
    pub abi_minor: u8,
    pub smt: bool,
    pub migrate_ma: bool,
    pub debug: bool,
    pub single_socket: bool,
    pub cxl_allowed: bool,
    pub mem_aes256_xts: bool,
    pub rapl_disabled: bool,
    pub ciphertext_hiding_dram: bool,
    pub page_swap_disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformInfo {
    pub raw: u64,
    pub smt_enabled: bool,
    pub tsme_enabled: bool,
    pub ecc_enabled: bool,
    pub rapl_disabled: bool,
    pub ciphertext_hiding_enabled: bool,
    pub alias_check_complete: bool,
    pub iommu_write_safe: bool,
    pub tio_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerInfo {
    pub signing_key: SigningKey,
    pub mask_chip_key: bool,
    pub author_key_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpuid {
    pub family: u8,
    pub model: u8,
    pub stepping: u8,
}

/// r and s big-endian, 48 bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

/// Immutable: owns a private copy of the report; byte-valued accessors borrow from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    bytes: Vec<u8>,
    pub version: u32,
    pub guest_svn: u32,
    pub policy: GuestPolicy,
    pub vmpl: u32,
    pub current_tcb: u64,
    pub platform_info: PlatformInfo,
    pub signer_info: SignerInfo,
    pub reported_tcb: u64,
    /// Report version 3 and later.
    pub cpuid: Option<Cpuid>,
    pub committed_tcb: u64,
    pub current_version: FirmwareVersion,
    pub committed_version: FirmwareVersion,
    pub launch_tcb: u64,
    /// Report version 5 and later.
    pub launch_mit_vector: Option<u64>,
    pub current_mit_vector: Option<u64>,
    sig_r: Vec<u8>,
    sig_s: Vec<u8>,
}

impl Report {
    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }
    pub fn family_id(&self) -> &[u8] {
        &self.bytes[0x10..0x20]
    }
    pub fn image_id(&self) -> &[u8] {
        &self.bytes[0x20..0x30]
    }
    pub fn report_data(&self) -> &[u8] {
        &self.bytes[0x50..0x90]
    }
    pub fn measurement(&self) -> &[u8] {
        &self.bytes[0x90..0xc0]
    }
    pub fn host_data(&self) -> &[u8] {
        &self.bytes[0xc0..0xe0]
    }
    pub fn id_key_digest(&self) -> &[u8] {
        &self.bytes[0xe0..0x110]
    }
    pub fn author_key_digest(&self) -> &[u8] {
        &self.bytes[0x110..0x140]
    }
    pub fn report_id(&self) -> &[u8] {
        &self.bytes[0x140..0x160]
    }
    pub fn report_id_ma(&self) -> &[u8] {
        &self.bytes[0x160..0x180]
    }
    pub fn chip_id(&self) -> &[u8] {
        &self.bytes[0x1a0..0x1e0]
    }
    pub fn signature(&self) -> EcdsaSignature {
        EcdsaSignature {
            r: self.sig_r.clone(),
            s: self.sig_s.clone(),
        }
    }
    pub(crate) fn signature_parts(&self) -> (&[u8], &[u8]) {
        (&self.sig_r, &self.sig_s)
    }
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[..SIGNED_SIZE]
    }
}

fn mbz(b: &[u8], s: usize, e: usize) -> Result<()> {
    if !is_zero(&b[s..e]) {
        fail!(ErrorCode::ReportMalformed, "reserved bytes 0x{s:x}..0x{e:x} not zero");
    }
    Ok(())
}

fn bit(raw: u64, n: u32) -> bool {
    (raw >> n) & 1 == 1
}

pub(crate) fn decode_guest_policy(raw: u64) -> Result<GuestPolicy> {
    if !bit(raw, 17) {
        fail!(ErrorCode::ReportMalformed => "guest_policy", "guest_policy bit 17 must be 1");
    }
    if raw >> 26 != 0 {
        fail!(ErrorCode::ReportMalformed => "guest_policy", "guest_policy bits 63:26 must be 0");
    }
    Ok(GuestPolicy {
        raw,
        abi_major: ((raw >> 8) & 0xff) as u8,
        abi_minor: (raw & 0xff) as u8,
        smt: bit(raw, 16),
        migrate_ma: bit(raw, 18),
        debug: bit(raw, 19),
        single_socket: bit(raw, 20),
        cxl_allowed: bit(raw, 21),
        mem_aes256_xts: bit(raw, 22),
        rapl_disabled: bit(raw, 23),
        ciphertext_hiding_dram: bit(raw, 24),
        page_swap_disabled: bit(raw, 25),
    })
}

/// Bits this library knows. Unknown set bits are a policy matter (AppraisalPolicy.platform_info.allow_unknown_bits).
pub(crate) const KNOWN_PLATFORM_INFO_BITS: u64 = 0xff;

pub(crate) fn decode_platform_info(raw: u64) -> PlatformInfo {
    PlatformInfo {
        raw,
        smt_enabled: bit(raw, 0),
        tsme_enabled: bit(raw, 1),
        ecc_enabled: bit(raw, 2),
        rapl_disabled: bit(raw, 3),
        ciphertext_hiding_enabled: bit(raw, 4),
        alias_check_complete: bit(raw, 5),
        iommu_write_safe: bit(raw, 6),
        tio_enabled: bit(raw, 7),
    }
}

pub(crate) fn decode_signer_info(raw: u32) -> Result<SignerInfo> {
    if raw >> 5 != 0 {
        fail!(ErrorCode::ReportMalformed => "signer_info", "signer_info bits 31:5 must be 0");
    }
    let key = (raw >> 2) & 7;
    if key != 0 && key != 1 {
        fail!(ErrorCode::ReportMalformed => "signer_info.signing_key", "signer_info.signing_key {key} is not VCEK or VLEK");
    }
    Ok(SignerInfo {
        signing_key: if key == 0 { SigningKey::Vcek } else { SigningKey::Vlek },
        mask_chip_key: raw & 2 != 0,
        author_key_enabled: raw & 1 != 0,
    })
}

pub(crate) fn decode_tcb(raw: u64, layout: TcbLayout) -> Result<TcbVersion> {
    let byte = |n: u32| ((raw >> (8 * n)) & 0xff) as u8;
    match layout {
        TcbLayout::V0 => {
            if raw & 0x0000ffffffff0000 != 0 {
                fail!(ErrorCode::ReportMalformed, "TCB reserved bytes 2..5 not zero");
            }
            Ok(TcbVersion {
                bootloader: byte(0),
                tee: byte(1),
                snp: byte(6),
                microcode: byte(7),
                fmc: None,
            })
        }
        TcbLayout::V1 => {
            if raw & 0x00ffffff00000000 != 0 {
                fail!(ErrorCode::ReportMalformed, "Turin TCB reserved bytes 4..6 not zero");
            }
            Ok(TcbVersion {
                bootloader: byte(1),
                tee: byte(2),
                snp: byte(3),
                microcode: byte(7),
                fmc: Some(byte(0)),
            })
        }
        TcbLayout::V2 => fail!(ErrorCode::ReportMalformed, "Venice TCB layout not supported yet"),
    }
}

pub(crate) fn tcb_at_least(a: &TcbVersion, min: &TcbFloor) -> bool {
    min.bootloader.is_none_or(|m| a.bootloader >= m)
        && min.tee.is_none_or(|m| a.tee >= m)
        && min.snp.is_none_or(|m| a.snp >= m)
        && min.microcode.is_none_or(|m| a.microcode >= m)
        && min.fmc.is_none_or(|m| a.fmc.unwrap_or(0) >= m)
}

pub(crate) fn floor_of(t: &TcbVersion) -> TcbFloor {
    TcbFloor {
        bootloader: Some(t.bootloader),
        tee: Some(t.tee),
        snp: Some(t.snp),
        microcode: Some(t.microcode),
        fmc: t.fmc,
    }
}

pub(crate) fn tcb_equal(a: &TcbVersion, b: &TcbVersion) -> bool {
    a.bootloader == b.bootloader && a.tee == b.tee && a.snp == b.snp && a.microcode == b.microcode && a.fmc.unwrap_or(0) == b.fmc.unwrap_or(0)
}

fn le72_to_be48(b: &[u8], off: usize, what: &str) -> Result<Vec<u8>> {
    if !is_zero(&b[off + 48..off + 72]) {
        fail!(ErrorCode::ReportMalformed => "signature", "signature {what} exceeds 384 bits");
    }
    Ok((0..48).map(|i| b[off + 47 - i]).collect())
}

/// Parse and structurally validate an attestation report.
pub fn parse_report(data: &[u8]) -> Result<Report> {
    if data.len() != REPORT_SIZE {
        fail!(ErrorCode::ReportTruncated, "report is {} bytes, want {REPORT_SIZE}", data.len());
    }
    let data = data.to_vec();
    let version = u32le(&data, 0x00);
    if !(2..=5).contains(&version) {
        fail!(ErrorCode::ReportVersionUnsupported => "version", "report version {version}");
    }
    let vmpl = u32le(&data, 0x30);
    if vmpl == 0xffffffff {
        fail!(ErrorCode::ReportHostRequested => "vmpl", "report was requested by the host (VMPL=0xFFFFFFFF), not by the guest");
    }
    if vmpl > 3 {
        fail!(ErrorCode::ReportMalformed => "vmpl", "vmpl {vmpl} out of range 0..3");
    }
    let signature_algo = u32le(&data, 0x34);
    if signature_algo != 1 {
        fail!(ErrorCode::ReportSignatureAlgoUnsupported => "signature_algo", "signature_algo {signature_algo}");
    }
    mbz(&data, 0x4c, 0x50)?;
    mbz(&data, if version >= 3 { 0x18b } else { 0x188 }, 0x1a0)?;
    mbz(&data, 0x1eb, 0x1ec)?;
    mbz(&data, 0x1ef, 0x1f0)?;
    if version < 5 {
        mbz(&data, 0x1f8, 0x208)?;
    }
    mbz(&data, 0x208, SIGNED_SIZE)?;
    mbz(&data, SIGNED_SIZE + 144, REPORT_SIZE)?;
    Ok(Report {
        version,
        guest_svn: u32le(&data, 0x04),
        policy: decode_guest_policy(u64le(&data, 0x08))?,
        vmpl,
        current_tcb: u64le(&data, 0x38),
        platform_info: decode_platform_info(u64le(&data, 0x40)),
        signer_info: decode_signer_info(u32le(&data, 0x48))?,
        reported_tcb: u64le(&data, 0x180),
        cpuid: (version >= 3).then(|| Cpuid {
            family: data[0x188],
            model: data[0x189],
            stepping: data[0x18a],
        }),
        committed_tcb: u64le(&data, 0x1e0),
        current_version: FirmwareVersion {
            build: data[0x1e8],
            minor: data[0x1e9],
            major: data[0x1ea],
        },
        committed_version: FirmwareVersion {
            build: data[0x1ec],
            minor: data[0x1ed],
            major: data[0x1ee],
        },
        launch_tcb: u64le(&data, 0x1f0),
        launch_mit_vector: (version >= 5).then(|| u64le(&data, 0x1f8)),
        current_mit_vector: (version >= 5).then(|| u64le(&data, 0x200)),
        sig_r: le72_to_be48(&data, SIGNED_SIZE, "r")?,
        sig_s: le72_to_be48(&data, SIGNED_SIZE + 72, "s")?,
        bytes: data,
    })
}
