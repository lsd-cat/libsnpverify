//! AppraisalPolicy definition, defaults and checks. `check_appraisal_policy` returns all violations. Mirrors ts/src/policy.ts.

use std::collections::BTreeMap;

use crate::bind::Tcbs;
use crate::bytes::{hex, is_zero};
use crate::chain::EndorsementKey;
use crate::errors::{ErrorCode, Result, Violation};
use crate::report::{floor_of, tcb_at_least, FirmwareVersion, Product, Report, SigningKey, TcbFloor, TcbVersion, KNOWN_PLATFORM_INFO_BITS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bit {
    Required,
    Forbidden,
    Any,
}

impl Bit {
    pub fn as_str(self) -> &'static str {
        match self {
            Bit::Required => "required",
            Bit::Forbidden => "forbidden",
            Bit::Any => "any",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportDataPin {
    Exact(Vec<u8>),
    Prefix(Vec<u8>),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdBlockPin {
    Forbid,
    Any,
    Pinned {
        id_key_digest: Vec<u8>,
        /// All-zero means "no author key".
        author_key_digest: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementPin {
    Allowlist(Vec<Vec<u8>>),
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyPolicy {
    Vcek,
    Vlek,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestPolicyRules {
    pub debug: Option<Bit>,
    pub migrate_ma: Option<Bit>,
    pub smt: Option<Bit>,
    pub single_socket: Option<Bit>,
    pub cxl_allowed: Option<Bit>,
    pub mem_aes256_xts: Option<Bit>,
    pub rapl_disabled: Option<Bit>,
    pub ciphertext_hiding_dram: Option<Bit>,
    pub page_swap_disabled: Option<Bit>,
    /// (major, minor).
    pub min_abi: Option<(u8, u8)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlatformInfoRules {
    pub smt_enabled: Option<Bit>,
    pub tsme_enabled: Option<Bit>,
    pub ecc_enabled: Option<Bit>,
    pub rapl_disabled: Option<Bit>,
    pub ciphertext_hiding_enabled: Option<Bit>,
    pub alias_check_complete: Option<Bit>,
    pub iommu_write_safe: Option<Bit>,
    pub tio_enabled: Option<Bit>,
    pub allow_unknown_bits: Option<bool>,
}

/// `None` means "use the default" (SPEC §5). `measurement` is required: build with [`AppraisalPolicy::new`] and struct update syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppraisalPolicy {
    pub measurement: MeasurementPin,
    /// Default Genoa, Turin.
    pub products: Option<Vec<Product>>,
    /// Default VCEK.
    pub signing_key: Option<SigningKeyPolicy>,
    pub allow_masked_chip_id: Option<bool>,
    /// CHIP_ID allowlist (VCEK, unmasked).
    pub chip_ids: Option<Vec<Vec<u8>>>,
    /// SHA-256(DER) allowlist of the leaf cert; reissuance changes it.
    pub endorsement_key_fingerprints: Option<Vec<Vec<u8>>>,
    /// Exact CSP_ID allowlist for VLEK deployments.
    pub csp_ids: Option<Vec<String>>,
    pub require_crl: Option<bool>,
    /// Defaults: debug, migrate_ma, cxl_allowed forbidden; rest any.
    pub guest_policy: Option<GuestPolicyRules>,
    pub platform_info: Option<PlatformInfoRules>,
    /// Default 0; set `vmpl_any` to skip.
    pub vmpl: Option<u32>,
    pub vmpl_any: bool,
    /// Default 2; 3 requires the CPUID product cross-check.
    pub min_report_version: Option<u32>,
    pub min_guest_svn: Option<u32>,
    /// Floor for current, committed, reported.
    pub min_tcb: Option<BTreeMap<Product, TcbFloor>>,
    /// Floor for launch; default = min_tcb.
    pub min_launch_tcb: Option<BTreeMap<Product, TcbFloor>>,
    pub min_firmware: Option<FirmwareVersion>,
    pub allow_provisional_firmware: Option<bool>,
    pub min_launch_mit_vector: Option<u64>,
    pub min_current_mit_vector: Option<u64>,
    /// Default Any.
    pub report_data: Option<ReportDataPin>,
    pub host_data: Option<Vec<u8>>,
    pub family_id: Option<Vec<u8>>,
    pub image_id: Option<Vec<u8>>,
    pub report_id: Option<Vec<u8>>,
    /// Default Forbid.
    pub id_block: Option<IdBlockPin>,
}

impl AppraisalPolicy {
    /// A policy with the given measurement pin and every other field at its default.
    pub fn new(measurement: MeasurementPin) -> Self {
        AppraisalPolicy {
            measurement,
            products: None,
            signing_key: None,
            allow_masked_chip_id: None,
            chip_ids: None,
            endorsement_key_fingerprints: None,
            csp_ids: None,
            require_crl: None,
            guest_policy: None,
            platform_info: None,
            vmpl: None,
            vmpl_any: false,
            min_report_version: None,
            min_guest_svn: None,
            min_tcb: None,
            min_launch_tcb: None,
            min_firmware: None,
            allow_provisional_firmware: None,
            min_launch_mit_vector: None,
            min_current_mit_vector: None,
            report_data: None,
            host_data: None,
            family_id: None,
            image_id: None,
            report_id: None,
            id_block: None,
        }
    }
}

/// AppraisalPolicy with defaults filled in; recorded in the result as `appraisal_policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAppraisalPolicy {
    pub products: Vec<Product>,
    pub signing_key: SigningKeyPolicy,
    pub allow_masked_chip_id: bool,
    pub chip_ids: Option<Vec<Vec<u8>>>,
    pub endorsement_key_fingerprints: Option<Vec<Vec<u8>>>,
    pub csp_ids: Option<Vec<String>>,
    pub require_crl: bool,
    pub guest_policy: GuestPolicyRules,
    pub platform_info: PlatformInfoRules,
    /// `None` means any.
    pub vmpl: Option<u32>,
    pub min_report_version: u32,
    pub min_guest_svn: u32,
    pub min_tcb: BTreeMap<Product, TcbFloor>,
    pub min_launch_tcb: BTreeMap<Product, TcbFloor>,
    pub min_firmware: FirmwareVersion,
    pub allow_provisional_firmware: bool,
    pub min_launch_mit_vector: Option<u64>,
    pub min_current_mit_vector: Option<u64>,
    pub measurement: MeasurementPin,
    pub report_data: ReportDataPin,
    pub host_data: Option<Vec<u8>>,
    pub family_id: Option<Vec<u8>>,
    pub image_id: Option<Vec<u8>>,
    pub report_id: Option<Vec<u8>>,
    pub id_block: IdBlockPin,
}

fn need(cond: bool, msg: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Violation::new(ErrorCode::PolicyInvalid, msg))
    }
}

fn len_is(v: Option<&Vec<u8>>, n: usize, what: &str) -> Result<()> {
    need(v.is_none_or(|v| v.len() == n), &format!("policy.{what} must be {n} bytes"))
}

/// Fill defaults and validate shapes. A malformed policy yields a POLICY_INVALID violation.
pub fn resolve_appraisal_policy(p: &AppraisalPolicy) -> Result<ResolvedAppraisalPolicy> {
    if let MeasurementPin::Allowlist(values) = &p.measurement {
        need(!values.is_empty(), "policy.measurement must be a nonempty array or \"any\"")?;
        for m in values {
            len_is(Some(m), 48, "measurement[]")?;
        }
    }
    match &p.report_data {
        Some(ReportDataPin::Exact(v)) => len_is(Some(v), 64, "reportData.value")?,
        Some(ReportDataPin::Prefix(v)) => need((1..=64).contains(&v.len()), "policy.reportData.value must be 1..64 bytes")?,
        _ => {}
    }
    len_is(p.host_data.as_ref(), 32, "hostData")?;
    len_is(p.family_id.as_ref(), 16, "familyId")?;
    len_is(p.image_id.as_ref(), 16, "imageId")?;
    len_is(p.report_id.as_ref(), 32, "reportId")?;
    for c in p.chip_ids.iter().flatten() {
        len_is(Some(c), 64, "chipIds[]")?;
    }
    for f in p.endorsement_key_fingerprints.iter().flatten() {
        len_is(Some(f), 32, "endorsementKeyFingerprints[]")?;
    }
    if let Some(IdBlockPin::Pinned { id_key_digest, author_key_digest }) = &p.id_block {
        len_is(Some(id_key_digest), 48, "idBlock.idKeyDigest")?;
        len_is(author_key_digest.as_ref(), 48, "idBlock.authorKeyDigest")?;
    }
    need(p.vmpl.is_none_or(|v| v <= 3), "policy.vmpl must be 0..3")?;
    need(
        p.csp_ids.as_ref().is_none_or(|ids| !ids.is_empty() && ids.iter().all(|s| !s.is_empty())),
        "policy.cspIds must be nonempty strings",
    )?;
    need(p.products.as_ref().is_none_or(|ps| !ps.is_empty()), "policy.products must be a nonempty Product list")?;
    need(p.min_report_version.is_none_or(|v| (2..=5).contains(&v)), "policy.minReportVersion must be 2..5")?;
    let min_tcb = p.min_tcb.clone().unwrap_or_default();
    let g = p.guest_policy.unwrap_or_default();
    let q = p.platform_info.unwrap_or_default();
    Ok(ResolvedAppraisalPolicy {
        products: p.products.clone().unwrap_or_else(|| vec![Product::Genoa, Product::Turin]),
        signing_key: p.signing_key.unwrap_or(SigningKeyPolicy::Vcek),
        allow_masked_chip_id: p.allow_masked_chip_id.unwrap_or(false),
        chip_ids: p.chip_ids.clone(),
        endorsement_key_fingerprints: p.endorsement_key_fingerprints.clone(),
        csp_ids: p.csp_ids.clone(),
        require_crl: p.require_crl.unwrap_or(false),
        guest_policy: GuestPolicyRules {
            debug: Some(g.debug.unwrap_or(Bit::Forbidden)),
            migrate_ma: Some(g.migrate_ma.unwrap_or(Bit::Forbidden)),
            cxl_allowed: Some(g.cxl_allowed.unwrap_or(Bit::Forbidden)),
            mem_aes256_xts: Some(g.mem_aes256_xts.unwrap_or(Bit::Any)),
            ..g
        },
        platform_info: PlatformInfoRules {
            allow_unknown_bits: Some(q.allow_unknown_bits.unwrap_or(false)),
            ..q
        },
        vmpl: if p.vmpl_any { None } else { Some(p.vmpl.unwrap_or(0)) },
        min_report_version: p.min_report_version.unwrap_or(2),
        min_guest_svn: p.min_guest_svn.unwrap_or(0),
        min_launch_tcb: p.min_launch_tcb.clone().unwrap_or_else(|| min_tcb.clone()),
        min_tcb,
        min_firmware: p.min_firmware.unwrap_or_default(),
        allow_provisional_firmware: p.allow_provisional_firmware.unwrap_or(false),
        min_launch_mit_vector: p.min_launch_mit_vector,
        min_current_mit_vector: p.min_current_mit_vector,
        measurement: p.measurement.clone(),
        report_data: p.report_data.clone().unwrap_or(ReportDataPin::Any),
        host_data: p.host_data.clone(),
        family_id: p.family_id.clone(),
        image_id: p.image_id.clone(),
        report_id: p.report_id.clone(),
        id_block: p.id_block.clone().unwrap_or(IdBlockPin::Forbid),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppraisalContext {
    pub tcb: Tcbs,
    pub crl_present: bool,
    pub leaf_fingerprint: Vec<u8>,
}

/// Check a signature-verified report against the policy. Empty = satisfied.
pub fn check_appraisal_policy(report: &Report, ek: &EndorsementKey, ctx: &AppraisalContext, policy: &AppraisalPolicy) -> Vec<Violation> {
    match resolve_appraisal_policy(policy) {
        Ok(p) => check_resolved_appraisal_policy(report, ek, ctx, &p),
        Err(e) => vec![e],
    }
}

/// Collects violations; `bad`, `bit` and `pin` mirror the helpers in the other ports.
struct Violations(Vec<Violation>);

impl Violations {
    fn bad(&mut self, code: ErrorCode, message: String, field: Option<&str>) {
        let mut x = Violation::new(code, message);
        x.field = field.map(str::to_string);
        self.0.push(x);
    }

    fn bit(&mut self, code: ErrorCode, field: &str, want: Option<Bit>, got: bool) {
        if want == Some(Bit::Required) && !got {
            self.bad(code, format!("{field} is required but not set"), Some(field));
        }
        if want == Some(Bit::Forbidden) && got {
            self.bad(code, format!("{field} is set but forbidden"), Some(field));
        }
    }

    fn pin(&mut self, code: ErrorCode, field: &str, want: Option<&Vec<u8>>, got: &[u8]) {
        if let Some(want) = want {
            if want != got {
                self.bad(code, format!("{field} {} != expected {}", hex(got), hex(want)), Some(field));
            }
        }
    }
}

pub(crate) fn check_resolved_appraisal_policy(report: &Report, ek: &EndorsementKey, ctx: &AppraisalContext, p: &ResolvedAppraisalPolicy) -> Vec<Violation> {
    let mut v = Violations(Vec::new());

    // Who signed, on what.
    let chip_id = report.chip_id();
    if !p.products.contains(&ek.product) {
        let list = p.products.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ");
        v.bad(ErrorCode::PolicyProductNotAllowed, format!("product {} not in [{list}]", ek.product), None);
    }
    if p.signing_key != SigningKeyPolicy::Any && ek.kind.as_str() != signing_key_policy_name(p.signing_key) {
        v.bad(
            ErrorCode::PolicySignerNotAllowed,
            format!("signed by {}, policy requires {}", ek.kind, signing_key_policy_name(p.signing_key)),
            Some("signer_info.signing_key"),
        );
    }
    if ek.kind == SigningKey::Vcek && is_zero(chip_id) && !p.allow_masked_chip_id {
        v.bad(ErrorCode::PolicyChipIdMasked, "CHIP_ID is masked; chip identity is not in the report".into(), Some("chip_id"));
        // VLEK reports carry no CHIP_ID by design
    }
    if p.chip_ids.as_ref().is_some_and(|ids| !ids.iter().any(|c| c == chip_id)) {
        v.bad(ErrorCode::PolicyChipIdNotAllowed, format!("chip_id {} not in allowlist", hex(chip_id)), Some("chip_id"));
    }
    if p.endorsement_key_fingerprints.as_ref().is_some_and(|fps| !fps.contains(&ctx.leaf_fingerprint)) {
        v.bad(
            ErrorCode::PolicyChipIdNotAllowed,
            format!("{} fingerprint {} not in allowlist", ek.kind, hex(&ctx.leaf_fingerprint)),
            None,
        );
    }
    if p.csp_ids
        .as_ref()
        .is_some_and(|ids| ek.kind != SigningKey::Vlek || !ek.csp_id.as_ref().is_some_and(|c| ids.contains(c)))
    {
        v.bad(ErrorCode::PolicySignerNotAllowed, "VLEK CSP_ID is not in the allowed list".into(), Some("endorsement_key.csp_id"));
    }
    if p.require_crl && !ctx.crl_present {
        v.bad(ErrorCode::PolicyInvalid, "policy requires a CRL but none was supplied".into(), None);
    }

    // Guest policy.
    let (gp, g) = (&report.policy, &p.guest_policy);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.debug", g.debug, gp.debug);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.migrate_ma", g.migrate_ma, gp.migrate_ma);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.smt", g.smt, gp.smt);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.single_socket", g.single_socket, gp.single_socket);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.cxl_allow", g.cxl_allowed, gp.cxl_allowed);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.mem_aes_256_xts", g.mem_aes256_xts, gp.mem_aes256_xts);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.rapl_dis", g.rapl_disabled, gp.rapl_disabled);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.ciphertext_hiding_dram", g.ciphertext_hiding_dram, gp.ciphertext_hiding_dram);
    v.bit(ErrorCode::PolicyGuestPolicy, "guest_policy.page_swap_disable", g.page_swap_disabled, gp.page_swap_disabled);
    if let Some((maj, min)) = g.min_abi {
        if gp.abi_major < maj || (gp.abi_major == maj && gp.abi_minor < min) {
            v.bad(
                ErrorCode::PolicyAbiVersion,
                format!("guest_policy ABI {}.{} < {maj}.{min}", gp.abi_major, gp.abi_minor),
                Some("guest_policy.abi_major"),
            );
        }
    }

    // Platform info.
    let (pi, q) = (&report.platform_info, &p.platform_info);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.smt_en", q.smt_enabled, pi.smt_enabled);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.tsme_en", q.tsme_enabled, pi.tsme_enabled);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.ecc_en", q.ecc_enabled, pi.ecc_enabled);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.rapl_dis", q.rapl_disabled, pi.rapl_disabled);
    v.bit(
        ErrorCode::PolicyPlatformInfo,
        "platform_info.ciphertext_hiding_dram_en",
        q.ciphertext_hiding_enabled,
        pi.ciphertext_hiding_enabled,
    );
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.alias_check_complete", q.alias_check_complete, pi.alias_check_complete);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.iommu_write_safe", q.iommu_write_safe, pi.iommu_write_safe);
    v.bit(ErrorCode::PolicyPlatformInfo, "platform_info.tio_en", q.tio_enabled, pi.tio_enabled);
    if q.allow_unknown_bits != Some(true) && pi.raw & !KNOWN_PLATFORM_INFO_BITS != 0 {
        v.bad(ErrorCode::PolicyPlatformInfo, format!("platform_info has unknown bits: 0x{:x}", pi.raw), Some("platform_info"));
    }

    if report.version < p.min_report_version {
        v.bad(
            ErrorCode::PolicyInvalid,
            format!("report version {} < required {}", report.version, p.min_report_version),
            Some("version"),
        );
    }
    if p.vmpl.is_some_and(|vmpl| report.vmpl != vmpl) {
        v.bad(ErrorCode::PolicyVmpl, format!("vmpl {} != {}", report.vmpl, p.vmpl.unwrap()), Some("vmpl"));
    }
    if report.guest_svn < p.min_guest_svn {
        v.bad(ErrorCode::PolicyGuestSvn, format!("guest_svn {} < {}", report.guest_svn, p.min_guest_svn), Some("guest_svn"));
    }

    // TCB floors, per product.
    let floor = p.min_tcb.get(&ek.product).copied().unwrap_or_default();
    let launch_floor = p.min_launch_tcb.get(&ek.product).copied().unwrap_or_default();
    for (name, t) in [("current", &ctx.tcb.current), ("committed", &ctx.tcb.committed), ("reported", &ctx.tcb.reported)] {
        if !tcb_at_least(t, &floor) {
            v.bad(
                ErrorCode::PolicyTcbOutOfDate,
                format!("{name}_tcb {} below minimum {}", fmt_tcb(t), fmt_floor(&floor)),
                Some(&format!("{name}_tcb")),
            );
        }
    }
    if !tcb_at_least(&ctx.tcb.launch, &launch_floor) {
        v.bad(
            ErrorCode::PolicyLaunchTcbOutOfDate,
            format!("launch_tcb {} below minimum {}", fmt_tcb(&ctx.tcb.launch), fmt_floor(&launch_floor)),
            Some("launch_tcb"),
        );
    }
    if !tcb_at_least(&ctx.tcb.current, &floor_of(&ek.tcb)) {
        v.bad(
            ErrorCode::PolicyTcbOutOfDate,
            format!("current_tcb {} below the endorsement key TCB {}", fmt_tcb(&ctx.tcb.current), fmt_tcb(&ek.tcb)),
            Some("current_tcb"),
        );
    }

    // Firmware.
    for (name, fw) in [("current", &report.current_version), ("committed", &report.committed_version)] {
        if !fw_at_least(fw, &p.min_firmware) {
            v.bad(
                ErrorCode::PolicyFirmwareVersion,
                format!("{name} firmware {}.{}.{} below minimum", fw.major, fw.minor, fw.build),
                Some(&format!("{name}_build")),
            );
        }
    }
    if !p.allow_provisional_firmware && (report.current_version != report.committed_version || report.current_tcb != report.committed_tcb) {
        v.bad(
            ErrorCode::PolicyProvisionalFirmware,
            "committed firmware/TCB differs from current (uncommitted update; rollback possible)".into(),
            Some("committed_tcb"),
        );
    }
    if p.min_launch_mit_vector.is_some_and(|m| report.launch_mit_vector.unwrap_or(0) & m != m) {
        v.bad(ErrorCode::PolicyMitigationVector, "launch_mit_vector lacks required bits".into(), Some("launch_mit_vector"));
    }
    if p.min_current_mit_vector.is_some_and(|m| report.current_mit_vector.unwrap_or(0) & m != m) {
        v.bad(ErrorCode::PolicyMitigationVector, "current_mit_vector lacks required bits".into(), Some("current_mit_vector"));
    }

    // Identity pins.
    if let MeasurementPin::Allowlist(values) = &p.measurement {
        if !values.iter().any(|m| m == report.measurement()) {
            v.bad(
                ErrorCode::PolicyMeasurementMismatch,
                format!("measurement {} not in allowlist", hex(report.measurement())),
                Some("measurement"),
            );
        }
    }
    match &p.report_data {
        ReportDataPin::Exact(value) => v.pin(ErrorCode::PolicyReportDataMismatch, "report_data", Some(value), report.report_data()),
        ReportDataPin::Prefix(value) => {
            if value[..] != report.report_data()[..value.len()] {
                v.bad(ErrorCode::PolicyReportDataMismatch, format!("report_data does not start with {}", hex(value)), Some("report_data"));
            }
        }
        ReportDataPin::Any => {}
    }
    v.pin(ErrorCode::PolicyHostDataMismatch, "host_data", p.host_data.as_ref(), report.host_data());
    v.pin(ErrorCode::PolicyFamilyIdMismatch, "family_id", p.family_id.as_ref(), report.family_id());
    v.pin(ErrorCode::PolicyImageIdMismatch, "image_id", p.image_id.as_ref(), report.image_id());
    v.pin(ErrorCode::PolicyReportIdMismatch, "report_id", p.report_id.as_ref(), report.report_id());
    match &p.id_block {
        IdBlockPin::Forbid => {
            if report.signer_info.author_key_enabled {
                v.bad(ErrorCode::PolicyIdBlock, "author_key_en set but ID block forbidden".into(), Some("signer_info.author_key_en"));
            }
            if !is_zero(report.id_key_digest()) {
                v.bad(ErrorCode::PolicyIdBlock, "id_key_digest nonzero but ID block forbidden".into(), Some("id_key_digest"));
            }
            if !is_zero(report.author_key_digest()) {
                v.bad(ErrorCode::PolicyIdBlock, "author_key_digest nonzero but ID block forbidden".into(), Some("author_key_digest"));
            }
        }
        IdBlockPin::Pinned { id_key_digest, author_key_digest } => {
            v.pin(ErrorCode::PolicyIdBlock, "id_key_digest", Some(id_key_digest), report.id_key_digest());
            if let Some(ak) = author_key_digest {
                let want_author = !is_zero(ak); // all-zero pin means "no author key"
                if report.signer_info.author_key_enabled != want_author {
                    v.bad(
                        ErrorCode::PolicyIdBlock,
                        format!(
                            "author_key_en is {}, pinned author_key_digest implies {}",
                            report.signer_info.author_key_enabled as u8, want_author as u8
                        ),
                        Some("author_key_digest"),
                    );
                }
                v.pin(ErrorCode::PolicyIdBlock, "author_key_digest", Some(ak), report.author_key_digest());
            }
        }
        IdBlockPin::Any => {}
    }
    v.0
}

pub(crate) fn signing_key_policy_name(s: SigningKeyPolicy) -> &'static str {
    match s {
        SigningKeyPolicy::Vcek => "VCEK",
        SigningKeyPolicy::Vlek => "VLEK",
        SigningKeyPolicy::Any => "any",
    }
}

fn fw_at_least(fw: &FirmwareVersion, min: &FirmwareVersion) -> bool {
    (fw.major, fw.minor, fw.build) >= (min.major, min.minor, min.build)
}

fn fmt_tcb(t: &TcbVersion) -> String {
    format!(
        "bl={} tee={} snp={} ucode={}{}",
        t.bootloader,
        t.tee,
        t.snp,
        t.microcode,
        t.fmc.map_or(String::new(), |f| format!(" fmc={f}"))
    )
}

fn fmt_floor(t: &TcbFloor) -> String {
    let f = |x: Option<u8>| x.map_or("*".to_string(), |v| v.to_string());
    format!(
        "bl={} tee={} snp={} ucode={}{}",
        f(t.bootloader),
        f(t.tee),
        f(t.snp),
        f(t.microcode),
        t.fmc.map_or(String::new(), |f| format!(" fmc={f}"))
    )
}
