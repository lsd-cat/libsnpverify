//! Mutation and API tests on the real Genoa fixture (vectors/attestation-sev/200) and the KDS CRL snapshot (vectors/kds). Mirrors ts/test/mutation.test.ts.

mod common;

use std::collections::BTreeMap;

use common::*;
use snpverify::*;

struct Genoa {
    report: Vec<u8>,
    vcek: Vec<u8>,
    crl: Vec<u8>,
    ask: Vec<u8>,
    ark: Vec<u8>,
    now: i64,
    policy: AppraisalPolicy,
    base: AppraisalInput,
    v: SnpVerifier,
}

fn genoa() -> Genoa {
    let (i, _) = fixture("200-real-sev-snp-happy");
    let crl = read("kds/Genoa.crl");
    let mut chain = pem_to_der(&read_text("kds/Genoa.cert_chain.pem"));
    let (ask, ark) = (chain.remove(0), chain.remove(0));
    let now = this_update(&crl) + 60; // inside the CRL snapshot's window and the VCEK's 7-year window
    let report = i.evidence;
    let policy = AppraisalPolicy {
        products: Some(vec![Product::Genoa]),
        require_crl: Some(true),
        ..AppraisalPolicy::new(MeasurementPin::Allowlist(vec![report[0x90..0xc0].to_vec()]))
    };
    let vcek = i.endorsements.vcek;
    let base = AppraisalInput {
        evidence: report.clone(),
        endorsements: Endorsements {
            vcek: vcek.clone(),
            crl: Some(crl.clone()),
            ..Default::default()
        },
        now,
        policy: policy.clone(),
    };
    Genoa {
        report,
        vcek,
        crl,
        ask,
        ark,
        now,
        policy,
        base,
        v: SnpVerifier::default(),
    }
}

impl Genoa {
    fn expect_fail(&self, i: AppraisalInput, stage: Stage, code: ErrorCode, what: &str) {
        let e = expect_err(self.v.appraise(&i), what);
        assert_eq!(e.stage, stage, "{what}: stage");
        assert_eq!(e.violations[0].code, code, "{what}: {:?}", e.violations);
    }

    fn ok(&self, i: AppraisalInput) -> AttestationResult {
        expect_ok(self.v.appraise(&i))
    }

    fn with_evidence(&self, evidence: Vec<u8>) -> AppraisalInput {
        AppraisalInput { evidence, ..self.base.clone() }
    }

    fn with_endorsements(&self, endorsements: Endorsements) -> AppraisalInput {
        AppraisalInput { endorsements, ..self.base.clone() }
    }

    fn with_policy(&self, policy: AppraisalPolicy) -> AppraisalInput {
        AppraisalInput { policy, ..self.base.clone() }
    }

    fn with_chain(&self) -> AppraisalInput {
        self.with_endorsements(Endorsements {
            ask: Some(self.ask.clone()),
            ark: Some(self.ark.clone()),
            ..self.base.endorsements.clone()
        })
    }
}

#[test]
fn real_genoa_verifies() {
    let g = genoa();
    let a = g.ok(g.with_chain());
    assert_eq!(a.platform.product, Product::Genoa);
    assert_eq!(a.evidence.report_version, 3);
    assert_eq!(
        a.platform.tcb.reported,
        TcbVersion {
            bootloader: 10,
            tee: 0,
            snp: 23,
            microcode: 84,
            fmc: None
        }
    );
    assert_eq!(a.endorsements.endorsement_key.tcb, a.platform.tcb.reported);
    assert!(a.endorsements.crl.is_some());
    assert_eq!(a.evidence.report_sha256.len(), 32);
    assert_eq!(a.appraisal_policy.vmpl, Some(0));
    assert_eq!(a.appraised_at, g.now);
    let j = to_json(&a);
    assert_eq!(j["identity"]["chipId"].as_str().unwrap().len(), 128);
    serde_json::to_string(&j).unwrap(); // must be serialisable
}

#[test]
fn embedded_roots_equal_kds_snapshot() {
    let g = genoa();
    g.ok(g.base.clone());
}

#[test]
fn flipped_signature() {
    let g = genoa();
    g.expect_fail(g.with_evidence(flip(&g.report, 0x2a0)), Stage::Signature, ErrorCode::ReportSignatureInvalid, "sig");
}

#[test]
fn flipped_measurement() {
    let g = genoa();
    g.expect_fail(g.with_evidence(flip(&g.report, 0x90)), Stage::Signature, ErrorCode::ReportSignatureInvalid, "measurement");
}

#[test]
fn flipped_reported_tcb() {
    let g = genoa();
    g.expect_fail(g.with_evidence(flip(&g.report, 0x180)), Stage::Bind, ErrorCode::VcekTcbMismatch, "tcb");
}

#[test]
fn flipped_chip_id() {
    let g = genoa();
    g.expect_fail(g.with_evidence(flip(&g.report, 0x1a0)), Stage::Bind, ErrorCode::VcekHwidMismatch, "chip");
}

#[test]
fn trailing_byte() {
    let g = genoa();
    g.expect_fail(g.with_evidence([g.report.clone(), vec![0]].concat()), Stage::Parse, ErrorCode::ReportTruncated, "trailing");
}

#[test]
fn version_6() {
    let g = genoa();
    let mut r = g.report.clone();
    r[0] = 6;
    g.expect_fail(g.with_evidence(r), Stage::Parse, ErrorCode::ReportVersionUnsupported, "v6");
}

#[test]
fn host_requested() {
    let g = genoa();
    let mut r = g.report.clone();
    r[0x30..0x34].fill(0xff);
    g.expect_fail(g.with_evidence(r), Stage::Parse, ErrorCode::ReportHostRequested, "host");
}

#[test]
fn reserved_byte_set() {
    let g = genoa();
    g.expect_fail(g.with_evidence(flip(&g.report, 0x4c)), Stage::Parse, ErrorCode::ReportMalformed, "mbz");
}

#[test]
fn flipped_vcek() {
    let g = genoa();
    g.expect_fail(
        g.with_endorsements(Endorsements {
            vcek: flip(&g.vcek, g.vcek.len() - 1),
            ..g.base.endorsements.clone()
        }),
        Stage::Chain,
        ErrorCode::ChainSignatureInvalid,
        "vcek",
    );
}

#[test]
fn untrusted_root() {
    let g = genoa();
    g.expect_fail(
        g.with_endorsements(Endorsements {
            ark: Some(g.ask.clone()),
            ask: Some(g.ark.clone()),
            ..g.base.endorsements.clone()
        }),
        Stage::Chain,
        ErrorCode::ArkUntrusted,
        "swap",
    );
}

#[test]
fn expired() {
    let g = genoa();
    g.expect_fail(AppraisalInput { now: 2100000000, ..g.base.clone() }, Stage::Chain, ErrorCode::CertExpired, "expired");
}

#[test]
fn not_yet_valid() {
    let g = genoa();
    g.expect_fail(AppraisalInput { now: 1600000000, ..g.base.clone() }, Stage::Chain, ErrorCode::CertNotYetValid, "early");
}

#[test]
fn flipped_crl() {
    let g = genoa();
    g.expect_fail(
        g.with_endorsements(Endorsements {
            crl: Some(flip(&g.crl, g.crl.len() - 1)),
            ..g.base.endorsements.clone()
        }),
        Stage::Chain,
        ErrorCode::CrlInvalid,
        "crl",
    );
}

#[test]
fn crl_required_but_absent() {
    let g = genoa();
    g.expect_fail(
        g.with_endorsements(Endorsements {
            crl: None,
            ..g.base.endorsements.clone()
        }),
        Stage::Policy,
        ErrorCode::PolicyInvalid,
        "nocrl",
    );
}

#[test]
fn measurement_mismatch() {
    let g = genoa();
    g.expect_fail(
        g.with_policy(AppraisalPolicy {
            measurement: MeasurementPin::Allowlist(vec![vec![0; 48]]),
            ..g.policy.clone()
        }),
        Stage::Policy,
        ErrorCode::PolicyMeasurementMismatch,
        "meas",
    );
}

#[test]
fn report_data_prefix() {
    let g = genoa();
    g.ok(g.with_policy(AppraisalPolicy {
        report_data: Some(ReportDataPin::Prefix(g.report[0x50..0x70].to_vec())),
        ..g.policy.clone()
    }));
    g.expect_fail(
        g.with_policy(AppraisalPolicy {
            report_data: Some(ReportDataPin::Prefix(vec![0; 32])),
            ..g.policy.clone()
        }),
        Stage::Policy,
        ErrorCode::PolicyReportDataMismatch,
        "prefix",
    );
}

#[test]
fn chip_id_allowlist() {
    let g = genoa();
    g.ok(g.with_policy(AppraisalPolicy {
        chip_ids: Some(vec![g.report[0x1a0..0x1e0].to_vec()]),
        ..g.policy.clone()
    }));
    g.expect_fail(
        g.with_policy(AppraisalPolicy {
            chip_ids: Some(vec![vec![0; 64]]),
            ..g.policy.clone()
        }),
        Stage::Policy,
        ErrorCode::PolicyChipIdNotAllowed,
        "chipIds",
    );
}

#[test]
fn report_id_and_product() {
    let g = genoa();
    g.ok(g.with_policy(AppraisalPolicy {
        report_id: Some(g.report[0x140..0x160].to_vec()),
        ..g.policy.clone()
    }));
    g.expect_fail(
        g.with_policy(AppraisalPolicy {
            products: Some(vec![Product::Turin]),
            ..g.policy.clone()
        }),
        Stage::Policy,
        ErrorCode::PolicyProductNotAllowed,
        "product",
    );
}

#[test]
fn all_violations_reported() {
    let g = genoa();
    let policy = AppraisalPolicy {
        vmpl: Some(1),
        min_guest_svn: Some(5),
        guest_policy: Some(GuestPolicyRules {
            smt: Some(Bit::Forbidden),
            ..Default::default()
        }),
        ..g.policy.clone()
    };
    let e = expect_err(g.v.appraise(&g.with_policy(policy)), "several");
    assert_eq!(e.stage, Stage::Policy);
    let mut codes: Vec<&str> = e.violations.iter().map(|x| x.code.as_str()).collect();
    codes.sort();
    assert_eq!(codes, ["POLICY_GUEST_POLICY", "POLICY_GUEST_SVN", "POLICY_VMPL"]);
}

#[test]
fn malformed_policy() {
    let g = genoa();
    let e = expect_err(g.v.appraise(&g.with_policy(AppraisalPolicy::new(MeasurementPin::Allowlist(vec![vec![0; 47]])))), "malformed");
    assert_eq!(e.violations[0].code, ErrorCode::PolicyInvalid);
}

#[test]
fn tcb_floor_per_product() {
    let g = genoa();
    let floor = |f: TcbFloor| AppraisalPolicy {
        min_tcb: Some(BTreeMap::from([(Product::Genoa, f)])),
        ..g.policy.clone()
    };
    g.ok(g.with_policy(floor(TcbFloor {
        snp: Some(23),
        microcode: Some(84),
        ..Default::default()
    })));
    g.expect_fail(
        g.with_policy(floor(TcbFloor { snp: Some(24), ..Default::default() })),
        Stage::Policy,
        ErrorCode::PolicyTcbOutOfDate,
        "floor",
    );
}

#[test]
fn matches_cross_port_golden() {
    let g = genoa();
    let mut i = g.with_chain();
    i.policy.report_data = Some(ReportDataPin::Prefix(g.report[0x50..0x60].to_vec()));
    i.policy.min_tcb = Some(BTreeMap::from([(Product::Genoa, TcbFloor { snp: Some(20), ..Default::default() })]));
    let a = g.ok(i);
    assert_eq!(json("golden/real-genoa.json"), to_json(&a));
}

#[test]
fn parsed_records_cannot_be_altered_between_stages() {
    let g = genoa();
    let rep = parse_report(&g.report).unwrap();
    let mut m = rep.measurement().to_vec(); // mutate a copy; the parsed record only hands out borrows
    m[0] ^= 1;
    assert_eq!(rep.measurement(), &g.report[0x90..0xc0]);
    let ch =
        g.v.verify_chain(&ChainInput {
            leaf: g.vcek.clone(),
            intermediate: Some(g.ask.clone()),
            root: Some(g.ark.clone()),
            crl: Some(g.crl.clone()),
            now: g.now,
        })
        .unwrap();
    let mut spki = ch.leaf.cert.spki().to_vec();
    spki[30] ^= 1;
    assert!(g.v.verify_report_signature(&rep, &ch).is_ok());
    assert!(bind_endorsement(&rep, &ch.leaf).is_ok());
}

#[test]
fn extensions_and_crl_serials_do_not_alias_caller_memory() {
    let g = genoa();
    let (mut my_ark, mut my_crl) = (g.ark.clone(), g.crl.clone());
    let cert = parse_certificate(&my_ark).unwrap();
    let parsed = parse_crl(&my_crl).unwrap();
    let ku = cert.extensions()["2.5.29.15"].value().to_vec();
    let n = parsed.revoked_serials().len();
    my_ark.fill(0); // caller mutates its own buffers after parsing
    my_crl.fill(0);
    assert_eq!(cert.extensions()["2.5.29.15"].value(), &ku[..]);
    assert_eq!(parsed.revoked_serials().len(), n);
    assert!(g
        .v
        .verify_chain(&ChainInput {
            leaf: g.vcek.clone(),
            intermediate: Some(g.ask.clone()),
            root: Some(g.ark.clone()),
            crl: Some(g.crl.clone()),
            now: g.now
        })
        .is_ok());
}

#[test]
fn oversized_collateral_rejected() {
    let g = genoa();
    let policy = AppraisalPolicy {
        products: Some(vec![Product::Genoa]),
        ..AppraisalPolicy::new(MeasurementPin::Any)
    };
    let mut big = vec![0; 16 * 1024 + 1];
    big[..g.vcek.len()].copy_from_slice(&g.vcek);
    let r1 = expect_err(
        g.v.appraise(&AppraisalInput {
            endorsements: Endorsements {
                vcek: big,
                crl: Some(g.crl.clone()),
                ..Default::default()
            },
            policy: policy.clone(),
            ..g.base.clone()
        }),
        "bigcert",
    );
    assert_eq!(r1.violations[0].code, ErrorCode::CertMalformed);
    let mut big_crl = vec![0; 1024 * 1024 + 1];
    big_crl[..g.crl.len()].copy_from_slice(&g.crl);
    let r2 = expect_err(
        g.v.appraise(&AppraisalInput {
            endorsements: Endorsements {
                vcek: g.vcek.clone(),
                crl: Some(big_crl),
                ..Default::default()
            },
            policy,
            ..g.base.clone()
        }),
        "bigcrl",
    );
    assert_eq!(r2.violations[0].code, ErrorCode::CrlInvalid);
}
