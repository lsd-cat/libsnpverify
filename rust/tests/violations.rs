//! Cross-port violation vector: the cases in ts/test/violations.test.ts, compared against vectors/expected-violations.json.

mod common;

use std::collections::BTreeMap;

use common::*;
use serde_json::{json, Map, Value};
use snpverify::*;

#[test]
fn matches_cross_port_violation_vector() {
    let (i, _) = fixture("200-real-sev-snp-happy");
    let (report, vcek) = (i.evidence, i.endorsements.vcek);
    let crl = read("kds/Genoa.crl");
    let chain = pem_to_der(&read_text("kds/Genoa.cert_chain.pem"));
    let now = this_update(&crl) + 60;
    let policy = AppraisalPolicy {
        products: Some(vec![Product::Genoa]),
        require_crl: Some(true),
        ..AppraisalPolicy::new(MeasurementPin::Allowlist(vec![report[0x90..0xc0].to_vec()]))
    };
    let base = AppraisalInput {
        evidence: report.clone(),
        endorsements: Endorsements {
            vcek: vcek.clone(),
            ask: Some(chain[0].clone()),
            ark: Some(chain[1].clone()),
            crl: Some(crl.clone()),
        },
        now,
        policy: policy.clone(),
    };
    let evidence = |e: Vec<u8>| AppraisalInput { evidence: e, ..base.clone() };
    let endorsements = |e: Endorsements| AppraisalInput { endorsements: e, ..base.clone() };
    let with_policy = |p: AppraisalPolicy| AppraisalInput { policy: p, ..base.clone() };
    let mut version6 = report.clone();
    version6[0] = 6;
    let mut host_requested = report.clone();
    host_requested[0x30..0x34].fill(0xff);
    let mut oversized = vec![0; 16 * 1024 + 1];
    oversized[..vcek.len()].copy_from_slice(&vcek);

    let cases: Vec<(&str, AppraisalInput)> = vec![
        ("flipped-signature", evidence(flip(&report, 0x2a0))),
        ("flipped-reported-tcb", evidence(flip(&report, 0x180))),
        ("flipped-chip-id", evidence(flip(&report, 0x1a0))),
        ("trailing-byte", evidence([report.clone(), vec![0]].concat())),
        ("version-6", evidence(version6)),
        ("host-requested", evidence(host_requested)),
        ("reserved-byte", evidence(flip(&report, 0x4c))),
        (
            "flipped-vcek",
            endorsements(Endorsements {
                vcek: flip(&vcek, vcek.len() - 1),
                ..base.endorsements.clone()
            }),
        ),
        (
            "untrusted-root",
            endorsements(Endorsements {
                ark: Some(chain[0].clone()),
                ask: Some(chain[1].clone()),
                ..base.endorsements.clone()
            }),
        ),
        ("expired", AppraisalInput { now: 2100000000, ..base.clone() }),
        ("not-yet-valid", AppraisalInput { now: 1600000000, ..base.clone() }),
        (
            "flipped-crl",
            endorsements(Endorsements {
                crl: Some(flip(&crl, crl.len() - 1)),
                ..base.endorsements.clone()
            }),
        ),
        (
            "crl-absent",
            endorsements(Endorsements {
                crl: None,
                ..base.endorsements.clone()
            }),
        ),
        (
            "measurement-mismatch",
            with_policy(AppraisalPolicy {
                measurement: MeasurementPin::Allowlist(vec![vec![0; 48]]),
                ..policy.clone()
            }),
        ),
        (
            "report-data-prefix-mismatch",
            with_policy(AppraisalPolicy {
                report_data: Some(ReportDataPin::Prefix(vec![0; 32])),
                ..policy.clone()
            }),
        ),
        (
            "chip-id-not-allowed",
            with_policy(AppraisalPolicy {
                chip_ids: Some(vec![vec![0; 64]]),
                ..policy.clone()
            }),
        ),
        (
            "product-not-allowed",
            with_policy(AppraisalPolicy {
                products: Some(vec![Product::Turin]),
                ..policy.clone()
            }),
        ),
        (
            "several-policy-violations",
            with_policy(AppraisalPolicy {
                vmpl: Some(1),
                min_guest_svn: Some(5),
                guest_policy: Some(GuestPolicyRules {
                    smt: Some(Bit::Forbidden),
                    ..Default::default()
                }),
                ..policy.clone()
            }),
        ),
        (
            "tcb-floor",
            with_policy(AppraisalPolicy {
                min_tcb: Some(BTreeMap::from([(Product::Genoa, TcbFloor { snp: Some(24), ..Default::default() })])),
                ..policy.clone()
            }),
        ),
        (
            "oversized-vcek",
            endorsements(Endorsements {
                vcek: oversized,
                ..base.endorsements.clone()
            }),
        ),
    ];

    let v = SnpVerifier::default();
    let mut actual = Map::new();
    for (name, input) in cases {
        let e = expect_err(v.appraise(&input), name);
        let violations: Vec<Value> = e
            .violations
            .iter()
            .map(|x| {
                let mut j = json!({"code": x.code.as_str(), "message": x.message});
                if let Some(f) = &x.field {
                    j["field"] = json!(f);
                }
                j
            })
            .collect();
        actual.insert(name.to_string(), json!({"stage": e.stage.as_str(), "violations": violations}));
    }
    assert_eq!(json("expected-violations.json"), Value::Object(actual));
}
