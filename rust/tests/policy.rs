//! Cross-port policy vector: JSON policies with their resolved form, or the POLICY_INVALID message they produce (vectors/policy.json).

mod common;

use common::*;
use serde_json::Value;
use snpverify::*;

#[test]
fn matches_cross_port_policy_vector() {
    let cases = json("policy.json");
    let cases = cases.as_object().unwrap();
    assert!(!cases.is_empty());
    for (name, c) in cases {
        let policy = match &c["policy"] {
            Value::String(text) => appraisal_policy_from_json(text), // the document is given as text
            value => appraisal_policy_from_value(value),
        };
        if let Some(error) = c.get("error").and_then(Value::as_str) {
            let e = policy.err().unwrap_or_else(|| panic!("{name}: expected POLICY_INVALID"));
            assert_eq!((e.code, e.message.as_str()), (ErrorCode::PolicyInvalid, error), "{name}");
            continue;
        }
        let resolved = resolve_appraisal_policy(&policy.unwrap_or_else(|e| panic!("{name}: {e}"))).unwrap();
        assert_eq!(c["resolved"], appraisal_policy_to_json(&resolved), "{name}");
    }
}
