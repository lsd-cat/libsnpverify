package snpverify_test

// Cross-port policy vector: JSON policies with their resolved form, or the POLICY_INVALID message they produce (vectors/policy.json).

import (
	"encoding/json"
	"errors"
	"testing"

	snp "github.com/lsd-cat/snpverify/go"
)

func TestMatchesCrossPortPolicyVector(t *testing.T) {
	var cases map[string]struct {
		Policy   json.RawMessage `json:"policy"`
		Resolved json.RawMessage `json:"resolved"`
		Error    string          `json:"error"`
	}
	readJSON(t, "policy.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			text := []byte(c.Policy)
			var asString string
			if json.Unmarshal(c.Policy, &asString) == nil { // the document is given as text
				text = []byte(asString)
			}
			policy, err := snp.AppraisalPolicyFromJSON(text)
			if c.Error != "" {
				var v *snp.Violation
				if !errors.As(err, &v) || v.Code != snp.PolicyInvalid || v.Message != c.Error {
					t.Fatalf("want POLICY_INVALID %q, got %v", c.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := snp.ResolveAppraisalPolicy(policy)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(c.Resolved, &want); err != nil {
				t.Fatal(err)
			}
			jsonEqual(t, want, snp.AppraisalPolicyToJSON(resolved))
		})
	}
}
