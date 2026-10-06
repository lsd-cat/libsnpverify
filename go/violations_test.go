package snpverify_test

// Cross-port violation vector: the cases in ts/test/violations.test.ts, compared against vectors/expected-violations.json.

import (
	"bytes"
	"testing"

	snp "github.com/lsd-cat/snpverify/go"
)

func TestMatchesCrossPortViolationVector(t *testing.T) {
	g := loadGenoa(t)
	base := with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.ASK, i.Endorsements.ARK = g.ask, g.ark })
	policy := func(edit func(p *snp.AppraisalPolicy)) snp.AppraisalInput {
		return with(base, func(i *snp.AppraisalInput) { edit(&i.Policy) })
	}
	evidence := func(ev []byte) snp.AppraisalInput { return with(base, func(i *snp.AppraisalInput) { i.Evidence = ev }) }
	endorsements := func(edit func(e *snp.Endorsements)) snp.AppraisalInput {
		return with(base, func(i *snp.AppraisalInput) { edit(&i.Endorsements) })
	}
	version6, hostRequested := bytes.Clone(g.report), bytes.Clone(g.report)
	version6[0] = 6
	copy(hostRequested[0x30:0x34], []byte{0xff, 0xff, 0xff, 0xff})
	oversized := make([]byte, 16*1024+1)
	copy(oversized, g.vcek)

	cases := []struct {
		name  string
		input snp.AppraisalInput
	}{
		{"flipped-signature", evidence(flip(g.report, 0x2a0))},
		{"flipped-reported-tcb", evidence(flip(g.report, 0x180))},
		{"flipped-chip-id", evidence(flip(g.report, 0x1a0))},
		{"trailing-byte", evidence(append(bytes.Clone(g.report), 0))},
		{"version-6", evidence(version6)},
		{"host-requested", evidence(hostRequested)},
		{"reserved-byte", evidence(flip(g.report, 0x4c))},
		{"flipped-vcek", endorsements(func(e *snp.Endorsements) { e.VCEK = flip(g.vcek, len(g.vcek)-1) })},
		{"untrusted-root", endorsements(func(e *snp.Endorsements) { e.ARK, e.ASK = g.ask, g.ark })},
		{"expired", with(base, func(i *snp.AppraisalInput) { i.Now = 2100000000 })},
		{"not-yet-valid", with(base, func(i *snp.AppraisalInput) { i.Now = 1600000000 })},
		{"flipped-crl", endorsements(func(e *snp.Endorsements) { e.CRL = flip(g.crl, len(g.crl)-1) })},
		{"crl-absent", endorsements(func(e *snp.Endorsements) { e.CRL = nil })},
		{"measurement-mismatch", policy(func(p *snp.AppraisalPolicy) { p.Measurement = snp.MeasurementAllowlist{make([]byte, 48)} })},
		{"report-data-prefix-mismatch", policy(func(p *snp.AppraisalPolicy) { p.ReportData = snp.ReportDataPrefix(make([]byte, 32)) })},
		{"chip-id-not-allowed", policy(func(p *snp.AppraisalPolicy) { p.ChipIDs = [][]byte{make([]byte, 64)} })},
		{"product-not-allowed", policy(func(p *snp.AppraisalPolicy) { p.Products = []snp.Product{snp.Turin} })},
		{"several-policy-violations", policy(func(p *snp.AppraisalPolicy) {
			p.VMPL, p.MinGuestSVN, p.GuestPolicy = 1, 5, snp.GuestPolicyRules{SMT: snp.BitForbidden}
		})},
		{"tcb-floor", policy(func(p *snp.AppraisalPolicy) { p.MinTCB = map[snp.Product]snp.TCBFloor{snp.Genoa: {SNP: new(24)}} })},
		{"oversized-vcek", endorsements(func(e *snp.Endorsements) { e.VCEK = oversized })},
	}

	actual := snp.J{}
	for _, c := range cases {
		_, err := g.v.Appraise(c.input)
		e := mustFail(t, err, c.name)
		var violations []snp.J
		for _, x := range e.Violations {
			j := snp.J{"code": x.Code, "message": x.Message}
			if x.Field != "" {
				j["field"] = x.Field
			}
			violations = append(violations, j)
		}
		actual[c.name] = snp.J{"stage": e.Stage, "violations": violations}
	}
	var expected any
	readJSON(t, "expected-violations.json", &expected)
	jsonEqual(t, expected, actual)
}
