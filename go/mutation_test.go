package snpverify_test

// Mutation and API tests on the real Genoa fixture (vectors/attestation-sev/200) and the KDS CRL snapshot (vectors/kds). Mirrors ts/test/mutation.test.ts.

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	snp "github.com/lsd-cat/snpverify/go"
)

type genoa struct {
	report, vcek, crl, ask, ark []byte
	now                         int64
	policy                      snp.AppraisalPolicy
	base                        snp.AppraisalInput
	v                           *snp.Verifier
}

func loadGenoa(t *testing.T) genoa {
	t.Helper()
	i, _ := fixture(t, "200-real-sev-snp-happy")
	g := genoa{report: i.Evidence, vcek: i.Endorsements.VCEK, crl: readFile(t, "kds/Genoa.crl")}
	chain := snp.PEMToDER(string(readFile(t, "kds/Genoa.cert_chain.pem")))
	g.ask, g.ark = chain[0], chain[1]
	g.now = thisUpdate(t, g.crl) + 60 // inside the CRL snapshot's window and the VCEK's 7-year window
	g.policy = snp.AppraisalPolicy{Measurement: snp.MeasurementAllowlist{g.report[0x90:0xc0]}, Products: []snp.Product{snp.Genoa}, RequireCRL: true}
	g.base = snp.AppraisalInput{Evidence: g.report, Endorsements: snp.Endorsements{VCEK: g.vcek, CRL: g.crl}, Now: g.now, Policy: g.policy}
	g.v = snp.NewVerifier(snp.VerifierOptions{})
	return g
}

func (g genoa) expectFail(t *testing.T, i snp.AppraisalInput, stage snp.Stage, code snp.ErrorCode, what string) {
	t.Helper()
	_, err := g.v.Appraise(i)
	e := mustFail(t, err, what)
	if e.Stage != stage {
		t.Fatalf("%s: stage %s, want %s", what, e.Stage, stage)
	}
	if e.Violations[0].Code != code {
		t.Fatalf("%s: %v, want %s", what, e.Violations, code)
	}
}

func (g genoa) ok(t *testing.T, i snp.AppraisalInput) *snp.AttestationResult {
	t.Helper()
	r, err := g.v.Appraise(i)
	return mustOK(t, r, err)
}

func (g genoa) withPolicy(edit func(p *snp.AppraisalPolicy)) snp.AppraisalInput {
	return with(g.base, func(i *snp.AppraisalInput) { edit(&i.Policy) })
}

func TestRealGenoaVerifies(t *testing.T) {
	g := loadGenoa(t)
	a := g.ok(t, with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.ASK, i.Endorsements.ARK = g.ask, g.ark }))
	if a.Platform.Product != snp.Genoa || a.Evidence.ReportVersion != 3 {
		t.Fatalf("product %s version %d", a.Platform.Product, a.Evidence.ReportVersion)
	}
	if want := (snp.TCBVersion{Bootloader: 10, TEE: 0, SNP: 23, Microcode: 84}); !reflect.DeepEqual(a.Platform.TCB.Reported, want) {
		t.Fatalf("reported tcb %+v", a.Platform.TCB.Reported)
	}
	if !reflect.DeepEqual(a.Endorsements.EndorsementKey.TCB, a.Platform.TCB.Reported) {
		t.Fatal("endorsement key TCB != reported")
	}
	if a.Endorsements.CRL == nil || a.Endorsements.CRL.RevokedCount < 0 {
		t.Fatal("crl info")
	}
	if len(a.Evidence.ReportSHA256) != 32 || a.AppraisalPolicy.VMPL != 0 || a.AppraisedAt != g.now {
		t.Fatal("result fields")
	}
	j := snp.ToJSON(a)
	if chip, _ := j["identity"].(snp.J)["chipId"].(string); len(chip) != 128 {
		t.Fatalf("chipId %q", chip)
	}
	if _, err := json.Marshal(j); err != nil { // must be serialisable
		t.Fatal(err)
	}
}

func TestEmbeddedRootsEqualKdsSnapshot(t *testing.T) {
	g := loadGenoa(t)
	g.ok(t, g.base)
}

func TestFlippedSignature(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = flip(g.report, 0x2a0) }), snp.StageSignature, snp.ReportSignatureInvalid, "sig")
}

func TestFlippedMeasurement(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = flip(g.report, 0x90) }), snp.StageSignature, snp.ReportSignatureInvalid, "measurement")
}

func TestFlippedReportedTcb(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = flip(g.report, 0x180) }), snp.StageBind, snp.VCEKTCBMismatch, "tcb")
}

func TestFlippedChipId(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = flip(g.report, 0x1a0) }), snp.StageBind, snp.VCEKHWIDMismatch, "chip")
}

func TestTrailingByte(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = append(bytes.Clone(g.report), 0) }), snp.StageParse, snp.ReportTruncated, "trailing")
}

func TestVersion6(t *testing.T) {
	g := loadGenoa(t)
	r := bytes.Clone(g.report)
	r[0] = 6
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = r }), snp.StageParse, snp.ReportVersionUnsupported, "v6")
}

func TestHostRequested(t *testing.T) {
	g := loadGenoa(t)
	r := bytes.Clone(g.report)
	copy(r[0x30:0x34], []byte{0xff, 0xff, 0xff, 0xff})
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = r }), snp.StageParse, snp.ReportHostRequested, "host")
}

func TestReservedByteSet(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Evidence = flip(g.report, 0x4c) }), snp.StageParse, snp.ReportMalformed, "mbz")
}

func TestFlippedVcek(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.VCEK = flip(g.vcek, len(g.vcek)-1) }), snp.StageChain, snp.ChainSignatureInvalid, "vcek")
}

func TestUntrustedRoot(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.ARK, i.Endorsements.ASK = g.ask, g.ark }), snp.StageChain, snp.ARKUntrusted, "swap")
}

func TestExpired(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Now = 2100000000 }), snp.StageChain, snp.CertExpired, "expired")
}

func TestNotYetValid(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Now = 1600000000 }), snp.StageChain, snp.CertNotYetValid, "early")
}

func TestFlippedCrl(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.CRL = flip(g.crl, len(g.crl)-1) }), snp.StageChain, snp.CRLInvalid, "crl")
}

func TestCrlRequiredButAbsent(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, with(g.base, func(i *snp.AppraisalInput) { i.Endorsements.CRL = nil }), snp.StagePolicy, snp.PolicyInvalid, "nocrl")
}

func TestMeasurementMismatch(t *testing.T) {
	g := loadGenoa(t)
	g.expectFail(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.Measurement = snp.MeasurementAllowlist{make([]byte, 48)} }), snp.StagePolicy, snp.PolicyMeasurementMismatch, "meas")
}

func TestReportDataPrefix(t *testing.T) {
	g := loadGenoa(t)
	g.ok(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.ReportData = snp.ReportDataPrefix(g.report[0x50:0x70]) }))
	g.expectFail(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.ReportData = snp.ReportDataPrefix(make([]byte, 32)) }), snp.StagePolicy, snp.PolicyReportDataMismatch, "prefix")
}

func TestChipIdAllowlist(t *testing.T) {
	g := loadGenoa(t)
	g.ok(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.ChipIDs = [][]byte{g.report[0x1a0:0x1e0]} }))
	g.expectFail(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.ChipIDs = [][]byte{make([]byte, 64)} }), snp.StagePolicy, snp.PolicyChipIDNotAllowed, "chipIds")
}

func TestReportIdAndProduct(t *testing.T) {
	g := loadGenoa(t)
	g.ok(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.ReportID = g.report[0x140:0x160] }))
	g.expectFail(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.Products = []snp.Product{snp.Turin} }), snp.StagePolicy, snp.PolicyProductNotAllowed, "product")
}

func TestAllViolationsReported(t *testing.T) {
	g := loadGenoa(t)
	_, err := g.v.Appraise(g.withPolicy(func(p *snp.AppraisalPolicy) {
		p.VMPL, p.MinGuestSVN, p.GuestPolicy = 1, 5, snp.GuestPolicyRules{SMT: snp.BitForbidden}
	}))
	e := mustFail(t, err, "several")
	if e.Stage != snp.StagePolicy {
		t.Fatal(e.Stage)
	}
	var codes []string
	for _, x := range e.Violations {
		codes = append(codes, string(x.Code))
	}
	sort.Strings(codes)
	if !reflect.DeepEqual(codes, []string{"POLICY_GUEST_POLICY", "POLICY_GUEST_SVN", "POLICY_VMPL"}) {
		t.Fatal(codes)
	}
}

func TestMalformedPolicy(t *testing.T) {
	g := loadGenoa(t)
	_, err := g.v.Appraise(with(g.base, func(i *snp.AppraisalInput) {
		i.Policy = snp.AppraisalPolicy{Measurement: snp.MeasurementAllowlist{make([]byte, 47)}}
	}))
	if e := mustFail(t, err, "malformed"); e.Violations[0].Code != snp.PolicyInvalid {
		t.Fatal(e.Violations)
	}
}

func TestTcbFloorPerProduct(t *testing.T) {
	g := loadGenoa(t)
	g.ok(t, g.withPolicy(func(p *snp.AppraisalPolicy) {
		p.MinTCB = map[snp.Product]snp.TCBFloor{snp.Genoa: {SNP: new(23), Microcode: new(84)}}
	}))
	g.expectFail(t, g.withPolicy(func(p *snp.AppraisalPolicy) { p.MinTCB = map[snp.Product]snp.TCBFloor{snp.Genoa: {SNP: new(24)}} }), snp.StagePolicy, snp.PolicyTCBOutOfDate, "floor")
}

func TestMatchesCrossPortGolden(t *testing.T) {
	g := loadGenoa(t)
	a := g.ok(t, with(g.base, func(i *snp.AppraisalInput) {
		i.Endorsements.ASK, i.Endorsements.ARK = g.ask, g.ark
		i.Policy.ReportData = snp.ReportDataPrefix(g.report[0x50:0x60])
		i.Policy.MinTCB = map[snp.Product]snp.TCBFloor{snp.Genoa: {SNP: new(20)}}
	}))
	var golden any
	readJSON(t, "golden/real-genoa.json", &golden)
	jsonEqual(t, golden, snp.ToJSON(a))
}

func TestParsedRecordsCannotBeAlteredBetweenStages(t *testing.T) {
	g := loadGenoa(t)
	rep, err := snp.ParseReport(g.report)
	if err != nil {
		t.Fatal(err)
	}
	rep.Measurement()[0] ^= 1 // mutate a returned copy
	if !bytes.Equal(rep.Measurement(), g.report[0x90:0xc0]) {
		t.Fatal("measurement altered")
	}
	ch, err := g.v.VerifyChain(snp.ChainInput{Leaf: g.vcek, Intermediate: g.ask, Root: g.ark, CRL: g.crl, Now: g.now})
	if err != nil {
		t.Fatal(err)
	}
	ch.Leaf.Cert.SPKI()[30] ^= 1 // returned copy; the chain's key is untouched
	ch.Leaf.HWID()[0] ^= 1
	if err := g.v.VerifyReportSignature(rep, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := snp.BindEndorsement(rep, ch.Leaf); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionsAndCrlSerialsDoNotAliasCallerMemory(t *testing.T) {
	g := loadGenoa(t)
	myArk, myCrl := bytes.Clone(g.ark), bytes.Clone(g.crl)
	cert, err := snp.ParseCertificate(myArk)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := snp.ParseCRL(myCrl)
	if err != nil {
		t.Fatal(err)
	}
	ku := cert.Extensions()["2.5.29.15"].Value()
	clear(myArk) // caller mutates its own buffers after parsing
	clear(myCrl)
	cert.Extensions()["2.5.29.15"].Value()[0] = 0 // and a returned copy
	if !bytes.Equal(cert.Extensions()["2.5.29.15"].Value(), ku) {
		t.Fatal("keyUsage altered")
	}
	n := len(parsed.RevokedSerials())
	if n > 0 {
		parsed.RevokedSerials()[0][0] ^= 1
	}
	if len(parsed.RevokedSerials()) != n {
		t.Fatal("serials altered")
	}
	if _, err := g.v.VerifyChain(snp.ChainInput{Leaf: g.vcek, Intermediate: g.ask, Root: g.ark, CRL: g.crl, Now: g.now}); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionMapIsACopy(t *testing.T) {
	g := loadGenoa(t)
	cert, err := snp.ParseCertificate(g.ark)
	if err != nil {
		t.Fatal(err)
	}
	delete(cert.Extensions(), "2.5.29.15")
	if _, ok := cert.Extensions()["2.5.29.15"]; !ok {
		t.Fatal("extension removed")
	}
	crl, err := snp.ParseCRL(g.crl)
	if err != nil {
		t.Fatal(err)
	}
	n := len(crl.Extensions())
	clear(crl.Extensions())
	if len(crl.Extensions()) != n {
		t.Fatal("CRL extensions cleared")
	}
}

func TestOversizedCollateralRejected(t *testing.T) {
	g := loadGenoa(t)
	policy := snp.AppraisalPolicy{Measurement: snp.MeasurementAny{}, Products: []snp.Product{snp.Genoa}}
	big := make([]byte, 16*1024+1)
	copy(big, g.vcek)
	_, err := g.v.Appraise(snp.AppraisalInput{Evidence: g.report, Endorsements: snp.Endorsements{VCEK: big, CRL: g.crl}, Now: g.now, Policy: policy})
	if e := mustFail(t, err, "bigcert"); e.Violations[0].Code != snp.CertMalformed {
		t.Fatal(e.Violations)
	}
	bigCrl := make([]byte, 1024*1024+1)
	copy(bigCrl, g.crl)
	_, err = g.v.Appraise(snp.AppraisalInput{Evidence: g.report, Endorsements: snp.Endorsements{VCEK: g.vcek, CRL: bigCrl}, Now: g.now, Policy: policy})
	if e := mustFail(t, err, "bigcrl"); e.Violations[0].Code != snp.CRLInvalid {
		t.Fatal(e.Violations)
	}
}
