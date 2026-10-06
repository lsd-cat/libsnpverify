// Package snpverify appraises AMD SEV-SNP attestation reports.
//
//	verifier := snpverify.NewVerifier(snpverify.VerifierOptions{}) // standard-library crypto, embedded AMD certificates
//	result, err := verifier.Appraise(snpverify.AppraisalInput{
//		Evidence: report, Endorsements: snpverify.Endorsements{VCEK: vcek, CRL: crl}, Now: now,
//		Policy: snpverify.AppraisalPolicy{Measurement: snpverify.MeasurementAllowlist{m}},
//	})
//	var failed *snpverify.AppraisalError
//	if errors.As(err, &failed) { show(failed.Stage, failed.Violations) } else { use(result) }
//
// Inputs: the report (Evidence), AMD certificates and optional CRL (Endorsements), appraisal time, appraisal policy. No network, no clock. See SPEC.md.
package snpverify

import (
	"bytes"
	"fmt"
)

type Endorsements struct {
	VCEK []byte // VCEK or VLEK, DER
	ASK  []byte // ASK or ASVK, DER; default embedded for the product
	ARK  []byte // ARK, DER; default embedded for the product
	CRL  []byte // ARK-signed CRL, DER
}

type AppraisalInput struct {
	Evidence     []byte // the attestation report, exactly 1184 bytes
	Endorsements Endorsements
	Now          int64 // appraisal time, unix seconds
	Policy       AppraisalPolicy
}

// Partial holds the records produced before the failing stage.
type Partial struct {
	Report *Report
	Chain  *Chain
	TCB    *TCBs
}

// AppraisalError is the error returned by Appraise: the stage that failed and its violations.
type AppraisalError struct {
	Stage      Stage
	Violations []Violation
	Partial    Partial
}

func (e *AppraisalError) Error() string {
	return fmt.Sprintf("appraisal failed at stage %s: %s", e.Stage, e.Violations[0].Error())
}

type VerifierOptions struct {
	// Crypto defaults to StdCrypto.
	Crypto CryptoProvider
	// TrustedARKs are the DER ARKs the verifier trusts; the root used must be byte-equal to one. Default: the embedded ARK of the leaf's product.
	TrustedARKs [][]byte
}

type Verifier struct {
	crypto      CryptoProvider
	trustedARKs [][]byte
}

func NewVerifier(options VerifierOptions) *Verifier {
	v := &Verifier{crypto: options.Crypto}
	if v.crypto == nil {
		v.crypto = StdCrypto{}
	}
	if options.TrustedARKs != nil {
		v.trustedARKs = cloneAll(options.TrustedARKs)
	}
	return v
}

func (v *Verifier) VerifyChain(input ChainInput) (*Chain, error) {
	return VerifyChain(input, v.trustedARKs, v.crypto)
}

func (v *Verifier) VerifyReportSignature(report *Report, chain *Chain) error {
	return VerifyReportSignature(report, chain.Leaf, v.crypto)
}

// Appraise runs every stage. On failure the error is an *AppraisalError.
func (v *Verifier) Appraise(input AppraisalInput) (*AttestationResult, error) {
	failed := func(stage Stage, err error, partial Partial) (*AttestationResult, error) {
		return nil, &AppraisalError{Stage: stage, Violations: []Violation{*err.(*Violation)}, Partial: partial}
	}
	resolved, err := ResolveAppraisalPolicy(input.Policy)
	if err != nil {
		return failed(StagePolicy, err, Partial{})
	}
	// Parse the report (it checks its length before copying), check endorsement sizes, then copy every input.
	report, err := ParseReport(input.Evidence)
	if err != nil {
		return failed(StageParse, err, Partial{})
	}
	e := input.Endorsements
	if _, err := stage(func() struct{} { checkEndorsementSizes(e.VCEK, e.ASK, e.ARK, e.CRL); return struct{}{} }); err != nil {
		return failed(StageChain, err, Partial{})
	}
	chainInput := ChainInput{bytes.Clone(e.VCEK), bytes.Clone(e.ASK), bytes.Clone(e.ARK), bytes.Clone(e.CRL), input.Now}
	chain, err := v.VerifyChain(chainInput)
	if err != nil {
		return failed(StageChain, err, Partial{Report: report})
	}
	tcb, err := BindEndorsement(report, chain.Leaf)
	if err != nil {
		return failed(StageBind, err, Partial{Report: report, Chain: chain})
	}
	if err := v.VerifyReportSignature(report, chain); err != nil {
		return failed(StageSignature, err, Partial{Report: report, Chain: chain, TCB: tcb})
	}
	ctx := AppraisalContext{TCB: *tcb, CRLPresent: chain.CRL != nil, LeafFingerprint: v.crypto.SHA256(chain.Leaf.Cert.DER())}
	if violations := checkResolvedAppraisalPolicy(report, chain.Leaf, ctx, resolved); len(violations) > 0 {
		return nil, &AppraisalError{Stage: StagePolicy, Violations: violations, Partial: Partial{Report: report, Chain: chain, TCB: tcb}}
	}
	return buildAttestationResult(report, chain, *tcb, resolved, chainInput.Now, v.crypto), nil
}
