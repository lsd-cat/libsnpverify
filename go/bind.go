package snpverify

// Bind the endorsement key to the report, then verify the report signature. Mirrors ts/src/bind.ts.

import "fmt"

type TCBs struct{ Current, Committed, Reported, Launch TCBVersion }

// BindEndorsement checks that the key derives from exactly REPORTED_TCB, on this chip (unless masked), for the product the CPU reports.
// The error, when non-nil, is a *Violation.
func BindEndorsement(report *Report, ek *EndorsementKey) (*TCBs, error) {
	return stage(func() *TCBs {
		if ek.Kind != report.SignerInfo.SigningKey {
			fail(SignerKindMismatch, fmt.Sprintf("report says %s, certificate is a %s", report.SignerInfo.SigningKey, ek.Kind), "signer_info.signing_key")
		}
		layout := Products[ek.Product].TCBLayout
		tcb := &TCBs{decodeTCB(report.CurrentTCB, layout), decodeTCB(report.CommittedTCB, layout), decodeTCB(report.ReportedTCB, layout), decodeTCB(report.LaunchTCB, layout)}
		if !tcbEqual(tcb.Reported, ek.TCB) {
			fail(VCEKTCBMismatch, fmt.Sprintf("reported_tcb does not match the %s certificate TCB", ek.Kind), "reported_tcb")
		}
		// A zero CHIP_ID means the host masked it; there is nothing to compare with the HWID.
		if ek.Kind == VCEK {
			chipID := report.ChipID()
			chip := chipID[:len(ek.hwid)]
			if !isZero(chipID) && !equal(chip, ek.hwid) {
				fail(VCEKHWIDMismatch, fmt.Sprintf("chip_id %s != VCEK HWID %s", toHex(chip), toHex(ek.hwid)), "chip_id")
			}
		}
		if c := report.CPUID; c != nil {
			fromCPU, ok := ProductFromCPUID(c.Family, c.Model)
			if !ok || fromCPU != ek.Product {
				name := string(fromCPU)
				if !ok {
					name = "unknown"
				}
				fail(ProductMismatch, fmt.Sprintf("CPUID family 0x%x model 0x%x is %s, certificate says %s", c.Family, c.Model, name, ek.Product), "cpuid_fam_id")
			}
		}
		return tcb
	})
}

// VerifyReportSignature checks the report signature with the endorsement key. The error, when non-nil, is a *Violation.
func VerifyReportSignature(report *Report, ek *EndorsementKey, crypto CryptoProvider) error {
	_, err := stage(func() struct{} {
		sig := report.Signature()
		if !crypto.VerifyECDSAP384(ek.Cert.SPKI(), report.SignedBytes(), sig.R, sig.S) {
			fail(ReportSignatureInvalid, fmt.Sprintf("report signature does not verify with the %s", ek.Kind), "signature")
		}
		return struct{}{}
	})
	return err
}
