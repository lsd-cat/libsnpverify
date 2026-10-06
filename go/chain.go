package snpverify

// AMD endorsement chain: ARK (pinned) -> ASK/ASVK -> VCEK/VLEK. VCEK extension parsing (57230). Optional CRL. Mirrors ts/src/chain.ts.

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

const (
	kdsStructVersion = "1.3.6.1.4.1.3704.1.1"
	kdsProductName   = "1.3.6.1.4.1.3704.1.2"
	kdsBl            = "1.3.6.1.4.1.3704.1.3.1"
	kdsTee           = "1.3.6.1.4.1.3704.1.3.2"
	kdsSnp           = "1.3.6.1.4.1.3704.1.3.3"
	kdsSpl4          = "1.3.6.1.4.1.3704.1.3.4"
	kdsSpl5          = "1.3.6.1.4.1.3704.1.3.5"
	kdsSpl6          = "1.3.6.1.4.1.3704.1.3.6"
	kdsSpl7          = "1.3.6.1.4.1.3704.1.3.7"
	kdsUcode         = "1.3.6.1.4.1.3704.1.3.8"
	kdsFmc           = "1.3.6.1.4.1.3704.1.3.9"
	kdsHwid          = "1.3.6.1.4.1.3704.1.4"
	kdsCspID         = "1.3.6.1.4.1.3704.1.5"
)

// EndorsementKey is the parsed VCEK or VLEK.
type EndorsementKey struct {
	Kind        SigningKey
	Product     Product
	ProductName string // e.g. "Genoa-B2"
	hwid        []byte
	CSPID       string // VLEK; empty for a VCEK
	TCB         TCBVersion
	Cert        *Certificate
}

// HWID is the VCEK hardware id: 64 (Milan/Genoa) or 8 (Turin) bytes, a fresh copy on every access; nil for a VLEK.
func (ek *EndorsementKey) HWID() []byte { return bytes.Clone(ek.hwid) }

type ChainInput struct {
	Leaf         []byte // VCEK or VLEK, DER
	Intermediate []byte // ASK or ASVK, DER; default embedded for the leaf's product
	Root         []byte // ARK, DER; default embedded
	CRL          []byte // DER, ARK-signed
	Now          int64  // unix seconds
}

type CRLInfo struct {
	ThisUpdate, NextUpdate int64
	RevokedCount           int
}

type Chain struct {
	Leaf               *EndorsementKey
	Intermediate, Root *Certificate
	CRL                *CRLInfo
}

func extInt(cert *Certificate, oid, what string) int {
	e, ok := cert.extensions[oid]
	if !ok {
		fail(VCEKExtensionInvalid, fmt.Sprintf("missing %s extension", what))
	}
	t := readTlv(e.value, 0, len(e.value))
	if t.end != len(e.value) {
		fail(VCEKExtensionInvalid, what+": trailing bytes")
	}
	v := smallInt(e.value, t, what)
	if v > 255 {
		fail(VCEKExtensionInvalid, what+" out of range")
	}
	return int(v)
}

func extString(cert *Certificate, oid, what string) (string, bool) {
	e, ok := cert.extensions[oid]
	if !ok {
		return "", false
	}
	t := readTlv(e.value, 0, len(e.value))
	if t.tag != tagIA5 && t.tag != tagUTF8 && t.tag != tagPrintable {
		fail(VCEKExtensionInvalid, what+": not a string")
	}
	value := content(e.value, t)
	if len(value) > 4096 {
		fail(VCEKExtensionInvalid, what+": invalid ASCII")
	}
	for _, x := range value {
		if x > 0x7f {
			fail(VCEKExtensionInvalid, what+": invalid ASCII")
		}
	}
	return string(value), true
}

// parseEndorsementKey parses the AMD extensions of a VCEK/VLEK. KDS emits HWID either raw or wrapped in an OCTET STRING.
func parseEndorsementKey(cert *Certificate) *EndorsementKey {
	productName, ok := extString(cert, kdsProductName, "productName")
	if !ok {
		fail(VCEKExtensionInvalid, "missing productName extension")
	}
	product, ok := ProductFromName(productName)
	if !ok {
		fail(VCEKExtensionInvalid, fmt.Sprintf("unknown product %q", productName))
	}
	info := Products[product]
	structVersion := extInt(cert, kdsStructVersion, "structVersion")
	if structVersion != info.StructVersion {
		fail(VCEKExtensionInvalid, fmt.Sprintf("structVersion %d does not match %s", structVersion, product))
	}

	hwidExt, hasHwid := cert.extensions[kdsHwid]
	cspID, hasCspID := extString(cert, kdsCspID, "cspId")
	if hasHwid && hasCspID {
		fail(VCEKExtensionInvalid, "certificate has both HWID and CSP_ID")
	}
	if !hasHwid && !hasCspID {
		fail(VCEKExtensionInvalid, "certificate has neither HWID (VCEK) nor CSP_ID (VLEK)")
	}
	var hwid []byte
	if hasHwid {
		h := hwidExt.value
		if len(h) != info.HWIDLength && len(h) > 0 && h[0] == tagOctetString {
			h = content(h, expect(readTlv(h, 0, len(h)), tagOctetString, "HWID"))
		}
		if len(h) != info.HWIDLength {
			fail(VCEKExtensionInvalid, fmt.Sprintf("HWID is %d bytes, want %d", len(h), info.HWIDLength))
		}
		hwid = bytes.Clone(h)
	}

	tcb := TCBVersion{Bootloader: extInt(cert, kdsBl, "blSPL"), TEE: extInt(cert, kdsTee, "teeSPL"), SNP: extInt(cert, kdsSnp, "snpSPL"), Microcode: extInt(cert, kdsUcode, "ucodeSPL")}
	for _, s := range []struct{ oid, what string }{{kdsSpl5, "spl5"}, {kdsSpl6, "spl6"}, {kdsSpl7, "spl7"}} {
		if extInt(cert, s.oid, s.what) != 0 {
			fail(VCEKExtensionInvalid, s.what+" must be 0")
		}
	}
	if info.TCBLayout == TCBLayoutV0 {
		if _, has := cert.extensions[kdsFmc]; has {
			fail(VCEKExtensionInvalid, "fmcSPL not valid for this product")
		}
		if extInt(cert, kdsSpl4, "spl4") != 0 {
			fail(VCEKExtensionInvalid, "spl4 must be 0")
		}
	} else {
		if _, has := cert.extensions[kdsSpl4]; has {
			fail(VCEKExtensionInvalid, "spl4 not valid for this product")
		}
		fmc := extInt(cert, kdsFmc, "fmcSPL")
		tcb.FMC = &fmc
	}
	kind := VLEK
	if hwid != nil {
		kind = VCEK
	}
	if !strings.HasPrefix(cert.SubjectCN(), "SEV-"+string(kind)) {
		fail(VCEKExtensionInvalid, fmt.Sprintf("leaf CN %q is not SEV-%s", cert.SubjectCN(), kind))
	}
	return &EndorsementKey{Kind: kind, Product: product, ProductName: productName, hwid: hwid, CSPID: cspID, TCB: tcb, Cert: cert}
}

func iso(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02T15:04:05Z") }

func checkValidity(cert *Certificate, now int64, what string) {
	if now < cert.NotBefore {
		fail(CertNotYetValid, fmt.Sprintf("%s not valid before %s", what, iso(cert.NotBefore)))
	}
	if now > cert.NotAfter {
		fail(CertExpired, fmt.Sprintf("%s expired at %s", what, iso(cert.NotAfter)))
	}
}

func checkCertificatePurpose(cert *Certificate, ca bool) {
	for _, e := range cert.extensions {
		if e.Critical && e.OID != "2.5.29.19" && e.OID != "2.5.29.15" {
			fail(CertMalformed, "unsupported critical certificate extension "+e.OID)
		}
	}
	bc, hasBc := cert.extensions["2.5.29.19"]
	if ca && !hasBc {
		fail(CertMalformed, "CA certificate lacks basicConstraints")
	}
	if hasBc {
		t := expect(readTlv(bc.value, 0, len(bc.value)), tagSequence, "basicConstraints")
		if t.end != len(bc.value) {
			fail(CertMalformed, "basicConstraints trailing bytes")
		}
		fields := children(bc.value, t)
		isCa := len(fields) > 0 && fields[0].tag == tagBoolean && bytes.Equal(content(bc.value, fields[0]), []byte{0xff})
		if ca != isCa {
			fail(CertMalformed, fmt.Sprintf("basicConstraints CA=%t is wrong for %s", isCa, map[bool]string{true: "issuer", false: "leaf"}[ca]))
		}
	}
	if ku, ok := keyUsageBits(cert); ok {
		if ca && ku&0x04 == 0 {
			fail(CertMalformed, "keyUsage does not permit certificate signing")
		}
		if !ca && ku&0x80 == 0 {
			fail(CertMalformed, "keyUsage does not permit digital signing")
		}
	}
}

// keyUsageBits returns the first keyUsage byte, or false when the extension is absent.
func keyUsageBits(cert *Certificate) (int, bool) {
	e, ok := cert.extensions["2.5.29.15"]
	if !ok {
		return 0, false
	}
	t := expect(readTlv(e.value, 0, len(e.value)), tagBitString, "keyUsage")
	if t.end != len(e.value) || t.end-t.start < 2 {
		fail(CertMalformed, "invalid keyUsage")
	}
	return int(e.value[t.start+1]), true
}

func signedBy(crypto CryptoProvider, alg SignatureAlgorithm, signature, tbs []byte, issuer *Certificate) bool {
	if alg.OID != oidRSASSAPSS || alg.PSS == nil {
		fail(CertAlgoUnsupported, "signature algorithm "+alg.OID)
	}
	if alg.PSS.Hash != "SHA-384" || alg.PSS.SaltLength != 48 {
		fail(CertAlgoUnsupported, "RSASSA-PSS must use SHA-384 with salt length 48")
	}
	if issuer.SPKIAlgorithm != oidRSAEncryption {
		fail(CertAlgoUnsupported, "issuer key is not RSA")
	}
	return crypto.VerifyRSAPSS(issuer.SPKI(), bytes.Clone(tbs), bytes.Clone(signature), 48)
}

// VerifyChain verifies the chain. trustedRoots must contain a DER byte-equal to the root used (nil: the embedded ARK of the leaf's product).
// The error, when non-nil, is a *Violation.
func VerifyChain(callerInput ChainInput, trustedRoots [][]byte, crypto CryptoProvider) (*Chain, error) {
	return stage(func() *Chain {
		// Check sizes, then copy every input at entry.
		checkEndorsementSizes(callerInput.Leaf, callerInput.Intermediate, callerInput.Root, callerInput.CRL)
		input := ChainInput{bytes.Clone(callerInput.Leaf), bytes.Clone(callerInput.Intermediate), bytes.Clone(callerInput.Root), bytes.Clone(callerInput.CRL), callerInput.Now}
		if trustedRoots != nil {
			trustedRoots = cloneAll(trustedRoots)
		}
		leafCert := parseCertificate(input.Leaf)
		leaf := parseEndorsementKey(leafCert)
		defaults, hasDefaults := EmbeddedRoots(leaf.Product)
		rootDer := input.Root
		if rootDer == nil {
			if !hasDefaults {
				fail(ARKUntrusted, fmt.Sprintf("no embedded root for %s; pass one", leaf.Product))
			}
			rootDer = defaults.ARK
		}
		interDer := input.Intermediate
		if interDer == nil {
			if !hasDefaults {
				fail(CertMalformed, fmt.Sprintf("no embedded intermediate for %s; pass one", leaf.Product))
			}
			interDer = defaults.ASK
		}
		trusted := trustedRoots
		if trusted == nil && hasDefaults {
			trusted = [][]byte{defaults.ARK}
		}
		if !containsBytes(trusted, rootDer) {
			fail(ARKUntrusted, "root certificate is not a trusted ARK")
		}
		root := parseCertificate(rootDer)
		intermediate := parseCertificate(interDer)

		// Product consistency: ARK "ARK-Genoa", ASK "SEV-Genoa", ASVK "SEV-VLEK-Genoa". Siena/Bergamo use the Genoa chain.
		p := leaf.Product
		if !strings.HasSuffix(root.SubjectCN(), "-"+string(p)) {
			fail(ProductMismatch, fmt.Sprintf("ARK %q is not for %s", root.SubjectCN(), p))
		}
		if !strings.HasSuffix(intermediate.SubjectCN(), "-"+string(p)) {
			fail(ProductMismatch, fmt.Sprintf("intermediate %q is not for %s", intermediate.SubjectCN(), p))
		}
		if (leaf.Kind == VLEK) != strings.HasPrefix(intermediate.SubjectCN(), "SEV-VLEK") {
			issuer := "an ASK"
			if leaf.Kind == VLEK {
				issuer = "an ASVK"
			}
			fail(ProductMismatch, fmt.Sprintf("%s must be issued by %s", leaf.Kind, issuer))
		}

		// All AMD endorsement certificates carry O=Advanced Micro Devices, OU=Engineering.
		for _, c := range []struct {
			cert *Certificate
			what string
		}{{root, "ARK"}, {intermediate, "ASK"}, {leafCert, string(leaf.Kind)}} {
			if c.cert.SubjectName.O != "Advanced Micro Devices" || c.cert.SubjectName.OU != "Engineering" {
				fail(ChainNameMismatch, c.what+" subject is not AMD Engineering")
			}
		}
		if !equal(leafCert.issuer, intermediate.subject) {
			fail(ChainNameMismatch, "leaf issuer != intermediate subject")
		}
		if !equal(intermediate.issuer, root.subject) {
			fail(ChainNameMismatch, "intermediate issuer != root subject")
		}
		if !equal(root.issuer, root.subject) {
			fail(ChainNameMismatch, "root is not self-issued")
		}

		checkValidity(root, input.Now, "ARK")
		checkValidity(intermediate, input.Now, "ASK")
		checkValidity(leafCert, input.Now, string(leaf.Kind))
		checkCertificatePurpose(root, true)
		checkCertificatePurpose(intermediate, true)
		checkCertificatePurpose(leafCert, false)
		if leafCert.SPKIAlgorithm != oidECPublicKey || leafCert.SPKICurve != oidP384 {
			fail(CertAlgoUnsupported, fmt.Sprintf("%s key is not EC P-384", leaf.Kind))
		}

		if !signedBy(crypto, root.SignatureAlgorithm, root.signature, root.tbs, root) {
			fail(ChainSignatureInvalid, "ARK self-signature invalid")
		}
		if !signedBy(crypto, intermediate.SignatureAlgorithm, intermediate.signature, intermediate.tbs, root) {
			fail(ChainSignatureInvalid, "ASK not signed by ARK")
		}
		if !signedBy(crypto, leafCert.SignatureAlgorithm, leafCert.signature, leafCert.tbs, intermediate) {
			fail(ChainSignatureInvalid, fmt.Sprintf("%s not signed by ASK", leaf.Kind))
		}

		var crl *CRLInfo
		if input.CRL != nil {
			crl = checkCRL(input.CRL, root, intermediate, input.Now, crypto)
		}
		return &Chain{Leaf: leaf, Intermediate: intermediate, Root: root, CRL: crl}
	})
}

func cloneAll(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = bytes.Clone(b)
	}
	return out
}

func containsBytes(set [][]byte, b []byte) bool {
	for _, s := range set {
		if equal(s, b) {
			return true
		}
	}
	return false
}

// checkEndorsementSizes applies the size caps, before any copy or parse.
func checkEndorsementSizes(leaf, intermediate, root, crl []byte) {
	for _, c := range []struct {
		what string
		b    []byte
	}{{"leaf", leaf}, {"intermediate", intermediate}, {"root", root}} {
		if len(c.b) > MaxCertBytes {
			fail(CertMalformed, fmt.Sprintf("%s certificate is %d bytes, limit %d", c.what, len(c.b), MaxCertBytes))
		}
	}
	if len(crl) > MaxCRLBytes {
		fail(CRLInvalid, fmt.Sprintf("CRL is %d bytes, limit %d", len(crl), MaxCRLBytes))
	}
}

// checkCRL: KDS CRLs are ARK-signed and list revoked ASK/ASVK serials. VCEKs (serial 0) are never revoked; TCB supersedes them.
func checkCRL(crlDer []byte, root, intermediate *Certificate, now int64, crypto CryptoProvider) *CRLInfo {
	crl := parseCRL(crlDer)
	if crl.NextUpdate == nil {
		fail(CRLInvalid, "CRL has no nextUpdate")
	}
	if _, delta := crl.extensions["2.5.29.27"]; delta {
		fail(CRLInvalid, "delta CRL requires a base CRL")
	}
	for _, ext := range crl.extensions {
		if ext.Critical {
			fail(CRLInvalid, "unsupported critical CRL extension "+ext.OID)
		}
	}
	ku, ok := keyUsageBits(root)
	if !ok {
		fail(CRLInvalid, "CRL issuer lacks keyUsage")
	}
	if ku&0x02 == 0 {
		fail(CRLInvalid, "CRL issuer keyUsage does not permit CRL signing")
	}
	if !equal(crl.issuer, root.subject) {
		fail(CRLInvalid, "CRL issuer is not the ARK")
	}
	if !signedBy(crypto, crl.SignatureAlgorithm, crl.signature, crl.tbs, root) {
		fail(CRLInvalid, "CRL signature invalid")
	}
	if now < crl.ThisUpdate {
		fail(CRLInvalid, "CRL thisUpdate is in the future")
	}
	if now > *crl.NextUpdate {
		fail(CRLExpired, fmt.Sprintf("CRL nextUpdate %s passed", iso(*crl.NextUpdate)))
	}
	for _, serial := range crl.revokedSerials {
		if equal(serial, intermediate.serial) {
			fail(CertRevoked, fmt.Sprintf("intermediate serial %s is revoked", toHex(serial)))
		}
		if equal(serial, root.serial) {
			fail(CertRevoked, fmt.Sprintf("root serial %s is revoked", toHex(serial)))
		}
	}
	return &CRLInfo{ThisUpdate: crl.ThisUpdate, NextUpdate: *crl.NextUpdate, RevokedCount: len(crl.revokedSerials)}
}
