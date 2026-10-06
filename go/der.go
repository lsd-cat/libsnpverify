package snpverify

// DER reader and X.509 certificate / CRL parser for AMD's ARK, ASK, VCEK, VLEK certificates and KDS CRLs. Mirrors ts/src/der.ts.

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// tlv: at is the offset of the tag byte, start the first content byte, end one past the last content byte.
type tlv struct{ tag, start, end, at int }

const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagBitString   = 0x03
	tagOctetString = 0x04
	tagOID         = 0x06
	tagUTF8        = 0x0c
	tagSequence    = 0x30
	tagPrintable   = 0x13
	tagIA5         = 0x16
	tagUTCTime     = 0x17
	tagGenTime     = 0x18
	tagCtx0        = 0xa0
	tagCtx1        = 0xa1
	tagCtx2        = 0xa2
	tagCtx3        = 0xa3
)

const (
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	oidRSASSAPSS     = "1.2.840.113549.1.1.10"
	oidECPublicKey   = "1.2.840.10045.2.1"
	oidP384          = "1.3.132.0.34"
	oidSHA256        = "2.16.840.1.101.3.4.2.1"
	oidSHA384        = "2.16.840.1.101.3.4.2.2"
	oidSHA512        = "2.16.840.1.101.3.4.2.3"
	oidMGF1          = "1.2.840.113549.1.1.8"
	oidCN            = "2.5.4.3"
	oidO             = "2.5.4.10"
	oidOU            = "2.5.4.11"
)

func readTlv(b []byte, at, limit int) tlv {
	if at+2 > limit {
		fail(CertMalformed, "DER: truncated header")
	}
	tag := int(b[at])
	if tag&0x1f == 0x1f {
		fail(CertMalformed, "DER: multi-byte tags unsupported")
	}
	i := at + 1
	n := int(b[i])
	i++
	if n == 0x80 {
		fail(CertMalformed, "DER: indefinite length")
	}
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || i+k > limit {
			fail(CertMalformed, "DER: bad length")
		}
		n = 0
		for range k {
			n = n*256 + int(b[i])
			i++
		}
		if n < 0x80 && k == 1 {
			fail(CertMalformed, "DER: non-minimal length")
		}
	}
	if i+n > limit {
		fail(CertMalformed, "DER: content exceeds bounds")
	}
	return tlv{tag, i, i + n, at}
}

func children(b []byte, t tlv) []tlv {
	var out []tlv
	for o := t.start; o < t.end; {
		c := readTlv(b, o, t.end)
		out = append(out, c)
		o = c.end
	}
	return out
}

func expect(t tlv, tag int, what string) tlv {
	if t.tag != tag {
		fail(CertMalformed, fmt.Sprintf("DER: %s: expected tag 0x%x, got 0x%x", what, tag, t.tag))
	}
	return t
}

// raw and content return views into b; callers that expose bytes must copy.
func raw(b []byte, t tlv) []byte     { return b[t.at:t.end] }
func content(b []byte, t tlv) []byte { return b[t.start:t.end] }

func oidToString(b []byte, t tlv) string {
	expect(t, tagOID, "OID")
	c := content(b, t)
	if len(c) == 0 {
		fail(CertMalformed, "DER: empty OID")
	}
	var parts []string
	v := int64(0)
	for _, x := range c {
		if v >= 1<<56 {
			fail(CertMalformed, "DER: OID arc too large")
		}
		v = v*128 + int64(x&0x7f)
		if x&0x80 == 0 {
			if len(parts) == 0 {
				first := min(int64(2), v/40)
				parts = append(parts, strconv.FormatInt(first, 10), strconv.FormatInt(v-40*first, 10))
			} else {
				parts = append(parts, strconv.FormatInt(v, 10))
			}
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

// smallInt reads a small non-negative INTEGER.
func smallInt(b []byte, t tlv, what string) int64 {
	expect(t, tagInteger, what)
	c := content(b, t)
	if len(c) == 0 || len(c) > 6 {
		fail(CertMalformed, fmt.Sprintf("DER: %s: bad integer length", what))
	}
	if c[0]&0x80 != 0 {
		fail(CertMalformed, fmt.Sprintf("DER: %s: negative integer", what))
	}
	v := int64(0)
	for _, x := range c {
		v = v*256 + int64(x)
	}
	return v
}

func parseTime(b []byte, t tlv) int64 {
	s := string(content(b, t))
	yearDigits := 0
	switch t.tag {
	case tagUTCTime:
		yearDigits = 2
	case tagGenTime:
		yearDigits = 4
	default:
		fail(CertMalformed, "bad time tag")
	}
	n := yearDigits + 10
	if len(s) != n+1 || s[n] != 'Z' || strings.Trim(s[:n], "0123456789") != "" {
		fail(CertMalformed, "bad time "+s)
	}
	num := func(a, z int) int { v, _ := strconv.Atoi(s[a:z]); return v }
	year := num(0, yearDigits)
	if yearDigits == 2 {
		if year >= 50 {
			year += 1900
		} else {
			year += 2000
		}
	}
	mo, d, h, mi, sec := num(n-10, n-8), num(n-8, n-6), num(n-6, n-4), num(n-4, n-2), num(n-2, n)
	dt := time.Date(year, time.Month(mo), d, h, mi, sec, 0, time.UTC)
	if dt.Year() != year || int(dt.Month()) != mo || dt.Day() != d || dt.Hour() != h || dt.Minute() != mi || dt.Second() != sec {
		fail(CertMalformed, "invalid certificate time "+s)
	}
	return dt.Unix()
}

// Extension is immutable: Value returns a fresh copy on every access.
type Extension struct {
	OID      string
	Critical bool
	value    []byte // content of the OCTET STRING
}

func (e Extension) Value() []byte { return bytes.Clone(e.value) }

type PSSParams struct {
	Hash       string // "SHA-256", "SHA-384" or "SHA-512"
	SaltLength int
}

type SignatureAlgorithm struct {
	OID string
	PSS *PSSParams // for RSASSA-PSS: parsed params
}

func sameAlg(a, b SignatureAlgorithm) bool {
	return a.OID == b.OID && (a.PSS == nil) == (b.PSS == nil) && (a.PSS == nil || *a.PSS == *b.PSS)
}

type Name struct{ CN, O, OU string }

// Certificate is immutable: it owns a private copy of the DER and every byte-valued accessor returns a fresh copy.
type Certificate struct {
	der, tbs, serial, issuer, subject, spki, signature []byte // views into der
	SubjectName                                        Name
	NotBefore, NotAfter                                int64 // unix seconds
	SPKIAlgorithm                                      string
	SPKICurve                                          string // OID for EC keys, else empty
	SignatureAlgorithm                                 SignatureAlgorithm
	extensions                                         map[string]Extension
}

func (c *Certificate) DER() []byte       { return bytes.Clone(c.der) }
func (c *Certificate) TBS() []byte       { return bytes.Clone(c.tbs) }
func (c *Certificate) Serial() []byte    { return bytes.Clone(c.serial) }
func (c *Certificate) Issuer() []byte    { return bytes.Clone(c.issuer) }
func (c *Certificate) Subject() []byte   { return bytes.Clone(c.subject) }
func (c *Certificate) SPKI() []byte      { return bytes.Clone(c.spki) }
func (c *Certificate) Signature() []byte { return bytes.Clone(c.signature) }
func (c *Certificate) SubjectCN() string { return c.SubjectName.CN }

// Extensions returns a fresh map, keyed by OID.
func (c *Certificate) Extensions() map[string]Extension { return copyExtensions(c.extensions) }

func copyExtensions(m map[string]Extension) map[string]Extension {
	out := make(map[string]Extension, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// CRL is immutable: it owns private copies and every byte-valued accessor returns a fresh copy.
type CRL struct {
	der, tbs, issuer, signature []byte
	ThisUpdate                  int64
	NextUpdate                  *int64
	revokedSerials              [][]byte
	extensions                  map[string]Extension
	SignatureAlgorithm          SignatureAlgorithm
}

func (c *CRL) DER() []byte                      { return bytes.Clone(c.der) }
func (c *CRL) TBS() []byte                      { return bytes.Clone(c.tbs) }
func (c *CRL) Issuer() []byte                   { return bytes.Clone(c.issuer) }
func (c *CRL) Signature() []byte                { return bytes.Clone(c.signature) }
func (c *CRL) Extensions() map[string]Extension { return copyExtensions(c.extensions) }
func (c *CRL) RevokedSerials() [][]byte {
	out := make([][]byte, len(c.revokedSerials))
	for i, s := range c.revokedSerials {
		out[i] = bytes.Clone(s)
	}
	return out
}

func hashName(oid string) string {
	switch oid {
	case oidSHA256:
		return "SHA-256"
	case oidSHA384:
		return "SHA-384"
	case oidSHA512:
		return "SHA-512"
	}
	fail(CertAlgoUnsupported, "unsupported hash OID "+oid)
	return ""
}

func parseSigAlg(b []byte, t tlv) SignatureAlgorithm {
	expect(t, tagSequence, "AlgorithmIdentifier")
	kids := children(b, t)
	oid := oidToString(b, kids[0])
	if oid != oidRSASSAPSS {
		return SignatureAlgorithm{OID: oid}
	}
	if len(kids) < 2 {
		fail(CertAlgoUnsupported, "RSASSA-PSS without parameters")
	}
	// RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength, [3] trailerField }
	hash, mgfHash, saltLength := "", "", 20
	for _, p := range children(b, kids[1]) {
		inner := children(b, p)[0]
		switch p.tag {
		case tagCtx0:
			hash = hashName(oidToString(b, children(b, inner)[0]))
		case tagCtx1:
			mgf := children(b, inner)
			if oidToString(b, mgf[0]) != oidMGF1 {
				fail(CertAlgoUnsupported, "PSS MGF is not MGF1")
			}
			mgfHash = hashName(oidToString(b, children(b, mgf[1])[0]))
		case tagCtx2:
			saltLength = int(smallInt(b, inner, "saltLength"))
		case tagCtx3:
			if smallInt(b, inner, "trailerField") != 1 {
				fail(CertAlgoUnsupported, "PSS trailerField")
			}
		}
	}
	if hash == "" {
		fail(CertAlgoUnsupported, "PSS without explicit hash (SHA-1 default) is not accepted")
	}
	if mgfHash != hash {
		fail(CertAlgoUnsupported, "PSS MGF1 must explicitly use the message hash")
	}
	return SignatureAlgorithm{OID: oid, PSS: &PSSParams{hash, saltLength}}
}

func parseName(b []byte, name tlv) Name {
	var out Name
	for _, rdn := range children(b, name) {
		for _, atv := range children(b, rdn) {
			kids := children(b, atv)
			oidT, v := kids[0], kids[1]
			if v.end-v.start > 4096 {
				fail(CertMalformed, "DN attribute too long")
			}
			str := string(content(b, v))
			switch oidToString(b, oidT) {
			case oidCN:
				out.CN = str
			case oidO:
				out.O = str
			case oidOU:
				out.OU = str
			}
		}
	}
	return out
}

func bitStringContent(b []byte, t tlv) []byte {
	expect(t, tagBitString, "BIT STRING")
	if t.end == t.start {
		fail(CertMalformed, "DER: BIT STRING is empty")
	}
	if b[t.start] != 0 {
		fail(CertMalformed, "BIT STRING with unused bits")
	}
	return b[t.start+1 : t.end]
}

func parseExtensions(b []byte, extsSeq tlv) map[string]Extension {
	m := map[string]Extension{}
	for _, ext := range children(b, expect(extsSeq, tagSequence, "Extensions")) {
		parts := children(b, ext)
		oid := oidToString(b, parts[0])
		critical, i := false, 1
		if parts[i].tag == tagBoolean {
			flag := content(b, parts[i])
			if len(flag) != 1 {
				fail(CertMalformed, "DER: extension critical flag must be one byte")
			}
			critical = flag[0] != 0
			i++
		}
		value := content(b, expect(parts[i], tagOctetString, "extnValue"))
		if _, dup := m[oid]; dup {
			fail(CertMalformed, "duplicate extension "+oid)
		}
		m[oid] = Extension{oid, critical, value}
	}
	return m
}

// Input size caps. AMD certificates are about 2 KiB, CRLs a few hundred bytes.
const (
	MaxCertBytes = 16 * 1024
	MaxCRLBytes  = 1024 * 1024
)

// recoverMalformed turns an out-of-bounds access (a structurally broken input) into a violation.
func recoverMalformed(code ErrorCode, message string) {
	r := recover()
	if r == nil {
		return
	}
	if _, ok := r.(runtime.Error); ok {
		fail(code, message)
	}
	panic(r)
}

// ParseCertificate parses an X.509 v3 certificate. The error, when non-nil, is a *Violation.
func ParseCertificate(der []byte) (*Certificate, error) {
	return stage(func() *Certificate { return parseCertificate(der) })
}

func parseCertificate(der []byte) *Certificate {
	defer recoverMalformed(CertMalformed, "malformed certificate structure")
	if len(der) > MaxCertBytes {
		fail(CertMalformed, fmt.Sprintf("certificate is %d bytes, limit %d", len(der), MaxCertBytes))
	}
	der = bytes.Clone(der) // private copy; all views below point into it
	cert := readTlv(der, 0, len(der))
	expect(cert, tagSequence, "Certificate")
	if cert.end != len(der) {
		fail(CertMalformed, "trailing bytes after certificate")
	}
	top := children(der, cert)
	if len(top) < 3 {
		fail(CertMalformed, "Certificate: missing fields")
	}
	tbsT, sigAlgT, sigValT := top[0], top[1], top[2]
	expect(tbsT, tagSequence, "TBSCertificate")
	f := children(der, tbsT)
	if len(f) == 0 || f[0].tag != tagCtx0 || smallInt(der, children(der, f[0])[0], "version") != 2 {
		fail(CertMalformed, "not X.509 v3")
	}
	if len(f) < 7 {
		fail(CertMalformed, "TBSCertificate: missing fields")
	}
	serialT, tbsSigAlgT, issuerT, validityT, subjectT, spkiT := f[1], f[2], f[3], f[4], f[5], f[6]
	validity := children(der, expect(validityT, tagSequence, "Validity"))
	spkiKids := children(der, expect(spkiT, tagSequence, "SPKI"))
	spkiAlgKids := children(der, expect(spkiKids[0], tagSequence, "SPKI alg"))
	spkiAlgorithm := oidToString(der, spkiAlgKids[0])
	spkiCurve := ""
	if spkiAlgorithm == oidECPublicKey && len(spkiAlgKids) > 1 && spkiAlgKids[1].tag == tagOID {
		spkiCurve = oidToString(der, spkiAlgKids[1])
	}
	extensions := map[string]Extension{}
	for _, t := range f[7:] {
		if t.tag == tagCtx3 {
			extensions = parseExtensions(der, children(der, t)[0])
			break
		}
	}
	sigAlg := parseSigAlg(der, sigAlgT)
	if !sameAlg(sigAlg, parseSigAlg(der, tbsSigAlgT)) {
		fail(CertMalformed, "signatureAlgorithm mismatch between TBS and outer")
	}
	return &Certificate{
		der: der, tbs: raw(der, tbsT), serial: content(der, expect(serialT, tagInteger, "serialNumber")),
		issuer: raw(der, issuerT), subject: raw(der, subjectT), SubjectName: parseName(der, subjectT),
		NotBefore: parseTime(der, validity[0]), NotAfter: parseTime(der, validity[1]),
		spki: raw(der, spkiT), SPKIAlgorithm: spkiAlgorithm, SPKICurve: spkiCurve,
		SignatureAlgorithm: sigAlg, signature: bitStringContent(der, sigValT), extensions: extensions,
	}
}

// ParseCRL parses an X.509 CRL. The error, when non-nil, is a *Violation.
func ParseCRL(der []byte) (*CRL, error) {
	return stage(func() *CRL { return parseCRL(der) })
}

func parseCRL(der []byte) *CRL {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if v, ok := r.(*Violation); ok && v.Code == CertMalformed {
			fail(CRLInvalid, v.Message)
		}
		if _, ok := r.(runtime.Error); ok {
			fail(CRLInvalid, "malformed CRL structure")
		}
		panic(r)
	}()
	if len(der) > MaxCRLBytes {
		fail(CRLInvalid, fmt.Sprintf("CRL is %d bytes, limit %d", len(der), MaxCRLBytes))
	}
	der = bytes.Clone(der)
	crl := readTlv(der, 0, len(der))
	expect(crl, tagSequence, "CertificateList")
	if crl.end != len(der) {
		fail(CRLInvalid, "trailing bytes after CRL")
	}
	top := children(der, crl)
	if len(top) < 3 {
		fail(CRLInvalid, "CRL: missing fields")
	}
	tbsT, sigAlgT, sigValT := top[0], top[1], top[2]
	f := children(der, expect(tbsT, tagSequence, "TBSCertList"))
	i := 0
	if f[0].tag == tagInteger { // optional version
		i = 1
	}
	if len(f) < i+3 {
		fail(CRLInvalid, "TBSCertList: missing fields")
	}
	issuerT, thisUpdateT := f[i+1], f[i+2]
	j := i + 3
	var nextUpdate *int64
	if j < len(f) && (f[j].tag == tagUTCTime || f[j].tag == tagGenTime) {
		t := parseTime(der, f[j])
		nextUpdate = &t
		j++
	}
	var revoked [][]byte
	if j < len(f) && f[j].tag == tagSequence {
		for _, entry := range children(der, f[j]) {
			revoked = append(revoked, content(der, expect(children(der, entry)[0], tagInteger, "revoked serial")))
		}
		j++
	}
	extensions := map[string]Extension{}
	if j < len(f) && f[j].tag == tagCtx0 {
		extensions = parseExtensions(der, children(der, f[j])[0])
		j++
	}
	if j != len(f) {
		fail(CRLInvalid, "unexpected CRL fields")
	}
	sigAlg := parseSigAlg(der, sigAlgT)
	if !sameAlg(sigAlg, parseSigAlg(der, f[i])) {
		fail(CRLInvalid, "signatureAlgorithm mismatch between TBS and outer")
	}
	return &CRL{der: der, tbs: raw(der, tbsT), issuer: raw(der, issuerT), ThisUpdate: parseTime(der, thisUpdateT), NextUpdate: nextUpdate,
		revokedSerials: revoked, extensions: extensions, SignatureAlgorithm: sigAlg, signature: bitStringContent(der, sigValT)}
}
