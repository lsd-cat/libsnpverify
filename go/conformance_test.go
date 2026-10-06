package snpverify_test

// Runs the Tinfoil conformance vectors (vectors/attestation-sev, vectors/quote-sev) through the Verifier. Mirrors ts/test/conformance.test.ts.
// Two policy profiles: baseline for real-hardware fixtures, hardened for synthetic ones (which encode the hardened stance).

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	snp "github.com/lsd-cat/snpverify/go"
)

// Policies are built in the JSON form (SPEC §5) so that every port runs the vectors through its JSON loader.
type jsonObj = map[string]any

var baseline = jsonObj{"measurement": "any", "vmpl": "any", "products": []string{"Milan", "Genoa", "Turin"}}

// hardened mirrors the expectations encoded by the synthetic fixtures (SPEC §3.7.1 defaults + DECIDE-LATER probes).
var hardened = merge(baseline, jsonObj{
	"allowMaskedChipId": true,
	"minTcb":            jsonObj{"Genoa": jsonObj{"snp": 14}},
	"minFirmware":       jsonObj{"major": 1, "minor": 55, "build": 21},
	"guestPolicy":       jsonObj{"debug": "forbidden", "migrateMa": "forbidden", "cxlAllowed": "forbidden", "memAes256Xts": "forbidden"},
	"platformInfo":      jsonObj{"tsmeEnabled": "required"},
})

// The 27x probes encode the DECIDE-LATER hardened stance that the rest of the synthetic suite does not satisfy.
var hardenedPlatform = jsonObj{"tsmeEnabled": "required", "eccEnabled": "required", "raplDisabled": "required", "ciphertextHidingEnabled": "required", "aliasCheckComplete": "required", "tioEnabled": "required"}

func merge(base jsonObj, over jsonObj) jsonObj {
	out := jsonObj{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func policyFromJSON(t *testing.T, j jsonObj) snp.AppraisalPolicy {
	t.Helper()
	text, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	p, err := snp.AppraisalPolicyFromJSON(text)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// tinfoilCode maps our code to the Tinfoil taxonomy, so vectors that name a code can be asserted.
func tinfoilCode(e *snp.AppraisalError) string {
	v := e.Violations[0]
	switch v.Code {
	case snp.ReportTruncated:
		return "REPORT_TRUNCATED"
	case snp.ReportVersionUnsupported:
		return "WRONG_REPORT_VERSION"
	case snp.ReportSignatureInvalid:
		return "REPORT_SIGNATURE_INVALID"
	case snp.CertMalformed, snp.ChainSignatureInvalid, snp.ChainNameMismatch, snp.VCEKExtensionInvalid:
		return "VCEK_CHAIN_INVALID"
	case snp.CertExpired:
		return "VCEK_EXPIRED"
	case snp.VCEKHWIDMismatch:
		return "VCEK_HWID_MISMATCH"
	case snp.VCEKTCBMismatch:
		return "VCEK_TCB_MISMATCH"
	case snp.PolicyTCBOutOfDate, snp.PolicyLaunchTCBOutOfDate:
		return "TCB_OUT_OF_DATE"
	case snp.PolicyMeasurementMismatch:
		return "MEASUREMENT_MISMATCH"
	case snp.PolicyReportDataMismatch:
		return "REPORT_DATA_MISMATCH"
	case snp.PolicyHostDataMismatch:
		return "HOST_DATA_MISMATCH"
	case snp.PolicyGuestPolicy:
		switch v.Field {
		case "guest_policy.debug":
			return "GUEST_POLICY_DEBUG_SET"
		case "guest_policy.migrate_ma":
			return "GUEST_POLICY_MIGRATE_MA_SET"
		}
		return "GUEST_POLICY_RESERVED_BIT_SET"
	case snp.ReportMalformed:
		if v.Field == "guest_policy" {
			return "GUEST_POLICY_RESERVED_BIT_SET"
		}
		return "REPORT_FORMAT_UNSUPPORTED"
	case snp.PolicyIDBlock:
		if v.Field == "author_key_digest" {
			return "AUTHOR_KEY_DIGEST_MISMATCH"
		}
		return "ID_KEY_DIGEST_MISMATCH"
	}
	return string(v.Code)
}

type sevInput struct {
	AttestationDocB64       string `json:"attestation_doc_b64"`
	VcekDerB64              string `json:"vcek_der_b64"`
	AskPem                  string `json:"ask_pem"`
	AmdRootCaPem            string `json:"amd_root_ca_pem"`
	ExpirationCheckDateUnix *int64 `json:"expiration_check_date_unix"`
	Policy                  struct {
		ExpectedMeasurementHex     string `json:"expected_measurement_hex"`
		ExpectedReportDataHex      string `json:"expected_report_data_hex"`
		ExpectedHostDataHex        string `json:"expected_host_data_hex"`
		ExpectedIDKeyDigestHex     string `json:"expected_id_key_digest_hex"`
		ExpectedAuthorKeyDigestHex string `json:"expected_author_key_digest_hex"`
		MinTcbBlSpl                *int   `json:"min_tcb_bl_spl"`
		MinTcbTeeSpl               *int   `json:"min_tcb_tee_spl"`
		MinTcbSnpSpl               *int   `json:"min_tcb_snp_spl"`
		MinTcbUcodeSpl             *int   `json:"min_tcb_ucode_spl"`
	} `json:"policy"`
}

// fixture loads an attestation-sev vector as an AppraisalInput with a measurement-any policy.
func fixture(t *testing.T, name string) (snp.AppraisalInput, sevInput) {
	t.Helper()
	var x sevInput
	readJSON(t, filepath.Join("attestation-sev", name, "input.json"), &x)
	i := snp.AppraisalInput{
		Evidence:     gunzip(t, fromBase64(t, x.AttestationDocB64)),
		Endorsements: snp.Endorsements{VCEK: fromBase64(t, x.VcekDerB64)},
		Now:          1780272000,
		Policy:       snp.AppraisalPolicy{Measurement: snp.MeasurementAny{}},
	}
	if x.AskPem != "" {
		i.Endorsements.ASK = pemFirst(t, x.AskPem)
	}
	if x.AmdRootCaPem != "" {
		i.Endorsements.ARK = pemFirst(t, x.AmdRootCaPem)
	}
	if x.ExpirationCheckDateUnix != nil {
		i.Now = *x.ExpirationCheckDateUnix
	}
	return i, x
}

// verifierFor trusts the input's own ARK when one is supplied, else the embedded roots.
func verifierFor(i snp.AppraisalInput) *snp.Verifier {
	if i.Endorsements.ARK != nil {
		return snp.NewVerifier(snp.VerifierOptions{TrustedARKs: [][]byte{i.Endorsements.ARK}})
	}
	return snp.NewVerifier(snp.VerifierOptions{})
}

func manifest(t *testing.T, dir string) (exit int, codes []string) {
	t.Helper()
	m := string(readFile(t, filepath.Join(dir, "manifest.yaml")))
	exit, _ = strconv.Atoi(regexp.MustCompile(`exit_code:\s*(\d+)`).FindStringSubmatch(m)[1])
	if line := regexp.MustCompile(`(?m)^\s*rejection_code:\s*(.+)$`).FindStringSubmatch(m); line != nil {
		s := strings.TrimSpace(line[1])
		if strings.HasPrefix(s, "[") {
			for _, c := range regexp.MustCompile(`"([A-Z_]+)"`).FindAllStringSubmatch(s, -1) {
				codes = append(codes, c[1])
			}
		} else {
			codes = []string{strings.Trim(s, `"`)}
		}
	}
	return exit, codes
}

func TestAttestationSev(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(vectors, "attestation-sev"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run("attestation-sev/"+name, func(t *testing.T) {
			input, x := fixture(t, name)
			exit, codes := manifest(t, filepath.Join("attestation-sev", name))
			synthetic := x.AmdRootCaPem != ""
			pol := x.Policy
			j := merge(baseline, nil)
			if synthetic {
				j = merge(hardened, nil)
			}
			if regexp.MustCompile(`^27[0-4]`).MatchString(name) {
				j["platformInfo"] = hardenedPlatform
			}
			if pol.ExpectedMeasurementHex != "" {
				j["measurement"] = []string{pol.ExpectedMeasurementHex}
			}
			if pol.ExpectedReportDataHex != "" {
				j["reportData"] = jsonObj{"kind": "exact", "value": pol.ExpectedReportDataHex}
			}
			if pol.ExpectedHostDataHex != "" {
				j["hostData"] = pol.ExpectedHostDataHex
			}
			if pol.ExpectedIDKeyDigestHex != "" || pol.ExpectedAuthorKeyDigestHex != "" {
				pin := jsonObj{"idKeyDigest": strings.Repeat("00", 48)}
				if pol.ExpectedIDKeyDigestHex != "" {
					pin["idKeyDigest"] = pol.ExpectedIDKeyDigestHex
				}
				if pol.ExpectedAuthorKeyDigestHex != "" {
					pin["authorKeyDigest"] = pol.ExpectedAuthorKeyDigestHex
				}
				j["idBlock"] = pin
			}
			if pol.MinTcbBlSpl != nil || pol.MinTcbTeeSpl != nil || pol.MinTcbSnpSpl != nil || pol.MinTcbUcodeSpl != nil {
				f := jsonObj{}
				for k, v := range map[string]*int{"bootloader": pol.MinTcbBlSpl, "tee": pol.MinTcbTeeSpl, "snp": pol.MinTcbSnpSpl, "microcode": pol.MinTcbUcodeSpl} {
					if v != nil {
						f[k] = *v
					}
				}
				j["minTcb"] = jsonObj{"Milan": f, "Genoa": f, "Turin": f}
			}
			policy := policyFromJSON(t, j)
			input.Policy = policy
			result, err := verifierFor(input).Appraise(input)
			if exit == 0 {
				a := mustOK(t, result, err)
				var expected struct {
					Outputs struct {
						Measurement struct {
							Registers []string `json:"registers"`
						} `json:"measurement"`
					} `json:"outputs"`
				}
				readJSON(t, filepath.Join("attestation-sev", name, "expected.json"), &expected)
				if regs := expected.Outputs.Measurement.Registers; len(regs) > 0 && !bytesEqualHex(a.Identity.Measurement, regs[0]) {
					t.Fatalf("measurement %x != %s", a.Identity.Measurement, regs[0])
				}
			} else {
				e := mustFail(t, err, "expected rejection, got accept")
				if len(codes) > 0 && !contains(codes, tinfoilCode(e)) {
					t.Fatalf("code %s (%v) not in %v", tinfoilCode(e), e.Violations[0], codes)
				}
			}
		})
	}
}

func bytesEqualHex(b []byte, h string) bool { return strings.EqualFold(h, hex.EncodeToString(b)) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type quoteVector struct {
	Input struct {
		DocumentB64  string `json:"document_b64"`
		AmdRootCaPem string `json:"amd_root_ca_pem"`
	} `json:"input"`
	Expected struct {
		Accepted bool `json:"accepted"`
	} `json:"expected"`
}

type quoteDoc struct {
	CPUEvidence struct {
		ReportBase64 string `json:"report_base64"`
	} `json:"cpu_evidence"`
	Collateral []struct {
		ID   string `json:"id"`
		Data struct {
			VcekDerBase64 string `json:"vcek_der_base64"`
			CertChainPem  string `json:"cert_chain_pem"`
			CrlDerBase64  string `json:"crl_der_base64"`
		} `json:"data"`
	} `json:"collateral"`
}

func TestQuoteSev(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(vectors, "quote-sev", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	for _, file := range files {
		name := filepath.Base(file)
		t.Run("quote-sev/"+name, func(t *testing.T) {
			var vec quoteVector
			readJSON(t, filepath.Join("quote-sev", name), &vec)
			var doc quoteDoc
			if err := json.Unmarshal(fromBase64(t, vec.Input.DocumentB64), &doc); err != nil {
				t.Fatal(err)
			}
			var vcekB64, crlB64 string
			var chain [][]byte
			for _, c := range doc.Collateral {
				switch c.ID {
				case "vcek":
					vcekB64 = c.Data.VcekDerBase64
					if c.Data.CertChainPem != "" {
						chain = snp.PEMToDER(c.Data.CertChainPem)
					}
				case "crl":
					crlB64 = c.Data.CrlDerBase64
				}
			}
			// The v3 stage demands a VCEK, a 2-cert chain and a CRL; the core sees those as structural inputs.
			if vcekB64 == "" || len(chain) != 2 || crlB64 == "" {
				if vec.Expected.Accepted {
					t.Fatal("structural vector expected to be accepted")
				}
				return
			}
			ark := pemFirst(t, vec.Input.AmdRootCaPem)
			policy := policyFromJSON(t, merge(baseline, jsonObj{"requireCrl": true, "minReportVersion": 3}))
			result, err := snp.NewVerifier(snp.VerifierOptions{TrustedARKs: [][]byte{ark}}).Appraise(snp.AppraisalInput{
				Evidence:     fromBase64(t, doc.CPUEvidence.ReportBase64),
				Endorsements: snp.Endorsements{VCEK: fromBase64(t, vcekB64), ASK: chain[0], ARK: chain[1], CRL: fromBase64(t, crlB64)},
				Now:          time.Now().Unix(),
				Policy:       policy,
			})
			// This older synthetic happy vector has a v3 CRL issuer without keyUsage.
			// RFC 10007 requires cRLSign, so the hardened verifier must reject it.
			if name == "sev-happy.json" {
				if e := mustFail(t, err, name); e.Violations[0].Code != snp.CRLInvalid {
					t.Fatalf("want CRL_INVALID, got %v", e.Violations)
				}
				return
			}
			if (err == nil) != vec.Expected.Accepted {
				t.Fatalf("accepted=%v, want %v: %v (%v)", err == nil, vec.Expected.Accepted, err, result != nil)
			}
		})
	}
}
