package snpverify_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	snp "github.com/lsd-cat/snpverify/go"
)

// vectors is the shared test-vector directory; override with SNP_VECTORS_DIR.
var vectors = func() string {
	if d := os.Getenv("SNP_VECTORS_DIR"); d != "" {
		return d
	}
	return "../vectors"
}()

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readJSON(t *testing.T, name string, into any) {
	t.Helper()
	if err := json.Unmarshal(readFile(t, name), into); err != nil {
		t.Fatal(err)
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fromBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pemFirst(t *testing.T, pem string) []byte {
	t.Helper()
	ders := snp.PEMToDER(pem)
	if len(ders) == 0 {
		t.Fatal("no PEM block")
	}
	return ders[0]
}

// with returns a copy of i with the Evidence, one Endorsement, the time or the policy replaced.
func with(i snp.AppraisalInput, edit func(i *snp.AppraisalInput)) snp.AppraisalInput {
	edit(&i)
	return i
}

func flip(b []byte, at int) []byte {
	c := bytes.Clone(b)
	c[at] ^= 1
	return c
}

func thisUpdate(t *testing.T, crl []byte) int64 {
	t.Helper()
	parsed, err := snp.ParseCRL(crl)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.ThisUpdate
}

// mustFail returns the AppraisalError or fails the test.
func mustFail(t *testing.T, err error, what string) *snp.AppraisalError {
	t.Helper()
	var ae *snp.AppraisalError
	if !errors.As(err, &ae) {
		t.Fatalf("%s: expected rejection, got %v", what, err)
	}
	return ae
}

func mustOK(t *testing.T, r *snp.AttestationResult, err error) *snp.AttestationResult {
	t.Helper()
	if err != nil {
		t.Fatalf("expected accept: %v", err)
	}
	return r
}

// jsonEqual compares two values by their JSON encoding.
func jsonEqual(t *testing.T, want, got any) {
	t.Helper()
	norm := func(v any) (any, string) {
		b, err := json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out, string(b)
	}
	w, ws := norm(want)
	g, gs := norm(got)
	if !reflect.DeepEqual(w, g) {
		t.Fatalf("JSON mismatch\nwant:\n%s\ngot:\n%s", ws, gs)
	}
}
