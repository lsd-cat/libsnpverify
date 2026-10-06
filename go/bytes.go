package snpverify

// Byte helpers. Mirrors ts/src/bytes.ts; hex, base64 and little-endian reads come from the standard library.

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/pem"
)

func toHex(b []byte) string { return hex.EncodeToString(b) }

// equal compares in constant time; different lengths are unequal.
func equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// PEMToDER extracts all DER blobs from a PEM string, in order.
func PEMToDER(s string) [][]byte {
	var out [][]byte
	rest := []byte(s)
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, block.Bytes)
		rest = r
	}
}
