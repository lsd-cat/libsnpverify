package snpverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"math/big"
)

// CryptoProvider is the crypto interface. Mirrors ts/src/crypto.ts.
type CryptoProvider interface {
	// VerifyRSAPSS verifies RSASSA-PSS with SHA-384 and MGF1-SHA-384 over msg, public key as SPKI DER.
	VerifyRSAPSS(spki, msg, sig []byte, saltLength int) bool
	// VerifyECDSAP384 verifies ECDSA P-384 with SHA-384, r and s as 48-byte big-endian integers, public key as SPKI DER.
	VerifyECDSAP384(spki, msg, r, s []byte) bool
	SHA256(data []byte) []byte
}

// StdCrypto is the default provider, backed by the Go standard library.
type StdCrypto struct{}

func (StdCrypto) VerifyRSAPSS(spki, msg, sig []byte, saltLength int) bool {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 4096 {
		return false
	}
	h := sha512.Sum384(msg)
	return rsa.VerifyPSS(key, crypto.SHA384, h[:], sig, &rsa.PSSOptions{SaltLength: saltLength, Hash: crypto.SHA384}) == nil
}

func (StdCrypto) VerifyECDSAP384(spki, msg, r, s []byte) bool {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return false
	}
	h := sha512.Sum384(msg)
	return ecdsa.Verify(key, h[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
}

func (StdCrypto) SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
