package snpverify

// ATTESTATION_REPORT parsing (AMD 56860), report versions 2 to 5. Mirrors ts/src/report.ts.
// TCBs stay raw; decodeTCB() takes the product layout established by the chain stage.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ReportSize = 0x4a0
	SignedSize = 0x2a0
)

type Product string

const (
	Milan  Product = "Milan"
	Genoa  Product = "Genoa"
	Turin  Product = "Turin"
	Venice Product = "Venice"
)

type TCBLayout string

const (
	TCBLayoutV0 TCBLayout = "v0"
	TCBLayoutV1 TCBLayout = "v1"
	TCBLayoutV2 TCBLayout = "v2"
)

type SigningKey string

const (
	VCEK SigningKey = "VCEK"
	VLEK SigningKey = "VLEK"
)

// TCBVersion holds the decoded security patch levels. FMC is nil on products without it (Milan, Genoa).
type TCBVersion struct {
	Bootloader, TEE, SNP, Microcode int
	FMC                             *int
}

// TCBFloor is a partial minimum: a nil component is not constrained. Build literals with new: TCBFloor{SNP: new(23)}.
type TCBFloor struct{ Bootloader, TEE, SNP, Microcode, FMC *int }

type GuestPolicy struct {
	Raw                                                                uint64
	ABIMajor, ABIMinor                                                 int
	SMT, MigrateMA, Debug, SingleSocket, CXLAllowed                    bool
	MemAES256XTS, RAPLDisabled, CiphertextHidingDRAM, PageSwapDisabled bool
}

type PlatformInfo struct {
	Raw                                                                     uint64
	SMTEnabled, TSMEEnabled, ECCEnabled, RAPLDisabled                       bool
	CiphertextHidingEnabled, AliasCheckComplete, IOMMUWriteSafe, TIOEnabled bool
}

type SignerInfo struct {
	SigningKey                    SigningKey
	MaskChipKey, AuthorKeyEnabled bool
}

type FirmwareVersion struct{ Major, Minor, Build int }
type CPUID struct{ Family, Model, Stepping int }

// ECDSASignature: R and S big-endian, 48 bytes each.
type ECDSASignature struct{ R, S []byte }

// Report is immutable: it owns a private copy of the report bytes and every byte-valued accessor returns a fresh copy.
type Report struct {
	bytes                             []byte
	Version                           int
	GuestSVN                          uint32
	Policy                            GuestPolicy
	VMPL                              int
	CurrentTCB                        uint64
	PlatformInfo                      PlatformInfo
	SignerInfo                        SignerInfo
	ReportedTCB                       uint64
	CPUID                             *CPUID // report version 3 and later
	CommittedTCB                      uint64
	CurrentVersion, CommittedVersion  FirmwareVersion
	LaunchTCB                         uint64
	LaunchMitVector, CurrentMitVector *uint64 // report version 5 and later
	sigR, sigS                        []byte
}

func (r *Report) Raw() []byte             { return bytes.Clone(r.bytes) }
func (r *Report) FamilyID() []byte        { return bytes.Clone(r.bytes[0x10:0x20]) }
func (r *Report) ImageID() []byte         { return bytes.Clone(r.bytes[0x20:0x30]) }
func (r *Report) ReportData() []byte      { return bytes.Clone(r.bytes[0x50:0x90]) }
func (r *Report) Measurement() []byte     { return bytes.Clone(r.bytes[0x90:0xc0]) }
func (r *Report) HostData() []byte        { return bytes.Clone(r.bytes[0xc0:0xe0]) }
func (r *Report) IDKeyDigest() []byte     { return bytes.Clone(r.bytes[0xe0:0x110]) }
func (r *Report) AuthorKeyDigest() []byte { return bytes.Clone(r.bytes[0x110:0x140]) }
func (r *Report) ReportID() []byte        { return bytes.Clone(r.bytes[0x140:0x160]) }
func (r *Report) ReportIDMA() []byte      { return bytes.Clone(r.bytes[0x160:0x180]) }
func (r *Report) ChipID() []byte          { return bytes.Clone(r.bytes[0x1a0:0x1e0]) }
func (r *Report) SignedBytes() []byte     { return bytes.Clone(r.bytes[:SignedSize]) }
func (r *Report) Signature() ECDSASignature {
	return ECDSASignature{bytes.Clone(r.sigR), bytes.Clone(r.sigS)}
}

func mbz(b []byte, s, e int) {
	if !isZero(b[s:e]) {
		fail(ReportMalformed, fmt.Sprintf("reserved bytes 0x%x..0x%x not zero", s, e))
	}
}

func bit(raw uint64, n int) bool { return (raw>>n)&1 == 1 }

func decodeGuestPolicy(raw uint64) GuestPolicy {
	if !bit(raw, 17) {
		fail(ReportMalformed, "guest_policy bit 17 must be 1", "guest_policy")
	}
	if raw>>26 != 0 {
		fail(ReportMalformed, "guest_policy bits 63:26 must be 0", "guest_policy")
	}
	return GuestPolicy{Raw: raw, ABIMinor: int(raw & 0xff), ABIMajor: int((raw >> 8) & 0xff), SMT: bit(raw, 16), MigrateMA: bit(raw, 18), Debug: bit(raw, 19),
		SingleSocket: bit(raw, 20), CXLAllowed: bit(raw, 21), MemAES256XTS: bit(raw, 22), RAPLDisabled: bit(raw, 23), CiphertextHidingDRAM: bit(raw, 24), PageSwapDisabled: bit(raw, 25)}
}

// knownPlatformInfoBits are the bits this library knows. Unknown set bits are a policy matter (AppraisalPolicy.PlatformInfo.AllowUnknownBits).
const knownPlatformInfoBits uint64 = 0xff

func decodePlatformInfo(raw uint64) PlatformInfo {
	return PlatformInfo{Raw: raw, SMTEnabled: bit(raw, 0), TSMEEnabled: bit(raw, 1), ECCEnabled: bit(raw, 2), RAPLDisabled: bit(raw, 3), CiphertextHidingEnabled: bit(raw, 4),
		AliasCheckComplete: bit(raw, 5), IOMMUWriteSafe: bit(raw, 6), TIOEnabled: bit(raw, 7)}
}

func decodeSignerInfo(raw uint32) SignerInfo {
	if raw>>5 != 0 {
		fail(ReportMalformed, "signer_info bits 31:5 must be 0", "signer_info")
	}
	key := (raw >> 2) & 7
	if key != 0 && key != 1 {
		fail(ReportMalformed, fmt.Sprintf("signer_info.signing_key %d is not VCEK or VLEK", key), "signer_info.signing_key")
	}
	kind := VCEK
	if key == 1 {
		kind = VLEK
	}
	return SignerInfo{SigningKey: kind, MaskChipKey: raw&2 != 0, AuthorKeyEnabled: raw&1 != 0}
}

func decodeTCB(raw uint64, layout TCBLayout) TCBVersion {
	byteAt := func(n int) int { return int((raw >> (8 * n)) & 0xff) }
	switch layout {
	case TCBLayoutV0:
		if raw&0x0000ffffffff0000 != 0 {
			fail(ReportMalformed, "TCB reserved bytes 2..5 not zero")
		}
		return TCBVersion{Bootloader: byteAt(0), TEE: byteAt(1), SNP: byteAt(6), Microcode: byteAt(7)}
	case TCBLayoutV1:
		if raw&0x00ffffff00000000 != 0 {
			fail(ReportMalformed, "Turin TCB reserved bytes 4..6 not zero")
		}
		fmc := byteAt(0)
		return TCBVersion{Bootloader: byteAt(1), TEE: byteAt(2), SNP: byteAt(3), Microcode: byteAt(7), FMC: &fmc}
	default:
		fail(ReportMalformed, "Venice TCB layout not supported yet")
		return TCBVersion{}
	}
}

func fmcOf(t TCBVersion) int {
	if t.FMC == nil {
		return 0
	}
	return *t.FMC
}

func atLeast(a int, min *int) bool { return min == nil || a >= *min }

func tcbAtLeast(a TCBVersion, min TCBFloor) bool {
	return atLeast(a.Bootloader, min.Bootloader) && atLeast(a.TEE, min.TEE) && atLeast(a.SNP, min.SNP) && atLeast(a.Microcode, min.Microcode) && atLeast(fmcOf(a), min.FMC)
}

func floorOf(t TCBVersion) TCBFloor {
	return TCBFloor{new(t.Bootloader), new(t.TEE), new(t.SNP), new(t.Microcode), t.FMC}
}

func tcbEqual(a, b TCBVersion) bool {
	return a.Bootloader == b.Bootloader && a.TEE == b.TEE && a.SNP == b.SNP && a.Microcode == b.Microcode && fmcOf(a) == fmcOf(b)
}

func le72ToBe48(b []byte, off int, what string) []byte {
	if !isZero(b[off+48 : off+72]) {
		fail(ReportMalformed, fmt.Sprintf("signature %s exceeds 384 bits", what), "signature")
	}
	out := make([]byte, 48)
	for i := range out {
		out[i] = b[off+47-i]
	}
	return out
}

// ParseReport parses and structurally validates an attestation report. The error, when non-nil, is a *Violation.
func ParseReport(data []byte) (*Report, error) {
	return stage(func() *Report {
		if len(data) != ReportSize {
			fail(ReportTruncated, fmt.Sprintf("report is %d bytes, want %d", len(data), ReportSize))
		}
		data = bytes.Clone(data)
		le := binary.LittleEndian
		version := int(le.Uint32(data[0x00:]))
		if version < 2 || version > 5 {
			fail(ReportVersionUnsupported, fmt.Sprintf("report version %d", version), "version")
		}
		vmpl := le.Uint32(data[0x30:])
		if vmpl == 0xffffffff {
			fail(ReportHostRequested, "report was requested by the host (VMPL=0xFFFFFFFF), not by the guest", "vmpl")
		}
		if vmpl > 3 {
			fail(ReportMalformed, fmt.Sprintf("vmpl %d out of range 0..3", vmpl), "vmpl")
		}
		signatureAlgo := le.Uint32(data[0x34:])
		if signatureAlgo != 1 {
			fail(ReportSignatureAlgoUnsupported, fmt.Sprintf("signature_algo %d", signatureAlgo), "signature_algo")
		}
		mbz(data, 0x4c, 0x50)
		if version >= 3 {
			mbz(data, 0x18b, 0x1a0)
		} else {
			mbz(data, 0x188, 0x1a0)
		}
		mbz(data, 0x1eb, 0x1ec)
		mbz(data, 0x1ef, 0x1f0)
		if version < 5 {
			mbz(data, 0x1f8, 0x208)
		}
		mbz(data, 0x208, SignedSize)
		mbz(data, SignedSize+144, ReportSize)
		r := &Report{
			bytes:            data,
			Version:          version,
			GuestSVN:         le.Uint32(data[0x04:]),
			Policy:           decodeGuestPolicy(le.Uint64(data[0x08:])),
			VMPL:             int(vmpl),
			CurrentTCB:       le.Uint64(data[0x38:]),
			PlatformInfo:     decodePlatformInfo(le.Uint64(data[0x40:])),
			SignerInfo:       decodeSignerInfo(le.Uint32(data[0x48:])),
			ReportedTCB:      le.Uint64(data[0x180:]),
			CommittedTCB:     le.Uint64(data[0x1e0:]),
			CurrentVersion:   FirmwareVersion{Build: int(data[0x1e8]), Minor: int(data[0x1e9]), Major: int(data[0x1ea])},
			CommittedVersion: FirmwareVersion{Build: int(data[0x1ec]), Minor: int(data[0x1ed]), Major: int(data[0x1ee])},
			LaunchTCB:        le.Uint64(data[0x1f0:]),
			sigR:             le72ToBe48(data, SignedSize, "r"),
			sigS:             le72ToBe48(data, SignedSize+72, "s"),
		}
		if version >= 3 {
			r.CPUID = &CPUID{Family: int(data[0x188]), Model: int(data[0x189]), Stepping: int(data[0x18a])}
		}
		if version >= 5 {
			launch, current := le.Uint64(data[0x1f8:]), le.Uint64(data[0x200:])
			r.LaunchMitVector, r.CurrentMitVector = &launch, &current
		}
		return r
	})
}
