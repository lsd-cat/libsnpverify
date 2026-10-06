package snpverify

// AppraisalPolicy definition, defaults and checks. CheckAppraisalPolicy returns all violations. Mirrors ts/src/policy.ts.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Bit is a per-bit rule. The zero value means "use the default" (SPEC §5).
type Bit string

const (
	BitRequired  Bit = "required"
	BitForbidden Bit = "forbidden"
	BitAny       Bit = "any"
)

// MeasurementPin is MeasurementAllowlist or MeasurementAny.
type MeasurementPin interface{ measurementPin() }
type MeasurementAllowlist [][]byte
type MeasurementAny struct{}

func (MeasurementAllowlist) measurementPin() {}
func (MeasurementAny) measurementPin()       {}

// ReportDataPin is ReportDataExact, ReportDataPrefix or ReportDataAny.
type ReportDataPin interface{ reportDataPin() }
type ReportDataExact []byte
type ReportDataPrefix []byte
type ReportDataAny struct{}

func (ReportDataExact) reportDataPin()  {}
func (ReportDataPrefix) reportDataPin() {}
func (ReportDataAny) reportDataPin()    {}

// IDBlockPin is IDBlockForbid, IDBlockAny or IDBlockPinned.
type IDBlockPin interface{ idBlockPin() }
type IDBlockForbid struct{}
type IDBlockAny struct{}
type IDBlockPinned struct {
	IDKeyDigest     []byte
	AuthorKeyDigest []byte // optional; all-zero means "no author key"
}

func (IDBlockForbid) idBlockPin() {}
func (IDBlockAny) idBlockPin()    {}
func (IDBlockPinned) idBlockPin() {}

type SigningKeyPolicy string

const (
	SigningKeyPolicyVCEK SigningKeyPolicy = "VCEK"
	SigningKeyPolicyVLEK SigningKeyPolicy = "VLEK"
	SigningKeyPolicyAny  SigningKeyPolicy = "any"
)

type ABIVersion struct{ Major, Minor int }

type GuestPolicyRules struct {
	Debug, MigrateMA, SMT, SingleSocket, CXLAllowed, MemAES256XTS, RAPLDisabled, CiphertextHidingDRAM, PageSwapDisabled Bit
	MinABI                                                                                                              *ABIVersion
}

type PlatformInfoRules struct {
	SMTEnabled, TSMEEnabled, ECCEnabled, RAPLDisabled, CiphertextHidingEnabled, AliasCheckComplete, IOMMUWriteSafe, TIOEnabled Bit
	AllowUnknownBits                                                                                                           bool
}

// AppraisalPolicy holds the Reference Values. A zero-valued or nil field means "use the default" (SPEC §5). Measurement is required.
type AppraisalPolicy struct {
	Measurement                MeasurementPin // REQUIRED
	Products                   []Product      // default Genoa, Turin
	SigningKey                 SigningKeyPolicy
	AllowMaskedChipID          bool
	ChipIDs                    [][]byte // CHIP_ID allowlist (VCEK, unmasked)
	EndorsementKeyFingerprints [][]byte // SHA-256(DER) allowlist of the leaf cert; reissuance changes it
	CSPIDs                     []string // exact CSP_ID allowlist for VLEK deployments
	RequireCRL                 bool

	GuestPolicy  GuestPolicyRules  // defaults: Debug, MigrateMA, CXLAllowed forbidden; rest any
	PlatformInfo PlatformInfoRules // defaults: all any; AllowUnknownBits false

	VMPL                     int // default 0; set VMPLAny to skip
	VMPLAny                  bool
	MinReportVersion         int // 0 means the default 2; 3 requires the CPUID product cross-check
	MinGuestSVN              int64
	MinTCB                   map[Product]TCBFloor // floor for current, committed, reported
	MinLaunchTCB             map[Product]TCBFloor // floor for launch; nil means MinTCB
	MinFirmware              FirmwareVersion
	AllowProvisionalFirmware bool
	MinLaunchMitVector       *uint64 // bits that must be set
	MinCurrentMitVector      *uint64

	ReportData                            ReportDataPin // default ReportDataAny
	HostData, FamilyID, ImageID, ReportID []byte
	IDBlock                               IDBlockPin // default IDBlockForbid
}

// ResolvedAppraisalPolicy is the AppraisalPolicy with defaults filled in; recorded in the result as AppraisalPolicy.
type ResolvedAppraisalPolicy struct {
	Products                              []Product
	SigningKey                            SigningKeyPolicy
	AllowMaskedChipID                     bool
	ChipIDs                               [][]byte
	EndorsementKeyFingerprints            [][]byte
	CSPIDs                                []string
	RequireCRL                            bool
	GuestPolicy                           GuestPolicyRules
	PlatformInfo                          PlatformInfoRules
	VMPL                                  int
	VMPLAny                               bool
	MinReportVersion                      int
	MinGuestSVN                           int64
	MinTCB, MinLaunchTCB                  map[Product]TCBFloor
	MinFirmware                           FirmwareVersion
	AllowProvisionalFirmware              bool
	MinLaunchMitVector                    *uint64
	MinCurrentMitVector                   *uint64
	Measurement                           MeasurementPin
	ReportData                            ReportDataPin
	HostData, FamilyID, ImageID, ReportID []byte
	IDBlock                               IDBlockPin
}

type invalidPolicy struct{ msg string }

func need(cond bool, msg string) {
	if !cond {
		panic(invalidPolicy{msg})
	}
}

func lenIs(v []byte, n int, what string) {
	need(v == nil || len(v) == n, fmt.Sprintf("policy.%s must be %d bytes", what, n))
}

func inRange(v int, lo, hi int) bool { return v >= lo && v <= hi }

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneFloors(m map[Product]TCBFloor) map[Product]TCBFloor {
	out := make(map[Product]TCBFloor, len(m))
	for k, v := range m {
		out[k] = TCBFloor{clonePtr(v.Bootloader), clonePtr(v.TEE), clonePtr(v.SNP), clonePtr(v.Microcode), clonePtr(v.FMC)}
	}
	return out
}

// ResolveAppraisalPolicy fills defaults and validates shapes. A malformed policy yields a POLICY_INVALID *Violation.
func ResolveAppraisalPolicy(p AppraisalPolicy) (ResolvedAppraisalPolicy, error) {
	return catchInvalid(func() ResolvedAppraisalPolicy { return resolveAppraisalPolicy(p) })
}

func resolveAppraisalPolicy(p AppraisalPolicy) ResolvedAppraisalPolicy {
	need(p.Measurement != nil, "policy.measurement is required: an allowlist or the explicit MeasurementAny")
	if m, ok := p.Measurement.(MeasurementAllowlist); ok {
		need(len(m) > 0, `policy.measurement must be a nonempty array or "any"`)
		for _, x := range m {
			need(len(x) == 48, "policy.measurement[] must be 48 bytes")
		}
	}
	switch rd := p.ReportData.(type) {
	case ReportDataExact:
		need(len(rd) == 64, "policy.reportData.value must be 64 bytes")
	case ReportDataPrefix:
		need(inRange(len(rd), 1, 64), "policy.reportData.value must be 1..64 bytes")
	}
	lenIs(p.HostData, 32, "hostData")
	lenIs(p.FamilyID, 16, "familyId")
	lenIs(p.ImageID, 16, "imageId")
	lenIs(p.ReportID, 32, "reportId")
	for _, c := range p.ChipIDs {
		need(len(c) == 64, "policy.chipIds[] must be 64 bytes")
	}
	for _, f := range p.EndorsementKeyFingerprints {
		need(len(f) == 32, "policy.endorsementKeyFingerprints[] must be 32 bytes")
	}
	if ib, ok := p.IDBlock.(IDBlockPinned); ok {
		need(len(ib.IDKeyDigest) == 48, "policy.idBlock.idKeyDigest must be 48 bytes")
		lenIs(ib.AuthorKeyDigest, 48, "idBlock.authorKeyDigest")
	}
	need(inRange(p.VMPL, 0, 3), "policy.vmpl must be 0..3")
	if p.CSPIDs != nil {
		need(len(p.CSPIDs) > 0 && !slices.Contains(p.CSPIDs, ""), "policy.cspIds must be nonempty strings")
	}
	if p.Products != nil {
		need(len(p.Products) > 0, "policy.products must be a nonempty Product list")
		for _, x := range p.Products {
			_, known := Products[x]
			need(known, "policy.products must be a nonempty Product list")
		}
	}
	need(p.SigningKey == "" || p.SigningKey == SigningKeyPolicyVCEK || p.SigningKey == SigningKeyPolicyVLEK || p.SigningKey == SigningKeyPolicyAny, "policy.signingKey is invalid")
	need(p.MinReportVersion == 0 || inRange(p.MinReportVersion, 2, 5), "policy.minReportVersion must be 2..5")
	need(p.MinGuestSVN >= 0 && p.MinGuestSVN <= 0xffffffff, "policy.minGuestSvn must be an integer in 0..4294967295")
	if abi := p.GuestPolicy.MinABI; abi != nil {
		need(inRange(abi.Major, 0, 255) && inRange(abi.Minor, 0, 255), "policy.guestPolicy.minAbi must be byte values")
	}
	for _, b := range []struct {
		what string
		bit  Bit
	}{
		{"guestPolicy.debug", p.GuestPolicy.Debug}, {"guestPolicy.migrateMa", p.GuestPolicy.MigrateMA}, {"guestPolicy.smt", p.GuestPolicy.SMT}, {"guestPolicy.singleSocket", p.GuestPolicy.SingleSocket},
		{"guestPolicy.cxlAllowed", p.GuestPolicy.CXLAllowed}, {"guestPolicy.memAes256Xts", p.GuestPolicy.MemAES256XTS}, {"guestPolicy.raplDisabled", p.GuestPolicy.RAPLDisabled},
		{"guestPolicy.ciphertextHidingDram", p.GuestPolicy.CiphertextHidingDRAM}, {"guestPolicy.pageSwapDisabled", p.GuestPolicy.PageSwapDisabled},
		{"platformInfo.smtEnabled", p.PlatformInfo.SMTEnabled}, {"platformInfo.tsmeEnabled", p.PlatformInfo.TSMEEnabled}, {"platformInfo.eccEnabled", p.PlatformInfo.ECCEnabled},
		{"platformInfo.raplDisabled", p.PlatformInfo.RAPLDisabled}, {"platformInfo.ciphertextHidingEnabled", p.PlatformInfo.CiphertextHidingEnabled},
		{"platformInfo.aliasCheckComplete", p.PlatformInfo.AliasCheckComplete}, {"platformInfo.iommuWriteSafe", p.PlatformInfo.IOMMUWriteSafe}, {"platformInfo.tioEnabled", p.PlatformInfo.TIOEnabled},
	} {
		need(b.bit == "" || b.bit == BitRequired || b.bit == BitForbidden || b.bit == BitAny, "policy."+b.what+" is not a Bit")
	}
	for _, t := range []struct {
		name  string
		table map[Product]TCBFloor
	}{{"minTcb", p.MinTCB}, {"minLaunchTcb", p.MinLaunchTCB}} {
		for product, floor := range t.table {
			_, known := Products[product]
			need(known, "policy."+t.name+" has an unknown product")
			for _, c := range []struct {
				part  string
				value *int
			}{{"bootloader", floor.Bootloader}, {"tee", floor.TEE}, {"snp", floor.SNP}, {"microcode", floor.Microcode}, {"fmc", floor.FMC}} {
				need(c.value == nil || inRange(*c.value, 0, 255), fmt.Sprintf("policy.%s.%s.%s must be an integer in 0..255", t.name, product, c.part))
			}
		}
	}
	need(inRange(p.MinFirmware.Major, 0, 255) && inRange(p.MinFirmware.Minor, 0, 255) && inRange(p.MinFirmware.Build, 0, 255), "policy.minFirmware must be byte values")

	g := p.GuestPolicy
	g.MinABI = clonePtr(g.MinABI)
	if g.Debug == "" {
		g.Debug = BitForbidden
	}
	if g.MigrateMA == "" {
		g.MigrateMA = BitForbidden
	}
	if g.CXLAllowed == "" {
		g.CXLAllowed = BitForbidden
	}
	if g.MemAES256XTS == "" {
		g.MemAES256XTS = BitAny
	}
	products := []Product{Genoa, Turin}
	if p.Products != nil {
		products = slices.Clone(p.Products)
	}
	signingKey := p.SigningKey
	if signingKey == "" {
		signingKey = SigningKeyPolicyVCEK
	}
	minReportVersion := p.MinReportVersion
	if minReportVersion == 0 {
		minReportVersion = 2
	}
	minTCB := cloneFloors(p.MinTCB)
	minLaunchTCB := minTCB
	if p.MinLaunchTCB != nil {
		minLaunchTCB = cloneFloors(p.MinLaunchTCB)
	}
	var measurement MeasurementPin = MeasurementAny{}
	if m, ok := p.Measurement.(MeasurementAllowlist); ok {
		measurement = MeasurementAllowlist(cloneAll(m))
	}
	var reportData ReportDataPin = ReportDataAny{}
	switch rd := p.ReportData.(type) {
	case ReportDataExact:
		reportData = ReportDataExact(slices.Clone(rd))
	case ReportDataPrefix:
		reportData = ReportDataPrefix(slices.Clone(rd))
	}
	var idBlock IDBlockPin = IDBlockForbid{}
	switch ib := p.IDBlock.(type) {
	case IDBlockPinned:
		idBlock = IDBlockPinned{slices.Clone(ib.IDKeyDigest), slices.Clone(ib.AuthorKeyDigest)}
	case IDBlockAny:
		idBlock = ib
	}
	var chipIDs, fingerprints [][]byte
	if p.ChipIDs != nil {
		chipIDs = cloneAll(p.ChipIDs)
	}
	if p.EndorsementKeyFingerprints != nil {
		fingerprints = cloneAll(p.EndorsementKeyFingerprints)
	}
	return ResolvedAppraisalPolicy{
		Products: products, SigningKey: signingKey, AllowMaskedChipID: p.AllowMaskedChipID,
		ChipIDs: chipIDs, EndorsementKeyFingerprints: fingerprints, CSPIDs: slices.Clone(p.CSPIDs),
		RequireCRL: p.RequireCRL, GuestPolicy: g, PlatformInfo: p.PlatformInfo,
		VMPL: p.VMPL, VMPLAny: p.VMPLAny, MinReportVersion: minReportVersion, MinGuestSVN: p.MinGuestSVN,
		MinTCB: minTCB, MinLaunchTCB: minLaunchTCB, MinFirmware: p.MinFirmware, AllowProvisionalFirmware: p.AllowProvisionalFirmware,
		MinLaunchMitVector: clonePtr(p.MinLaunchMitVector), MinCurrentMitVector: clonePtr(p.MinCurrentMitVector),
		Measurement: measurement, ReportData: reportData,
		HostData: slices.Clone(p.HostData), FamilyID: slices.Clone(p.FamilyID), ImageID: slices.Clone(p.ImageID), ReportID: slices.Clone(p.ReportID),
		IDBlock: idBlock,
	}
}

type AppraisalContext struct {
	TCB             TCBs
	CRLPresent      bool
	LeafFingerprint []byte
}

// CheckAppraisalPolicy checks a signature-verified report against the policy. An empty result means the policy is satisfied.
func CheckAppraisalPolicy(report *Report, ek *EndorsementKey, ctx AppraisalContext, policy AppraisalPolicy) []Violation {
	p, err := ResolveAppraisalPolicy(policy)
	if err != nil {
		return []Violation{*err.(*Violation)}
	}
	return checkResolvedAppraisalPolicy(report, ek, ctx, p)
}

func checkResolvedAppraisalPolicy(report *Report, ek *EndorsementKey, ctx AppraisalContext, p ResolvedAppraisalPolicy) []Violation {
	var v []Violation
	bad := func(code ErrorCode, message string, field ...string) {
		x := Violation{Code: code, Message: message}
		if len(field) > 0 {
			x.Field = field[0]
		}
		v = append(v, x)
	}
	bit := func(code ErrorCode, field string, want Bit, got bool) {
		if want == BitRequired && !got {
			bad(code, field+" is required but not set", field)
		}
		if want == BitForbidden && got {
			bad(code, field+" is set but forbidden", field)
		}
	}
	pin := func(code ErrorCode, field string, want, got []byte) {
		if want != nil && !equal(want, got) {
			bad(code, fmt.Sprintf("%s %s != expected %s", field, toHex(got), toHex(want)), field)
		}
	}

	// Who signed, on what.
	chipID := report.ChipID()
	if !slices.Contains(p.Products, ek.Product) {
		bad(PolicyProductNotAllowed, fmt.Sprintf("product %s not in %s", ek.Product, fmtProducts(p.Products)))
	}
	if p.SigningKey != SigningKeyPolicyAny && string(ek.Kind) != string(p.SigningKey) {
		bad(PolicySignerNotAllowed, fmt.Sprintf("signed by %s, policy requires %s", ek.Kind, p.SigningKey), "signer_info.signing_key")
	}
	if ek.Kind == VCEK && isZero(chipID) && !p.AllowMaskedChipID {
		bad(PolicyChipIDMasked, "CHIP_ID is masked; chip identity is not in the report", "chip_id") // VLEK reports carry no CHIP_ID by design
	}
	if p.ChipIDs != nil && !containsBytes(p.ChipIDs, chipID) {
		bad(PolicyChipIDNotAllowed, fmt.Sprintf("chip_id %s not in allowlist", toHex(chipID)), "chip_id")
	}
	if p.EndorsementKeyFingerprints != nil && !containsBytes(p.EndorsementKeyFingerprints, ctx.LeafFingerprint) {
		bad(PolicyChipIDNotAllowed, fmt.Sprintf("%s fingerprint %s not in allowlist", ek.Kind, toHex(ctx.LeafFingerprint)))
	}
	if p.CSPIDs != nil && (ek.Kind != VLEK || !slices.Contains(p.CSPIDs, ek.CSPID)) {
		bad(PolicySignerNotAllowed, "VLEK CSP_ID is not in the allowed list", "endorsement_key.csp_id")
	}
	if p.RequireCRL && !ctx.CRLPresent {
		bad(PolicyInvalid, "policy requires a CRL but none was supplied")
	}

	// Guest policy.
	gp, g := report.Policy, p.GuestPolicy
	bit(PolicyGuestPolicy, "guest_policy.debug", g.Debug, gp.Debug)
	bit(PolicyGuestPolicy, "guest_policy.migrate_ma", g.MigrateMA, gp.MigrateMA)
	bit(PolicyGuestPolicy, "guest_policy.smt", g.SMT, gp.SMT)
	bit(PolicyGuestPolicy, "guest_policy.single_socket", g.SingleSocket, gp.SingleSocket)
	bit(PolicyGuestPolicy, "guest_policy.cxl_allow", g.CXLAllowed, gp.CXLAllowed)
	bit(PolicyGuestPolicy, "guest_policy.mem_aes_256_xts", g.MemAES256XTS, gp.MemAES256XTS)
	bit(PolicyGuestPolicy, "guest_policy.rapl_dis", g.RAPLDisabled, gp.RAPLDisabled)
	bit(PolicyGuestPolicy, "guest_policy.ciphertext_hiding_dram", g.CiphertextHidingDRAM, gp.CiphertextHidingDRAM)
	bit(PolicyGuestPolicy, "guest_policy.page_swap_disable", g.PageSwapDisabled, gp.PageSwapDisabled)
	if abi := g.MinABI; abi != nil && (gp.ABIMajor < abi.Major || (gp.ABIMajor == abi.Major && gp.ABIMinor < abi.Minor)) {
		bad(PolicyABIVersion, fmt.Sprintf("guest_policy ABI %d.%d < %d.%d", gp.ABIMajor, gp.ABIMinor, abi.Major, abi.Minor), "guest_policy.abi_major")
	}

	// Platform info.
	pi, q := report.PlatformInfo, p.PlatformInfo
	bit(PolicyPlatformInfo, "platform_info.smt_en", q.SMTEnabled, pi.SMTEnabled)
	bit(PolicyPlatformInfo, "platform_info.tsme_en", q.TSMEEnabled, pi.TSMEEnabled)
	bit(PolicyPlatformInfo, "platform_info.ecc_en", q.ECCEnabled, pi.ECCEnabled)
	bit(PolicyPlatformInfo, "platform_info.rapl_dis", q.RAPLDisabled, pi.RAPLDisabled)
	bit(PolicyPlatformInfo, "platform_info.ciphertext_hiding_dram_en", q.CiphertextHidingEnabled, pi.CiphertextHidingEnabled)
	bit(PolicyPlatformInfo, "platform_info.alias_check_complete", q.AliasCheckComplete, pi.AliasCheckComplete)
	bit(PolicyPlatformInfo, "platform_info.iommu_write_safe", q.IOMMUWriteSafe, pi.IOMMUWriteSafe)
	bit(PolicyPlatformInfo, "platform_info.tio_en", q.TIOEnabled, pi.TIOEnabled)
	if !q.AllowUnknownBits && pi.Raw&^knownPlatformInfoBits != 0 {
		bad(PolicyPlatformInfo, fmt.Sprintf("platform_info has unknown bits: 0x%x", pi.Raw), "platform_info")
	}

	if report.Version < p.MinReportVersion {
		bad(PolicyInvalid, fmt.Sprintf("report version %d < required %d", report.Version, p.MinReportVersion), "version")
	}
	if !p.VMPLAny && report.VMPL != p.VMPL {
		bad(PolicyVMPL, fmt.Sprintf("vmpl %d != %d", report.VMPL, p.VMPL), "vmpl")
	}
	if int64(report.GuestSVN) < p.MinGuestSVN {
		bad(PolicyGuestSVN, fmt.Sprintf("guest_svn %d < %d", report.GuestSVN, p.MinGuestSVN), "guest_svn")
	}

	// TCB floors, per product.
	floor, launchFloor := p.MinTCB[ek.Product], p.MinLaunchTCB[ek.Product]
	for _, t := range []struct {
		name string
		tcb  TCBVersion
	}{{"current", ctx.TCB.Current}, {"committed", ctx.TCB.Committed}, {"reported", ctx.TCB.Reported}} {
		if !tcbAtLeast(t.tcb, floor) {
			bad(PolicyTCBOutOfDate, fmt.Sprintf("%s_tcb %s below minimum %s", t.name, fmtTCB(t.tcb), fmtFloor(floor)), t.name+"_tcb")
		}
	}
	if !tcbAtLeast(ctx.TCB.Launch, launchFloor) {
		bad(PolicyLaunchTCBOutOfDate, fmt.Sprintf("launch_tcb %s below minimum %s", fmtTCB(ctx.TCB.Launch), fmtFloor(launchFloor)), "launch_tcb")
	}
	if !tcbAtLeast(ctx.TCB.Current, floorOf(ek.TCB)) {
		bad(PolicyTCBOutOfDate, fmt.Sprintf("current_tcb %s below the endorsement key TCB %s", fmtTCB(ctx.TCB.Current), fmtTCB(ek.TCB)), "current_tcb")
	}

	// Firmware.
	for _, f := range []struct {
		name string
		fw   FirmwareVersion
	}{{"current", report.CurrentVersion}, {"committed", report.CommittedVersion}} {
		if !fwAtLeast(f.fw, p.MinFirmware) {
			bad(PolicyFirmwareVersion, fmt.Sprintf("%s firmware %d.%d.%d below minimum", f.name, f.fw.Major, f.fw.Minor, f.fw.Build), f.name+"_build")
		}
	}
	if !p.AllowProvisionalFirmware && (report.CurrentVersion != report.CommittedVersion || report.CurrentTCB != report.CommittedTCB) {
		bad(PolicyProvisionalFirmware, "committed firmware/TCB differs from current (uncommitted update; rollback possible)", "committed_tcb")
	}
	if m := p.MinLaunchMitVector; m != nil && deref(report.LaunchMitVector)&*m != *m {
		bad(PolicyMitigationVector, "launch_mit_vector lacks required bits", "launch_mit_vector")
	}
	if m := p.MinCurrentMitVector; m != nil && deref(report.CurrentMitVector)&*m != *m {
		bad(PolicyMitigationVector, "current_mit_vector lacks required bits", "current_mit_vector")
	}

	// Identity pins.
	measurement, reportData := report.Measurement(), report.ReportData()
	if m, ok := p.Measurement.(MeasurementAllowlist); ok && !containsBytes(m, measurement) {
		bad(PolicyMeasurementMismatch, fmt.Sprintf("measurement %s not in allowlist", toHex(measurement)), "measurement")
	}
	switch rd := p.ReportData.(type) {
	case ReportDataExact:
		pin(PolicyReportDataMismatch, "report_data", rd, reportData)
	case ReportDataPrefix:
		if !equal(rd, reportData[:len(rd)]) {
			bad(PolicyReportDataMismatch, fmt.Sprintf("report_data does not start with %s", toHex(rd)), "report_data")
		}
	}
	pin(PolicyHostDataMismatch, "host_data", p.HostData, report.HostData())
	pin(PolicyFamilyIDMismatch, "family_id", p.FamilyID, report.FamilyID())
	pin(PolicyImageIDMismatch, "image_id", p.ImageID, report.ImageID())
	pin(PolicyReportIDMismatch, "report_id", p.ReportID, report.ReportID())
	switch ib := p.IDBlock.(type) {
	case IDBlockForbid:
		if report.SignerInfo.AuthorKeyEnabled {
			bad(PolicyIDBlock, "author_key_en set but ID block forbidden", "signer_info.author_key_en")
		}
		if !isZero(report.IDKeyDigest()) {
			bad(PolicyIDBlock, "id_key_digest nonzero but ID block forbidden", "id_key_digest")
		}
		if !isZero(report.AuthorKeyDigest()) {
			bad(PolicyIDBlock, "author_key_digest nonzero but ID block forbidden", "author_key_digest")
		}
	case IDBlockPinned:
		pin(PolicyIDBlock, "id_key_digest", ib.IDKeyDigest, report.IDKeyDigest())
		if ib.AuthorKeyDigest != nil {
			wantAuthor := !isZero(ib.AuthorKeyDigest) // all-zero pin means "no author key"
			if report.SignerInfo.AuthorKeyEnabled != wantAuthor {
				bad(PolicyIDBlock, fmt.Sprintf("author_key_en is %d, pinned author_key_digest implies %d", b2i(report.SignerInfo.AuthorKeyEnabled), b2i(wantAuthor)), "author_key_digest")
			}
			pin(PolicyIDBlock, "author_key_digest", ib.AuthorKeyDigest, report.AuthorKeyDigest())
		}
	}
	return v
}

func deref(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fwAtLeast(fw, min FirmwareVersion) bool {
	a, b := [3]int{fw.Major, fw.Minor, fw.Build}, [3]int{min.Major, min.Minor, min.Build}
	for i := range 3 {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return true
}

func fmtProducts(ps []Product) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = string(p)
	}
	return "[" + strings.Join(s, ", ") + "]"
}

func fmtTCB(t TCBVersion) string {
	s := fmt.Sprintf("bl=%d tee=%d snp=%d ucode=%d", t.Bootloader, t.TEE, t.SNP, t.Microcode)
	if t.FMC != nil {
		s += " fmc=" + strconv.Itoa(*t.FMC)
	}
	return s
}

func fmtFloor(t TCBFloor) string {
	star := func(x *int) string {
		if x == nil {
			return "*"
		}
		return strconv.Itoa(*x)
	}
	s := fmt.Sprintf("bl=%s tee=%s snp=%s ucode=%s", star(t.Bootloader), star(t.TEE), star(t.SNP), star(t.Microcode))
	if t.FMC != nil {
		s += " fmc=" + strconv.Itoa(*t.FMC)
	}
	return s
}
