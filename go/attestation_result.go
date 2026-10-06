package snpverify

// The result record (SPEC §6) and its JSON-shaped projection. Mirrors ts/src/attestation-result.ts.

import "strconv"

type CertSummary struct {
	SHA256, Serial      []byte
	SubjectCN           string
	NotBefore, NotAfter int64
}

type EndorsementKeySummary struct {
	Cert  CertSummary
	Kind  SigningKey
	HWID  []byte // VCEK only
	CSPID string // VLEK only
	TCB   TCBVersion
}

type Identity struct {
	ChipID, ReportID, ReportIDMA, Measurement, HostData, ReportData, FamilyID, ImageID []byte
	GuestSVN                                                                           uint32
	VMPL                                                                               int
}

type Platform struct {
	Product                            Product
	ProductName                        string
	CPUID                              *CPUID
	GuestPolicy                        GuestPolicy
	PlatformInfo                       PlatformInfo
	TCB                                TCBs
	FirmwareCurrent, FirmwareCommitted FirmwareVersion
	LaunchMitVector, CurrentMitVector  *uint64
	Signer                             SignerInfo
	IDKeyDigest, AuthorKeyDigest       []byte
}

type EvidenceSummary struct {
	ReportVersion int
	ReportSHA256  []byte
	Signature     ECDSASignature
}

type EndorsementsSummary struct {
	EndorsementKey EndorsementKeySummary
	ASK, ARK       CertSummary
	CRL            *CRLInfo
}

type AttestationResult struct {
	Identity        Identity
	Platform        Platform
	Evidence        EvidenceSummary
	Endorsements    EndorsementsSummary
	AppraisalPolicy ResolvedAppraisalPolicy
	AppraisedAt     int64
}

func buildAttestationResult(report *Report, chain *Chain, tcb TCBs, policy ResolvedAppraisalPolicy, now int64, crypto CryptoProvider) *AttestationResult {
	sum := func(c *Certificate) CertSummary {
		return CertSummary{crypto.SHA256(c.DER()), c.Serial(), c.SubjectCN(), c.NotBefore, c.NotAfter}
	}
	ek := chain.Leaf
	return &AttestationResult{
		Identity: Identity{report.ChipID(), report.ReportID(), report.ReportIDMA(), report.Measurement(), report.HostData(), report.ReportData(), report.FamilyID(), report.ImageID(), report.GuestSVN, report.VMPL},
		Platform: Platform{ek.Product, ek.ProductName, report.CPUID, report.Policy, report.PlatformInfo, tcb, report.CurrentVersion, report.CommittedVersion,
			report.LaunchMitVector, report.CurrentMitVector, report.SignerInfo, report.IDKeyDigest(), report.AuthorKeyDigest()},
		Evidence:        EvidenceSummary{report.Version, crypto.SHA256(report.Raw()), report.Signature()},
		Endorsements:    EndorsementsSummary{EndorsementKeySummary{sum(ek.Cert), ek.Kind, ek.HWID(), ek.CSPID, ek.TCB}, sum(chain.Intermediate), sum(chain.Root), chain.CRL},
		AppraisalPolicy: policy,
		AppraisedAt:     now,
	}
}

// J is a JSON object produced by ToJSON.
type J = map[string]any

// ToJSON is the JSON-shaped projection: bytes as lowercase hex, unsigned 64-bit as decimal strings, enums as names, absent values omitted.
// Same keys as the TypeScript and Kotlin ports.
func ToJSON(a *AttestationResult) J {
	return filterNilsDeep(J{
		"identity": J{
			"chipId": toHex(a.Identity.ChipID), "reportId": toHex(a.Identity.ReportID), "reportIdMa": toHex(a.Identity.ReportIDMA), "measurement": toHex(a.Identity.Measurement),
			"hostData": toHex(a.Identity.HostData), "reportData": toHex(a.Identity.ReportData), "familyId": toHex(a.Identity.FamilyID), "imageId": toHex(a.Identity.ImageID),
			"guestSvn": a.Identity.GuestSVN, "vmpl": a.Identity.VMPL,
		},
		"platform": J{
			"product": a.Platform.Product, "productName": a.Platform.ProductName, "cpuid": cpuidJSON(a.Platform.CPUID),
			"guestPolicy":  guestPolicyJSON(a.Platform.GuestPolicy),
			"platformInfo": platformInfoJSON(a.Platform.PlatformInfo),
			"tcb":          J{"current": tcbJSON(a.Platform.TCB.Current), "committed": tcbJSON(a.Platform.TCB.Committed), "reported": tcbJSON(a.Platform.TCB.Reported), "launch": tcbJSON(a.Platform.TCB.Launch)},
			"firmware":     J{"current": fwJSON(a.Platform.FirmwareCurrent), "committed": fwJSON(a.Platform.FirmwareCommitted)},
			"mitVectors":   mitVectorsJSON(a.Platform.LaunchMitVector, a.Platform.CurrentMitVector),
			"signer":       J{"signingKey": a.Platform.Signer.SigningKey, "maskChipKey": a.Platform.Signer.MaskChipKey, "authorKeyEnabled": a.Platform.Signer.AuthorKeyEnabled},
			"idKeyDigest":  toHex(a.Platform.IDKeyDigest), "authorKeyDigest": toHex(a.Platform.AuthorKeyDigest),
		},
		"evidence": J{"reportVersion": a.Evidence.ReportVersion, "reportSha256": toHex(a.Evidence.ReportSHA256), "signature": J{"r": toHex(a.Evidence.Signature.R), "s": toHex(a.Evidence.Signature.S)}},
		"endorsements": J{
			"endorsementKey": endorsementKeyJSON(a.Endorsements.EndorsementKey),
			"ask":            certJSON(a.Endorsements.ASK), "ark": certJSON(a.Endorsements.ARK),
			"crl": crlJSON(a.Endorsements.CRL),
		},
		"appraisalPolicy": AppraisalPolicyToJSON(a.AppraisalPolicy),
		"appraisedAt":     a.AppraisedAt,
	})
}

// AppraisalPolicyToJSON is the JSON form of a resolved policy; AppraisalPolicyFromJSON reads it back.
func AppraisalPolicyToJSON(p ResolvedAppraisalPolicy) J {
	return filterNilsDeep(J{
		"products": productsJSON(p.Products), "signingKey": signingKeyJSON(p.SigningKey), "allowMaskedChipId": p.AllowMaskedChipID,
		"chipIds": hexList(p.ChipIDs), "endorsementKeyFingerprints": hexList(p.EndorsementKeyFingerprints), "cspIds": stringList(p.CSPIDs), "requireCrl": p.RequireCRL,
		"guestPolicy": J{
			"debug": bitJSON(p.GuestPolicy.Debug), "migrateMa": bitJSON(p.GuestPolicy.MigrateMA), "smt": bitJSON(p.GuestPolicy.SMT), "singleSocket": bitJSON(p.GuestPolicy.SingleSocket),
			"cxlAllowed": bitJSON(p.GuestPolicy.CXLAllowed), "memAes256Xts": bitJSON(p.GuestPolicy.MemAES256XTS), "raplDisabled": bitJSON(p.GuestPolicy.RAPLDisabled),
			"ciphertextHidingDram": bitJSON(p.GuestPolicy.CiphertextHidingDRAM), "pageSwapDisabled": bitJSON(p.GuestPolicy.PageSwapDisabled), "minAbi": abiJSON(p.GuestPolicy.MinABI),
		},
		"platformInfo": J{
			"smtEnabled": bitJSON(p.PlatformInfo.SMTEnabled), "tsmeEnabled": bitJSON(p.PlatformInfo.TSMEEnabled), "eccEnabled": bitJSON(p.PlatformInfo.ECCEnabled), "raplDisabled": bitJSON(p.PlatformInfo.RAPLDisabled),
			"ciphertextHidingEnabled": bitJSON(p.PlatformInfo.CiphertextHidingEnabled), "aliasCheckComplete": bitJSON(p.PlatformInfo.AliasCheckComplete), "iommuWriteSafe": bitJSON(p.PlatformInfo.IOMMUWriteSafe),
			"tioEnabled": bitJSON(p.PlatformInfo.TIOEnabled), "allowUnknownBits": p.PlatformInfo.AllowUnknownBits,
		},
		"vmpl": vmplJSON(p.VMPL, p.VMPLAny), "minReportVersion": p.MinReportVersion, "minGuestSvn": p.MinGuestSVN,
		"minTcb": floorsJSON(p.MinTCB), "minLaunchTcb": floorsJSON(p.MinLaunchTCB), "minFirmware": fwJSON(p.MinFirmware), "allowProvisionalFirmware": p.AllowProvisionalFirmware,
		"minLaunchMitVector": u64JSON(p.MinLaunchMitVector), "minCurrentMitVector": u64JSON(p.MinCurrentMitVector),
		"measurement": measurementJSON(p.Measurement), "reportData": reportDataJSON(p.ReportData),
		"hostData": hexOpt(p.HostData), "familyId": hexOpt(p.FamilyID), "imageId": hexOpt(p.ImageID), "reportId": hexOpt(p.ReportID),
		"idBlock": idBlockJSON(p.IDBlock),
	})
}

func productsJSON(ps []Product) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

func hexOpt(b []byte) any {
	if b == nil {
		return nil
	}
	return toHex(b)
}

func hexList(bs [][]byte) any {
	if bs == nil {
		return nil
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = toHex(b)
	}
	return out
}

func stringList(s []string) any {
	if s == nil {
		return nil
	}
	return s
}

func u64JSON(v *uint64) any {
	if v == nil {
		return nil
	}
	return strconv.FormatUint(*v, 10)
}

func bitJSON(b Bit) any {
	if b == "" {
		return nil
	}
	return string(b)
}

func vmplJSON(vmpl int, anyVMPL bool) any {
	if anyVMPL {
		return "any"
	}
	return vmpl
}

func signingKeyJSON(s SigningKeyPolicy) string { return string(s) }

func abiJSON(a *ABIVersion) any {
	if a == nil {
		return nil
	}
	return J{"major": a.Major, "minor": a.Minor}
}

func cpuidJSON(c *CPUID) any {
	if c == nil {
		return nil
	}
	return J{"family": c.Family, "model": c.Model, "stepping": c.Stepping}
}

func mitVectorsJSON(launch, current *uint64) any {
	if launch == nil {
		return nil
	}
	return J{"launch": strconv.FormatUint(*launch, 10), "current": strconv.FormatUint(deref(current), 10)}
}

func crlJSON(c *CRLInfo) any {
	if c == nil {
		return nil
	}
	return J{"thisUpdate": c.ThisUpdate, "nextUpdate": c.NextUpdate, "revokedCount": c.RevokedCount}
}

func guestPolicyJSON(g GuestPolicy) J {
	return J{"raw": strconv.FormatUint(g.Raw, 10), "abiMajor": g.ABIMajor, "abiMinor": g.ABIMinor, "smt": g.SMT, "migrateMa": g.MigrateMA, "debug": g.Debug, "singleSocket": g.SingleSocket,
		"cxlAllowed": g.CXLAllowed, "memAes256Xts": g.MemAES256XTS, "raplDisabled": g.RAPLDisabled, "ciphertextHidingDram": g.CiphertextHidingDRAM, "pageSwapDisabled": g.PageSwapDisabled}
}

func platformInfoJSON(p PlatformInfo) J {
	return J{"raw": strconv.FormatUint(p.Raw, 10), "smtEnabled": p.SMTEnabled, "tsmeEnabled": p.TSMEEnabled, "eccEnabled": p.ECCEnabled, "raplDisabled": p.RAPLDisabled,
		"ciphertextHidingEnabled": p.CiphertextHidingEnabled, "aliasCheckComplete": p.AliasCheckComplete, "iommuWriteSafe": p.IOMMUWriteSafe, "tioEnabled": p.TIOEnabled}
}

func tcbJSON(t TCBVersion) J {
	j := J{"bootloader": t.Bootloader, "tee": t.TEE, "snp": t.SNP, "microcode": t.Microcode}
	if t.FMC != nil {
		j["fmc"] = *t.FMC
	}
	return j
}

func floorJSON(t TCBFloor) J {
	j := J{}
	for k, v := range map[string]*int{"bootloader": t.Bootloader, "tee": t.TEE, "snp": t.SNP, "microcode": t.Microcode, "fmc": t.FMC} {
		if v != nil {
			j[k] = *v
		}
	}
	return j
}

func floorsJSON(m map[Product]TCBFloor) J {
	j := J{}
	for k, v := range m {
		j[string(k)] = floorJSON(v)
	}
	return j
}

func fwJSON(f FirmwareVersion) J { return J{"major": f.Major, "minor": f.Minor, "build": f.Build} }

func certJSON(c CertSummary) J {
	return J{"sha256": toHex(c.SHA256), "serial": toHex(c.Serial), "subjectCn": c.SubjectCN, "notBefore": c.NotBefore, "notAfter": c.NotAfter}
}

func endorsementKeyJSON(e EndorsementKeySummary) J {
	j := certJSON(e.Cert)
	j["kind"] = string(e.Kind)
	j["hwid"] = hexOpt(e.HWID)
	j["tcb"] = tcbJSON(e.TCB)
	if e.CSPID != "" {
		j["cspId"] = e.CSPID
	}
	return j
}

func measurementJSON(m MeasurementPin) any {
	if a, ok := m.(MeasurementAllowlist); ok {
		return hexList(a)
	}
	return "any"
}

func reportDataJSON(r ReportDataPin) J {
	switch v := r.(type) {
	case ReportDataExact:
		return J{"kind": "exact", "value": toHex(v)}
	case ReportDataPrefix:
		return J{"kind": "prefix", "value": toHex(v)}
	}
	return J{"kind": "any"}
}

func idBlockJSON(i IDBlockPin) any {
	switch v := i.(type) {
	case IDBlockAny:
		return "any"
	case IDBlockPinned:
		return J{"idKeyDigest": toHex(v.IDKeyDigest), "authorKeyDigest": hexOpt(v.AuthorKeyDigest)}
	}
	return "forbid"
}

func filterNilsDeep(j J) J {
	for k, v := range j {
		switch x := v.(type) {
		case nil:
			delete(j, k)
		case J:
			j[k] = filterNilsDeep(x)
		}
	}
	return j
}
