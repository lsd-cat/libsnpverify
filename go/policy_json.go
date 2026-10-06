package snpverify

// JSON form of the appraisal policy: the shape ToJSON renders as appraisalPolicy, read back. Mirrors ts/src/policy-json.ts.
// Bytes are lowercase hex, 64-bit values decimal strings, enumerations strings; a "$comment" key in any object is ignored.
// The checks run in the same order as the TypeScript port, so the same document yields the same POLICY_INVALID message.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
)

type jsonObj = map[string]any

var (
	policyKeys = []string{"measurement", "products", "signingKey", "allowMaskedChipId", "chipIds", "endorsementKeyFingerprints", "cspIds", "requireCrl",
		"guestPolicy", "platformInfo", "vmpl", "minReportVersion", "minGuestSvn", "minTcb", "minLaunchTcb", "minFirmware", "allowProvisionalFirmware",
		"minLaunchMitVector", "minCurrentMitVector", "reportData", "hostData", "familyId", "imageId", "reportId", "idBlock"}
	guestPolicyBits  = []string{"debug", "migrateMa", "smt", "singleSocket", "cxlAllowed", "memAes256Xts", "raplDisabled", "ciphertextHidingDram", "pageSwapDisabled"}
	platformInfoBits = []string{"smtEnabled", "tsmeEnabled", "eccEnabled", "raplDisabled", "ciphertextHidingEnabled", "aliasCheckComplete", "iommuWriteSafe", "tioEnabled"}
	floorKeys        = []string{"bootloader", "tee", "snp", "microcode", "fmc"}
	productNames     = []string{"Milan", "Genoa", "Turin", "Venice"}
)

// catchInvalid runs fn; a need() failure becomes a POLICY_INVALID *Violation.
func catchInvalid[T any](fn func() T) (out T, err error) {
	defer func() {
		if r := recover(); r != nil {
			inv, ok := r.(invalidPolicy)
			if !ok {
				panic(r)
			}
			err = &Violation{Code: PolicyInvalid, Message: inv.msg}
		}
	}()
	return fn(), nil
}

// AppraisalPolicyFromJSON parses the JSON form. A malformed document yields a POLICY_INVALID *Violation.
func AppraisalPolicyFromJSON(text []byte) (AppraisalPolicy, error) {
	return catchInvalid(func() AppraisalPolicy {
		var v any
		need(json.Unmarshal(text, &v) == nil, "policy is not valid JSON")
		return policyFromJSONValue(v)
	})
}

func stripComments(v any) any {
	switch x := v.(type) {
	case jsonObj:
		out := jsonObj{}
		for k, y := range x {
			if k != "$comment" {
				out[k] = stripComments(y)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, y := range x {
			out[i] = stripComments(y)
		}
		return out
	}
	return v
}

func jsonObject(v any, path string) jsonObj {
	o, ok := v.(jsonObj)
	need(ok, path+" must be an object")
	return o
}

func jsonKeys(o jsonObj, path string, allowed []string) {
	for k := range o {
		need(slices.Contains(allowed, k), path+" has unknown fields")
	}
}

func jsonBool(o jsonObj, key, path string) bool {
	v, has := o[key]
	if !has {
		return false
	}
	b, ok := v.(bool)
	need(ok, path+" must be boolean")
	return b
}

func jsonUint(v any, max int64, path string) int64 {
	f, ok := v.(float64)
	need(ok && f == math.Trunc(f) && f >= 0 && f <= float64(max), fmt.Sprintf("%s must be an integer in 0..%d", path, max))
	return int64(f)
}

func isHexString(v any) bool {
	s, ok := v.(string)
	if !ok || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func hexSyntax(v any, path string) { need(isHexString(v), path+" must be a hex string") }

func hexListSyntax(v any, path string) {
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			hexSyntax(x, path+"[]")
		}
	}
}

// checkHexSyntax mirrors the conversion pass of the TypeScript port, which runs before its shape validation.
func checkHexSyntax(p jsonObj) {
	if p["measurement"] != "any" {
		hexListSyntax(p["measurement"], "policy.measurement")
	}
	hexListSyntax(p["chipIds"], "policy.chipIds")
	hexListSyntax(p["endorsementKeyFingerprints"], "policy.endorsementKeyFingerprints")
	if rd, ok := p["reportData"].(jsonObj); ok {
		if v, has := rd["value"]; has {
			hexSyntax(v, "policy.reportData.value")
		}
	}
	for _, k := range []string{"hostData", "familyId", "imageId", "reportId"} {
		if v, has := p[k]; has {
			hexSyntax(v, "policy."+k)
		}
	}
	if ib, ok := p["idBlock"].(jsonObj); ok {
		for _, k := range []string{"idKeyDigest", "authorKeyDigest"} {
			if v, has := ib[k]; has {
				hexSyntax(v, "policy.idBlock."+k)
			}
		}
	}
	for _, k := range []string{"minLaunchMitVector", "minCurrentMitVector"} {
		if v, has := p[k]; has {
			s, ok := v.(string)
			need(ok && s != "" && !slices.ContainsFunc([]byte(s), func(c byte) bool { return c < '0' || c > '9' }), "policy."+k+" must be uint64")
		}
	}
}

// hexBytes decodes a value already checked by checkHexSyntax; nil when absent.
func hexBytes(v any) []byte {
	if v == nil {
		return nil
	}
	b, _ := hex.DecodeString(v.(string))
	return b
}

func hexLen(v any, n int, path string) []byte {
	if v == nil {
		return nil
	}
	b := hexBytes(v)
	need(len(b) == n, fmt.Sprintf("%s must be %d bytes", path, n))
	return b
}

func hexListLen(arr []any, n int, path string) [][]byte {
	out := make([][]byte, len(arr))
	for i, x := range arr {
		out[i] = hexLen(x, n, path)
	}
	return out
}

func jsonBit(o jsonObj, key, path string) Bit {
	v, has := o[key]
	if !has {
		return ""
	}
	s, ok := v.(string)
	need(ok && (Bit(s) == BitRequired || Bit(s) == BitForbidden || Bit(s) == BitAny), path+"."+key+" is not a Bit")
	return Bit(s)
}

func jsonFloors(v any, path string) map[Product]TCBFloor {
	o := jsonObject(v, path)
	jsonKeys(o, path, productNames)
	out := map[Product]TCBFloor{}
	for _, name := range productNames {
		fv, has := o[name]
		if !has {
			continue
		}
		fo := jsonObject(fv, path+"."+name)
		jsonKeys(fo, path+"."+name, floorKeys)
		var f TCBFloor
		for _, c := range []struct {
			key string
			dst **int
		}{{"bootloader", &f.Bootloader}, {"tee", &f.TEE}, {"snp", &f.SNP}, {"microcode", &f.Microcode}, {"fmc", &f.FMC}} {
			if x, has := fo[c.key]; has {
				*c.dst = new(int(jsonUint(x, 255, path+"."+name+"."+c.key)))
			}
		}
		out[Product(name)] = f
	}
	return out
}

func policyFromJSONValue(v any) AppraisalPolicy {
	p, ok := v.(jsonObj)
	need(ok, "policy must be an object")
	p = stripComments(p).(jsonObj)
	checkHexSyntax(p)
	jsonKeys(p, "policy", policyKeys)
	var out AppraisalPolicy

	m, has := p["measurement"]
	need(has, `policy.measurement is required: an allowlist or the explicit string "any"`)
	if m == "any" {
		out.Measurement = MeasurementAny{}
	} else {
		arr, ok := m.([]any)
		need(ok && len(arr) > 0, `policy.measurement must be a nonempty array or "any"`)
		out.Measurement = MeasurementAllowlist(hexListLen(arr, 48, "policy.measurement[]"))
	}
	if v, has := p["reportData"]; has {
		o := jsonObject(v, "policy.reportData")
		kind, _ := o["kind"].(string)
		need(kind == "any" || kind == "exact" || kind == "prefix", "policy.reportData.kind is invalid")
		if kind == "any" {
			jsonKeys(o, "policy.reportData", []string{"kind"})
			out.ReportData = ReportDataAny{}
		} else {
			jsonKeys(o, "policy.reportData", []string{"kind", "value"})
			value := hexBytes(o["value"])
			need(len(value) >= 1 && len(value) <= 64, "policy.reportData.value must be 1..64 bytes")
			if kind == "exact" {
				need(len(value) == 64, "policy.reportData.value must be 64 bytes")
				out.ReportData = ReportDataExact(value)
			} else {
				out.ReportData = ReportDataPrefix(value)
			}
		}
	}
	out.HostData = hexLen(p["hostData"], 32, "policy.hostData")
	out.FamilyID = hexLen(p["familyId"], 16, "policy.familyId")
	out.ImageID = hexLen(p["imageId"], 16, "policy.imageId")
	out.ReportID = hexLen(p["reportId"], 32, "policy.reportId")
	if v, has := p["products"]; has {
		arr, ok := v.([]any)
		good := ok && len(arr) > 0
		for _, x := range arr {
			s, isStr := x.(string)
			good = good && isStr && slices.Contains(productNames, s)
		}
		need(good, "policy.products must be a nonempty Product list")
		out.Products = make([]Product, len(arr))
		for i, x := range arr {
			out.Products[i] = Product(x.(string))
		}
	}
	if v, has := p["signingKey"]; has {
		s, ok := v.(string)
		need(ok && (s == "VCEK" || s == "VLEK" || s == "any"), "policy.signingKey is invalid")
		out.SigningKey = SigningKeyPolicy(s)
	}
	out.AllowMaskedChipID = jsonBool(p, "allowMaskedChipId", "policy.allowMaskedChipId")
	out.RequireCRL = jsonBool(p, "requireCrl", "policy.requireCrl")
	out.AllowProvisionalFirmware = jsonBool(p, "allowProvisionalFirmware", "policy.allowProvisionalFirmware")
	chipIDs, hasChipIDs := p["chipIds"]
	fingerprints, hasFingerprints := p["endorsementKeyFingerprints"]
	if hasChipIDs {
		_, ok := chipIDs.([]any)
		need(ok, "policy.chipIds must be an array")
	}
	if hasFingerprints {
		_, ok := fingerprints.([]any)
		need(ok, "policy.endorsementKeyFingerprints must be an array")
	}
	if hasChipIDs {
		out.ChipIDs = hexListLen(chipIDs.([]any), 64, "policy.chipIds[]")
	}
	if hasFingerprints {
		out.EndorsementKeyFingerprints = hexListLen(fingerprints.([]any), 32, "policy.endorsementKeyFingerprints[]")
	}
	if v, has := p["cspIds"]; has {
		arr, ok := v.([]any)
		good := ok && len(arr) > 0
		out.CSPIDs = []string{}
		for _, x := range arr {
			s, isStr := x.(string)
			good = good && isStr && s != ""
			out.CSPIDs = append(out.CSPIDs, s)
		}
		need(good, "policy.cspIds must be nonempty strings")
	}
	if v, has := p["idBlock"]; has {
		o, isObj := v.(jsonObj)
		need(v == "forbid" || v == "any" || isObj, "policy.idBlock is invalid")
		switch {
		case v == "forbid":
			out.IDBlock = IDBlockForbid{}
		case v == "any":
			out.IDBlock = IDBlockAny{}
		default:
			jsonKeys(o, "policy.idBlock", []string{"idKeyDigest", "authorKeyDigest"})
			_, hasDigest := o["idKeyDigest"]
			need(hasDigest, "policy.idBlock.idKeyDigest is required")
			out.IDBlock = IDBlockPinned{IDKeyDigest: hexLen(o["idKeyDigest"], 48, "policy.idBlock.idKeyDigest"), AuthorKeyDigest: hexLen(o["authorKeyDigest"], 48, "policy.idBlock.authorKeyDigest")}
		}
	}
	if v, has := p["guestPolicy"]; has {
		o := jsonObject(v, "policy.guestPolicy")
		jsonKeys(o, "policy.guestPolicy", append(slices.Clone(guestPolicyBits), "minAbi"))
		g := &out.GuestPolicy
		for _, b := range []struct {
			key string
			dst *Bit
		}{{"debug", &g.Debug}, {"migrateMa", &g.MigrateMA}, {"smt", &g.SMT}, {"singleSocket", &g.SingleSocket}, {"cxlAllowed", &g.CXLAllowed},
			{"memAes256Xts", &g.MemAES256XTS}, {"raplDisabled", &g.RAPLDisabled}, {"ciphertextHidingDram", &g.CiphertextHidingDRAM}, {"pageSwapDisabled", &g.PageSwapDisabled}} {
			*b.dst = jsonBit(o, b.key, "policy.guestPolicy")
		}
		if a, has := o["minAbi"]; has {
			ao := jsonObject(a, "policy.guestPolicy.minAbi")
			jsonKeys(ao, "policy.guestPolicy.minAbi", []string{"major", "minor"})
			_, hasMajor := ao["major"]
			_, hasMinor := ao["minor"]
			need(hasMajor && hasMinor, "policy.guestPolicy.minAbi requires major and minor")
			g.MinABI = &ABIVersion{Major: int(jsonUint(ao["major"], 255, "policy.guestPolicy.minAbi.major")), Minor: int(jsonUint(ao["minor"], 255, "policy.guestPolicy.minAbi.minor"))}
		}
	}
	if v, has := p["platformInfo"]; has {
		o := jsonObject(v, "policy.platformInfo")
		jsonKeys(o, "policy.platformInfo", append(slices.Clone(platformInfoBits), "allowUnknownBits"))
		q := &out.PlatformInfo
		for _, b := range []struct {
			key string
			dst *Bit
		}{{"smtEnabled", &q.SMTEnabled}, {"tsmeEnabled", &q.TSMEEnabled}, {"eccEnabled", &q.ECCEnabled}, {"raplDisabled", &q.RAPLDisabled},
			{"ciphertextHidingEnabled", &q.CiphertextHidingEnabled}, {"aliasCheckComplete", &q.AliasCheckComplete}, {"iommuWriteSafe", &q.IOMMUWriteSafe}, {"tioEnabled", &q.TIOEnabled}} {
			*b.dst = jsonBit(o, b.key, "policy.platformInfo")
		}
		q.AllowUnknownBits = jsonBool(o, "allowUnknownBits", "policy.platformInfo.allowUnknownBits")
	}
	if v, has := p["vmpl"]; has {
		if f, ok := v.(float64); ok {
			need(f == math.Trunc(f) && f >= 0 && f <= 3, "policy.vmpl must be 0..3")
			out.VMPL = int(f)
		} else {
			need(v == "any", "policy.vmpl must be 0..3 or any")
			out.VMPLAny = true
		}
	}
	if v, has := p["minReportVersion"]; has {
		f, ok := v.(float64)
		need(ok && f == math.Trunc(f) && f >= 2 && f <= 5, "policy.minReportVersion must be 2..5")
		out.MinReportVersion = int(f)
	}
	if v, has := p["minGuestSvn"]; has {
		out.MinGuestSVN = jsonUint(v, 0xffffffff, "policy.minGuestSvn")
	}
	if v, has := p["minTcb"]; has {
		out.MinTCB = jsonFloors(v, "policy.minTcb")
	}
	if v, has := p["minLaunchTcb"]; has {
		out.MinLaunchTCB = jsonFloors(v, "policy.minLaunchTcb")
	}
	if v, has := p["minFirmware"]; has {
		o := jsonObject(v, "policy.minFirmware")
		jsonKeys(o, "policy.minFirmware", []string{"major", "minor", "build"})
		for _, c := range []struct {
			key string
			dst *int
		}{{"major", &out.MinFirmware.Major}, {"minor", &out.MinFirmware.Minor}, {"build", &out.MinFirmware.Build}} {
			if x, has := o[c.key]; has {
				*c.dst = int(jsonUint(x, 255, "policy.minFirmware."+c.key))
			}
		}
	}
	for _, c := range []struct {
		key string
		dst **uint64
	}{{"minLaunchMitVector", &out.MinLaunchMitVector}, {"minCurrentMitVector", &out.MinCurrentMitVector}} {
		if x, has := p[c.key]; has {
			u, err := strconv.ParseUint(x.(string), 10, 64)
			need(err == nil, "policy."+c.key+" must be uint64")
			*c.dst = new(u)
		}
	}
	return out
}
