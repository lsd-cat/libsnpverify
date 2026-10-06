package snpverify

import (
	"errors"
	"fmt"
	"slices"
)

// BaseAppraisalPolicyConfig holds the caller-maintained reference values; ReportData must bind a fresh session.
type BaseAppraisalPolicyConfig struct {
	Products     []Product
	Measurements [][]byte
	ReportData   []byte               // exactly 64 bytes, e.g. SHA-512 of nonce and peer key
	MinTCB       map[Product]TCBFloor // explicit component floors for every allowed product
}

func base(config BaseAppraisalPolicyConfig) (AppraisalPolicy, error) {
	supported := []Product{Milan, Genoa, Turin}
	if len(config.Products) == 0 {
		return AppraisalPolicy{}, errors.New("base policy requires supported products")
	}
	for _, p := range config.Products {
		if !slices.Contains(supported, p) {
			return AppraisalPolicy{}, errors.New("base policy requires supported products")
		}
	}
	if len(config.Measurements) == 0 {
		return AppraisalPolicy{}, errors.New("base policy requires one or more 48-byte measurements")
	}
	for _, m := range config.Measurements {
		if len(m) != 48 {
			return AppraisalPolicy{}, errors.New("base policy requires one or more 48-byte measurements")
		}
	}
	if len(config.ReportData) != 64 || isZero(config.ReportData) {
		return AppraisalPolicy{}, errors.New("base policy requires a nonzero, 64-byte report-data binding")
	}
	for _, product := range config.Products {
		f, ok := config.MinTCB[product]
		if !ok {
			return AppraisalPolicy{}, fmt.Errorf("base policy requires a TCB floor for %s", product)
		}
		values := []*int{f.Bootloader, f.TEE, f.SNP, f.Microcode}
		if product == Turin {
			values = append(values, f.FMC)
		}
		for _, v := range values {
			if v == nil || !inRange(*v, 0, 255) {
				return AppraisalPolicy{}, fmt.Errorf("base policy requires all TCB component floors for %s", product)
			}
		}
	}
	return AppraisalPolicy{
		Measurement:      MeasurementAllowlist(cloneAll(config.Measurements)),
		Products:         slices.Clone(config.Products),
		ReportData:       ReportDataExact(slices.Clone(config.ReportData)),
		MinTCB:           cloneFloors(config.MinTCB),
		MinReportVersion: 3,
		RequireCRL:       true,
		VMPL:             0,
		IDBlock:          IDBlockAny{},
	}, nil
}

// BaseVCEKAppraisalPolicy: guest-owned endorsement key. CHIP_ID must be present.
func BaseVCEKAppraisalPolicy(config BaseAppraisalPolicyConfig) (AppraisalPolicy, error) {
	p, err := base(config)
	p.SigningKey = SigningKeyPolicyVCEK
	return p, err
}

// BaseVLEKAppraisalPolicy: cloud-provider endorsement key. A signed CSP_ID pin selects the allowed provider.
func BaseVLEKAppraisalPolicy(config BaseAppraisalPolicyConfig, cspIDs []string) (AppraisalPolicy, error) {
	if len(cspIDs) == 0 || slices.Contains(cspIDs, "") {
		return AppraisalPolicy{}, errors.New("base VLEK policy requires one or more CSP_IDs")
	}
	p, err := base(config)
	p.SigningKey = SigningKeyPolicyVLEK
	p.CSPIDs = slices.Clone(cspIDs)
	return p, err
}
