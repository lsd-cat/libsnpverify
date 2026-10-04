# Attacks on SEV-SNP and the policy fields that address them

The table lists published attacks on SEV-SNP. For each attack it gives the reference, the AMD
advisory where one exists, the `Policy` field that enforces the mitigation, and the products on
which the field exists. TCB floor numbers are not listed. They come from the AMD bulletin for
the product and firmware in use.

| Attack | Reference | Advisory | Policy field | Products |
|---|---|---|---|---|
| CacheWarp (stale cache lines via INVD) | Zhang et al., USENIX Security 2024 | AMD-SB-3005, CVE-2023-20592 | `minTcb[product].microcode` | Milan, Genoa |
| EntrySign (microcode signature bypass) | Google, 2025 | AMD-SB-3019, AMD-SB-7033 | `minTcb[product].microcode` | all |
| StackWarp (stack-pointer corruption from sibling thread) | Zhang et al., USENIX Security 2026 | AMD-SB-3027, CVE-2025-29943 | `minTcb[product].microcode`; full mitigation `guestPolicy.smt: forbidden` and `platformInfo.smtEnabled: forbidden` | all |
| RMPocalypse (RMP initialisation race) | Schlüter, Shinde, CCS 2025 | AMD-SB-3020, CVE-2025-0033 | `minTcb[product].snp` | all |
| Fabricked (fabric routing misconfiguration) | ETH Zurich, 2026 | AMD-SB-3034, CVE-2025-54510 | `minTcb[product].snp`, `minTcb[product].bootloader` | all |
| SNP firmware memory bugs | AMD | AMD-SB-3007, AMD-SB-3011 | `minTcb[product].snp` | all |
| IOMMU write buffer | AMD | AMD-SB-3016, CVE-2023-20585 | `platformInfo.iommuWriteSafe: required`, `minTcb[product].snp` | all; a host OS update is also required |
| BadRAM (static DRAM aliasing) | De Meulemeester et al., IEEE S&P 2025 | AMD-SB-3015, CVE-2024-21944 | `platformInfo.aliasCheckComplete: required`, `minTcb[product].snp` | all |
| CipherLeaks, ciphertext side channel | Li et al., USENIX Security 2021; IEEE S&P 2022 | AMD-SB-3021 | `guestPolicy.ciphertextHidingDram: required`, `platformInfo.ciphertextHidingEnabled: required` | Genoa, Turin |
| Heracles (chosen plaintext via page move/swap) | Schlüter et al., CCS 2025 | AMD-SB-3021 | `guestPolicy.pageSwapDisabled: required`, `guestPolicy.ciphertextHidingDram: required` | Genoa, Turin (ABI 1.58 firmware) |
| PwrLeak (RAPL power side channel) | Wang et al., DIMVA 2023 | | `guestPolicy.raplDisabled: required`, `platformInfo.raplDisabled: required` | Genoa, Turin |
| CounterSEVeillance (performance counters) | Gast et al., NDSS 2025 | | `guestPolicy.smt: forbidden` reduces exposure; the report has no field for this on Milan or Genoa | Turin virtualises performance counters |
| Heckler, WeSee (malicious interrupt injection) | Schlüter et al., USENIX Security 2024; IEEE S&P 2024 | CVE-2024-25744, CVE-2024-25743 | `measurement` allowlist of guest images with a patched kernel | all |
| BadAML (host-supplied ACPI tables) | Takekoshi et al., CCS 2025 | | `measurement` allowlist of images that measure ACPI tables | all |
| Debug and migration policy | AMD 56860 | | `guestPolicy.debug: forbidden`, `guestPolicy.migrateMa: forbidden` (defaults) | all |
| Firmware rollback | AMD 56860 | | `allowProvisionalFirmware: false` (default), `minFirmware`, `minLaunchTcb` | all |
| Report replay | RFC 9334 §10; Paradžik et al., IEEE TDSC 2025 | | `reportData` with a verifier nonce (`exact` or `prefix`) | all |
| Report relay from another machine | Proof of Cloud, 2025; Contrast CVE-2026-100835 | | `chipIds` allowlist with `reportData` bound to the channel key | VCEK only (CHIP_ID is zero under VLEK) |
| Host-requested report | AMD 56860 | | rejected in every case (`REPORT_HOST_REQUESTED`) | all |
| Leaked or revoked endorsement key | Buhren et al., CCS 2019, CCS 2021 | | `requireCrl: true` with a current CRL | all |
| Milan root seed extraction | Shen, Qin, arXiv 2605.12990 | | `products` without Milan | Milan |
| Battering RAM, DDRop (dynamic memory interposers) | De Meulemeester et al., IEEE S&P 2026; CCS 2026 | | none; the report does not reflect these attacks | all |
| Cache and page-fault side channels (SEV-Step, Cohere+Reload, SNPeek) | Wilke et al., TCHES 2024; Giner et al., DIMVA 2025; NDSS 2026 | | none; the report does not reflect these attacks | all |

A `required` bit rejects every report from a product that lacks the feature. A policy that
allows several products sets such bits only when every product in the list has the feature.
Where a mitigation also requires a guest OS update or a host restart, the report does not carry
that state.

## Recommended policy, 2026-10-04

The policy below sets every field in the table. It accepts Genoa and Turin. It excludes Milan for
two reasons: the root seed extraction result, and the absence of ciphertext hiding and RAPL
control on Milan. Fields whose value depends on the deployment are marked in the code.

The Genoa TCB floors are the values carried by the production Genoa report in
`vectors/attestation-sev/200` (firmware issued January 2026). They are values observed on
patched hardware. They are not a statement that lower values are vulnerable. A deployment raises
them when the AMD bulletin for its firmware requires it. The Turin floors are placeholders; the
deployment takes them from the AMD bulletin, because this repository has no Turin report to
observe.

```ts
const policy: Policy = {
  // deployment values
  measurement: [/* approved launch digests */],
  reportData: { kind: 'exact', value: sessionBinding },   // SHA-512 of nonce and channel key, per session
  chipIds: [/* CHIP_IDs of the machines you operate, or omit for cloud fleets */],

  products: ['Genoa', 'Turin'],
  signingKey: 'VCEK',
  allowMaskedChipId: false,
  requireCrl: true,
  minReportVersion: 3,
  vmpl: 0,
  idBlock: 'forbid',

  guestPolicy: {
    debug: 'forbidden',
    migrateMa: 'forbidden',
    cxlAllowed: 'forbidden',
    smt: 'forbidden',                      // StackWarp, CounterSEVeillance; relax to 'any' if the host cannot disable SMT
    ciphertextHidingDram: 'required',      // CipherLeaks, Heracles
    pageSwapDisabled: 'required',          // Heracles; needs ABI 1.58 firmware
    raplDisabled: 'required',              // PwrLeak
    memAes256Xts: 'any',
    singleSocket: 'any',
  },
  platformInfo: {
    smtEnabled: 'forbidden',               // with guestPolicy.smt
    aliasCheckComplete: 'required',        // BadRAM
    iommuWriteSafe: 'required',            // SB-3016; needs the host OS update as well
    ciphertextHidingEnabled: 'required',
    raplDisabled: 'required',
    tsmeEnabled: 'any',
    eccEnabled: 'any',
    tioEnabled: 'any',
    allowUnknownBits: false,
  },

  minTcb: {
    Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 },   // observed 2026-01; raise per bulletin
    Turin: { fmc: 0, bootloader: 0, tee: 0, snp: 0, microcode: 0 }, // fill from the Turin bulletin
  },
  minFirmware: { major: 1, minor: 58, build: 0 },                // ABI 1.58 for the page-swap bit
  allowProvisionalFirmware: false,
};
```

```kotlin
val policy = Policy(
    measurement = MeasurementPin.Allowlist(approvedDigests),
    reportData = ReportDataPin.Exact(sessionBinding),
    chipIds = operatedChipIds,
    products = listOf(Product.Genoa, Product.Turin),
    signingKey = SigningKeyPolicy.VCEK, allowMaskedChipId = false, requireCrl = true, minReportVersion = 3, vmpl = 0, idBlock = IdBlockPin.Forbid,
    guestPolicy = GuestPolicyRules(debug = Bit.FORBIDDEN, migrateMa = Bit.FORBIDDEN, cxlAllowed = Bit.FORBIDDEN, smt = Bit.FORBIDDEN,
        ciphertextHidingDram = Bit.REQUIRED, pageSwapDisabled = Bit.REQUIRED, raplDisabled = Bit.REQUIRED),
    platformInfo = PlatformInfoRules(smtEnabled = Bit.FORBIDDEN, aliasCheckComplete = Bit.REQUIRED, iommuWriteSafe = Bit.REQUIRED,
        ciphertextHidingEnabled = Bit.REQUIRED, raplDisabled = Bit.REQUIRED, allowUnknownBits = false),
    minTcb = mapOf(Product.Genoa to TcbFloor(10, 0, 23, 84), Product.Turin to TcbFloor(0, 0, 0, 0, fmc = 0)),
    minFirmware = FirmwareVersion(1, 58, 0),
    allowProvisionalFirmware = false,
)
```

This policy does not address dynamic memory interposers, cache and page-fault side channels,
performance counters on Genoa, or any condition that depends on guest OS state absent from the
report. The measurement allowlist and the choice of hosting are the controls for those.
