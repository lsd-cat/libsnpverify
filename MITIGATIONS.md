# Attacks on SEV-SNP and the appraisal policy fields that address them

The table lists published attacks on SEV-SNP. For each attack it gives the reference, the AMD
advisory where one exists, the `AppraisalPolicy` field that enforces the mitigation, and the
products on which the field exists. TCB floor numbers are not listed. They come from the AMD
bulletin for the product and firmware in use.

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

## Recommended appraisal policy, 2026-10-04

The appraisal policy below sets every field in the table. It accepts Genoa and Turin. It excludes Milan for
two reasons: the root seed extraction result, and the absence of ciphertext hiding and RAPL
control on Milan. Fields whose value depends on the deployment are marked in `$comment` notes, which every port ignores.

The Genoa TCB floors are the values carried by the production Genoa report in
`vectors/attestation-sev/200` (firmware issued January 2026). They are values observed on
patched hardware. They are not a statement that lower values are vulnerable. A deployment raises
them when the AMD bulletin for its firmware requires it. The Turin floors are placeholders; the
deployment takes them from the AMD bulletin, because this repository has no Turin report to
observe. The measurement and report-data values are zero placeholders so that the document is a
valid policy; a deployment replaces them.

```json
{
  "$comment": "snpverify appraisal policy, 2026-10-04. Replace measurement and reportData with deployment values; add chipIds for machines you operate.",
  "measurement": ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
  "reportData": { "$comment": "SHA-512 of nonce and channel key, per session", "kind": "exact",
    "value": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },

  "products": ["Genoa", "Turin"],
  "signingKey": "VCEK",
  "allowMaskedChipId": false,
  "requireCrl": true,
  "minReportVersion": 3,
  "vmpl": 0,
  "idBlock": "forbid",

  "guestPolicy": {
    "$comment": "smt: StackWarp, CounterSEVeillance; relax to any if the host cannot disable SMT. ciphertextHidingDram: CipherLeaks, Heracles. pageSwapDisabled: Heracles; needs ABI 1.58 firmware. raplDisabled: PwrLeak.",
    "debug": "forbidden",
    "migrateMa": "forbidden",
    "cxlAllowed": "forbidden",
    "smt": "forbidden",
    "ciphertextHidingDram": "required",
    "pageSwapDisabled": "required",
    "raplDisabled": "required",
    "memAes256Xts": "any",
    "singleSocket": "any"
  },
  "platformInfo": {
    "$comment": "smtEnabled: with guestPolicy.smt. aliasCheckComplete: BadRAM. iommuWriteSafe: SB-3016; needs the host OS update as well.",
    "smtEnabled": "forbidden",
    "aliasCheckComplete": "required",
    "iommuWriteSafe": "required",
    "ciphertextHidingEnabled": "required",
    "raplDisabled": "required",
    "tsmeEnabled": "any",
    "eccEnabled": "any",
    "tioEnabled": "any",
    "allowUnknownBits": false
  },

  "minTcb": {
    "$comment": "Genoa: observed 2026-01; raise per bulletin. Turin: placeholders, fill from the Turin bulletin.",
    "Genoa": { "bootloader": 10, "tee": 0, "snp": 23, "microcode": 84 },
    "Turin": { "fmc": 0, "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0 }
  },
  "minFirmware": { "$comment": "ABI 1.58 for the page-swap bit", "major": 1, "minor": 58, "build": 0 },
  "allowProvisionalFirmware": false
}
```

The same document loads in every port. Each call returns a `POLICY_INVALID` violation for a
malformed document; the vector `vectors/policy.json` pins the accepted documents and the messages.

```ts
const policy = appraisalPolicyFromJson(text);           // TypeScript: AppraisalPolicy | Violation
```
```kotlin
val policy = appraisalPolicyFromJson(text)              // Kotlin: Result<AppraisalPolicy>, org.json
```
```go
policy, err := snpverify.AppraisalPolicyFromJSON(text)  // Go: error is a *Violation
```
```rust
let policy = appraisal_policy_from_json(text)?;         // Rust: Result<AppraisalPolicy>
```

This appraisal policy does not address dynamic memory interposers, cache and page-fault side channels,
performance counters on Genoa, or any condition that depends on guest OS state absent from the
report. The measurement allowlist and the choice of hosting are the controls for those.
