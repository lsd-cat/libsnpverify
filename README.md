# snpverify

A library that appraises AMD SEV-SNP attestation reports, in the role of a Verifier as defined by
the RATS architecture ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)). It has a TypeScript
implementation for browsers and Node, a Kotlin implementation for the JVM and Android, a Go
implementation and a Rust implementation. All four follow [SPEC.md](SPEC.md) and are tested against
the same vectors.

| | TypeScript (`ts/`, npm `snpverify`) | Kotlin (`kotlin/`, artifact `snpverify`) | Go (`go/`, module `github.com/lsd-cat/snpverify/go`) | Rust (`rust/`, crate `snpverify`) |
|---|---|---|---|---|
| crypto | WebCrypto, or a `CryptoProvider` | `JcaCryptoProvider()`, or `JcaCryptoProvider(BouncyCastleProvider())` | `StdCrypto{}` (standard library), or a `CryptoProvider` | `RingCrypto` (`ring`), or a `CryptoProvider` |
| runtime dependencies | none | `org.json` | none | `ring`, `base64`, `serde_json` |

Inputs to an appraisal:

- Evidence: the 1184-byte attestation report produced by the guest (the Attester);
- Endorsements: the VCEK certificate for the chip, optionally the ASK and ARK certificates (the
  AMD certificates for Milan, Genoa and Turin are embedded), and optionally the AMD certificate
  revocation list for the product;
- the appraisal time, as Unix seconds;
- an appraisal policy: the Reference Values (measurements, products, TCB levels, platform bits)
  and the session binding the Relying Party accepts.

Output on success: an Attestation Result holding the decoded report fields, grouped as identity
(chip id, report id, measurement, report data), platform state (guest policy bits, platform bits,
the four TCB values, firmware versions), evidence (version, hash and signature of the report) and
endorsements (hash and validity of each certificate and of the CRL), together with the appraisal
policy as applied. Output on failure: the stage that failed and the list of violations, each with
an error code, the report field concerned and a message.

The library makes no network requests and does not read the system clock. The caller obtains the
Evidence and the Endorsements and supplies the time.

## TypeScript

```ts
import { SnpVerifier, baseVcekAppraisalPolicy } from 'snpverify';

const verifier = new SnpVerifier();                     // WebCrypto, embedded AMD certificates
const policy = baseVcekAppraisalPolicy({
  products: ['Genoa'],
  measurements: [launchDigest],                         // 48 bytes each
  reportData: sessionBinding,                           // 64 bytes: hash of the nonce and the channel key
  minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } },
});
const result = await verifier.appraise({
  evidence: report, endorsements: { vcek, crl }, now: Math.floor(Date.now() / 1000), policy,
});
if (result.ok) {
  const a = result.attestationResult;
  a.identity.chipId; a.identity.reportId; a.evidence.reportSha256; a.appraisalPolicy;
} else {
  result.stage; result.violations;                      // each violation names its field
}
```

```sh
cd ts && npm install
npm run lint          # eslint and tsc
npm test              # vitest: conformance vectors, mutation cases, review cases, golden result
npm run test:browser  # playwright: the built library in Chromium, Firefox and WebKit
npm run build
```

## Kotlin

```kotlin
val verifier = SnpVerifier(JcaCryptoProvider())
val policy = baseVcekAppraisalPolicy(BaseAppraisalPolicyConfig(
    products = listOf(Product.Genoa), measurements = listOf(launchDigest),
    reportData = sessionBinding, minTcb = mapOf(Product.Genoa to TcbFloor(10, 0, 23, 84))))
when (val r = verifier.appraise(AppraisalInput(report, Endorsements(vcek, crl = crl), now, policy))) {
    is AppraisalResult.Ok -> r.attestationResult.identity.reportId
    is AppraisalResult.Err -> r.violations
}
```

```sh
cd kotlin
./gradlew ktlintCheck detekt test   # requires JDK 21; the artifact targets JVM 11 (Android API 26 and later)
```

## Go

```go
import snp "github.com/lsd-cat/snpverify/go"

verifier := snp.NewVerifier(snp.VerifierOptions{})         // standard-library crypto, embedded AMD certificates
policy, err := snp.BaseVCEKAppraisalPolicy(snp.BaseAppraisalPolicyConfig{
    Products: []snp.Product{snp.Genoa}, Measurements: [][]byte{launchDigest}, ReportData: sessionBinding,
    MinTCB: map[snp.Product]snp.TCBFloor{snp.Genoa: {Bootloader: 10, TEE: 0, SNP: 23, Microcode: 84}}})
result, err := verifier.Appraise(snp.AppraisalInput{
    Evidence: report, Endorsements: snp.Endorsements{VCEK: vcek, CRL: crl}, Now: time.Now().Unix(), Policy: policy})
var failed *snp.AppraisalError
if errors.As(err, &failed) {
    failed.Stage; failed.Violations                           // each violation names its field
} else {
    result.Identity.ReportID; result.Evidence.ReportSHA256; result.AppraisalPolicy
}
```

```sh
cd go
go vet ./... && go test ./...      # requires Go 1.26 or later
```

## Rust

```rust
use snpverify::*;

let verifier = SnpVerifier::default();                    // ring crypto, embedded AMD certificates
let policy = base_vcek_appraisal_policy(&BaseAppraisalPolicyConfig {
    products: vec![Product::Genoa], measurements: vec![launch_digest], report_data: session_binding,
    min_tcb: BTreeMap::from([(Product::Genoa, TcbFloor { bootloader: Some(10), tee: Some(0), snp: Some(23), microcode: Some(84), fmc: None })]),
})?;
match verifier.appraise(&AppraisalInput { evidence: report, endorsements: Endorsements { vcek, crl: Some(crl), ..Default::default() }, now, policy }) {
    Ok(a) => { a.identity.report_id; a.evidence.report_sha256; a.appraisal_policy; }
    Err(e) => { e.stage; e.violations; }                   // each violation names its field
}
```

```sh
cd rust
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test   # requires Rust 1.82 or later
```

The Rust API uses `Result` and `?` instead of a thrown `Fail`, `Option` for every nullable field,
enums for the pins (`MeasurementPin::Allowlist`, `ReportDataPin::Prefix`, `IdBlockPin::Any`), and
builds a policy with `AppraisalPolicy { products: Some(..), ..AppraisalPolicy::new(measurement) }`.
Parsed records hand out borrowed slices, so immutability between stages comes from the type system.
Rust has no standard-library crypto, so the default provider is `ring`.

The Go API follows the same files and function names as the other two ports, with Go conventions
where the language asks for them: `(value, error)` returns instead of a `Result` type, Go
initialisms (`ChipID`, `TCBVersion`, `VCEK`), `Verifier` instead of `SnpVerifier`, the sum types
`MeasurementPin`, `ReportDataPin` and `IDBlockPin` as small interfaces, pointers for optional numbers
(`TCBFloor{SNP: new(23)}`), and zero-valued flags meaning "use the default".

## Appraisal policy

An `AppraisalPolicy` holds the Reference Values and the conditions the Evidence must satisfy. The
fields fall into four groups.

| Group | Fields | Form |
|---|---|---|
| identity | `measurement`, `products`, `chipIds`, `endorsementKeyFingerprints`, `signingKey`, `cspIds`, `reportId` | allowlists and exact values |
| session | `reportData` (`exact`, `prefix` or `any`), `hostData`, `familyId`, `imageId`, `idBlock` | exact values |
| configuration bits | `guestPolicy.*` (bits the VM owner set at launch), `platformInfo.*` (bits describing the host), `vmpl` | `required`, `forbidden` or `any` per bit |
| firmware | `minTcb` and `minLaunchTcb` per product, `minFirmware`, `allowProvisionalFirmware`, `minReportVersion`, `requireCrl`, `minLaunchMitVector`, `minCurrentMitVector` | minimum values and flags |

`measurement` is the one field without a default. The defaults forbid the debug, migration and CXL
bits, require VMPL 0, require the committed firmware to equal the running firmware, forbid an ID
block and accept the products Genoa and Turin. Every other field defaults to `any`. The resolved
policy is part of the result as `attestationResult.appraisalPolicy`. SPEC §5 lists every field.

A policy is also a JSON document with the same keys, in the encoding the result uses for
`appraisalPolicy`: bytes as hex strings, 64-bit values as decimal strings, enumerations as
strings, and an ignored `$comment` key in any object. `appraisalPolicyFromJson` loads it in every
port and reports a malformed document as `POLICY_INVALID` with the same message everywhere;
`vectors/policy.json` pins both. One document therefore serves the browser, Android, Go and Rust
verifiers of a deployment. [MITIGATIONS.md](MITIGATIONS.md) ends with a complete one.

`baseVcekAppraisalPolicy` and `baseVlekAppraisalPolicy` build an appraisal policy from four
deployment values: the products, the measurements, the session binding and the TCB floors. They set
`minReportVersion` 3, `requireCrl`, VMPL 0 and `idBlock: any`. `baseVlekAppraisalPolicy` also takes
a `cspIds` allowlist, and the caller supplies the ASVK and the VLEK CRL as Endorsements.

Three values must be produced by the caller for every appraisal. The session binding in
`reportData` is a hash of a fresh nonce and the Attester's channel key. The time `now` comes from
a clock the caller trusts. The Endorsements (the VCEK, the certificate chain and the CRL) are
fetched by the caller, and the CRL is refreshed before its `nextUpdate`.

## Mitigations

[MITIGATIONS.md](MITIGATIONS.md) is a table of published attacks on SEV-SNP. Each row gives the
paper or disclosure, the AMD security bulletin and CVE where one exists, the `AppraisalPolicy`
field that addresses the attack, and the products on which that field is available. The rows cover
microcode and firmware vulnerabilities (CacheWarp, EntrySign, StackWarp, RMPocalypse, Fabricked,
the SB-3007, SB-3011 and SB-3016 series), memory attacks (BadRAM, CipherLeaks, Heracles, PwrLeak,
CounterSEVeillance), guest-kernel attacks that only a measurement allowlist addresses (Heckler,
WeSee, BadAML), protocol conditions (replay, relay, host-requested reports, revoked keys, firmware
rollback), the Milan root-seed extraction, and the attacks the report cannot show (memory
interposers, cache side channels). The document ends with a complete appraisal policy, dated, that
sets every field named in the table, as one JSON document that every port loads.

## Acknowledgement

The design draws on the author's work with [Tinfoil](https://tinfoil.sh) on attestation
verification. The conformance vectors in `vectors/attestation-sev` and `vectors/quote-sev` come
from that work.

## License

GNU General Public License, version 3 or later. See [LICENSE](LICENSE).
