# snpverify

A library that verifies AMD SEV-SNP attestation reports. It has a TypeScript implementation for
browsers and Node and a Kotlin implementation for the JVM and Android. Both follow [SPEC.md](SPEC.md)
and are tested against the same vectors.

| | TypeScript (`ts/`, npm `snpverify`) | Kotlin (`kotlin/`, artifact `snpverify`) |
|---|---|---|
| crypto | WebCrypto, or a `CryptoProvider` | `JcaCryptoProvider()`, or `JcaCryptoProvider(BouncyCastleProvider())` |
| runtime dependencies | none | none |

Inputs to a verification:

- the 1184-byte attestation report produced by the guest;
- the VCEK certificate for the chip, and optionally the ASK and ARK certificates (the AMD
  certificates for Milan, Genoa and Turin are embedded);
- optionally the AMD certificate revocation list for the product;
- the verification time, as Unix seconds;
- a policy: the measurements, products, TCB levels, platform bits and session binding the
  relying party accepts.

Output on success: the decoded report fields, grouped as identity (chip id, report id,
measurement, report data), platform state (guest policy bits, platform bits, the four TCB values,
firmware versions) and evidence (hashes and validity of the report and of each certificate),
together with the policy as applied. Output on failure: the stage that failed and the list of
violations, each with an error code, the report field concerned and a message.

The library makes no network requests and does not read the system clock. The caller obtains the
report and the certificates and supplies the time.

## TypeScript

```ts
import { SnpVerifier, baseVcekPolicy } from 'snpverify';

const verifier = new SnpVerifier();                     // WebCrypto, embedded AMD certificates
const policy = baseVcekPolicy({
  products: ['Genoa'],
  measurements: [launchDigest],                         // 48 bytes each
  reportData: sessionBinding,                           // 64 bytes: hash of the nonce and the channel key
  minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } },
});
const result = await verifier.verify({ report, vcek, crl, now: Math.floor(Date.now() / 1000), policy });
if (result.ok) {
  const a = result.attestation;
  a.identity.chipId; a.identity.reportId; a.evidence.reportSha256; a.policyApplied;
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
val policy = baseVcekPolicy(BasePolicyConfig(
    products = listOf(Product.Genoa), measurements = listOf(launchDigest),
    reportData = sessionBinding, minTcb = mapOf(Product.Genoa to TcbFloor(10, 0, 23, 84))))
when (val r = verifier.verify(VerifyInput(report, vcek, crl = crl, now = now, policy = policy))) {
    is VerifyResult.Ok -> r.attestation.identity.reportId
    is VerifyResult.Err -> r.violations
}
```

```sh
cd kotlin
./gradlew ktlintCheck detekt test   # requires JDK 21; the artifact targets JVM 11 (Android API 26 and later)
```

## Policy

A `Policy` lists the conditions a report must satisfy. The fields fall into four groups.

| Group | Fields | Form |
|---|---|---|
| identity | `measurement`, `products`, `chipIds`, `endorsementKeyFingerprints`, `signingKey`, `cspIds`, `reportId` | allowlists and exact values |
| session | `reportData` (`exact`, `prefix` or `any`), `hostData`, `familyId`, `imageId`, `idBlock` | exact values |
| configuration bits | `guestPolicy.*` (bits the VM owner set at launch), `platformInfo.*` (bits describing the host), `vmpl` | `required`, `forbidden` or `any` per bit |
| firmware | `minTcb` and `minLaunchTcb` per product, `minFirmware`, `allowProvisionalFirmware`, `minReportVersion`, `requireCrl`, `minLaunchMitVector`, `minCurrentMitVector` | minimum values and flags |

`measurement` is the one field without a default. The defaults forbid the debug, migration and
CXL bits, require VMPL 0, require the committed firmware to equal the running firmware, forbid an
ID block and accept the products Genoa and Turin. Every other field defaults to `any`. The
resolved policy is part of the result as `attestation.policyApplied`. SPEC §5 lists every field.

`baseVcekPolicy` and `baseVlekPolicy` build a policy from four deployment values: the products,
the measurements, the session binding and the TCB floors. They set `minReportVersion` 3,
`requireCrl`, VMPL 0 and `idBlock: any`. `baseVlekPolicy` also takes a `cspIds` allowlist, and
the caller supplies the ASVK and the VLEK CRL as collateral.

Three values must be produced by the caller for every verification. The session binding in
`reportData` is a hash of a fresh nonce and the peer's channel key. The time `now` comes from a
clock the caller trusts. The VCEK, the certificate chain and the CRL are fetched by the caller,
and the CRL is refreshed before its `nextUpdate`.

## Mitigations

[MITIGATIONS.md](MITIGATIONS.md) is a table of published attacks on SEV-SNP. Each row gives the
paper or disclosure, the AMD security bulletin and CVE where one exists, the `Policy` field that
addresses the attack, and the products on which that field is available. The rows cover
microcode and firmware vulnerabilities (CacheWarp, EntrySign, StackWarp, RMPocalypse, Fabricked,
the SB-3007, SB-3011 and SB-3016 series), memory attacks (BadRAM, CipherLeaks, Heracles, PwrLeak,
CounterSEVeillance), guest-kernel attacks that only a measurement allowlist addresses (Heckler,
WeSee, BadAML), protocol conditions (replay, relay, host-requested reports, revoked keys, firmware
rollback), the Milan root-seed extraction, and the attacks the report cannot show (memory
interposers, cache side channels). The document ends with a complete policy, dated, that sets
every field named in the table, in both languages.

## Acknowledgement

The design draws on the author's work with [Tinfoil](https://tinfoil.sh) on attestation
verification. The conformance vectors in `vectors/attestation-sev` and `vectors/quote-sev` come
from that work.

## License

GNU General Public License, version 3 or later. See [LICENSE](LICENSE).
