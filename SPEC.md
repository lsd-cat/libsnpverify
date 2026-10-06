# snpverify — interface specification (v0.1)

This document defines the interface, the checks and the error codes of the AMD SEV-SNP
attestation verifier implemented in `ts/` (TypeScript) and `kotlin/` (Kotlin). Both
implementations are tested against the vectors in `vectors/`.

## 1. Scope

The library is a Verifier in the sense of the RATS architecture (RFC 9334). It appraises one
ATTESTATION_REPORT (AMD publication 56860, report versions 2 to 5) as Evidence. Appraisal consists
of parsing the Evidence, validating the AMD certificate chain that endorses the signing key,
binding that key to the Evidence, checking the Evidence signature, and evaluating an Appraisal
Policy for Evidence supplied by the caller. The Attestation Result contains the decoded report, a
summary of each Endorsement and the appraisal policy as applied. Fetching Endorsements, conveyance
formats, freshness protocols, Reference Value computation, the GHCB certificate table and Intel
TDX are outside this library (§11).

| RFC 9334 term | In this library |
|---|---|
| Attester | the SEV-SNP guest, whose report the AMD Secure Processor signs |
| Evidence | the 1184-byte ATTESTATION_REPORT (`AppraisalInput.evidence`) |
| Endorser | AMD |
| Endorsements | the VCEK or VLEK certificate, the ASK or ASVK certificate, the ARK certificate and the CRL (`AppraisalInput.endorsements`) |
| Trust anchor | the ARK for the product, embedded or supplied as `trustedArks` |
| Reference Value Provider | the builder of the guest image (launch measurements); AMD security bulletins (TCB floors) |
| Reference Values | the measurements, TCB floors, firmware versions and other expected values in the appraisal policy |
| Appraisal Policy for Evidence | `AppraisalPolicy` (§5) |
| Verifier | `SnpVerifier` |
| Attestation Result | `AttestationResult` (§6), or the failed stage and its violations |
| Verifier Owner | the caller that supplies the appraisal policy, the trust anchors and the appraisal time |
| Relying Party | the caller that acts on the Attestation Result |

## 2. Properties

1. The library makes no network requests, does not read the system clock and keeps no global
   state. The caller supplies the appraisal time and all Endorsements, so Evidence can be
   appraised as of any time.
2. The trust anchor is the AMD Root Key (ARK) for the product, compared byte for byte against
   the embedded or caller-supplied root.
3. Unknown report versions, set reserved bits, missing certificate extensions and malformed DER
   are rejected.
4. The caller supplies the appraisal policy. The resolved appraisal policy, with defaults filled
   in, is part of the Attestation Result.
5. The report signature is checked over the report bytes as received.
6. Inputs are size-checked (certificates 16 KiB, CRLs 1 MiB) and copied on entry. Parsed records
   hold their own copies and return copies on access.
7. Each stage returns a result value. Appraisal outcomes are not exceptions.
8. The library has no runtime dependencies. Cryptographic operations go through a provider
   interface with three methods.

## 3. Interface

```
verifier = SnpVerifier({ crypto?, trustedArks? })   // TS: crypto defaults to WebCrypto. Kotlin: SnpVerifier(crypto, trustedArks?)
result   = verifier.appraise(AppraisalInput)

AppraisalInput  { evidence: bytes(1184); endorsements: Endorsements; now: int64; policy: AppraisalPolicy }
Endorsements    { vcek: bytes; ask?: bytes; ark?: bytes; crl?: bytes }   // vcek holds a VCEK or a VLEK; ask an ASK or an ASVK
AppraisalResult = Ok { attestationResult: AttestationResult }
                | Err { stage: parse|chain|bind|signature|policy; violations: Violation[]; partial?: { report?, chain?, tcb? } }
Result<T>       = Ok { value: T } | Err { error: Violation }
Violation       { code: ErrorCode; message: string; field?: string }   // field in 56860 snake_case, e.g. "guest_policy.debug"
```

The constructor takes the cryptographic provider and the trust anchors. `appraise` takes one
piece of Evidence, its Endorsements, the appraisal time and the appraisal policy. The five stages
are also callable on their own: `parseReport`, `verifyChain`, `bindEndorsement`,
`verifyReportSignature` and `checkAppraisalPolicy`, with `resolveAppraisalPolicy` filling policy
defaults. `appraisalPolicyFromJson` reads the JSON form of a policy (§5) and
`appraisalPolicyToJson` writes the JSON form of a resolved policy. The parse, chain, bind and
signature stages return the first violation found. The policy stage returns all violations.

## 4. Providers

```
CryptoProvider {
  verifyRsaPss(spki, msg, sig, saltLength) -> bool    // RSASSA-PSS, SHA-384, MGF1-SHA-384, modulus >= 4096
  verifyEcdsaP384(spki, msg, r, s) -> bool            // SHA-384; r, s 48-byte big-endian
  sha256(data) -> bytes
}
```

The TypeScript implementation provides `webCrypto`, which uses the WebCrypto API. The Kotlin
implementation provides `JcaCryptoProvider(provider: java.security.Provider? = null)`, which uses
the Java Cryptography Architecture; `null` selects the platform provider, and
`BouncyCastleProvider()` selects BouncyCastle.

## 5. Appraisal policy

The appraisal policy holds the Reference Values and the rules for comparing the Evidence with them.
`Bit` has three values: `required` (the report bit must be set), `forbidden` (the report bit must
be clear) and `any`. Byte-valued fields are compared for equality when present. Defaults are in
brackets.

```
AppraisalPolicy {
  measurement:          bytes(48)[] | "any"      // required; an empty list is POLICY_INVALID
  products?:            Product[]               [Genoa, Turin]
  signingKey?:          VCEK | VLEK | any       [VCEK]
  allowMaskedChipId?:   bool                    [false]  // accept an all-zero CHIP_ID on a VCEK report
  chipIds?:             bytes(64)[]             // CHIP_ID allowlist; VCEK, unmasked
  endorsementKeyFingerprints?: bytes(32)[]      // SHA-256(DER) of the leaf; changes on reissuance
  cspIds?:              string[]                // CSP_ID allowlist for VLEK
  requireCrl?:          bool                    [false]  // a missing CRL is a violation
  guestPolicy?:  { debug, migrateMa, smt, singleSocket, cxlAllowed, memAes256Xts, raplDisabled,
                   ciphertextHidingDram, pageSwapDisabled: Bit; minAbi?: {major, minor} }
                                                [debug, migrateMa, cxlAllowed forbidden; rest any]
  platformInfo?: { smtEnabled, tsmeEnabled, eccEnabled, raplDisabled, ciphertextHidingEnabled,
                   aliasCheckComplete, iommuWriteSafe, tioEnabled: Bit; allowUnknownBits?: bool }
                                                [all any; allowUnknownBits false]
  vmpl?:                0..3 | any              [0]
  minReportVersion?:    2..5                    [2]      // 3 requires the CPUID product cross-check
  minGuestSvn?:         int                     [0]
  minTcb?:              { [Product]: TcbFloor } [none]   // floor for current, committed, reported
  minLaunchTcb?:        { [Product]: TcbFloor } [= minTcb]
  minFirmware?:         { major?, minor?, build? } [0.0.0]
  allowProvisionalFirmware?: bool               [false]  // committed must equal current
  minLaunchMitVector?, minCurrentMitVector?: uint64      // v5; bits that must be present
  reportData?:          { kind: exact, value: bytes(64) } | { kind: prefix, value: bytes(1..64) } | { kind: any }   [any]
  hostData?: bytes(32); familyId?, imageId?: bytes(16); reportId?: bytes(32)
  idBlock?:             forbid | any | { idKeyDigest: bytes(48), authorKeyDigest?: bytes(48) }   [forbid]
}
TcbFloor { bootloader?, tee?, snp?, microcode?, fmc?: int }   // absent = unconstrained
```

**JSON form.** A policy is also a JSON document with the keys above, in the encoding `toJson()`
uses for `attestationResult.appraisalPolicy` (§6): byte values as lowercase hexadecimal strings,
`minLaunchMitVector` and `minCurrentMitVector` as decimal strings, `Bit`, `vmpl: "any"`,
`signingKey`, `measurement: "any"` and `idBlock: "forbid" | "any"` as strings, `products` and
`minTcb` keys as product names. A `"$comment"` key is permitted in any object and ignored. Absent
keys take the defaults; unknown keys, wrong types and out-of-range values are `POLICY_INVALID`,
with the same message in every port. `appraisalPolicyToJson(resolveAppraisalPolicy(p))` is itself
a valid document that resolves to the same policy. Documents must be strict JSON without duplicate
keys; the ports' JSON parsers differ only outside that (org.json accepts a superset and, on the
JVM, rejects duplicate keys). `vectors/policy.json` pins accepted documents
with their resolved form and rejected documents with their message; MITIGATIONS.md carries a
complete document.

`reportData` carries the freshness and session binding. With `exact` or `prefix`, the Evidence must
contain the value the Verifier expects, for example a hash of a nonce chosen for this appraisal and
the Attester's channel key. With `any`, the Evidence may have been produced for another session. An
all-zero `authorKeyDigest` pin requires AUTHOR_KEY_EN to be 0.

`baseVcekAppraisalPolicy` and `baseVlekAppraisalPolicy` construct an appraisal policy from three
Reference Values (the products, a non-empty measurement allowlist and a complete TCB floor for each
product) and a non-zero 64-byte `reportData` value. Both set `minReportVersion` 3, `vmpl` 0,
`requireCrl` true, `allowProvisionalFirmware` false and `idBlock` any. `baseVlekAppraisalPolicy`
also takes a non-empty `cspIds` allowlist; the caller supplies the ASVK and the VLEK CRL as
Endorsements.

## 6. Attestation Result

```
AttestationResult {
  identity  { chipId(64) reportId(32) reportIdMa(32) measurement(48) hostData(32) reportData(64) familyId(16) imageId(16) guestSvn vmpl }
  platform  { product productName cpuid? guestPolicy platformInfo tcb{current,committed,reported,launch} firmware{current,committed}
              mitVectors?{launch,current} signer{signingKey,maskChipKey,authorKeyEnabled} idKeyDigest(48) authorKeyDigest(48) }
  evidence  { reportVersion reportSha256(32) signature{r,s} }
  endorsements { endorsementKey{sha256,serial,subjectCn,notBefore,notAfter,kind,hwid?,cspId?,tcb}
              ask{sha256,serial,subjectCn,notBefore,notAfter} ark{...} crl?{thisUpdate,nextUpdate,revokedCount} }
  appraisalPolicy: resolved AppraisalPolicy     appraisedAt: int64
}
```

CHIP_ID identifies the physical chip. REPORT_ID identifies the virtual machine instance; it is
constant for the life of one boot and differs between boots. `reportSha256` is the SHA-256 of the
1184 report bytes. `toJson()` renders byte arrays as lowercase hexadecimal, 64-bit raw values as
decimal strings, and enumerations as strings; `Bit` values are lowercase. Every port produces the
same JSON for the same input.

## 7. Error codes (closed set)

```
parse      REPORT_TRUNCATED REPORT_VERSION_UNSUPPORTED REPORT_HOST_REQUESTED REPORT_MALFORMED REPORT_SIGNATURE_ALGO_UNSUPPORTED
chain      CERT_MALFORMED CERT_ALGO_UNSUPPORTED ARK_UNTRUSTED CHAIN_SIGNATURE_INVALID CHAIN_NAME_MISMATCH CERT_NOT_YET_VALID CERT_EXPIRED
           VCEK_EXTENSION_INVALID PRODUCT_MISMATCH CRL_INVALID CRL_EXPIRED CERT_REVOKED
bind       VCEK_TCB_MISMATCH VCEK_HWID_MISMATCH SIGNER_KIND_MISMATCH PRODUCT_MISMATCH REPORT_MALFORMED
signature  REPORT_SIGNATURE_INVALID
policy     POLICY_INVALID POLICY_PRODUCT_NOT_ALLOWED POLICY_SIGNER_NOT_ALLOWED POLICY_CHIP_ID_MASKED POLICY_CHIP_ID_NOT_ALLOWED
           POLICY_GUEST_POLICY POLICY_ABI_VERSION POLICY_PLATFORM_INFO POLICY_VMPL POLICY_GUEST_SVN POLICY_TCB_OUT_OF_DATE
           POLICY_LAUNCH_TCB_OUT_OF_DATE POLICY_PROVISIONAL_FIRMWARE POLICY_FIRMWARE_VERSION POLICY_MITIGATION_VECTOR
           POLICY_MEASUREMENT_MISMATCH POLICY_REPORT_DATA_MISMATCH POLICY_HOST_DATA_MISMATCH POLICY_FAMILY_ID_MISMATCH
           POLICY_IMAGE_ID_MISMATCH POLICY_REPORT_ID_MISMATCH POLICY_ID_BLOCK
```

`POLICY_INVALID` is reported for a malformed policy object, for a missing CRL when `requireCrl`
is set, and for a report version below `minReportVersion`. A violation of a `guestPolicy` or
`platformInfo` rule names the bit in `field`, for example `guest_policy.debug`.

## 8. Products

| Product | CPUID family, model | TCB layout | HWID | structVersion | Roots |
|---|---|---|---|---|---|
| Milan | 0x19, 0x00–0x0F | v0 `[bl,tee,r,r,r,r,snp,ucode]` | 64 | 0 | embedded |
| Genoa | 0x19, 0x10–0x1F and 0xA0–0xAF (Bergamo, Siena) | v0 | 64 | 0 | embedded |
| Turin | 0x1A, 0x00–0x1F | v1 `[fmc,bl,tee,snp,r,r,r,ucode]` | 8 | 1 | embedded |
| Venice | 0x1A, 0x50–0x5F | v2, pending | 8 | 1 | pending |

The VCEK and VLEK certificates carry AMD extensions under 1.3.6.1.4.1.3704.1: .1 structVersion,
.2 productName, .3.1 bl, .3.2 tee, .3.3 snp, .3.4 spl4 (layout v0 only, value 0), .3.5 to .3.7
(value 0), .3.8 ucode, .3.9 fmc (layout v1), .4 hwid, .5 csp_id. The hwid value is accepted as a
raw byte string or wrapped in an OCTET STRING. The productName value may carry a stepping suffix,
for example `Genoa-B2`. PEM input may carry trailing whitespace. A certificate is rejected when a
listed extension for its layout is missing, when it carries both hwid and csp_id or neither, or
when structVersion does not match the product. The subject of each of the three certificates must
contain O=Advanced Micro Devices and OU=Engineering.

## 9. Checks, in order

1. **parse**: length 1184; version 2–5 (4 uses the v3 layout); VMPL 0xFFFFFFFF →
   REPORT_HOST_REQUESTED, VMPL > 3 → REPORT_MALFORMED; signature_algo 1; zero at 0x4C–0x4F,
   0x188–0x19F (v2) or 0x18B–0x19F (v3+), 0x1EB, 0x1EF, 0x1F8–0x207 (v<5), 0x208–0x29F,
   0x330–0x49F; policy bit 17 set and bits 63:26 clear; signer_info bits 31:5 clear and
   signing_key ∈ {VCEK, VLEK}; r and s upper 24 bytes zero.
2. **chain**: leaf extensions and product; root byte-equal to a trusted ARK; CNs end with the
   product; VLEK ⇔ ASVK; AMD O/OU; issuer/subject chaining; validity at `now`; basicConstraints
   CA on root and intermediate, not on the leaf; keyUsage, when present, permits the use
   (keyCertSign for CAs, digitalSignature for the leaf); no unsupported critical extensions;
   leaf key EC P-384; ARK self-signature, ASK by ARK, leaf by ASK (RSA-PSS SHA-384, explicit
   MGF1-SHA-384, salt 48, modulus ≥ 4096). CRL, when given: issuer is the ARK; the ARK carries
   keyUsage with cRLSign (RFC 5280, RFC 10007); signature; `nextUpdate` present and
   thisUpdate ≤ now ≤ nextUpdate; no delta CRL, no critical CRL extensions; ASK and ARK serials
   not listed.
3. **bind**: signer kind equals leaf kind; reported_tcb equals the leaf TCB; for a VCEK with
   nonzero CHIP_ID, chip_id[0:len(hwid)] equals hwid; v3+: CPUID product equals leaf product.
   SIGNER_INFO.MASK_CHIP_KEY is exposed, not enforced.
4. **signature**: ECDSA P-384/SHA-384 over bytes 0..0x29F.
5. **policy**: §5, and endorsement-key TCB ≤ current_tcb.

## 10. Conformance

Each port runs:

- the Tinfoil `attestation-sev` vectors (48) and `quote-sev` vectors (13);
- mutation tests on the real Genoa report in `attestation-sev/200`;
- regression cases for policy validation, input ownership and certificate rules, with fixtures
  in `vectors/review/`;
- the cross-port golden result `vectors/golden/real-genoa.json`;
- the cross-port violation vector `vectors/expected-violations.json` (stage, code, field and
  message for twenty rejections);
- the cross-port policy vector `vectors/policy.json` (JSON policies with their resolved form, or
  the `POLICY_INVALID` message). The conformance vectors are run with policies built in the JSON
  form, so the loader is exercised by every port.

The TypeScript tests write the regression fixtures, the golden result, the violation vector and
the policy vector when
the files are absent, or when the environment variable `SNP_VECTORS_REGEN` is set. `vectors/kds/`
is a snapshot of the AMD Key Distribution Service certificate chains and CRLs taken on
2026-10-04. `ts/scripts/fetch-roots.mjs` regenerates the embedded root certificates from the
Key Distribution Service.

The vector `quote-sev/sev-happy` is expected to produce `CRL_INVALID`. Its synthetic ARK has no
keyUsage extension, and RFC 10007 requires the keyUsage extension with cRLSign on a CRL issuer.
AMD's ARKs carry it.

## 11. Later modules

- **bundle and transport**: a RATS Conceptual Message Wrapper document carrying the Evidence, the
  Endorsements (VCEK, ASK and ARK certificates, CRL) and an optional epoch value, retrieved through a
  `Transport` interface (`request(method, url, headers?, body?) -> { status, headers, body }`),
  which an OHTTP client can implement.
- **epoch handles**: drand rounds, with BLS signature verification supplied by the caller, and
  Roughtime responses.
- **mitigations**: a versioned table mapping AMD bulletins to TCB floors and bits, a function
  that compiles a selection into an `AppraisalPolicy`, and a function that reports which entries
  an `AttestationResult` satisfies.
- **cert-table**: parsing of the GHCB extended-report certificate table (GUIDs for VCEK, VLEK,
  ASK, ARK and CRL) into `Endorsements`.
- **kds**: construction of AMD Key Distribution Service URLs and a cache contract (10-second rate
  limit, `nextUpdate` as time to live) for server-side callers.
- **measure**: computation of launch measurements, the Reference Values for the measurement
  allowlist.
- **Venice**: the product table row, TCB layout v2 and the root certificates.
- **EAR/EAT**: a mapping of `AttestationResult` to the EAT Attestation Result (EAR) format.
- **TDX**: Intel TDX quotes as Evidence, under the same Attestation Result shape.
