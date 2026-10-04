# Security review of the TypeScript and Kotlin verifiers

Review date: 2026-10-04. Scope: report parsing, endorsement-chain and CRL validation,
report-to-certificate binding, policy evaluation, and the base policies in both ports. The
review consists of code reading and executable regression cases with signed test collateral.
It is not a proof of X.509 or SEV-SNP implementation correctness.

The regression tests use a locally generated certificate chain. Its root is trusted only when a
test passes it to the verifier as `trustedArks`. It is not AMD collateral.

## Findings

Each row names a condition the review examined and states the behaviour of the code.

| ID | Severity | Condition examined | Behaviour of the code |
|---|---|---|---|
| R1 | High | Policy values that are undefined, misspelled, out of range or negative. | Both ports validate every policy value and numeric range before verification (`ts/src/policy.ts` `resolvePolicy`, `kotlin/.../Policy.kt` `resolvePolicy`). TypeScript rejects unknown field names and unknown `Bit` and `reportData.kind` values. A malformed policy yields `POLICY_INVALID`. |
| R2 | High | Caller-owned bytes or policy objects that change while an asynchronous signature check is in progress. | `SnpVerifier.verify` and `verifyChain` copy the report, every certificate, the CRL, the trusted roots, the policy and `now` on entry, before any cryptographic call (`ts/src/index.ts`, `ts/src/chain.ts`, `kotlin/.../SnpVerifier.kt`, `kotlin/.../Chain.kt`). `verifiedAt` in the result is the `now` value used for the chain checks. |
| R3 | Medium | Certificates and CRLs with structural defects. | Both DER readers map bounds and date failures to `CERT_MALFORMED` or `CRL_INVALID` violations (`ts/src/der.ts`, `kotlin/.../Der.kt`). |
| R4 | Medium | The relation between SIGNER_INFO.MASK_CHIP_KEY and an all-zero CHIP_ID. | The verifier detects a masked chip from an all-zero CHIP_ID. It compares the VCEK HWID with CHIP_ID only when CHIP_ID is nonzero. A zero CHIP_ID on a VCEK-signed report is accepted only when the policy sets `allowMaskedChipId`. MASK_CHIP_KEY is parsed and exposed and is not a check. |
| R5 | Low | The default for the guest policy bit MEM_AES_256_XTS. | The default is `any`. Setting the bit requests the 256-bit memory encryption mode. A policy can require or forbid it. |
| R6 | High with caller-supplied roots | Certificates and CRLs that carry a valid signature but lack the attributes for their role. | Root and intermediate certificates must carry basicConstraints CA=true; the leaf must not. keyUsage, when present, must include keyCertSign for a CA and digitalSignature for the leaf. Certificates and CRLs with an unsupported critical extension are rejected. Delta CRLs are rejected. The CRL issuer must carry keyUsage with cRLSign (RFC 5280 as updated by RFC 10007). |
| R7 | Medium | CRLs without `nextUpdate`. | A supplied CRL must carry `nextUpdate`, must satisfy `thisUpdate ≤ now ≤ nextUpdate`, and must carry a valid ARK signature. |

## Properties verified by the regression tests

Each statement describes current behaviour in both ports. The TypeScript tests are in
`ts/test/security-review.test.ts` and `ts/test/mutation.test.ts`; the Kotlin tests are in
`kotlin/src/test/kotlin/snpverify/SecurityReviewTest.kt` and `MutationTest.kt`.

- `POLICY_CHIP_ID_MASKED` applies to VCEK-signed reports. VLEK-signed reports carry an all-zero
  CHIP_ID by definition and are not subject to this check.
- An empty measurement allowlist is `POLICY_INVALID`.
- Parsed reports, certificates, CRLs, extensions and endorsement keys hold a private copy of
  their bytes. Every byte-valued field returns a copy on access. In TypeScript the records are
  frozen objects with copying getters (`protect` in `ts/src/bytes.ts`); in Kotlin they are
  classes with private buffers and copying properties. Mutating `report.measurement` or
  `chain.leaf.cert.spki` after parsing has no effect on `verifyReportSignature`,
  `bindEndorsement` or `checkPolicy`.
- The certificate and CRL parsers copy the input DER on entry. Extension values and revocation
  serials point into that copy. Kotlin exposes extension maps as unmodifiable.
- Every byte copy in the TypeScript port goes through `copy()` or `copyRange()` in
  `ts/src/bytes.ts`, implemented with `new Uint8Array(view)`. No `.slice()` call on bytes exists
  in `ts/src`; the test `source invariant: no .slice() on bytes in src` enforces this. Returned
  bytes are plain `Uint8Array` values when the caller passes a Node `Buffer`. The test
  `Node Buffer inputs never alias` passes `Buffer`s to every parser, to `verifyChain` and to
  `verify`, zeroes them while verification is in progress, and checks the results are unchanged.
- `verify()` and `verifyChain()` check the report length (1184 bytes) and the certificate and
  CRL size caps (16 KiB and 1 MiB) before copying any input.
- `resolvePolicy` copies the byte arrays in the policy in both ports. DN attributes longer than
  4096 bytes are rejected. `policyApplied.signingKey` renders `any` in lowercase in both ports.
- Kotlin `toJson` emits `cspIds`. The two ports produce identical JSON for
  `vectors/golden/real-genoa.json` and identical stage, code, field and message for every case
  in `vectors/expected-violations.json`.
- The test vector `quote-sev/sev-happy` is asserted as `CRL_INVALID` in both ports. Its synthetic
  ARK carries no keyUsage extension; RFC 10007 requires keyUsage with cRLSign on a v3 CRL
  issuer. AMD's ARKs carry keyUsage with cRLSign.
- Report version 6 (ABI 1.59) is rejected with `REPORT_VERSION_UNSUPPORTED`.

## Base policies

`baseVcekPolicy` and `baseVlekPolicy` (`ts/src/base-policies.ts`,
`kotlin/src/main/kotlin/snpverify/BasePolicies.kt`) build a `Policy` from caller values. They
require:

- a non-empty allowlist of 48-byte launch measurements and a non-empty list of supported
  products;
- a nonzero 64-byte `REPORT_DATA` value, matched exactly;
- a TCB floor for every product in the list, with every component present (`fmc` for Turin);
  the floor applies to the current, committed, reported and launch TCB.

They set report version 3 or later, VMPL 0, `requireCrl`, no provisional firmware and
`idBlock: any`. `baseVcekPolicy` requires a VCEK signer. `baseVlekPolicy` requires a VLEK
signer and a non-empty `cspIds` allowlist; the caller supplies the ASVK and the VLEK CRL as
collateral.

The base policies do not set a firmware version floor, mitigation vectors, a chip allowlist or
platform bits. A deployment sets those on the returned `Policy` when it needs them. The `Policy`
record also covers report version 2, masked chips, other VMPLs and ID-block pins.

## Deployment responsibilities and limits

1. The verifier does not generate a nonce, does not authenticate a transport and does not
   check how `REPORT_DATA` was computed. The caller chooses a fresh challenge per verification,
   binds it to the authenticated peer key or session transcript, computes the 64-byte expected
   value, passes it as `reportData`, and rejects reuse. A constant nonzero `REPORT_DATA` value
   satisfies the base policy constructors and gives no freshness.
2. The caller supplies `now`. It must come from a trusted clock, or from an archival policy
   when a stored report is verified as of a past time. The caller fetches the VCEK, the ASK and
   ARK, and the CRL, and refreshes the CRL before its `nextUpdate`. A caller-supplied
   `trustedArks` set replaces AMD's roots as the trust anchor.
3. TCB floors and mitigation requirements come from AMD security bulletins for the product and
   firmware in use. Some mitigations also require a host OS update or a guest restart
   (AMD-SB-3016 is one example). A report does not carry that state.
4. The DER reader supports the AMD certificate profile. It does not build arbitrary PKIX paths.
   A certificate or CRL with an unsupported critical extension is rejected. Input sizes are
   bounded per certificate and per CRL; the library has no request-level or process-level
   budget. A service that accepts reports from the network limits request size and
   verification concurrency before calling the library. Fuzzing and an independent audit are
   advisable before the library is the only trust decision in a production system.
5. The product table and the parsing rules follow ABI revision 1.58. AMD publishes revision
   1.59, which defines report version 6; this library rejects version 6. Venice appears in the
   product table as an entry that rejects reports.

## Reproduction

From the repository root:

```sh
cd ts && npm test              # includes test/security-review.test.ts; writes vectors/review/ fixtures when absent
cd ../kotlin && ./gradlew test # includes SecurityReviewTest.kt, reading vectors/review/
```

The TypeScript test writes only public DER, CRL and report fixtures to `vectors/review/`. Private
test keys exist only in the TypeScript process. `SNP_VECTORS_REGEN=1` regenerates the fixtures.

## Primary references

- [AMD SEV-SNP Firmware ABI, current document index](https://docs.amd.com/v/u/en-US/56860_PUB_SEV_SNP)
- [AMD VCEK certificate and KDS specification](https://docs.amd.com/v/u/en-US/57230)
- [AMD VLEK certificate definition](https://docs.amd.com/v/u/en-US/58369_PUB_0.10_VLEK)
- [RFC 5280, certificate and CRL profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [RFC 10007, CRL issuer key usage](https://www.rfc-editor.org/rfc/rfc10007.html)
- [AMD-SB-3016, firmware, OS and restart requirements](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html)
