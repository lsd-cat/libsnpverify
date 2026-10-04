// ATTESTATION_REPORT parsing (AMD 56860), report versions 2 to 5.
// TCBs stay raw; decodeTcb() takes the product layout established by the chain stage.
import { fail, stage, type Result } from './errors.ts';
import { copy, copyRange, isZero, protect, u32le, u64le } from './bytes.ts';

export const REPORT_SIZE = 0x4a0;
export const SIGNED_SIZE = 0x2a0;

export type Product = 'Milan' | 'Genoa' | 'Turin' | 'Venice';
export type TcbLayout = 'v0' | 'v1' | 'v2';
export type SigningKey = 'VCEK' | 'VLEK';

export interface TcbVersion { bootloader: number; tee: number; snp: number; microcode: number; fmc?: number }

export interface GuestPolicy {
  raw: bigint; abiMajor: number; abiMinor: number;
  smt: boolean; migrateMa: boolean; debug: boolean; singleSocket: boolean; cxlAllowed: boolean;
  memAes256Xts: boolean; raplDisabled: boolean; ciphertextHidingDram: boolean; pageSwapDisabled: boolean;
}

export interface PlatformInfo {
  raw: bigint;
  smtEnabled: boolean; tsmeEnabled: boolean; eccEnabled: boolean; raplDisabled: boolean;
  ciphertextHidingEnabled: boolean; aliasCheckComplete: boolean; iommuWriteSafe: boolean; tioEnabled: boolean;
}

export interface SignerInfo { signingKey: SigningKey; maskChipKey: boolean; authorKeyEnabled: boolean }
export interface FirmwareVersion { major: number; minor: number; build: number }

export interface Report {
  raw: Uint8Array;
  version: number;
  guestSvn: number;
  policy: GuestPolicy;
  familyId: Uint8Array; imageId: Uint8Array;
  vmpl: number;
  currentTcb: bigint;
  platformInfo: PlatformInfo;
  signerInfo: SignerInfo;
  reportData: Uint8Array; measurement: Uint8Array; hostData: Uint8Array;
  idKeyDigest: Uint8Array; authorKeyDigest: Uint8Array;
  reportId: Uint8Array; reportIdMa: Uint8Array;
  reportedTcb: bigint;
  cpuid?: { family: number; model: number; stepping: number };   // v3+
  chipId: Uint8Array;
  committedTcb: bigint;
  currentVersion: FirmwareVersion; committedVersion: FirmwareVersion;
  launchTcb: bigint;
  launchMitVector?: bigint; currentMitVector?: bigint;              // v5+
  /** r, s big-endian 48 bytes each. */
  signature: { r: Uint8Array; s: Uint8Array };
  signedBytes: Uint8Array;
}

const mbz = (b: Uint8Array, s: number, e: number) => { if (!isZero(b, s, e)) fail('REPORT_MALFORMED', `reserved bytes 0x${s.toString(16)}..0x${e.toString(16)} not zero`); };
const bitOf = (raw: bigint) => (n: number) => ((raw >> BigInt(n)) & 1n) === 1n;

export function decodeGuestPolicy(raw: bigint): GuestPolicy {
  const bit = bitOf(raw);
  if (!bit(17)) fail('REPORT_MALFORMED', 'guest_policy bit 17 must be 1', 'guest_policy');
  if (raw >> 26n !== 0n) fail('REPORT_MALFORMED', 'guest_policy bits 63:26 must be 0', 'guest_policy');
  return { raw, abiMinor: Number(raw & 0xffn), abiMajor: Number((raw >> 8n) & 0xffn), smt: bit(16), migrateMa: bit(18), debug: bit(19),
    singleSocket: bit(20), cxlAllowed: bit(21), memAes256Xts: bit(22), raplDisabled: bit(23), ciphertextHidingDram: bit(24), pageSwapDisabled: bit(25) };
}

/** Bits this library knows. Unknown set bits are a policy matter (Policy.platformInfo.allowUnknownBits). */
export const KNOWN_PLATFORM_INFO_BITS = 0xffn;

export function decodePlatformInfo(raw: bigint): PlatformInfo {
  const bit = bitOf(raw);
  return { raw, smtEnabled: bit(0), tsmeEnabled: bit(1), eccEnabled: bit(2), raplDisabled: bit(3), ciphertextHidingEnabled: bit(4),
    aliasCheckComplete: bit(5), iommuWriteSafe: bit(6), tioEnabled: bit(7) };
}

export function decodeSignerInfo(raw: number): SignerInfo {
  if (raw >>> 5 !== 0) fail('REPORT_MALFORMED', 'signer_info bits 31:5 must be 0', 'signer_info');
  const key = (raw >>> 2) & 7;
  if (key !== 0 && key !== 1) fail('REPORT_MALFORMED', `signer_info.signing_key ${key} is not VCEK or VLEK`, 'signer_info.signing_key');
  return { signingKey: key === 0 ? 'VCEK' : 'VLEK', maskChipKey: (raw & 2) !== 0, authorKeyEnabled: (raw & 1) !== 0 };
}

export function decodeTcb(raw: bigint, layout: TcbLayout): TcbVersion {
  const byte = (n: number) => Number((raw >> BigInt(8 * n)) & 0xffn);
  switch (layout) {
    case 'v0':
      if ((raw & 0x0000ffffffff0000n) !== 0n) fail('REPORT_MALFORMED', 'TCB reserved bytes 2..5 not zero');
      return { bootloader: byte(0), tee: byte(1), snp: byte(6), microcode: byte(7) };
    case 'v1':
      if ((raw & 0x00ffffff00000000n) !== 0n) fail('REPORT_MALFORMED', 'Turin TCB reserved bytes 4..6 not zero');
      return { fmc: byte(0), bootloader: byte(1), tee: byte(2), snp: byte(3), microcode: byte(7) };
    case 'v2':
      return fail('REPORT_MALFORMED', 'Venice TCB layout not supported yet');
  }
}

export function tcbAtLeast(a: TcbVersion, min: Partial<TcbVersion>): boolean {
  return (min.bootloader === undefined || a.bootloader >= min.bootloader) && (min.tee === undefined || a.tee >= min.tee)
    && (min.snp === undefined || a.snp >= min.snp) && (min.microcode === undefined || a.microcode >= min.microcode)
    && (min.fmc === undefined || (a.fmc ?? 0) >= min.fmc);
}

export function tcbEqual(a: TcbVersion, b: TcbVersion): boolean {
  return a.bootloader === b.bootloader && a.tee === b.tee && a.snp === b.snp && a.microcode === b.microcode && (a.fmc ?? 0) === (b.fmc ?? 0);
}

function le72ToBe48(b: Uint8Array, off: number, what: string): Uint8Array {
  if (!isZero(b, off + 48, off + 72)) fail('REPORT_MALFORMED', `signature ${what} exceeds 384 bits`, 'signature');
  const out = new Uint8Array(48);
  for (let i = 0; i < 48; i++) out[i] = b[off + 47 - i];
  return out;
}

export function parseReport(data: Uint8Array): Result<Report> {
  return stage(() => {
    if (data.length !== REPORT_SIZE) fail('REPORT_TRUNCATED', `report is ${data.length} bytes, want ${REPORT_SIZE}`);
    data = copy(data);
    const version = u32le(data, 0x00);
    if (version < 2 || version > 5) fail('REPORT_VERSION_UNSUPPORTED', `report version ${version}`, 'version');
    const vmpl = u32le(data, 0x30);
    if (vmpl === 0xffffffff) fail('REPORT_HOST_REQUESTED', 'report was requested by the host (VMPL=0xFFFFFFFF), not by the guest', 'vmpl');
    if (vmpl > 3) fail('REPORT_MALFORMED', `vmpl ${vmpl} out of range 0..3`, 'vmpl');
    const signatureAlgo = u32le(data, 0x34);
    if (signatureAlgo !== 1) fail('REPORT_SIGNATURE_ALGO_UNSUPPORTED', `signature_algo ${signatureAlgo}`, 'signature_algo');
    mbz(data, 0x4c, 0x50);
    mbz(data, version >= 3 ? 0x18b : 0x188, 0x1a0);
    mbz(data, 0x1eb, 0x1ec);
    mbz(data, 0x1ef, 0x1f0);
    if (version < 5) mbz(data, 0x1f8, 0x208);
    mbz(data, 0x208, SIGNED_SIZE);
    mbz(data, SIGNED_SIZE + 144, REPORT_SIZE);
    const r: Report = {
      raw: data,
      version,
      guestSvn: u32le(data, 0x04),
      policy: decodeGuestPolicy(u64le(data, 0x08)),
      familyId: copyRange(data, 0x10, 0x20), imageId: copyRange(data, 0x20, 0x30),
      vmpl,
      currentTcb: u64le(data, 0x38),
      platformInfo: decodePlatformInfo(u64le(data, 0x40)),
      signerInfo: decodeSignerInfo(u32le(data, 0x48)),
      reportData: copyRange(data, 0x50, 0x90), measurement: copyRange(data, 0x90, 0xc0), hostData: copyRange(data, 0xc0, 0xe0),
      idKeyDigest: copyRange(data, 0xe0, 0x110), authorKeyDigest: copyRange(data, 0x110, 0x140),
      reportId: copyRange(data, 0x140, 0x160), reportIdMa: copyRange(data, 0x160, 0x180),
      reportedTcb: u64le(data, 0x180),
      chipId: copyRange(data, 0x1a0, 0x1e0),
      committedTcb: u64le(data, 0x1e0),
      currentVersion: { build: data[0x1e8], minor: data[0x1e9], major: data[0x1ea] },
      committedVersion: { build: data[0x1ec], minor: data[0x1ed], major: data[0x1ee] },
      launchTcb: u64le(data, 0x1f0),
      signature: { r: le72ToBe48(data, SIGNED_SIZE, 'r'), s: le72ToBe48(data, SIGNED_SIZE + 72, 's') },
      signedBytes: copyRange(data, 0, SIGNED_SIZE),
    };
    if (version >= 3) r.cpuid = { family: data[0x188], model: data[0x189], stepping: data[0x18a] };
    if (version >= 5) { r.launchMitVector = u64le(data, 0x1f8); r.currentMitVector = u64le(data, 0x200); }
    return protect(r);
  });
}
