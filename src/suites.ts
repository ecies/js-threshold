import { SHAMIR_SHARE_LENGTH, TAG_LENGTH } from "./consts";

/** A row of SPEC.md's suite table. The field names follow eciesjs's `Config`. */
export interface Suite {
  readonly id: number;
  readonly ellipticCurve: "secp256k1" | "x25519" | "ed25519";
  /** secp256k1 only; false on the others */
  readonly isEphemeralKeyCompressed: boolean;
  /** secp256k1 only; false on the others */
  readonly isHkdfKeyCompressed: boolean;
  readonly symmetricAlgorithm: "aes-256-gcm" | "xchacha20";
  /** Ln: 12 or 16 for AES-256-GCM, 24 for XChaCha20-Poly1305 */
  readonly nonceLength: number;
  /** W: the ephemeral key, the nonce, the tag and the encrypted share */
  readonly wrappedLength: number;
}

type Cipher = readonly [Suite["symmetricAlgorithm"], number];

const AES_16: Cipher = ["aes-256-gcm", 16];
const AES_12: Cipher = ["aes-256-gcm", 12];
const XCHACHA: Cipher = ["xchacha20", 24];

function row(
  id: number,
  ellipticCurve: Suite["ellipticCurve"],
  isEphemeralKeyCompressed: boolean,
  isHkdfKeyCompressed: boolean,
  [symmetricAlgorithm, nonceLength]: Cipher
): Suite {
  const ephemeralKey =
    ellipticCurve !== "secp256k1" ? 32 : isEphemeralKeyCompressed ? 33 : 65;
  return {
    id,
    ellipticCurve,
    isEphemeralKeyCompressed,
    isHkdfKeyCompressed,
    symmetricAlgorithm,
    nonceLength,
    wrappedLength: ephemeralKey + nonceLength + TAG_LENGTH + SHAMIR_SHARE_LENGTH,
  };
}

const SUITES = new Map(
  [
    row(0x01, "secp256k1", false, false, AES_16),
    row(0x02, "secp256k1", false, false, AES_12),
    row(0x03, "secp256k1", false, false, XCHACHA),
    row(0x04, "secp256k1", true, false, AES_16),
    row(0x05, "secp256k1", true, false, AES_12),
    row(0x06, "secp256k1", true, false, XCHACHA),
    row(0x07, "secp256k1", false, true, AES_16),
    row(0x08, "secp256k1", false, true, AES_12),
    row(0x09, "secp256k1", false, true, XCHACHA),
    row(0x0a, "secp256k1", true, true, AES_16),
    row(0x0b, "secp256k1", true, true, AES_12),
    row(0x0c, "secp256k1", true, true, XCHACHA),
    row(0x11, "x25519", false, false, AES_16),
    row(0x12, "x25519", false, false, AES_12),
    row(0x13, "x25519", false, false, XCHACHA),
    row(0x21, "ed25519", false, false, AES_16),
    row(0x22, "ed25519", false, false, AES_12),
    row(0x23, "ed25519", false, false, XCHACHA),
  ].map((suite) => [suite.id, suite])
);

/** The suite with this ID, or undefined if the table doesn't list it. */
export function getSuite(id: number): Suite | undefined {
  return SUITES.get(id);
}
