import { SHAMIR_SHARE_LENGTH, TAG_LENGTH } from "./consts";

/**
 * A row of SPEC.md's suite table. The field names follow eciesjs's `Config`, except
 * `nonceLength`, which also holds XChaCha20-Poly1305's 24 bytes.
 */
export interface Suite {
  readonly id: number;
  readonly ellipticCurve: "secp256k1" | "x25519" | "ed25519";
  /** secp256k1 only; false on the others */
  readonly isEphemeralKeyCompressed: boolean;
  /** secp256k1 only; false on the others */
  readonly isHkdfKeyCompressed: boolean;
  readonly symmetricAlgorithm: "aes-256-gcm" | "xchacha20";
  /** Ln: 12 or 16 for AES-256-GCM, 24 for XChaCha20-Poly1305 */
  readonly nonceLength: 12 | 16 | 24;
  /** W: the ephemeral key, the nonce, the tag and the encrypted share */
  readonly wrappedLength: number;
}

type Cipher = Pick<Suite, "symmetricAlgorithm" | "nonceLength">;
// how a SEC1 public key is encoded
type PointEncoding = "compressed" | "uncompressed";

const AES_16: Cipher = { symmetricAlgorithm: "aes-256-gcm", nonceLength: 16 };
const AES_12: Cipher = { symmetricAlgorithm: "aes-256-gcm", nonceLength: 12 };
const XCHACHA20: Cipher = { symmetricAlgorithm: "xchacha20", nonceLength: 24 };

const CURVE25519_PUBLIC_KEY_LENGTH = 32;
const COMPRESSED_PUBLIC_KEY_LENGTH = 33;
const UNCOMPRESSED_PUBLIC_KEY_LENGTH = 65;

function wrappedLength(ephemeralKeyLength: number, { nonceLength }: Cipher): number {
  return ephemeralKeyLength + nonceLength + TAG_LENGTH + SHAMIR_SHARE_LENGTH;
}

// the columns follow SPEC.md's table: ephemeral key, HKDF input, then cipher and nonce
function secp256k1(
  id: number,
  ephemeralKey: PointEncoding,
  hkdfInput: PointEncoding,
  cipher: Cipher
): Suite {
  const isEphemeralKeyCompressed = ephemeralKey === "compressed";
  return {
    id,
    ellipticCurve: "secp256k1",
    isEphemeralKeyCompressed,
    isHkdfKeyCompressed: hkdfInput === "compressed",
    ...cipher,
    wrappedLength: wrappedLength(
      isEphemeralKeyCompressed
        ? COMPRESSED_PUBLIC_KEY_LENGTH
        : UNCOMPRESSED_PUBLIC_KEY_LENGTH,
      cipher
    ),
  };
}

function curve25519(
  id: number,
  ellipticCurve: "x25519" | "ed25519",
  cipher: Cipher
): Suite {
  return {
    id,
    ellipticCurve,
    isEphemeralKeyCompressed: false,
    isHkdfKeyCompressed: false,
    ...cipher,
    wrappedLength: wrappedLength(CURVE25519_PUBLIC_KEY_LENGTH, cipher),
  };
}

const SUITES = new Map(
  [
    secp256k1(0x01, "uncompressed", "uncompressed", AES_16),
    secp256k1(0x02, "uncompressed", "uncompressed", AES_12),
    secp256k1(0x03, "uncompressed", "uncompressed", XCHACHA20),
    secp256k1(0x04, "compressed", "uncompressed", AES_16),
    secp256k1(0x05, "compressed", "uncompressed", AES_12),
    secp256k1(0x06, "compressed", "uncompressed", XCHACHA20),
    secp256k1(0x07, "uncompressed", "compressed", AES_16),
    secp256k1(0x08, "uncompressed", "compressed", AES_12),
    secp256k1(0x09, "uncompressed", "compressed", XCHACHA20),
    secp256k1(0x0a, "compressed", "compressed", AES_16),
    secp256k1(0x0b, "compressed", "compressed", AES_12),
    secp256k1(0x0c, "compressed", "compressed", XCHACHA20),
    curve25519(0x11, "x25519", AES_16),
    curve25519(0x12, "x25519", AES_12),
    curve25519(0x13, "x25519", XCHACHA20),
    curve25519(0x21, "ed25519", AES_16),
    curve25519(0x22, "ed25519", AES_12),
    curve25519(0x23, "ed25519", XCHACHA20),
  ].map((suite) => [suite.id, suite])
);

/** The suite with this ID, or undefined if the table doesn't list it. */
export function getSuite(id: number): Suite | undefined {
  return SUITES.get(id);
}
