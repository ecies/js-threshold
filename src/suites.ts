// eciesjs's `Config` type, through the package root: these declarations ship, and a
// consumer whose TypeScript ignores `exports` can't resolve `eciesjs/config`
import type { ECIES_CONFIG } from "eciesjs";

import { SHAMIR_SHARE_LENGTH, TAG_LENGTH } from "./consts";

type Config = typeof ECIES_CONFIG;

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

/** The length of the ephemeral key E, the first field of a wrapped share. */
export function ephemeralKeyLength(
  suite: Pick<Suite, "ellipticCurve" | "isEphemeralKeyCompressed">
): number {
  if (suite.ellipticCurve !== "secp256k1") {
    return CURVE25519_PUBLIC_KEY_LENGTH;
  }
  return suite.isEphemeralKeyCompressed
    ? COMPRESSED_PUBLIC_KEY_LENGTH
    : UNCOMPRESSED_PUBLIC_KEY_LENGTH;
}

function withWrappedLength(fields: Omit<Suite, "wrappedLength">): Suite {
  return {
    ...fields,
    wrappedLength:
      ephemeralKeyLength(fields) + fields.nonceLength + TAG_LENGTH + SHAMIR_SHARE_LENGTH,
  };
}

// the columns follow SPEC.md's table: ephemeral key, HKDF input, then cipher and nonce
function secp256k1(
  id: number,
  ephemeralKey: PointEncoding,
  hkdfInput: PointEncoding,
  cipher: Cipher
): Suite {
  return withWrappedLength({
    id,
    ellipticCurve: "secp256k1",
    isEphemeralKeyCompressed: ephemeralKey === "compressed",
    isHkdfKeyCompressed: hkdfInput === "compressed",
    ...cipher,
  });
}

function curve25519(
  id: number,
  ellipticCurve: "x25519" | "ed25519",
  cipher: Cipher
): Suite {
  return withWrappedLength({
    id,
    ellipticCurve,
    isEphemeralKeyCompressed: false,
    isHkdfKeyCompressed: false,
    ...cipher,
  });
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

/** The fields of eciesjs's `Config` that pick a suite. */
export type SuiteConfig = Pick<
  Config,
  | "ellipticCurve"
  | "isEphemeralKeyCompressed"
  | "isHkdfKeyCompressed"
  | "symmetricAlgorithm"
  | "symmetricNonceLength"
>;

/**
 * The suite these `Config` fields pick, or undefined if no row matches. Like eciesjs, it
 * ignores the compression options off secp256k1, and the nonce length for XChaCha20.
 */
export function suiteFor(config: SuiteConfig): Suite | undefined {
  for (const suite of SUITES.values()) {
    const sameCurve = suite.ellipticCurve === config.ellipticCurve;
    const sameKeyEncodings =
      suite.ellipticCurve !== "secp256k1" ||
      (suite.isEphemeralKeyCompressed === config.isEphemeralKeyCompressed &&
        suite.isHkdfKeyCompressed === config.isHkdfKeyCompressed);
    const sameCipher =
      suite.symmetricAlgorithm === config.symmetricAlgorithm &&
      (suite.symmetricAlgorithm === "xchacha20" ||
        suite.nonceLength === config.symmetricNonceLength);
    if (sameCurve && sameKeyEncodings && sameCipher) {
      return suite;
    }
  }
  return undefined;
}
