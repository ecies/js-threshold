import type { Suite, SuiteConfig } from "../../src/suites";

const U = "uncompressed";
const C = "compressed";
const AES = "AES-256-GCM";
const XCHACHA20 = "XChaCha20-Poly1305";

// SPEC.md's suite table, column for column: ID, curve, ephemeral key, HKDF input, cipher,
// nonce length Ln, wrapped share size W
export const SPEC_TABLE = [
  [0x01, "secp256k1", U, U, AES, 16, 130],
  [0x02, "secp256k1", U, U, AES, 12, 126],
  [0x03, "secp256k1", U, U, XCHACHA20, 24, 138],
  [0x04, "secp256k1", C, U, AES, 16, 98],
  [0x05, "secp256k1", C, U, AES, 12, 94],
  [0x06, "secp256k1", C, U, XCHACHA20, 24, 106],
  [0x07, "secp256k1", U, C, AES, 16, 130],
  [0x08, "secp256k1", U, C, AES, 12, 126],
  [0x09, "secp256k1", U, C, XCHACHA20, 24, 138],
  [0x0a, "secp256k1", C, C, AES, 16, 98],
  [0x0b, "secp256k1", C, C, AES, 12, 94],
  [0x0c, "secp256k1", C, C, XCHACHA20, 24, 106],
  [0x11, "x25519", "", "", AES, 16, 97],
  [0x12, "x25519", "", "", AES, 12, 93],
  [0x13, "x25519", "", "", XCHACHA20, 24, 105],
  [0x21, "ed25519", "", "", AES, 16, 97],
  [0x22, "ed25519", "", "", AES, 12, 93],
  [0x23, "ed25519", "", "", XCHACHA20, 24, 105],
] as const;

// the same rows in eciesjs's Config terms, as a Suite holds them
export const SPEC_SUITES = SPEC_TABLE.map(
  ([id, curve, ephemeralKey, hkdfInput, cipher, nonceLength, wrappedLength]): Suite => ({
    id,
    ellipticCurve: curve,
    isEphemeralKeyCompressed: ephemeralKey === C,
    isHkdfKeyCompressed: hkdfInput === C,
    symmetricAlgorithm: cipher === AES ? "aes-256-gcm" : "xchacha20",
    nonceLength,
    wrappedLength,
  })
);

// the eciesjs Config fields that pick a suite. XChaCha20 ignores the nonce length, so it
// gets eciesjs's default, 16.
export const configOf = (suite: Suite): SuiteConfig => ({
  ellipticCurve: suite.ellipticCurve,
  isEphemeralKeyCompressed: suite.isEphemeralKeyCompressed,
  isHkdfKeyCompressed: suite.isHkdfKeyCompressed,
  symmetricAlgorithm: suite.symmetricAlgorithm,
  symmetricNonceLength: suite.nonceLength === 24 ? 16 : suite.nonceLength,
});

export const hex = (byte: number) => `0x${byte.toString(16).padStart(2, "0")}`;
