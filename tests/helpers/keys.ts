import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

export type Curve = "secp256k1" | "x25519" | "ed25519";

export interface KeyPair {
  readonly secretKey: Uint8Array;
  /** compressed on secp256k1: SPEC.md's canonical form, pk* */
  readonly publicKey: Uint8Array;
}

export function keyPair(curve: Curve): KeyPair {
  if (curve === "secp256k1") {
    const secretKey = secp256k1.utils.randomSecretKey();
    return { secretKey, publicKey: secp256k1.getPublicKey(secretKey, true) };
  }
  const lib = curve === "x25519" ? x25519 : ed25519;
  const secretKey = lib.utils.randomSecretKey();
  return { secretKey, publicKey: lib.getPublicKey(secretKey) };
}

export function keyPairs(curve: Curve, n: number): KeyPair[] {
  return Array.from({ length: n }, () => keyPair(curve));
}
