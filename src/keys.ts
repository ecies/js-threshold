import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import type { Suite } from "./suites";

type Curve = Suite["ellipticCurve"];

const SECRET_KEY_LENGTH = 32;
const CURVE25519_PUBLIC_KEY_LENGTH = 32;
// 2^255 − 19, the field prime of both x25519 and ed25519
const CURVE25519_PRIME = 2n ** 255n - 19n;
// any scalar works for the small-order test, since X25519 clamps it to a multiple of 8
const SMALL_ORDER_TEST_SCALAR = new Uint8Array(32).fill(1);

/**
 * The canonical public key pk* of a key valid on the curve, or undefined if it isn't valid
 * (SPEC.md, "Keys and fingerprints"). On secp256k1, pk* is the compressed point; on x25519
 * and ed25519, a copy of the key.
 */
export function canonicalPublicKey(
  curve: Curve,
  key: Uint8Array
): Uint8Array | undefined {
  try {
    if (curve === "secp256k1") {
      // fromBytes takes only SEC1's 33- and 65-byte forms, and checks the point is on the curve
      return secp256k1.Point.fromBytes(key).toBytes(true);
    }
    const isValid = curve === "x25519" ? isValidX25519(key) : isValidEd25519(key);
    return isValid ? Uint8Array.from(key) : undefined;
  } catch {
    return undefined;
  }
}

/** The canonical public key pk* of a secret key, or undefined if it isn't valid on the curve. */
export function publicKeyOf(curve: Curve, secretKey: Uint8Array): Uint8Array | undefined {
  if (secretKey.length !== SECRET_KEY_LENGTH) {
    return undefined;
  }
  if (curve === "secp256k1") {
    return secp256k1.utils.isValidSecretKey(secretKey)
      ? secp256k1.getPublicKey(secretKey, true)
      : undefined;
  }
  return curve === "x25519"
    ? x25519.getPublicKey(secretKey)
    : ed25519.getPublicKey(secretKey);
}

function isValidX25519(u: Uint8Array): boolean {
  if (u.length !== CURVE25519_PUBLIC_KEY_LENGTH) {
    return false;
  }
  // canonical: below the prime, which also clears bit 255. noble masks and reduces instead.
  let value = 0n;
  for (let i = u.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(u[i]);
  }
  if (value >= CURVE25519_PRIME) {
    return false;
  }
  // not of small order: noble throws on the all-zero shared secret that gives
  const shared = x25519.getSharedSecret(SMALL_ORDER_TEST_SCALAR, u);
  return shared.some((b) => b !== 0);
}

function isValidEd25519(key: Uint8Array): boolean {
  if (key.length !== CURVE25519_PUBLIC_KEY_LENGTH) {
    return false;
  }
  // strict RFC 8032 decoding: y below the prime, no x = 0 with the sign bit set, on the curve
  const point = ed25519.Point.fromBytes(key);
  // the identity point is torsion-free, so the small-order test is what rejects it
  return point.isTorsionFree() && !point.isSmallOrder();
}
