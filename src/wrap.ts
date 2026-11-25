import { concatBytes, randomBytes } from "@noble/hashes/utils";
import { PrivateKey, PublicKey } from "eciesjs";

import { aeadDecrypt, aeadEncrypt } from "./aead";
import { canonicalPublicKey } from "./keys";
import { ephemeralKeyLength, type Suite } from "./suites";

/**
 * Wraps a share to a recipient's valid public key with eciesjs's ECIES, adding `ad` as the
 * AEAD's associated data. Returns E ‖ nonce ‖ tag ‖ ciphertext (SPEC.md, "Wrapped shares").
 */
export function wrapShare(
  suite: Suite,
  recipient: Uint8Array,
  share: Uint8Array,
  ad: Uint8Array
): Uint8Array {
  const curve = suite.ellipticCurve;
  const ephemeral = new PrivateKey(undefined, curve);
  let key: Uint8Array | undefined;
  try {
    key = ephemeral.encapsulate(
      new PublicKey(recipient, curve),
      suite.isHkdfKeyCompressed
    );
    const nonce = randomBytes(suite.nonceLength);
    return concatBytes(
      ephemeral.publicKey.toBytes(suite.isEphemeralKeyCompressed),
      nonce,
      aeadEncrypt(suite, key, nonce, ad, share)
    );
  } finally {
    key?.fill(0);
    ephemeral.secret.fill(0);
  }
}

/**
 * Unwraps a share with a valid secret key, or returns undefined if the ephemeral key E is
 * invalid or the share doesn't decrypt.
 */
export function unwrapShare(
  suite: Suite,
  secretKey: Uint8Array,
  wrapped: Uint8Array,
  ad: Uint8Array
): Uint8Array | undefined {
  const curve = suite.ellipticCurve;
  const keyLength = ephemeralKeyLength(suite);
  const ephemeralKey = wrapped.subarray(0, keyLength);
  // the suite fixes E's length, so on secp256k1 this also checks its SEC1 form
  if (canonicalPublicKey(curve, ephemeralKey) === undefined) {
    return undefined;
  }

  const ownKey = new PrivateKey(Uint8Array.from(secretKey), curve);
  let key: Uint8Array | undefined;
  try {
    key = new PublicKey(Uint8Array.from(ephemeralKey), curve).decapsulate(
      ownKey,
      suite.isHkdfKeyCompressed
    );
    const nonceEnd = keyLength + suite.nonceLength;
    const nonce = wrapped.subarray(keyLength, nonceEnd);
    try {
      return aeadDecrypt(suite, key, nonce, ad, wrapped.subarray(nonceEnd));
    } catch {
      return undefined;
    }
  } finally {
    key?.fill(0);
    ownKey.secret.fill(0);
  }
}
