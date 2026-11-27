import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils";

const KEY_LENGTH = 32;

const FINGERPRINT = utf8ToBytes("ecies-threshold/v1/fingerprint");
const SHARE = utf8ToBytes("ecies-threshold/v1/share");
const ENVELOPE_ID = utf8ToBytes("ecies-threshold/v1/envelope-id");
const WRAP = utf8ToBytes("ecies-threshold/v1/wrap");
const CONTENT = utf8ToBytes("ecies-threshold/v1/content");
const KEY_CHECK = utf8ToBytes("ecies-threshold/v1/key-check");

/** A recipient's fingerprint, from its canonical public key pk*. */
export function fingerprint(canonicalPublicKey: Uint8Array): Uint8Array {
  return sha256(concatBytes(FINGERPRINT, canonicalPublicKey));
}

/** A share's commitment, from the 33-byte Shamir share. */
export function commitment(share: Uint8Array): Uint8Array {
  // hashed in pieces, since a concatenation would leave a copy of the share; the hash
  // wipes its own buffer when it finishes
  return sha256.create().update(SHARE).update(share).digest();
}

export function envelopeId(prelude: Uint8Array): Uint8Array {
  return sha256(concatBytes(ENVELOPE_ID, prelude));
}

/** wrapAD_i: the associated data that binds wrapped share i to its envelope. */
export function wrapAD(index: number, prelude: Uint8Array): Uint8Array {
  return concatBytes(WRAP, Uint8Array.of(index), prelude);
}

// HKDF's salt is empty: noble's default, a hash-length zero salt, gives the same key
export function contentKey(dataKey: Uint8Array): Uint8Array {
  return hkdf(sha256, dataKey, undefined, CONTENT, KEY_LENGTH);
}

export function keyCheck(dataKey: Uint8Array): Uint8Array {
  return hkdf(sha256, dataKey, undefined, KEY_CHECK, KEY_LENGTH);
}
