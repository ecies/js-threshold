import { aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";
import { concatBytes } from "@noble/hashes/utils";

import { TAG_LENGTH } from "./consts";
import type { Suite } from "./suites";

function cipher(suite: Suite, key: Uint8Array, nonce: Uint8Array, ad: Uint8Array) {
  const algorithm = suite.symmetricAlgorithm === "aes-256-gcm" ? aes256gcm : xchacha20;
  // a copy, since a nonce read from an envelope is a view into it
  return algorithm(key, Uint8Array.from(nonce), ad);
}

/** Encrypts with the suite's cipher. Returns the tag, then the ciphertext, as SPEC.md lays them out. */
export function aeadEncrypt(
  suite: Suite,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  // @noble/ciphers puts the tag last
  const sealed = cipher(suite, key, nonce, ad).encrypt(plaintext);
  const tagOffset = sealed.length - TAG_LENGTH;
  return concatBytes(sealed.subarray(tagOffset), sealed.subarray(0, tagOffset));
}

/** Decrypts the tag and ciphertext. Throws if they don't authenticate. */
export function aeadDecrypt(
  suite: Suite,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  tagAndCiphertext: Uint8Array
): Uint8Array {
  const tag = tagAndCiphertext.subarray(0, TAG_LENGTH);
  const ciphertext = tagAndCiphertext.subarray(TAG_LENGTH);
  return cipher(suite, key, nonce, ad).decrypt(concatBytes(ciphertext, tag));
}
