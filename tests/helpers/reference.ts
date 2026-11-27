// SPEC.md's procedures, written from its text on noble and shamir-secret-sharing directly,
// independent of src/. The builder lets a test play a dishonest encryptor; the opener runs
// the honest path only, without SPEC.md's checks.

import { gcm } from "@noble/ciphers/aes";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { combine, split } from "shamir-secret-sharing";

import type { Suite } from "../../src/suites";

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

const ascii = (s: string) => new TextEncoder().encode(s);
const EMPTY = new Uint8Array(0);
const hashOf = (domain: string, data: Uint8Array) => sha256(concat(ascii(domain), data));
const kdf = (ikm: Uint8Array, info: Uint8Array) => hkdf(sha256, ikm, EMPTY, info, 32);

export const fingerprint = (pk: Uint8Array) =>
  hashOf("ecies-threshold/v1/fingerprint", pk);
export const commitment = (share: Uint8Array) =>
  hashOf("ecies-threshold/v1/share", share);
export const envelopeId = (prelude: Uint8Array) =>
  hashOf("ecies-threshold/v1/envelope-id", prelude);
export const wrapAD = (i: number, prelude: Uint8Array) =>
  concat(ascii("ecies-threshold/v1/wrap"), Uint8Array.of(i), prelude);
const contentKey = (dk: Uint8Array) => kdf(dk, ascii("ecies-threshold/v1/content"));
export const keyCheck = (dk: Uint8Array) =>
  kdf(dk, ascii("ecies-threshold/v1/key-check"));

function aead(suite: Suite, key: Uint8Array, nonce: Uint8Array, ad: Uint8Array) {
  return suite.symmetricAlgorithm === "aes-256-gcm"
    ? gcm(key, nonce, ad)
    : xchacha20poly1305(key, nonce, ad);
}

// SPEC.md puts the tag before the ciphertext; noble puts it after
function seal(
  suite: Suite,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  pt: Uint8Array
) {
  const out = aead(suite, key, nonce, ad).encrypt(pt);
  return concat(out.subarray(out.length - 16), out.subarray(0, out.length - 16));
}

function open(
  suite: Suite,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  sealed: Uint8Array
) {
  return aead(suite, key, nonce, ad).decrypt(
    concat(sealed.subarray(16), sealed.subarray(0, 16))
  );
}

// ed25519's s: SHA-512 of the secret key, clamped, read little-endian, reduced mod the order
export function ed25519Scalar(secretKey: Uint8Array): bigint {
  const h = sha512(secretKey).slice(0, 32);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  let s = 0n;
  for (let i = 31; i >= 0; i--) {
    s = (s << 8n) | BigInt(h[i]);
  }
  return s % ed25519.Point.Fn.ORDER;
}

/** A wrap's ephemeral key E, sender point S and shared point Z. */
export interface Ephemeral {
  readonly E: Uint8Array;
  readonly S: Uint8Array;
  readonly Z: Uint8Array;
}

/** E, S and Z for a fresh ephemeral key e and the recipient's key pk. */
export function freshEphemeral(suite: Suite, pk: Uint8Array): Ephemeral {
  if (suite.ellipticCurve === "secp256k1") {
    const e = secp256k1.utils.randomSecretKey();
    return {
      E: secp256k1.getPublicKey(e, suite.isEphemeralKeyCompressed),
      S: secp256k1.getPublicKey(e, suite.isHkdfKeyCompressed),
      Z: secp256k1.getSharedSecret(e, pk, suite.isHkdfKeyCompressed),
    };
  }
  if (suite.ellipticCurve === "x25519") {
    const e = x25519.utils.randomSecretKey();
    const E = x25519.getPublicKey(e);
    return { E, S: E, Z: x25519.getSharedSecret(e, pk) };
  }
  const e = ed25519.utils.randomSecretKey();
  const E = ed25519.getPublicKey(e);
  return { E, S: E, Z: ed25519.Point.fromBytes(pk).multiply(ed25519Scalar(e)).toBytes() };
}

/** wrapped_i = E ‖ nonce ‖ tag ‖ ct, with k = HKDF(S ‖ Z) and AD = wrapAD_i. */
export function wrap(
  suite: Suite,
  { E, S, Z }: Ephemeral,
  i: number,
  prelude: Uint8Array,
  share: Uint8Array
): Uint8Array {
  const k = kdf(concat(S, Z), EMPTY);
  const nonce = randomBytes(suite.nonceLength);
  return concat(E, nonce, seal(suite, k, nonce, wrapAD(i, prelude), share));
}

export interface Build {
  readonly suite: Suite;
  readonly threshold: number;
  /** each recipient's canonical public key pk* */
  readonly recipients: readonly Uint8Array[];
  readonly plaintext: Uint8Array;
  readonly aad?: Uint8Array;
  /** what keyCheck and the content key derive from; random by default */
  readonly dataKey?: Uint8Array;
  /** the shares to wrap; by default a split of the data key */
  readonly shares?: readonly Uint8Array[];
  /** the shares the commitments cover; by default the wrapped ones */
  readonly committed?: readonly Uint8Array[];
  /** E, S and Z per recipient; by default fresh ones */
  readonly ephemerals?: readonly (Ephemeral | undefined)[];
}

/** An envelope laid out as SPEC.md's encrypt builds it, from whatever parts the test chose. */
export async function build(b: Build): Promise<Uint8Array> {
  const { suite, threshold, recipients } = b;
  const n = recipients.length;
  const dataKey = b.dataKey ?? randomBytes(32);
  const shares = b.shares ?? (await split(dataKey, n, threshold));
  const committed = b.committed ?? shares;
  const table = recipients.flatMap((pk, i) => [
    fingerprint(pk),
    commitment(committed[i]),
  ]);
  const prelude = concat(
    Uint8Array.of(0x01, suite.id, threshold, n),
    keyCheck(dataKey),
    ...table
  );
  const wrapped = shares.map((share, i) => {
    const ephemeral = b.ephemerals?.[i] ?? freshEphemeral(suite, recipients[i]);
    return wrap(suite, ephemeral, i, prelude, share);
  });
  const header = concat(prelude, ...wrapped);
  const nonce = randomBytes(suite.nonceLength);
  const ad = concat(header, b.aad ?? EMPTY);
  return concat(header, nonce, seal(suite, contentKey(dataKey), nonce, ad, b.plaintext));
}

/** pk*, from a secret key. */
export function canonicalKeyOf(suite: Suite, secretKey: Uint8Array): Uint8Array {
  if (suite.ellipticCurve === "secp256k1") {
    return secp256k1.getPublicKey(secretKey, true);
  }
  return suite.ellipticCurve === "x25519"
    ? x25519.getPublicKey(secretKey)
    : ed25519.getPublicKey(secretKey);
}

function layout(suite: Suite, envelope: Uint8Array) {
  const n = envelope[3];
  const p = 36 + 64 * n;
  const h = p + n * suite.wrappedLength;
  return {
    threshold: envelope[2],
    n,
    prelude: envelope.subarray(0, p),
    header: envelope.subarray(0, h),
  };
}

/**
 * The holder's share, in the share format, by SPEC.md's unwrapping steps. It skips the
 * checks, so it also opens a wrapped share whose E decryptShare must reject.
 */
export function decryptShareBySpec(
  suite: Suite,
  secretKey: Uint8Array,
  envelope: Uint8Array
): Uint8Array {
  const { n, prelude } = layout(suite, envelope);
  const own = fingerprint(canonicalKeyOf(suite, secretKey));
  const entry = (i: number) => envelope.subarray(36 + 64 * i, 36 + 64 * i + 32);
  const i = Array.from({ length: n }, (_, j) => j).find((j) =>
    entry(j).every((b, t) => b === own[t])
  );
  if (i === undefined) {
    throw new Error("not a recipient");
  }
  const start = prelude.length + i * suite.wrappedLength;
  const wrapped = envelope.subarray(start, start + suite.wrappedLength);
  const eLength =
    suite.ellipticCurve !== "secp256k1" ? 32 : suite.isEphemeralKeyCompressed ? 33 : 65;
  const E = wrapped.subarray(0, eLength);
  let S: Uint8Array;
  let Z: Uint8Array;
  if (suite.ellipticCurve === "secp256k1") {
    S = secp256k1.Point.fromBytes(E).toBytes(suite.isHkdfKeyCompressed);
    Z = secp256k1.getSharedSecret(secretKey, E, suite.isHkdfKeyCompressed);
  } else if (suite.ellipticCurve === "x25519") {
    S = E;
    Z = x25519.getSharedSecret(secretKey, E);
  } else {
    S = E;
    Z = ed25519.Point.fromBytes(E).multiply(ed25519Scalar(secretKey)).toBytes();
  }
  const k = kdf(concat(S, Z), EMPTY);
  const nonceEnd = eLength + suite.nonceLength;
  const nonce = wrapped.subarray(eLength, nonceEnd);
  const share = open(suite, k, nonce, wrapAD(i, prelude), wrapped.subarray(nonceEnd));
  return concat(Uint8Array.of(0x01), envelopeId(prelude), Uint8Array.of(i), share);
}

/**
 * The plaintext, from the first K shares in the share format. It checks the commitments and
 * the key check, so it fails on an envelope whose header doesn't follow SPEC.md.
 */
export async function combineBySpec(
  suite: Suite,
  envelope: Uint8Array,
  shares: readonly Uint8Array[],
  aad: Uint8Array = EMPTY
): Promise<Uint8Array> {
  const { threshold, header } = layout(suite, envelope);
  const raw = shares.slice(0, threshold).map((s) => Uint8Array.from(s.subarray(34)));
  for (const [p, s] of shares.slice(0, threshold).entries()) {
    const i = s[33];
    const stored = envelope.subarray(36 + 64 * i + 32, 36 + 64 * i + 64);
    if (!commitment(raw[p]).every((b, t) => b === stored[t])) {
      throw new Error(`share ${p} doesn't match its commitment`);
    }
  }
  const dk = await combine(raw);
  if (!keyCheck(dk).every((b, t) => b === envelope[4 + t])) {
    throw new Error("key check mismatch");
  }
  const nonce = envelope.subarray(header.length, header.length + suite.nonceLength);
  const sealed = envelope.subarray(header.length + suite.nonceLength);
  return open(suite, contentKey(dk), nonce, concat(header, aad), sealed);
}
