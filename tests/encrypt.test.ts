import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";

import { decryptShare, encrypt, type SuiteConfig } from "../src";
import { codeOf } from "./helpers/errors";
import { type Curve, keyPair, keyPairs } from "./helpers/keys";

const PLAINTEXT = new TextEncoder().encode("secret");
const fromHex = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const keysOf = (curve: Curve, n: number) => keyPairs(curve, n).map((h) => h.publicKey);

// encrypt with `bad` as the first of three recipients
const encryptTo = (curve: Curve, bad: Uint8Array) =>
  encrypt([bad, ...keysOf(curve, 2)], 2, PLAINTEXT, { config: { ellipticCurve: curve } });

describe("encrypt rejects with InvalidArgument", () => {
  it("a threshold below 2, above N, or not an integer", async () => {
    const recipients = keysOf("secp256k1", 3);
    for (const threshold of [-1, 0, 1, 4, 2.5, Number.NaN]) {
      expect(await codeOf(() => encrypt(recipients, threshold, PLAINTEXT))).toBe(
        "InvalidArgument"
      );
    }
  });

  it("fewer than 2 recipients, or more than 255", async () => {
    for (const n of [0, 1, 256]) {
      const recipients = keysOf("x25519", n);
      const config = { ellipticCurve: "x25519" } as const;
      expect(await codeOf(() => encrypt(recipients, 2, PLAINTEXT, { config }))).toBe(
        "InvalidArgument"
      );
    }
  });

  it("a config that matches no suite", async () => {
    const recipients = keysOf("secp256k1", 2);
    const configs = [
      { symmetricNonceLength: 24 },
      { ellipticCurve: "p256" },
      { symmetricAlgorithm: "aes-128-gcm" },
    ] as unknown as Partial<SuiteConfig>[];
    for (const config of configs) {
      expect(await codeOf(() => encrypt(recipients, 2, PLAINTEXT, { config }))).toBe(
        "InvalidArgument"
      );
    }
  });

  it("a secp256k1 key that isn't a SEC1 point on the curve", async () => {
    const { publicKey } = keyPair("secp256k1");
    const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
    const offCurve = Uint8Array.from(uncompressed);
    offCurve[64] ^= 1;
    const hybrid = Uint8Array.from(uncompressed);
    hybrid[0] = 0x06 | (uncompressed[64] & 1);
    const badPrefix = Uint8Array.from(publicKey);
    badPrefix[0] = 0x05;
    for (const bad of [
      offCurve,
      hybrid,
      badPrefix,
      uncompressed.subarray(1), // 64 bytes, no prefix
      publicKey.subarray(1), // 32 bytes
      new Uint8Array(0),
    ]) {
      expect(await codeOf(() => encryptTo("secp256k1", bad))).toBe("InvalidArgument");
    }
  });

  it("an x25519 key that isn't 32 bytes, isn't canonical, or is of small order", async () => {
    const { publicKey } = keyPair("x25519");
    const bit255 = Uint8Array.from(publicKey);
    bit255[31] |= 0x80;
    // u + p, which noble would reduce to u
    let u = 0n;
    for (let i = 31; i >= 0; i--) {
      u = (u << 8n) | BigInt(publicKey[i]);
    }
    const plusP = new Uint8Array(32);
    let v = u + 2n ** 255n - 19n;
    for (let i = 0; i < 32; i++) {
      plusP[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    const smallOrder = [
      "00".repeat(32),
      `01${"00".repeat(31)}`,
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      `ec${"ff".repeat(30)}7f`, // p − 1
    ].map(fromHex);
    for (const bad of [
      publicKey.subarray(1),
      new Uint8Array(33),
      bit255,
      plusP,
      ...smallOrder,
    ]) {
      expect(await codeOf(() => encryptTo("x25519", bad))).toBe("InvalidArgument");
    }
  });

  it("an ed25519 key that isn't a canonical point in the prime-order subgroup", async () => {
    const { publicKey } = keyPair("ed25519");
    const t8 = ed25519.Point.fromBytes(
      fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
    );
    const mixedOrder = ed25519.Point.fromBytes(publicKey).add(t8).toBytes();
    const yIsP = fromHex(`ed${"ff".repeat(30)}7f`);
    const signedZero = fromHex(`01${"00".repeat(30)}80`); // the identity, x = 0, sign bit set
    const offCurve = fromHex(`02${"00".repeat(31)}`);
    const smallOrder = [
      `01${"00".repeat(31)}`, // the identity
      `ec${"ff".repeat(30)}7f`, // order 2
      "00".repeat(32), // order 4
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ].map(fromHex);
    for (const bad of [
      publicKey.subarray(1),
      mixedOrder,
      yIsP,
      signedZero,
      offCurve,
      ...smallOrder,
    ]) {
      expect(await codeOf(() => encryptTo("ed25519", bad))).toBe("InvalidArgument");
    }
  });

  it("the same recipient twice, in either secp256k1 form", async () => {
    const [a, b] = keysOf("secp256k1", 2);
    const aUncompressed = secp256k1.Point.fromBytes(a).toBytes(false);
    for (const recipients of [
      [a, b, a],
      [a, b, aUncompressed],
    ]) {
      expect(await codeOf(() => encrypt(recipients, 2, PLAINTEXT))).toBe(
        "InvalidArgument"
      );
    }
  });
});

describe("encrypt accepts", () => {
  it("255 recipients", async () => {
    const holders = keyPairs("x25519", 255);
    const envelope = await encrypt(
      holders.map((h) => h.publicKey),
      255,
      PLAINTEXT,
      { config: { ellipticCurve: "x25519" } }
    );
    expect(envelope[2]).toBe(255);
    expect(envelope[3]).toBe(255);
    expect(decryptShare(holders[254].secretKey, envelope)[33]).toBe(254);
  });

  it("a secp256k1 key in either SEC1 form, with the same fingerprint", async () => {
    const holders = keyPairs("secp256k1", 2);
    const compressed = holders.map((h) => h.publicKey);
    const uncompressed = compressed.map((pk) =>
      secp256k1.Point.fromBytes(pk).toBytes(false)
    );
    const a = await encrypt(compressed, 2, PLAINTEXT);
    const b = await encrypt(uncompressed, 2, PLAINTEXT);

    // the recipient table's fingerprints, at 36 and 100
    for (const offset of [36, 100]) {
      expect(b.subarray(offset, offset + 32)).toEqual(a.subarray(offset, offset + 32));
    }
    expect(decryptShare(holders[1].secretKey, b)[33]).toBe(1);
  });
});
