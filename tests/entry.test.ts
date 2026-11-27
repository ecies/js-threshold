import { describe, expect, it } from "vitest";

import { combine, decryptShare, encrypt, ThresholdError } from "../src";

// The browser tests run a copy of this file against the built package, so it imports
// nothing but the entry: the keys are fixed, in hex.
const fromHex = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

const HOLDERS = {
  secp256k1: [
    [
      "243ff8d1390defb2ad4d898e22df843986641d8fa99dbe555ae14a9b85501c35",
      "02dbd0dd8ddeb707f31761225d30a79d15c0715311e14242cd37592850a09a0461",
    ],
    [
      "8a86754a7b738f8d718cf4fada1c04c563ca75a45c89a7314a4744d386d165cf",
      "03ad9eb031bb19b6f907ecab10aa65dc3bf7701fd60aebd454727d2dccc24a70b0",
    ],
  ],
  x25519: [
    [
      "21907d2344d3f74c525ce3d867780624cd0f127c5eda480e76d8fd4382449af1",
      "1aa0752842de5a73f59474ec6237d111bf0b686ad7fd09ef5573c8c5d900b134",
    ],
    [
      "5be88de251e226bf5f2bcf0a80d2f82a53f0011caa9334a32fb59138fbf700d3",
      "691c2d2be0aa1197a83de5b6f4e8bbe8a57cf9a9bf16e97e0d5f9e49abaf022d",
    ],
  ],
  ed25519: [
    [
      "a2be45404fec87c71d3d7e1b851176960fd16b6fb8f90d752858284bf395a167",
      "6a8371a3d05b24ad1a7308779482a2fbf2bd18b275931bbae9182920f1be2fb8",
    ],
    [
      "96c675b49b1e492900b2a3f725c80c3f0f71442898179d8ab0f646d3d5b372c5",
      "70057665ae14f925d15848852b42f588bc32e9fb6c2e17a4966ac3463f945c86",
    ],
  ],
} as const;

describe("the package entry", () => {
  for (const ellipticCurve of ["secp256k1", "x25519", "ed25519"] as const) {
    for (const symmetricAlgorithm of ["aes-256-gcm", "xchacha20"] as const) {
      it(`opens a 2-of-2 envelope on ${ellipticCurve} with ${symmetricAlgorithm}`, async () => {
        const holders = HOLDERS[ellipticCurve];
        const plaintext = new TextEncoder().encode("hello");
        const aad = new TextEncoder().encode("label");
        const envelope = await encrypt(
          holders.map(([, pk]) => fromHex(pk)),
          2,
          plaintext,
          { aad, config: { ellipticCurve, symmetricAlgorithm } }
        );
        const shares = holders.map(([sk]) => decryptShare(fromHex(sk), envelope));

        expect(await combine(envelope, shares, { aad })).toEqual(plaintext);
      });
    }
  }

  it("throws a ThresholdError with a code", async () => {
    const error = await combine(new Uint8Array(3), []).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ThresholdError);
    expect((error as ThresholdError).code).toBe("MalformedEnvelope");
  });
});
