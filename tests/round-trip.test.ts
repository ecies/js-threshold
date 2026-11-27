import { Buffer } from "node:buffer";
import { Config, ECIES_CONFIG } from "eciesjs/config";
import { describe, expect, it } from "vitest";

import { combine, decryptShare, encrypt } from "../src";
import { codeOf } from "./helpers/errors";
import { keyPairs } from "./helpers/keys";
import { configOf, hex, SPEC_SUITES } from "./helpers/spec-suites";

const PLAINTEXT = new TextEncoder().encode("the production env file");

// every subset of 0 … n − 1, as positions in index order
const subsets = (n: number) =>
  Array.from({ length: 2 ** n }, (_, mask) =>
    Array.from({ length: n }, (_, i) => i).filter((i) => mask & (1 << i))
  );

describe("encrypt, decryptShare and combine", () => {
  it("open a 2-of-3 envelope with any two holders' shares", async () => {
    const holders = keyPairs("secp256k1", 3);
    const envelope = await encrypt(
      holders.map((h) => h.publicKey),
      2,
      PLAINTEXT
    );
    const shares = holders.map((h) => decryptShare(h.secretKey, envelope));

    expect(await combine(envelope, [shares[0], shares[1]])).toEqual(PLAINTEXT);
    expect(await combine(envelope, [shares[2], shares[0]])).toEqual(PLAINTEXT);
  });

  for (let n = 2; n <= 5; n++) {
    for (let k = 2; k <= n; k++) {
      it(`${k}-of-${n}: every set of K or more shares opens it, in either order, and fewer fail`, async () => {
        const holders = keyPairs("x25519", n);
        const envelope = await encrypt(
          holders.map((h) => h.publicKey),
          k,
          PLAINTEXT,
          { config: { ellipticCurve: "x25519" } }
        );
        const shares = holders.map((h) => decryptShare(h.secretKey, envelope));

        for (const subset of subsets(n)) {
          const picked = subset.map((i) => shares[i]);
          for (const input of [picked, [...picked].reverse()]) {
            if (subset.length >= k) {
              expect(await combine(envelope, input)).toEqual(PLAINTEXT);
            } else {
              const code = await codeOf(() => combine(envelope, input));
              expect({ subset, code }).toEqual({ subset, code: "NotEnoughShares" });
            }
          }
        }
      });
    }
  }

  for (const suite of SPEC_SUITES) {
    it(`open an envelope on suite ${hex(suite.id)}`, async () => {
      const holders = keyPairs(suite.ellipticCurve, 3);
      const envelope = await encrypt(
        holders.map((h) => h.publicKey),
        2,
        PLAINTEXT,
        { config: configOf(suite) }
      );
      const shares = holders.map((h) => decryptShare(h.secretKey, envelope));

      expect(hex(envelope[1])).toBe(hex(suite.id));
      expect(await combine(envelope, [shares[1], shares[2]])).toEqual(PLAINTEXT);
    });
  }

  it("pick the suite from Config fields, ignoring the ones eciesjs ignores", async () => {
    const cases = [
      [undefined, 0x01],
      [{ ellipticCurve: "x25519" }, 0x11],
      [
        {
          ellipticCurve: "x25519",
          isEphemeralKeyCompressed: true,
          isHkdfKeyCompressed: true,
        },
        0x11,
      ],
      [{ ellipticCurve: "ed25519", symmetricNonceLength: 12 }, 0x22],
      [{ symmetricAlgorithm: "xchacha20", symmetricNonceLength: 12 }, 0x03],
      [{ isEphemeralKeyCompressed: true, isHkdfKeyCompressed: true }, 0x0a],
      [Object.assign(new Config(), { ellipticCurve: "ed25519" as const }), 0x21],
    ] as const;
    for (const [config, id] of cases) {
      const curve =
        config && "ellipticCurve" in config ? config.ellipticCurve : "secp256k1";
      const recipients = keyPairs(curve, 2).map((h) => h.publicKey);
      const envelope = await encrypt(recipients, 2, PLAINTEXT, { config });
      expect({ config, id: hex(envelope[1]) }).toEqual({ config, id: hex(id) });
    }
  });

  it("treat a Config field set to undefined as missing", async () => {
    const recipients = keyPairs("x25519", 2).map((h) => h.publicKey);
    const config = { ellipticCurve: "x25519", symmetricNonceLength: undefined } as const;
    const envelope = await encrypt(recipients, 2, PLAINTEXT, { config });
    expect(hex(envelope[1])).toBe(hex(0x11));
  });

  it("ignore eciesjs's global ECIES_CONFIG", async () => {
    const saved = { ...ECIES_CONFIG };
    Object.assign(ECIES_CONFIG, {
      ellipticCurve: "x25519",
      isEphemeralKeyCompressed: true,
      isHkdfKeyCompressed: true,
      symmetricAlgorithm: "xchacha20",
    });
    try {
      const holders = keyPairs("secp256k1", 2);
      const envelope = await encrypt(
        holders.map((h) => h.publicKey),
        2,
        PLAINTEXT
      );
      expect(hex(envelope[1])).toBe(hex(0x01));
      const shares = holders.map((h) => decryptShare(h.secretKey, envelope));
      expect(await combine(envelope, shares)).toEqual(PLAINTEXT);
    } finally {
      Object.assign(ECIES_CONFIG, saved);
    }
  });

  it("take Buffers, and views that start partway into their buffer", async () => {
    const view = (bytes: Uint8Array) => {
      const backing = Buffer.alloc(bytes.length + 3, 0xee);
      backing.set(bytes, 3);
      return backing.subarray(3);
    };
    const holders = keyPairs("secp256k1", 3);
    const aad = Buffer.from("prod/app.env");
    const envelope = await encrypt(
      holders.map((h) => view(h.publicKey)),
      2,
      view(PLAINTEXT),
      { aad: view(aad) }
    );
    const shares = holders.map((h) => decryptShare(view(h.secretKey), view(envelope)));

    const input = [view(shares[0]), view(shares[2])];
    expect(await combine(view(envelope), input, { aad })).toEqual(PLAINTEXT);
  });

  it("leave their inputs as they were", async () => {
    const holders = keyPairs("ed25519", 3);
    const recipients = holders.map((h) => h.publicKey);
    const plaintext = Uint8Array.from(PLAINTEXT);
    const config = { ellipticCurve: "ed25519" } as const;
    const envelope = await encrypt(recipients, 2, plaintext, { config });
    const shares = holders.map((h) => decryptShare(h.secretKey, envelope));
    const before = structuredClone({ recipients, plaintext, envelope, shares });

    await encrypt(recipients, 2, plaintext, { config });
    await combine(envelope, shares);
    await combine(envelope, [shares[0], shares[0]]).catch(() => undefined);

    expect({ recipients, plaintext, envelope, shares }).toEqual(before);
  });

  it("make SPEC.md's sizes: 2-of-3 on suite 0x01 has 650 bytes of overhead", async () => {
    const holders = keyPairs("secp256k1", 3);
    for (const plaintext of [new Uint8Array(0), PLAINTEXT]) {
      const envelope = await encrypt(
        holders.map((h) => h.publicKey),
        2,
        plaintext
      );
      expect(envelope.length).toBe(650 + plaintext.length);
      const shares = holders.map((h) => decryptShare(h.secretKey, envelope));
      expect(shares.map((s) => s.length)).toEqual([67, 67, 67]);
      expect(await combine(envelope, shares)).toEqual(plaintext);
    }
  });
});
