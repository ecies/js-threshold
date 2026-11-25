import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { split } from "shamir-secret-sharing";
import { describe, expect, it } from "vitest";

import { decryptShare, encrypt } from "../src";
import type { Suite } from "../src/suites";
import { codeOf } from "./helpers/errors";
import { type KeyPair, keyPair, keyPairs } from "./helpers/keys";
import {
  build,
  decryptShareBySpec,
  type Ephemeral,
  ed25519Scalar,
} from "./helpers/reference";
import { configOf, SPEC_SUITES } from "./helpers/spec-suites";

const PLAINTEXT = new TextEncoder().encode("secret");
const fromHex = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

function suiteWithId(id: number): Suite {
  const suite = SPEC_SUITES.find((s) => s.id === id);
  if (suite === undefined) {
    throw new Error(`no suite ${id}`);
  }
  return suite;
}

const SECP256K1 = suiteWithId(0x01);
const X25519 = suiteWithId(0x11);
const ED25519 = suiteWithId(0x21);

async function envelopeFor(suite: Suite, n = 3) {
  const holders = keyPairs(suite.ellipticCurve, n);
  const envelope = await encrypt(
    holders.map((h) => h.publicKey),
    2,
    PLAINTEXT,
    { config: configOf(suite) }
  );
  return { holders, envelope };
}

const flipped = (bytes: Uint8Array, offset: number) => {
  const out = Uint8Array.from(bytes);
  out[offset] ^= 0x01;
  return out;
};

describe("decryptShare", () => {
  it("rejects a secret key that isn't valid on the envelope's curve as InvalidArgument", async () => {
    const order = fromHex(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    );
    const cases = [
      [SECP256K1, [new Uint8Array(32), order, new Uint8Array(32).fill(0xff)]],
      [X25519, []],
      [ED25519, []],
    ] as const;
    for (const [suite, curveSpecific] of cases) {
      const { holders, envelope } = await envelopeFor(suite);
      const sk = holders[0].secretKey;
      for (const bad of [sk.subarray(1), new Uint8Array(33), ...curveSpecific]) {
        expect(await codeOf(() => decryptShare(bad, envelope))).toBe("InvalidArgument");
      }
    }
  });

  it("parses the envelope before it checks the key", async () => {
    const { envelope } = await envelopeFor(X25519);
    const badKey = new Uint8Array(31);
    expect(await codeOf(() => decryptShare(badKey, envelope.subarray(0, 3)))).toBe(
      "MalformedEnvelope"
    );
  });

  it("rejects a key with no entry as NotARecipient", async () => {
    const { envelope } = await envelopeFor(SECP256K1);
    const outsider = keyPair("secp256k1");
    expect(await codeOf(() => decryptShare(outsider.secretKey, envelope))).toBe(
      "NotARecipient"
    );
  });

  it("rejects an entry copied whole into another envelope as ShareDecryptionFailed", async () => {
    const [alice, bob, carol, dave] = keyPairs("secp256k1", 4);
    const keysOf = (...holders: KeyPair[]) => holders.map((h) => h.publicKey);
    const original = await encrypt(keysOf(alice, bob, carol), 2, PLAINTEXT);
    const decoy = await encrypt(keysOf(alice, dave, carol), 2, PLAINTEXT);
    // alice's entry 0: her fingerprint and commitment, then her wrapped share
    const p = 36 + 64 * 3;
    const forged = Uint8Array.from(decoy);
    forged.set(original.subarray(36, 100), 36);
    forged.set(original.subarray(p, p + SECP256K1.wrappedLength), p);

    expect(await codeOf(() => decryptShare(alice.secretKey, forged))).toBe(
      "ShareDecryptionFailed"
    );
  });

  it.each([SECP256K1, X25519, ED25519])(
    "rejects a changed byte in the holder's wrapped share or in the prelude, on $ellipticCurve",
    async (suite) => {
      const { holders, envelope } = await envelopeFor(suite);
      const p = 36 + 64 * 3;
      const offsets = [
        ...Array.from({ length: p - 4 }, (_, i) => 4 + i), // the key check and the table
        ...Array.from({ length: suite.wrappedLength }, (_, i) => p + i), // wrapped_0
      ];
      for (const offset of offsets) {
        // holder 0's own fingerprint, at 36, decides which entry is theirs
        const isOwnFingerprint = offset >= 36 && offset < 68;
        const expected = isOwnFingerprint ? "NotARecipient" : "ShareDecryptionFailed";
        const code = await codeOf(() =>
          decryptShare(holders[0].secretKey, flipped(envelope, offset))
        );
        expect({ offset, code }).toEqual({ offset, code: expected });
      }
    }
  );

  it("ignores the other wrapped shares and the content", async () => {
    const { holders, envelope } = await envelopeFor(SECP256K1);
    const sk = holders[0].secretKey;
    const share = decryptShare(sk, envelope);
    const p = 36 + 64 * 3;
    for (let offset = p + SECP256K1.wrappedLength; offset < envelope.length; offset++) {
      expect(decryptShare(sk, flipped(envelope, offset))).toEqual(share);
    }
  });

  it("leaves the secret key as it was", async () => {
    const { holders, envelope } = await envelopeFor(SECP256K1);
    const sk = holders[0].secretKey;
    const before = Uint8Array.from(sk);
    decryptShare(sk, envelope);
    expect(sk).toEqual(before);
  });
});

describe("decryptShare rejects an ephemeral key E that SPEC.md rules out, as ShareDecryptionFailed", () => {
  // An envelope whose wrapped share 0 uses this E, S and Z. When `opens` is set, the share
  // decrypts by SPEC.md's steps without the checks, so only the check on E stops it.
  async function rejects(
    suite: Suite,
    ephemeralFor: (holder: KeyPair) => Ephemeral,
    opens = true
  ) {
    const holders = keyPairs(suite.ellipticCurve, 2);
    const envelope = await build({
      suite,
      threshold: 2,
      recipients: holders.map((h) => h.publicKey),
      plaintext: PLAINTEXT,
      ephemerals: [ephemeralFor(holders[0])],
    });
    if (opens) {
      expect(decryptShareBySpec(suite, holders[0].secretKey, envelope)).toHaveLength(67);
    }
    expect(await codeOf(() => decryptShare(holders[0].secretKey, envelope))).toBe(
      "ShareDecryptionFailed"
    );
  }

  it("the ed25519 identity point, which gives anyone the share", async () => {
    const identity = ed25519.Point.ZERO.toBytes();
    await rejects(ED25519, () => ({ E: identity, S: identity, Z: identity }));
  });

  it("an ed25519 point outside the prime-order subgroup", async () => {
    const t8 = ed25519.Point.fromBytes(
      fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
    );
    await rejects(ED25519, (holder) => {
      const e = ed25519.utils.randomSecretKey();
      const point = ed25519.Point.fromBytes(ed25519.getPublicKey(e)).add(t8);
      const E = point.toBytes();
      return { E, S: E, Z: point.multiply(ed25519Scalar(holder.secretKey)).toBytes() };
    });
  });

  it("a non-canonical x25519 u-coordinate, with bit 255 set", async () => {
    await rejects(X25519, (holder) => {
      const e = x25519.utils.randomSecretKey();
      const E = Uint8Array.from(x25519.getPublicKey(e));
      E[31] |= 0x80;
      return { E, S: E, Z: x25519.getSharedSecret(e, holder.publicKey) };
    });
  });

  it("an x25519 point of small order", async () => {
    const E = fromHex(`01${"00".repeat(31)}`);
    await rejects(X25519, () => ({ E, S: E, Z: new Uint8Array(32) }), false);
  });

  it("a secp256k1 point off the curve", async () => {
    await rejects(
      SECP256K1,
      (holder) => {
        const e = secp256k1.utils.randomSecretKey();
        const E = Uint8Array.from(secp256k1.getPublicKey(e, false));
        E[64] ^= 1;
        return { E, S: E, Z: secp256k1.getSharedSecret(e, holder.publicKey, false) };
      },
      false
    );
  });
});

describe("decryptShare, on an envelope its encryptor built wrong", () => {
  async function builtWith(shares: Uint8Array[], committed?: Uint8Array[]) {
    const holders = keyPairs("secp256k1", 2);
    const envelope = await build({
      suite: SECP256K1,
      threshold: 2,
      recipients: holders.map((h) => h.publicKey),
      plaintext: PLAINTEXT,
      shares,
      committed,
    });
    return { holders, envelope };
  }

  it("rejects a share that doesn't match its commitment as CommitmentMismatch", async () => {
    const shares = await split(new Uint8Array(32).fill(7), 2, 2);
    const committed = [flipped(shares[0], 0), shares[1]];
    const { holders, envelope } = await builtWith(shares, committed);

    expect(await codeOf(() => decryptShare(holders[0].secretKey, envelope))).toBe(
      "CommitmentMismatch"
    );
    expect(decryptShare(holders[1].secretKey, envelope)[33]).toBe(1);
  });

  it("rejects a share whose x-coordinate is 0 as MalformedShare", async () => {
    const shares = await split(new Uint8Array(32).fill(7), 2, 2);
    shares[0][32] = 0;
    const { holders, envelope } = await builtWith(shares);

    expect(await codeOf(() => decryptShare(holders[0].secretKey, envelope))).toBe(
      "MalformedShare"
    );
  });

  it("checks the commitment before the x-coordinate", async () => {
    const shares = await split(new Uint8Array(32).fill(7), 2, 2);
    shares[0][32] = 0;
    const committed = [flipped(shares[0], 0), shares[1]];
    const { holders, envelope } = await builtWith(shares, committed);

    expect(await codeOf(() => decryptShare(holders[0].secretKey, envelope))).toBe(
      "CommitmentMismatch"
    );
  });
});
