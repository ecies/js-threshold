import { combine as interpolate, split } from "shamir-secret-sharing";
import { describe, expect, it } from "vitest";

import { combine, decryptShare, type ErrorCode, encrypt } from "../src";
import { codeOf, thresholdErrorOf } from "./helpers/errors";
import { keyPairs } from "./helpers/keys";
import { build, concat } from "./helpers/reference";
import { SPEC_SUITES } from "./helpers/spec-suites";
import { SLOW_TEST_TIMEOUT } from "./helpers/timeouts";

const PLAINTEXT = new TextEncoder().encode("secret");
const SUITE = SPEC_SUITES[0]; // 0x01: secp256k1, AES-256-GCM, W = 130

async function opened(n = 3, k = 2, aad?: Uint8Array) {
  const holders = keyPairs("secp256k1", n);
  const envelope = await encrypt(
    holders.map((h) => h.publicKey),
    k,
    PLAINTEXT,
    { aad }
  );
  const shares = holders.map((h) => decryptShare(h.secretKey, envelope));
  return { envelope, shares };
}

const withByte = (bytes: Uint8Array, offset: number, value: number) => {
  const out = Uint8Array.from(bytes);
  out[offset] = value;
  return out;
};

// this envelope's id and the share's index, with share bytes no holder had; x stays as it was
const garbled = (share: Uint8Array, index = share[33]) => {
  const out = withByte(share, 33, index);
  out.fill(0x5a, 34, 66);
  return out;
};

async function positionsOf(f: () => unknown) {
  const e = await thresholdErrorOf(f);
  return { code: e.code, positions: e.positions };
}

describe("combine rejects shares, naming every failing position", () => {
  it("MalformedShare: not 67 bytes with version 1", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1, s2] = shares;
    const input = [
      s0,
      s1.subarray(1),
      s2,
      concat(s0, Uint8Array.of(0)),
      withByte(s1, 0, 0x02),
      new Uint8Array(0),
    ];
    expect(await positionsOf(() => combine(envelope, input))).toEqual({
      code: "MalformedShare",
      positions: [1, 3, 4, 5],
    });
  });

  it("WrongEnvelope: from another envelope", async () => {
    const { envelope, shares } = await opened();
    const other = await opened();
    const input = [shares[0], other.shares[1], shares[2], other.shares[0]];
    expect(await positionsOf(() => combine(envelope, input))).toEqual({
      code: "WrongEnvelope",
      positions: [1, 3],
    });
  });

  it("MalformedShare: an index of N or more, or x-coordinate 0", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1, s2] = shares;
    const input = [withByte(s0, 33, 3), s1, withByte(s2, 66, 0), withByte(s1, 33, 255)];
    expect(await positionsOf(() => combine(envelope, input))).toEqual({
      code: "MalformedShare",
      positions: [0, 2, 3],
    });
  });

  it("CommitmentMismatch: not the share its index names", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1, s2] = shares;
    const input = [garbled(s0), s1, garbled(s2)];
    expect(await positionsOf(() => combine(envelope, input))).toEqual({
      code: "CommitmentMismatch",
      positions: [0, 2],
    });
  });

  it("CommitmentMismatch, not DuplicateShare, for a forged share that claims an honest holder's index", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1] = shares;
    expect(await positionsOf(() => combine(envelope, [garbled(s1, 0), s0, s1]))).toEqual({
      code: "CommitmentMismatch",
      positions: [0],
    });
  });

  it("DuplicateShare: the positions that repeat an earlier share's index", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1] = shares;
    expect(await positionsOf(() => combine(envelope, [s0, s1, s0]))).toEqual({
      code: "DuplicateShare",
      positions: [2],
    });
    expect(await positionsOf(() => combine(envelope, [s1, s1, s1]))).toEqual({
      code: "DuplicateShare",
      positions: [1, 2],
    });
  });

  it("opens with the others once the named shares are dropped", async () => {
    const { envelope, shares } = await opened();
    const input = [garbled(shares[0]), shares[1], shares[2]];
    const { positions = [] } = await thresholdErrorOf(() => combine(envelope, input));

    const rest = input.filter((_, p) => !positions.includes(p));
    expect(await combine(envelope, rest)).toEqual(PLAINTEXT);
  });
});

describe("combine", () => {
  it("rejects no shares as NotEnoughShares", async () => {
    const { envelope } = await opened();
    expect(await codeOf(() => combine(envelope, []))).toBe("NotEnoughShares");
  });

  it("runs SPEC.md's share checks in order", async () => {
    const { envelope, shares } = await opened();
    const [s0, s1] = shares;
    const other = (await opened()).shares[0];
    const badIndex = withByte(s0, 33, 9);
    const cases: [Uint8Array[], ErrorCode][] = [
      [[other, s0.subarray(1)], "MalformedShare"], // shape before envelope id
      [[badIndex, other], "WrongEnvelope"], // envelope id before index
      [[garbled(s0), badIndex], "MalformedShare"], // index before commitment
      [[s0, s0, garbled(s1)], "CommitmentMismatch"], // commitment before duplicates
    ];
    for (const [input, code] of cases) {
      expect(await codeOf(() => combine(envelope, input))).toBe(code);
    }

    // duplicates before the count: 2 shares of a 3-of-3 envelope are too few as well
    const threeOfThree = await opened(3, 3);
    const [t0] = threeOfThree.shares;
    expect(await positionsOf(() => combine(threeOfThree.envelope, [t0, t0]))).toEqual({
      code: "DuplicateShare",
      positions: [1],
    });
  });

  it("rejects the wrong aad as DecryptionFailed", async () => {
    const aad = new TextEncoder().encode("prod/app.env");
    const withAad = await opened(3, 2, aad);
    const without = await opened();
    const cases = [
      [withAad, new TextEncoder().encode("prod/app.env2")],
      [withAad, undefined],
      [without, aad],
    ] as const;
    for (const [{ envelope, shares }, wrong] of cases) {
      const input = shares.slice(0, 2);
      expect(await codeOf(() => combine(envelope, input, { aad: wrong }))).toBe(
        "DecryptionFailed"
      );
    }
    const { envelope, shares } = withAad;
    expect(await combine(envelope, shares.slice(1), { aad })).toEqual(PLAINTEXT);
  });

  it(
    "rejects a bit flipped anywhere in the envelope",
    async () => {
      const { envelope, shares } = await opened();
      const p = 36 + 64 * 3;
      // what SPEC.md's parse checks and combine's steps make of each flip
      const expected = (offset: number, flipped: Uint8Array): ErrorCode => {
        if (offset === 0) {
          return "UnsupportedVersion";
        }
        if (offset >= p) {
          return "DecryptionFailed"; // the wrapped shares and the content: the content's AD
        }
        const suite = SPEC_SUITES.find((s) => s.id === flipped[1]);
        if (suite === undefined) {
          return "UnsupportedSuite";
        }
        const [k, n] = [flipped[2], flipped[3]];
        const headerLength = 36 + n * (64 + suite.wrappedLength);
        if (k < 2 || k > n || flipped.length < headerLength + suite.nonceLength + 16) {
          return "MalformedEnvelope";
        }
        return "WrongEnvelope"; // the prelude changed, and with it the envelope id
      };

      const mismatches = [];
      for (let offset = 0; offset < envelope.length; offset++) {
        for (let bit = 0; bit < 8; bit++) {
          const flipped = withByte(envelope, offset, envelope[offset] ^ (1 << bit));
          const code = await codeOf(() => combine(flipped, shares.slice(0, 2)));
          if (code !== expected(offset, flipped)) {
            mismatches.push({ offset, bit, code });
          }
        }
      }
      expect(mismatches).toEqual([]);
    },
    SLOW_TEST_TIMEOUT
  );
});

describe("combine, on an envelope its encryptor built wrong", () => {
  async function builtWith(shares: Uint8Array[], dataKey: Uint8Array) {
    const holders = keyPairs("secp256k1", shares.length);
    const envelope = await build({
      suite: SUITE,
      threshold: 2,
      recipients: holders.map((h) => h.publicKey),
      plaintext: PLAINTEXT,
      dataKey,
      shares,
    });
    return { envelope, shares: holders.map((h) => decryptShare(h.secretKey, envelope)) };
  }
  const dataKey = new Uint8Array(32).fill(7);

  it("rejects two shares with one x-coordinate as InconsistentShares", async () => {
    const raw = await split(dataKey, 3, 2);
    raw[1][32] = raw[0][32];
    const { envelope, shares } = await builtWith(raw, dataKey);
    expect(await codeOf(() => combine(envelope, [shares[0], shares[1]]))).toBe(
      "InconsistentShares"
    );
  });

  it("rejects a share after the first K that repeats an x-coordinate as InconsistentShares", async () => {
    const raw = await split(dataKey, 3, 2);
    raw[2][32] = raw[0][32];
    const { envelope, shares } = await builtWith(raw, dataKey);

    expect(await combine(envelope, [shares[0], shares[1]])).toEqual(PLAINTEXT);
    expect(await codeOf(() => combine(envelope, shares))).toBe("InconsistentShares");
  });

  it("rejects shares that don't give the key check's data key as InconsistentShares", async () => {
    const raw = await split(new Uint8Array(32).fill(8), 3, 2);
    const { envelope, shares } = await builtWith(raw, dataKey);
    expect(await codeOf(() => combine(envelope, [shares[2], shares[0]]))).toBe(
      "InconsistentShares"
    );
  });

  it("rejects a share after the first K that isn't on their polynomial as InconsistentShares", async () => {
    const raw = await split(dataKey, 3, 2);
    raw[2][0] ^= 1;
    const { envelope, shares } = await builtWith(raw, dataKey);
    const [s0, s1, s2] = shares;

    expect(await combine(envelope, [s0, s1])).toEqual(PLAINTEXT);
    expect(await codeOf(() => combine(envelope, shares))).toBe("InconsistentShares");
    expect(await codeOf(() => combine(envelope, [s2, s0]))).toBe("InconsistentShares");
  });

  it("rejects shares of degree K, which only all of them would open, as InconsistentShares", async () => {
    // a 3-of-3 split under a 2-of-3 header: no 2 shares give the data key, all 3 do
    const raw = await split(dataKey, 3, 3);
    expect(await interpolate(raw.map((s) => Uint8Array.from(s)))).toEqual(dataKey);
    const { envelope, shares } = await builtWith(raw, dataKey);
    const [s0, s1, s2] = shares;

    for (const input of [[s0, s1], [s1, s2], [s2, s0], shares]) {
      expect(await codeOf(() => combine(envelope, input))).toBe("InconsistentShares");
    }
  });
});
