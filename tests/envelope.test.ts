import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import { encodePrelude, parseEnvelope } from "../src/envelope";
import { ThresholdError } from "../src/errors";
import { getSuite } from "../src/suites";

// SPEC.md's suite table: ID, nonce length Ln, wrapped share size W
const SPEC_SUITES = [
  [0x01, 16, 130],
  [0x02, 12, 126],
  [0x03, 24, 138],
  [0x04, 16, 98],
  [0x05, 12, 94],
  [0x06, 24, 106],
  [0x07, 16, 130],
  [0x08, 12, 126],
  [0x09, 24, 138],
  [0x0a, 16, 98],
  [0x0b, 12, 94],
  [0x0c, 24, 106],
  [0x11, 16, 97],
  [0x12, 12, 93],
  [0x13, 24, 105],
  [0x21, 16, 97],
  [0x22, 12, 93],
  [0x23, 24, 105],
] as const;

interface Shape {
  suite: number;
  ln: number;
  w: number;
  k: number;
  n: number;
  ciphertext: number;
}

const hex = (byte: number) => `0x${byte.toString(16).padStart(2, "0")}`;

const fill = (length: number, byte: number) => new Uint8Array(length).fill(byte);

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

// lays an envelope out by hand from SPEC.md's offsets, each field filled with its own byte
// so that a misread offset shows
function layOut({ suite, ln, w, k, n, ciphertext }: Shape) {
  const fields = {
    keyCheck: fill(32, 0x4c),
    fingerprints: Array.from({ length: n }, (_, i) => fill(32, 0x10 + i)),
    commitments: Array.from({ length: n }, (_, i) => fill(32, 0x50 + i)),
    wrapped: Array.from({ length: n }, (_, i) => fill(w, 0x90 + i)),
    content: concat(fill(ln, 0xd0), fill(16, 0xd1), fill(ciphertext, 0xd2)),
  };
  const table = fields.fingerprints.flatMap((f, i) => [f, fields.commitments[i]]);
  const prelude = concat(Uint8Array.of(0x01, suite, k, n), fields.keyCheck, ...table);
  const header = concat(prelude, ...fields.wrapped);
  return { fields, prelude, header, envelope: concat(header, fields.content) };
}

const DEFAULT: Shape = { suite: 0x01, ln: 16, w: 130, k: 2, n: 3, ciphertext: 5 };

function suiteOf(id: number) {
  const suite = getSuite(id);
  if (suite === undefined) {
    throw new Error(`suite ${hex(id)} isn't listed`);
  }
  return suite;
}

// the code of the ThresholdError f throws, or undefined if it returns
function codeOf(f: () => unknown): string | undefined {
  try {
    f();
  } catch (e) {
    if (e instanceof ThresholdError) {
      return e.code;
    }
    throw e;
  }
  return undefined;
}

describe("parseEnvelope", () => {
  it("rejects fewer than 4 bytes as MalformedEnvelope", () => {
    const { envelope } = layOut(DEFAULT);
    for (const length of [0, 1, 2, 3]) {
      expect(codeOf(() => parseEnvelope(envelope.subarray(0, length)))).toBe(
        "MalformedEnvelope"
      );
    }
  });

  it("rejects a version other than 1 as UnsupportedVersion", () => {
    for (const version of [0x00, 0x02, 0xff]) {
      const { envelope } = layOut(DEFAULT);
      envelope[0] = version;
      expect(codeOf(() => parseEnvelope(envelope))).toBe("UnsupportedVersion");
    }
  });

  it("rejects every suite the table doesn't list as UnsupportedSuite", () => {
    const listed = new Set<number>(SPEC_SUITES.map(([id]) => id));
    const unlisted = Array.from({ length: 256 }, (_, id) => id).filter(
      (id) => !listed.has(id)
    );
    expect(unlisted.length).toBe(256 - 18);
    for (const suite of unlisted) {
      const { envelope } = layOut(DEFAULT);
      envelope[1] = suite;
      expect(codeOf(() => parseEnvelope(envelope))).toBe("UnsupportedSuite");
    }
  });

  it("rejects K below 2 or above N as MalformedEnvelope", () => {
    for (const [k, n] of [
      [0, 3],
      [1, 3],
      [4, 3],
      [255, 3],
      [2, 1],
      [2, 0],
    ]) {
      const { envelope } = layOut(DEFAULT);
      envelope[2] = k;
      envelope[3] = n;
      expect(codeOf(() => parseEnvelope(envelope))).toBe("MalformedEnvelope");
    }
  });

  for (const [suite, ln, w] of SPEC_SUITES) {
    it(`rejects suite ${hex(suite)} cut short of its header, nonce and tag, at every length`, () => {
      const { envelope } = layOut({ ...DEFAULT, suite, ln, w });
      const minimum = 36 + 3 * (64 + w) + ln + 16;
      expect(envelope.length).toBe(minimum + DEFAULT.ciphertext);
      for (let length = 0; length <= envelope.length; length++) {
        expect(codeOf(() => parseEnvelope(envelope.subarray(0, length)))).toBe(
          length < minimum ? "MalformedEnvelope" : undefined
        );
      }
    });
  }

  it("reads each field at its offset, in every suite", () => {
    for (const [suite, ln, w] of SPEC_SUITES) {
      const { fields, prelude, header, envelope } = layOut({ ...DEFAULT, suite, ln, w });
      const parsed = parseEnvelope(envelope);
      expect(parsed.suite.id).toBe(suite);
      expect(parsed.threshold).toBe(2);
      expect(parsed.keyCheck).toEqual(fields.keyCheck);
      expect(parsed.recipients).toEqual(
        fields.fingerprints.map((fingerprint, i) => ({
          fingerprint,
          commitment: fields.commitments[i],
          wrapped: fields.wrapped[i],
        }))
      );
      expect(parsed.prelude).toEqual(prelude);
      expect(parsed.header).toEqual(header);
      expect(parsed.content).toEqual(fields.content);
    }
  });

  // SPEC.md's offsets of entry i's fields
  const fingerprintAt = (i: number) => 36 + 64 * i;
  const commitmentAt = (i: number) => 36 + 64 * i + 32;

  it("rejects a repeated fingerprint as MalformedEnvelope", () => {
    for (const [first, repeat] of [
      [0, 1],
      [0, 2],
      [1, 2],
    ]) {
      const { fields, envelope } = layOut(DEFAULT);
      envelope.set(fields.fingerprints[first], fingerprintAt(repeat));
      expect(codeOf(() => parseEnvelope(envelope))).toBe("MalformedEnvelope");
    }
  });

  it("rejects a repeated commitment as MalformedEnvelope", () => {
    for (const [first, repeat] of [
      [0, 1],
      [0, 2],
      [1, 2],
    ]) {
      const { fields, envelope } = layOut(DEFAULT);
      envelope.set(fields.commitments[first], commitmentAt(repeat));
      expect(codeOf(() => parseEnvelope(envelope))).toBe("MalformedEnvelope");
    }
  });

  it("accepts a fingerprint equal to a commitment", () => {
    for (const [fingerprint, commitment] of [
      [0, 0],
      [0, 1],
      [2, 1],
    ]) {
      const { fields, envelope } = layOut(DEFAULT);
      envelope.set(fields.commitments[commitment], fingerprintAt(fingerprint));
      expect(parseEnvelope(envelope).recipients[fingerprint].fingerprint).toEqual(
        fields.commitments[commitment]
      );
    }
  });

  it("runs its checks in SPEC.md's order", () => {
    const cases: [string, number[], string][] = [
      ["length, then version", [0x02, 0x01, 2], "MalformedEnvelope"],
      ["version, then suite", [0x02, 0x00, 2, 3], "UnsupportedVersion"],
      ["version, then length again", [0x02, 0x01, 2, 3], "UnsupportedVersion"],
      ["suite, then threshold", [0x01, 0x00, 1, 3], "UnsupportedSuite"],
      ["suite, then length again", [0x01, 0x80, 2, 3], "UnsupportedSuite"],
    ];
    for (const [order, bytes, code] of cases) {
      expect([order, codeOf(() => parseEnvelope(Uint8Array.from(bytes)))]).toEqual([
        order,
        code,
      ]);
    }
  });

  it("reads a Buffer, and a view that starts partway into its buffer", () => {
    const { fields, prelude, header, envelope } = layOut(DEFAULT);
    const padded = concat(fill(7, 0xee), envelope, fill(7, 0xee));
    const inputs = [
      Buffer.from(envelope),
      padded.subarray(7, 7 + envelope.length),
      Buffer.from(padded).subarray(7, 7 + envelope.length),
    ];
    for (const input of inputs) {
      const parsed = parseEnvelope(input);
      const copy = (b: Uint8Array) => Uint8Array.from(b);
      expect(copy(parsed.keyCheck)).toEqual(fields.keyCheck);
      expect(parsed.recipients.map((r) => copy(r.fingerprint))).toEqual(
        fields.fingerprints
      );
      expect(parsed.recipients.map((r) => copy(r.commitment))).toEqual(
        fields.commitments
      );
      expect(parsed.recipients.map((r) => copy(r.wrapped))).toEqual(fields.wrapped);
      expect(copy(parsed.prelude)).toEqual(prelude);
      expect(copy(parsed.header)).toEqual(header);
      expect(copy(parsed.content)).toEqual(fields.content);
    }
  });

  it("accepts K from 2 to N", () => {
    for (const k of [2, 3]) {
      expect(codeOf(() => parseEnvelope(layOut({ ...DEFAULT, k }).envelope))).toBe(
        undefined
      );
    }
  });
});

describe("encodePrelude", () => {
  it("writes SPEC.md's prelude, which parseEnvelope reads back", () => {
    for (const [suite, ln, w] of SPEC_SUITES) {
      for (const [k, n] of [
        [2, 2],
        [3, 5],
        [255, 255],
      ]) {
        const { fields, prelude } = layOut({ suite, ln, w, k, n, ciphertext: 0 });
        const written = encodePrelude({
          suite: suiteOf(suite),
          threshold: k,
          keyCheck: fields.keyCheck,
          recipients: fields.fingerprints.map((fingerprint, i) => ({
            fingerprint,
            commitment: fields.commitments[i],
          })),
        });
        expect(written).toEqual(prelude);

        const parsed = parseEnvelope(concat(written, ...fields.wrapped, fields.content));
        expect(parsed.suite).toBe(suiteOf(suite));
        expect(parsed.threshold).toBe(k);
        expect(parsed.recipients.length).toBe(n);
        expect(parsed.prelude).toEqual(written);
      }
    }
  });
});
