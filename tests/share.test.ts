import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import { decodeShare, encodeShare } from "../src/share";

const fill = (length: number, byte: number) => new Uint8Array(length).fill(byte);

// SPEC.md's share format, laid out by hand
const FIELDS = { envelopeId: fill(32, 0xa1), index: 7, share: fill(33, 0xb2) };
const LAID_OUT = Uint8Array.from([0x01, ...FIELDS.envelopeId, 7, ...FIELDS.share]);

describe("encodeShare", () => {
  it("writes SPEC.md's share format", () => {
    expect(LAID_OUT.length).toBe(67);
    expect(encodeShare(FIELDS)).toEqual(LAID_OUT);
  });
});

describe("decodeShare", () => {
  it("reads each field, from a Buffer and from a view partway into its buffer", () => {
    const padded = Uint8Array.from([0xee, 0xee, ...LAID_OUT, 0xee]);
    const inputs = [
      LAID_OUT,
      Buffer.from(LAID_OUT),
      padded.subarray(2, 69),
      Buffer.from(padded).subarray(2, 69),
    ];
    for (const input of inputs) {
      const decoded = decodeShare(input);
      expect(decoded && Uint8Array.from(decoded.envelopeId)).toEqual(FIELDS.envelopeId);
      expect(decoded?.index).toBe(7);
      expect(decoded && Uint8Array.from(decoded.share)).toEqual(FIELDS.share);
    }
  });

  it("rejects every length but 67", () => {
    const long = Uint8Array.from([...LAID_OUT, ...LAID_OUT]);
    for (let length = 0; length <= long.length; length++) {
      expect([length, decodeShare(long.subarray(0, length))]).toEqual([
        length,
        length === 67 ? expect.anything() : undefined,
      ]);
    }
  });

  it("accepts any index and x-coordinate, which combine checks after the envelope id", () => {
    for (const [index, x] of [
      [0, 0],
      [255, 0],
      [255, 1],
    ]) {
      const share = Uint8Array.from(LAID_OUT);
      // SPEC.md's offsets: the index at 33, the share at 34, its x-coordinate last
      share[33] = index;
      share[66] = x;
      const decoded = decodeShare(share);
      expect([decoded?.index, decoded?.share[32]]).toEqual([index, x]);
    }
  });

  it("rejects a version other than 1", () => {
    for (const version of [0x00, 0x02, 0xff]) {
      const share = Uint8Array.from(LAID_OUT);
      share[0] = version;
      expect(decodeShare(share)).toBe(undefined);
    }
  });
});
