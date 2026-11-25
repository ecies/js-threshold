import { SHAMIR_SHARE_LENGTH } from "./consts";

const SHARE_FORMAT_VERSION = 0x01;
const ENVELOPE_ID_LENGTH = 32;
const INDEX_OFFSET = 1 + ENVELOPE_ID_LENGTH;
const SHARE_OFFSET = INDEX_OFFSET + 1;
// 67 bytes
const ENCODED_SHARE_LENGTH = SHARE_OFFSET + SHAMIR_SHARE_LENGTH;

export interface ShareFields {
  readonly envelopeId: Uint8Array;
  /** the recipient index i */
  readonly index: number;
  /** the Shamir share: 32 bytes, then the x-coordinate */
  readonly share: Uint8Array;
}

/** Writes a share in SPEC.md's share format, into a new array. */
export function encodeShare(fields: ShareFields): Uint8Array {
  const out = new Uint8Array(ENCODED_SHARE_LENGTH);
  out[0] = SHARE_FORMAT_VERSION;
  out.set(fields.envelopeId, 1);
  out[INDEX_OFFSET] = fields.index;
  out.set(fields.share, SHARE_OFFSET);
  return out;
}

/**
 * Reads a share's fields, as views into `bytes`, or returns undefined if it isn't 67 bytes
 * with version 1. Whether the index is below N, and the x-coordinate isn't 0, depends on
 * the envelope, so `combine` checks those.
 */
export function decodeShare(bytes: Uint8Array): ShareFields | undefined {
  if (bytes.length !== ENCODED_SHARE_LENGTH || bytes[0] !== SHARE_FORMAT_VERSION) {
    return undefined;
  }
  return {
    envelopeId: bytes.subarray(1, INDEX_OFFSET),
    index: bytes[INDEX_OFFSET],
    share: bytes.subarray(SHARE_OFFSET),
  };
}
