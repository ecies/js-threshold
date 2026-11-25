import { TAG_LENGTH } from "./consts";
import { ThresholdError } from "./errors";
import { getSuite, type Suite } from "./suites";

const ENVELOPE_VERSION = 0x01;
// version, suite, K and N
const FIXED_FIELDS = 4;
const KEY_CHECK_LENGTH = 32;
// the recipient table starts after the key check, at 36
const TABLE_OFFSET = FIXED_FIELDS + KEY_CHECK_LENGTH;
const DIGEST_LENGTH = 32;
// a recipient table entry: the fingerprint, then the commitment
const ENTRY_LENGTH = 2 * DIGEST_LENGTH;

export interface Recipient {
  readonly fingerprint: Uint8Array;
  readonly commitment: Uint8Array;
  readonly wrapped: Uint8Array;
}

/**
 * An envelope's fields. Every `Uint8Array` is a view into the parsed bytes, not a copy.
 * N is `recipients.length`.
 */
export interface Envelope {
  readonly suite: Suite;
  readonly threshold: number;
  readonly keyCheck: Uint8Array;
  readonly recipients: readonly Recipient[];
  /** the header without the wrapped shares: what the wraps and the envelope id cover */
  readonly prelude: Uint8Array;
  /** the prelude and the wrapped shares: the content's associated data, before `aad` */
  readonly header: Uint8Array;
  /** the nonce, the tag and the ciphertext */
  readonly content: Uint8Array;
}

export interface PreludeFields {
  readonly suite: Suite;
  readonly threshold: number;
  readonly keyCheck: Uint8Array;
  /** N is `recipients.length` */
  readonly recipients: readonly Pick<Recipient, "fingerprint" | "commitment">[];
}

/**
 * Writes the prelude. The header is the prelude followed by the wrapped shares, and the
 * envelope is the header followed by the content. The caller checks the fields first.
 */
export function encodePrelude(fields: PreludeFields): Uint8Array {
  const n = fields.recipients.length;
  const prelude = new Uint8Array(TABLE_OFFSET + n * ENTRY_LENGTH);
  prelude.set([ENVELOPE_VERSION, fields.suite.id, fields.threshold, n]);
  prelude.set(fields.keyCheck, FIXED_FIELDS);
  fields.recipients.forEach(({ fingerprint, commitment }, i) => {
    const entry = TABLE_OFFSET + i * ENTRY_LENGTH;
    prelude.set(fingerprint, entry);
    prelude.set(commitment, entry + DIGEST_LENGTH);
  });
  return prelude;
}

/** Reads an envelope's fields, running SPEC.md's parse checks in order. */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length < FIXED_FIELDS) {
    throw new ThresholdError("MalformedEnvelope", "envelope is shorter than 4 bytes");
  }
  if (bytes[0] !== ENVELOPE_VERSION) {
    throw new ThresholdError("UnsupportedVersion", `envelope version ${bytes[0]}`);
  }
  const suite = getSuite(bytes[1]);
  if (suite === undefined) {
    throw new ThresholdError("UnsupportedSuite", `suite ${bytes[1]}`);
  }
  const threshold = bytes[2];
  const n = bytes[3];
  if (threshold < 2 || threshold > n) {
    throw new ThresholdError("MalformedEnvelope", `threshold ${threshold} of ${n}`);
  }
  const preludeLength = TABLE_OFFSET + n * ENTRY_LENGTH;
  const w = suite.wrappedLength;
  const headerLength = preludeLength + n * w;
  if (bytes.length < headerLength + suite.nonceLength + TAG_LENGTH) {
    throw new ThresholdError(
      "MalformedEnvelope",
      "envelope is shorter than its header, nonce and tag"
    );
  }

  const recipients: Recipient[] = [];
  for (let i = 0; i < n; i++) {
    const entry = TABLE_OFFSET + i * ENTRY_LENGTH;
    const wrapped = preludeLength + i * w;
    recipients.push({
      fingerprint: bytes.subarray(entry, entry + DIGEST_LENGTH),
      commitment: bytes.subarray(entry + DIGEST_LENGTH, entry + ENTRY_LENGTH),
      wrapped: bytes.subarray(wrapped, wrapped + w),
    });
  }
  if (!allDistinct(recipients.map((r) => r.fingerprint))) {
    throw new ThresholdError("MalformedEnvelope", "two recipients share a fingerprint");
  }
  if (!allDistinct(recipients.map((r) => r.commitment))) {
    throw new ThresholdError("MalformedEnvelope", "two recipients share a commitment");
  }

  return {
    suite,
    threshold,
    keyCheck: bytes.subarray(FIXED_FIELDS, TABLE_OFFSET),
    recipients,
    prelude: bytes.subarray(0, preludeLength),
    header: bytes.subarray(0, headerLength),
    content: bytes.subarray(headerLength),
  };
}

// header fields are public, so this needn't run in constant time
function allDistinct(values: readonly Uint8Array[]): boolean {
  const seen = new Set<string>();
  for (const value of values) {
    const key = Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return true;
}
