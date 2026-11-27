import { equalBytes } from "@noble/ciphers/utils";
import { concatBytes } from "@noble/hashes/utils";
import { combine as interpolate } from "shamir-secret-sharing";

import { aeadDecrypt } from "./aead";
import { SHAMIR_SHARE_LENGTH } from "./consts";
import { parseEnvelope } from "./envelope";
import { type ErrorCode, ThresholdError } from "./errors";
import { commitment, contentKey, envelopeId, keyCheck } from "./hashes";
import { decodeShare } from "./share";

const X_OFFSET = SHAMIR_SHARE_LENGTH - 1;

export interface CombineOptions {
  /** The associated data `encrypt` was given, empty by default. */
  readonly aad?: Uint8Array;
}

/**
 * Opens an envelope with K or more shares from `decryptShare`, in any order. It fails as a
 * whole if any share fails, and a share error names every failing position in `shares`.
 */
export async function combine(
  envelope: Uint8Array,
  shares: readonly Uint8Array[],
  options: CombineOptions = {}
): Promise<Uint8Array> {
  const parsed = parseEnvelope(envelope);
  const n = parsed.recipients.length;
  const k = parsed.threshold;

  const decoded = shares.map((share) => decodeShare(share));
  rejectAt(
    "MalformedShare",
    decoded.map((d) => d === undefined),
    "aren't 67 bytes with version 1"
  );
  const fields = decoded.filter((d) => d !== undefined);
  const id = envelopeId(parsed.prelude);
  rejectAt(
    "WrongEnvelope",
    fields.map((f) => !equalBytes(f.envelopeId, id)),
    "are from another envelope"
  );
  rejectAt(
    "MalformedShare",
    fields.map((f) => f.index >= n || f.share[X_OFFSET] === 0),
    "name no recipient, or have x-coordinate 0"
  );
  rejectAt(
    "CommitmentMismatch",
    fields.map(
      (f) => !equalBytes(commitment(f.share), parsed.recipients[f.index].commitment)
    ),
    "don't match their commitments"
  );
  const indexes = fields.map((f) => f.index);
  rejectAt(
    "DuplicateShare",
    indexes.map((index, p) => indexes.indexOf(index) < p),
    "repeat an earlier share's index"
  );
  if (fields.length < k) {
    throw new ThresholdError(
      "NotEnoughShares",
      `${fields.length} shares, and the threshold is ${k}`
    );
  }
  const xs = fields.map((f) => f.share[X_OFFSET]);
  if (xs.some((x, p) => xs.indexOf(x) < p)) {
    throw new ThresholdError(
      "InconsistentShares",
      "two shares have the same x-coordinate"
    );
  }

  // plain copies, since shamir-secret-sharing rejects a Buffer, and these get zeroed
  const copies = fields.map((f) => Uint8Array.from(f.share));
  let dataKey: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    dataKey = await interpolate(copies.slice(0, k));
    if (!equalBytes(keyCheck(dataKey), parsed.keyCheck)) {
      throw new ThresholdError(
        "InconsistentShares",
        "the first K shares don't give the envelope's data key"
      );
    }
    // A share lies on the first K shares' polynomial if swapping it in for the K-th gives the
    // same data key. Both polynomials pass through the first K − 1 shares, so they are the
    // same polynomial if they also agree at x = 0.
    for (const extra of copies.slice(k)) {
      const swapped = await interpolate([...copies.slice(0, k - 1), extra]);
      const onPolynomial = equalBytes(swapped, dataKey);
      swapped.fill(0);
      if (!onPolynomial) {
        throw new ThresholdError(
          "InconsistentShares",
          "the shares don't lie on one polynomial of degree K − 1"
        );
      }
    }

    key = contentKey(dataKey);
    const { content, suite } = parsed;
    const nonce = content.subarray(0, suite.nonceLength);
    const ad = concatBytes(parsed.header, options.aad ?? new Uint8Array());
    try {
      return aeadDecrypt(suite, key, nonce, ad, content.subarray(suite.nonceLength));
    } catch {
      throw new ThresholdError(
        "DecryptionFailed",
        "the content doesn't decrypt: the aad is wrong or the envelope was altered"
      );
    }
  } finally {
    dataKey?.fill(0);
    key?.fill(0);
    for (const copy of copies) {
      copy.fill(0);
    }
  }
}

function rejectAt(code: ErrorCode, failing: readonly boolean[], what: string): void {
  const positions = failing.flatMap((fails, p) => (fails ? [p] : []));
  if (positions.length > 0) {
    throw new ThresholdError(
      code,
      `the shares at positions ${positions.join(", ")} ${what}`,
      positions
    );
  }
}
