import { concatBytes, randomBytes } from "@noble/hashes/utils";
import { Config } from "eciesjs/config";
import { split } from "shamir-secret-sharing";

import { aeadEncrypt } from "./aead";
import { allDistinct } from "./bytes";
import { encodePrelude } from "./envelope";
import { ThresholdError } from "./errors";
import { commitment, contentKey, fingerprint, keyCheck, wrapAD } from "./hashes";
import { canonicalPublicKey } from "./keys";
import { type SuiteConfig, suiteFor } from "./suites";
import { wrapShare } from "./wrap";

const MAX_RECIPIENTS = 255;
const DATA_KEY_LENGTH = 32;

export interface EncryptOptions {
  /** Associated data, empty by default. It isn't stored: `combine` must be given the same bytes. */
  readonly aad?: Uint8Array;
  /**
   * The curve and cipher, as eciesjs's `Config` fields. A missing field takes the default
   * of eciesjs's `Config`, so the default is suite 0x01.
   */
  readonly config?: Partial<SuiteConfig>;
}

/**
 * Encrypts `plaintext` so that any `threshold` of the `recipients`, together, can open it.
 * Recipient i, in this order, gets the share at index i.
 */
export async function encrypt(
  recipients: readonly Uint8Array[],
  threshold: number,
  plaintext: Uint8Array,
  options: EncryptOptions = {}
): Promise<Uint8Array> {
  // a field set to undefined is missing, so it takes the default too
  const given = Object.entries(options.config ?? {}).filter(([, v]) => v !== undefined);
  const suite = suiteFor({ ...new Config(), ...Object.fromEntries(given) });
  if (suite === undefined) {
    throw new ThresholdError("InvalidArgument", "config matches no suite");
  }
  const n = recipients.length;
  const isInRange = threshold >= 2 && threshold <= n && n <= MAX_RECIPIENTS;
  if (!Number.isInteger(threshold) || !isInRange) {
    throw new ThresholdError("InvalidArgument", `threshold ${threshold} of ${n}`);
  }
  const curve = suite.ellipticCurve;
  const keys = recipients.map((recipient, i) => {
    const key = canonicalPublicKey(curve, recipient);
    if (key === undefined) {
      throw new ThresholdError(
        "InvalidArgument",
        `recipient ${i} isn't a valid ${curve} key`
      );
    }
    return key;
  });
  if (!allDistinct(keys)) {
    throw new ThresholdError(
      "InvalidArgument",
      "two recipients have the same public key"
    );
  }

  const dataKey = randomBytes(DATA_KEY_LENGTH);
  let shares: Uint8Array[] = [];
  let key: Uint8Array | undefined;
  try {
    shares = await split(dataKey, n, threshold);
    const prelude = encodePrelude({
      suite,
      threshold,
      keyCheck: keyCheck(dataKey),
      recipients: keys.map((k, i) => ({
        fingerprint: fingerprint(k),
        commitment: commitment(shares[i]),
      })),
    });
    const wrapped = shares.map((share, i) =>
      wrapShare(suite, keys[i], share, wrapAD(i, prelude))
    );
    const header = concatBytes(prelude, ...wrapped);

    key = contentKey(dataKey);
    const nonce = randomBytes(suite.nonceLength);
    const ad = concatBytes(header, options.aad ?? new Uint8Array());
    return concatBytes(header, nonce, aeadEncrypt(suite, key, nonce, ad, plaintext));
  } finally {
    dataKey.fill(0);
    key?.fill(0);
    for (const share of shares) {
      share.fill(0);
    }
  }
}
