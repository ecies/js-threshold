import { equalBytes } from "@noble/ciphers/utils";

import { SHAMIR_SHARE_LENGTH } from "./consts";
import { parseEnvelope } from "./envelope";
import { ThresholdError } from "./errors";
import { commitment, envelopeId, fingerprint, wrapAD } from "./hashes";
import { publicKeyOf } from "./keys";
import { encodeShare } from "./share";
import { unwrapShare } from "./wrap";

/**
 * Unwraps the holder's own share of an envelope and checks it against its commitment.
 * Returns it in SPEC.md's 67-byte share format, for the holder to send to `combine`.
 */
export function decryptShare(secretKey: Uint8Array, envelope: Uint8Array): Uint8Array {
  const parsed = parseEnvelope(envelope);
  const curve = parsed.suite.ellipticCurve;
  const ownKey = publicKeyOf(curve, secretKey);
  if (ownKey === undefined) {
    throw new ThresholdError("InvalidArgument", `not a valid ${curve} secret key`);
  }
  const ownFingerprint = fingerprint(ownKey);
  const index = parsed.recipients.findIndex((r) =>
    equalBytes(r.fingerprint, ownFingerprint)
  );
  if (index < 0) {
    throw new ThresholdError("NotARecipient", "no recipient has this key's fingerprint");
  }

  const recipient = parsed.recipients[index];
  const ad = wrapAD(index, parsed.prelude);
  const share = unwrapShare(parsed.suite, secretKey, recipient.wrapped, ad);
  if (share === undefined) {
    throw new ThresholdError(
      "ShareDecryptionFailed",
      `recipient ${index}'s wrapped share doesn't decrypt with this key`
    );
  }
  try {
    if (!equalBytes(commitment(share), recipient.commitment)) {
      throw new ThresholdError(
        "CommitmentMismatch",
        `recipient ${index}'s share doesn't match its commitment`
      );
    }
    if (share[SHAMIR_SHARE_LENGTH - 1] === 0) {
      throw new ThresholdError(
        "MalformedShare",
        `recipient ${index}'s share has x-coordinate 0`
      );
    }
    return encodeShare({ envelopeId: envelopeId(parsed.prelude), index, share });
  } finally {
    share.fill(0);
  }
}
