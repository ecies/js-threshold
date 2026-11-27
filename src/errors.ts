/** The failure conditions SPEC.md names, as `ThresholdError.code`. */
export type ErrorCode =
  | "InvalidArgument"
  | "MalformedEnvelope"
  | "UnsupportedVersion"
  | "UnsupportedSuite"
  | "NotARecipient"
  | "ShareDecryptionFailed"
  | "CommitmentMismatch"
  | "MalformedShare"
  | "WrongEnvelope"
  | "DuplicateShare"
  | "NotEnoughShares"
  | "InconsistentShares"
  | "DecryptionFailed";

/** A failure named in SPEC.md. Tell them apart by `code`. */
export class ThresholdError extends Error {
  readonly code: ErrorCode;
  /**
   * For a share that `combine` rejects (`MalformedShare`, `WrongEnvelope`,
   * `CommitmentMismatch` and `DuplicateShare`): every failing position in its `shares`
   * argument, in order.
   */
  readonly positions?: readonly number[];

  constructor(code: ErrorCode, message: string, positions?: readonly number[]) {
    super(message);
    this.name = "ThresholdError";
    this.code = code;
    if (positions !== undefined) {
      this.positions = positions;
    }
  }
}
