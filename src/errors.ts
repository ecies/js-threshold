/**
 * Failure conditions named in SPEC.md, as `ThresholdError.code`. These are the parser's;
 * `encrypt`, `decryptShare` and `combine` add theirs.
 */
export type ErrorCode = "MalformedEnvelope" | "UnsupportedVersion" | "UnsupportedSuite";

/** A failure named in SPEC.md. Tell them apart by `code`. */
export class ThresholdError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "ThresholdError";
    this.code = code;
  }
}
