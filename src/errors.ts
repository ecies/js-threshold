/** The failure conditions SPEC.md names, as `ThresholdError.code`. */
export type ErrorCode = "MalformedEnvelope" | "UnsupportedVersion" | "UnsupportedSuite";

/** Every failure SPEC.md names. Tell them apart by `code`. */
export class ThresholdError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "ThresholdError";
    this.code = code;
  }
}
