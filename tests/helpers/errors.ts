import { type ErrorCode, ThresholdError } from "../../src";

/** The ThresholdError `f` throws or rejects with. Anything else fails the test. */
export async function thresholdErrorOf(f: () => unknown): Promise<ThresholdError> {
  try {
    await f();
  } catch (e) {
    if (e instanceof ThresholdError) {
      return e;
    }
    throw e;
  }
  throw new Error("expected a ThresholdError, but it returned");
}

export async function codeOf(f: () => unknown): Promise<ErrorCode> {
  return (await thresholdErrorOf(f)).code;
}
