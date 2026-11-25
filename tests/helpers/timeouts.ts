/**
 * The timeout for a test that runs hundreds of curve operations. Vitest's and bun's default
 * is 5 seconds; these take seconds on a laptop, and longer on a busy CI runner.
 */
export const SLOW_TEST_TIMEOUT = 60_000;
