import { expect, it } from "vitest";

import * as threshold from "../src";

// a placeholder until the first real tests: it shows each test runner (Node, bun, deno,
// browsers) finds a test file and loads the package entry
it("loads the package entry", () => {
  expect(typeof threshold).toBe("object");
});
