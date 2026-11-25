import { describe, expect, it } from "vitest";

import { combine, decryptShare, encrypt } from "../src";
import { keyPairs } from "./helpers/keys";
import { build, combineBySpec, decryptShareBySpec } from "./helpers/reference";
import { configOf, hex, SPEC_SUITES } from "./helpers/spec-suites";

const PLAINTEXT = new TextEncoder().encode("the production env file");
const AAD = new TextEncoder().encode("prod/app.env");

// The reference in helpers/reference.ts follows SPEC.md's text. These tests pin what a round
// trip can't: the domain strings, the associated data and the HKDF inputs.
describe.each(SPEC_SUITES)("suite $id", (suite) => {
  it(`${hex(suite.id)}: encrypt's envelope opens by SPEC.md's steps`, async () => {
    const holders = keyPairs(suite.ellipticCurve, 3);
    const envelope = await encrypt(
      holders.map((h) => h.publicKey),
      2,
      PLAINTEXT,
      { aad: AAD, config: configOf(suite) }
    );

    expect(envelope[1]).toBe(suite.id);
    const bySpec = holders.map((h) => decryptShareBySpec(suite, h.secretKey, envelope));
    expect(await combineBySpec(suite, envelope, [bySpec[2], bySpec[0]], AAD)).toEqual(
      PLAINTEXT
    );
  });

  it(`${hex(suite.id)}: an envelope laid out by SPEC.md's steps opens with decryptShare and combine`, async () => {
    const holders = keyPairs(suite.ellipticCurve, 3);
    const envelope = await build({
      suite,
      threshold: 2,
      recipients: holders.map((h) => h.publicKey),
      plaintext: PLAINTEXT,
      aad: AAD,
    });

    const shares = holders.map((h) => decryptShare(h.secretKey, envelope));
    expect(shares).toEqual(
      holders.map((h) => decryptShareBySpec(suite, h.secretKey, envelope))
    );
    const opened = await combine(envelope, [shares[1], shares[2]], { aad: AAD });
    expect(opened).toEqual(PLAINTEXT);
  });
});
