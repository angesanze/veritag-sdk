/**
 * Browser SDM-CMAC validated against the official NXP AN12196 vectors — the same
 * ones that pin crypto/cmac.py and the Dart SDK. If these pass, a tag "tapped"
 * in the browser produces exactly the CMAC the server expects.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { computeSdmCmac, hexToBytes, bytesToHex } from "../dist/index.js";

const VECTORS = [
  { key: "00000000000000000000000000000000", uid: "04DE5F1EACC040", ctr: 61, cmac: "94eed9ee65337086" },
  { key: "00000000000000000000000000000000", uid: "041E3C8A2D6B80", ctr: 6, cmac: "4b00064004b0b3d3" },
];

test("computeSdmCmac matches the AN12196 vectors", async () => {
  for (const v of VECTORS) {
    const got = await computeSdmCmac(hexToBytes(v.key), hexToBytes(v.uid), v.ctr);
    assert.equal(bytesToHex(got), v.cmac, `vector uid=${v.uid} ctr=${v.ctr}`);
  }
});
