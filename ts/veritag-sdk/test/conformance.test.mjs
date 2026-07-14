/**
 * Cross-SDK conformance: buildBinding must match the shared vectors (and thus
 * the Dart SDK and the Python reference). See sdk/conformance/binding_vectors.json.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildBinding } from "../dist/index.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../../conformance/binding_vectors.json", import.meta.url)),
).vectors;

const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");

test("buildBinding matches the shared conformance vectors", async () => {
  for (const v of vectors) {
    const got = toHex(await buildBinding(v.uid, v.context));
    assert.equal(got, v.binding_hex, `binding for ${v.uid}|${v.context}`);
  }
});
