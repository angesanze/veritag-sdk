/**
 * Phase 3 (TS) — the private key is non-extractable, persists across reloads via
 * IndexedDB, rotates, and produces valid signatures. Runs on Node's WebCrypto +
 * a fake-indexeddb so the browser keystore is exercised for real.
 *
 *   npm test   (tsc -> dist, then `node --test test/`)
 */
import "fake-indexeddb/auto";
import test from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";

import {
  IndexedDbKeyStore,
  loadOrCreateIdentity,
  rotateIdentity,
  buildBinding,
} from "../dist/index.js";

function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

// Build a Node verifier KeyObject from the SDK's uncompressed 04||X||Y hex.
function publicKeyFromHex(pubHex) {
  const raw = hexToBytes(pubHex); // 65 bytes
  const x = Buffer.from(raw.slice(1, 33)).toString("base64url");
  const y = Buffer.from(raw.slice(33, 65)).toString("base64url");
  return nodeCrypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x, y },
    format: "jwk",
  });
}

async function freshStore() {
  const s = new IndexedDbKeyStore();
  await s.clear();
  return s;
}

test("private key is NON-EXTRACTABLE; public key is exportable", async () => {
  const store = await freshStore();
  await loadOrCreateIdentity(store);
  const pair = await store.load();
  assert.ok(pair, "pair persisted");

  // The whole point: the raw private key cannot be exported.
  await assert.rejects(
    () => crypto.subtle.exportKey("pkcs8", pair.privateKey),
    "exporting the private key must throw",
  );
  assert.equal(pair.privateKey.extractable, false);

  // The public key is exportable (we need it to register the issuer).
  const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
  assert.equal(new Uint8Array(raw).length, 65); // 04||X||Y
});

test("identity persists across reloads (same public key)", async () => {
  const store = await freshStore();
  const a = await loadOrCreateIdentity(store);
  const b = await loadOrCreateIdentity(store); // loaded, not regenerated
  assert.equal(a.publicKeyHex, b.publicKeyHex);
});

test("signBinding produces a signature that verifies under the public key", async () => {
  const store = await freshStore();
  const id = await loadOrCreateIdentity(store);
  const payload = await buildBinding("04D2760000850100", "some-context");
  const derHex = await id.signBinding(payload);

  const ok = nodeCrypto.verify(
    "sha256",
    Buffer.from(payload),
    { key: publicKeyFromHex(id.publicKeyHex), dsaEncoding: "der" },
    hexToBytes(derHex),
  );
  assert.equal(ok, true);
});

test("rotateIdentity yields a new key; old signatures don't verify under it", async () => {
  const store = await freshStore();
  const oldId = await loadOrCreateIdentity(store);
  const payload = await buildBinding("04D2760000850100", "ctx");
  const oldSig = hexToBytes(await oldId.signBinding(payload));

  const newId = await rotateIdentity(store);
  assert.notEqual(newId.publicKeyHex, oldId.publicKeyHex);

  // old signature must NOT verify under the rotated (new) public key
  const verifiesUnderNew = nodeCrypto.verify(
    "sha256",
    Buffer.from(payload),
    { key: publicKeyFromHex(newId.publicKeyHex), dsaEncoding: "der" },
    oldSig,
  );
  assert.equal(verifiesUnderNew, false);

  // the store now holds the new identity
  const reloaded = await loadOrCreateIdentity(store);
  assert.equal(reloaded.publicKeyHex, newId.publicKeyHex);
});

test("clear() removes the identity", async () => {
  const store = await freshStore();
  await loadOrCreateIdentity(store);
  assert.equal(await store.has(), true);
  await store.clear();
  assert.equal(await store.has(), false);
});
