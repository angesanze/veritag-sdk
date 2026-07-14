/**
 * AttestClient HTTP behaviour: non-2xx responses throw AttestApiError (not a
 * success body cast to the wrong type), and revokeIssuer hits the right route.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { AttestClient, AttestApiError } from "../dist/index.js";

function mockFetch(handler) {
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET" });
    const { status = 200, body = {} } = handler(String(url), init) ?? {};
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return calls;
}

test("verify returns the parsed result on 200", async () => {
  mockFetch(() => ({ body: { chip_authentic: true, not_replayed: true, issuer_verified: true, reason: "" } }));
  const c = new AttestClient("https://x");
  const r = await c.verify("04D2", 1, "aa");
  assert.equal(r.chip_authentic, true);
});

test("non-2xx throws AttestApiError with status + detail", async () => {
  mockFetch(() => ({ status: 400, body: { detail: "m is not valid hex" } }));
  const c = new AttestClient("https://x");
  await assert.rejects(c.verify("04D2", 1, "ZZ"), (e) => {
    assert.ok(e instanceof AttestApiError);
    assert.equal(e.status, 400);
    assert.match(e.detail, /not valid hex/);
    return true;
  });
});

test("registerIssuer returns issuer_id and token", async () => {
  mockFetch(() => ({ body: { issuer_id: "iss_abc", token: "isk_x" } }));
  const c = new AttestClient("https://x");
  const reg = await c.registerIssuer("04ab");
  assert.equal(reg.issuerId, "iss_abc");
  assert.equal(reg.token, "isk_x");
});

test("revokeIssuer POSTs the revoke route and resolves", async () => {
  const calls = mockFetch(() => ({ body: { issuer_id: "iss_abc", status: "revoked" } }));
  const c = new AttestClient("https://x", "tok");
  await c.revokeIssuer("iss_abc");
  assert.equal(calls[0].method, "POST");
  assert.match(calls[0].url, /\/v1\/issuers\/iss_abc\/revoke$/);
});

test("revokeIssuer throws on 403", async () => {
  mockFetch(() => ({ status: 403, body: { detail: "cannot revoke another issuer" } }));
  const c = new AttestClient("https://x");
  await assert.rejects(c.revokeIssuer("iss_other"), AttestApiError);
});
