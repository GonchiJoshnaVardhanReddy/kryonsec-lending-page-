// node --test "tests/*.test.mjs"
//
// The property worth guarding here is not "does a good key pass" — it is that
// a REFUSAL still answers 200. license.py reads any non-200 as "the network is
// down" and grants a grace period, so a 403 here would mean a key removed from
// the allowlist keeps working. Every rejection case asserts the status.

import test from "node:test";
import assert from "node:assert/strict";

import { onRequestGet } from "../functions/api/license/verify.js";

const GOOD = "KRYO-AB2C-DE3F-GH4J";
const KEYS = `${GOOD},KRYO-2222-2222-2222`;

async function verify(key, keys = KEYS) {
  const url = key === null
    ? "https://kryonsec.in/api/license/verify"
    : `https://kryonsec.in/api/license/verify?key=${encodeURIComponent(key)}`;
  // null means "no KRYONSEC_KEYS in the environment at all" — distinct from an
  // empty string, and not expressible via a default parameter.
  const env = keys === null ? {} : { KRYONSEC_KEYS: keys };
  const response = await onRequestGet({ request: new Request(url), env });
  return { status: response.status, body: await response.json() };
}

test("a listed key is accepted", async () => {
  const { status, body } = await verify(GOOD);
  assert.equal(status, 200);
  assert.equal(body.valid, true);
});

test("lowercase and padded keys are accepted", async () => {
  const { body } = await verify(`  ${GOOD.toLowerCase()}  `);
  assert.equal(body.valid, true);
});

test("every refusal still answers 200", async () => {
  // The whole point: a 403 would read as an outage and buy a grace period.
  const cases = [
    [GOOD, "KRYO-2222-2222-2222"], // a real-looking key not on the list
    ["KRYO-AB2C-DE3F", KEYS], // malformed
    ["nonsense", KEYS], // malformed
    [null, KEYS], // no key at all
    [GOOD, ""], // allowlist empty
    [GOOD, null], // allowlist missing entirely
  ];
  for (const [key, keys] of cases) {
    const { status, body } = await verify(key, keys);
    assert.equal(status, 200, `${key} / ${keys}`);
    assert.equal(body.valid, false, `${key} / ${keys}`);
    assert.ok(body.reason, "a refusal must say why");
  }
});

test("a key is not a prefix or superstring of a listed one", async () => {
  for (const key of ["KRYO-AB2C-DE3F-GH4", "KRYO-AB2C-DE3F-GH4JX", "KRYO-AB2C-DE3F-GH4K"]) {
    const { body } = await verify(key);
    assert.equal(body.valid, false, key);
  }
});

test("the verdict is never cached", async () => {
  const response = await onRequestGet({
    request: new Request(`https://kryonsec.in/api/license/verify?key=${GOOD}`),
    env: { KRYONSEC_KEYS: KEYS },
  });
  // A cached verdict would outlive a revocation for everyone behind the cache.
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});
