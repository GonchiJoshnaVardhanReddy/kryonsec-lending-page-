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

// ---------------------------------------------------------------------------
// The beta list.
//
// Purple Team needs two things from this endpoint: a verdict the app can cache
// and an address to record as the machine's owner. A membership key supplies
// neither address — the member claims one by browser — so a beta tester with
// only a key would read "run `kryonsec connect` first" forever. The server
// answers a beta key with a shared address instead, and revoking it stays a
// one-line edit to a secret rather than a client release.
// ---------------------------------------------------------------------------

const BETA = "KRYO-BETA-BETA-BETA";

async function ask(env, key) {
  const response = await onRequestGet({
    request: new Request(
      "https://kryonsec.in/api/license/verify",
      { headers: { "X-Kryonsec-Key": key } },
    ),
    env,
  });
  return { status: response.status, body: await response.json() };
}

test("a beta key is vouched for by the server", async () => {
  const { status, body } = await ask({ KRYONSEC_BETA_KEYS: BETA }, BETA);
  assert.equal(status, 200);
  assert.equal(body.valid, true);
  assert.equal(body.member, "beta@kryonsec.in");
});

test("a beta key works with no membership allowlist at all", async () => {
  // The state production is actually in when the beta list is the only one
  // filled in: a missing KRYONSEC_KEYS must not turn the beta door shut.
  const { body } = await ask({ KRYONSEC_BETA_KEYS: BETA }, BETA);
  assert.equal(body.valid, true);
});

test("a paid membership key carries no identity", async () => {
  // Absent, not empty: the CLI only adopts an address it does not already
  // have, and a blank here would overwrite a member's claimed email.
  const { body } = await ask({ KRYONSEC_KEYS: KEYS }, GOOD);
  assert.equal(body.valid, true);
  assert.equal("member" in body, false);
});

test("a membership key keeps claiming even while a beta list is live", async () => {
  const { body } = await ask(
    { KRYONSEC_KEYS: KEYS, KRYONSEC_BETA_KEYS: BETA },
    GOOD,
  );
  assert.equal(body.valid, true);
  assert.equal("member" in body, false);
});

test("a key on both lists answers with the identity", async () => {
  // The order is the product decision: one credential a beta tester types once
  // and both modes work. A membership-only key still answers with no identity,
  // so the claim step in the browser stays what names a paid member.
  const { status, body } = await ask(
    { KRYONSEC_KEYS: KEYS, KRYONSEC_BETA_KEYS: GOOD },
    GOOD,
  );
  assert.equal(status, 200);
  assert.equal(body.valid, true);
  assert.equal(body.member, "beta@kryonsec.in");
});

test("a key on neither list is refused with 200", async () => {
  const { status, body } = await ask(
    { KRYONSEC_KEYS: KEYS, KRYONSEC_BETA_KEYS: BETA },
    "KRYO-3333-3333-3333",
  );
  assert.equal(status, 200);
  assert.equal(body.valid, false);
  assert.ok(body.reason);
});

test("an unset beta list changes nothing for a membership key", async () => {
  const { body } = await ask({ KRYONSEC_KEYS: KEYS }, GOOD);
  assert.equal(body.valid, true);
});
