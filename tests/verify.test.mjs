// node --test "tests/*.test.mjs"
//
// The property worth guarding here is not "does a good key pass" — it is that
// a REFUSAL still answers 200. license.py reads any non-200 as "the network is
// down" and grants a grace period, so a 403 here would mean a key removed from
// the allowlist keeps working. Every rejection case asserts the status.

import test from "node:test";
import assert from "node:assert/strict";

import { onRequestGet } from "../functions/api/license/verify.js";
import { sha256Hex } from "../functions/_auth.js";
import { createCliSession, revokeCliSession } from "../functions/_cli.js";
import { grantEntitlement, revokeEntitlement } from "../functions/_store.js";
import { makeUser, testD1 } from "./helpers/d1.mjs";

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

// --- beta accounts, which have no key ---------------------------------------
//
// Same endpoint, second credential. What matters is that the verdict is
// `accessFor`'s and not a second opinion — so a revocation made in the review
// desk has to show up here on the next call, with no cache in between.

const BETA_ENV = (db) => ({ KRYONSEC_DB: db });

async function beta(token, db) {
  const response = await onRequestGet({
    request: new Request("https://kryonsec.in/api/license/verify", {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
    env: BETA_ENV(db),
  });
  return { status: response.status, body: await response.json() };
}

/** A beta account with an active entitlement and one signed-in machine. */
async function machine(db) {
  const userId = await makeUser(db);
  await grantEntitlement(db, { userId, actor: "admin" });
  return { userId, token: await createCliSession(db, { userId, label: "linux/x86_64" }) };
}

test("a CLI token with an active entitlement validates", async () => {
  const db = testD1();
  const { token } = await machine(db);

  const { status, body } = await beta(token, db);
  assert.equal(status, 200);
  assert.equal(body.valid, true);
});

test("a revocation in the review desk stops the next check-in", async () => {
  const db = testD1();
  const { userId, token } = await machine(db);
  await revokeEntitlement(db, { userId, actor: "admin", reason: "sharing the wheel" });

  const { status, body } = await beta(token, db);
  // 200 with valid:false, not 403 — a 403 is the grace period this endpoint
  // exists to avoid.
  assert.equal(status, 200);
  assert.equal(body.valid, false);
  assert.match(body.reason, /sharing the wheel|revoked/i);
});

test("ending the programme stops a token whose own access is still active", async () => {
  const db = testD1();
  const { token } = await machine(db);
  db._raw.prepare("UPDATE beta_program SET status = 'ended' WHERE id = 1").run();

  const { body } = await beta(token, db);
  assert.equal(body.valid, false);
  assert.match(body.reason, /programme has ended/i);
});

test("an unrecognised, expired or revoked token is refused the same way", async () => {
  const db = testD1();
  const { userId, token } = await machine(db);
  const cli = db._raw.prepare("SELECT id FROM cli_sessions WHERE user_id = ?").get(userId);
  await revokeCliSession(db, { id: cli.id, actor: "self" });
  const expired = await createCliSession(db, { userId });
  db._raw
    .prepare("UPDATE cli_sessions SET expires_at = ? WHERE token_hash = ?")
    .run("2020-01-01T00:00:00.000Z", await sha256Hex(expired));

  const reasons = [];
  for (const t of [token, expired, `s_${"a".repeat(64)}`, "", "not-a-token"]) {
    const { status, body } = await beta(t, db);
    assert.equal(status, 200);
    assert.equal(body.valid, false);
    reasons.push(body.reason);
  }

  // One sentence for all five. A distinct "that token was revoked" would tell
  // someone guessing which guesses were once real credentials.
  assert.equal(new Set(reasons).size, 1, `refusals differed: ${reasons.join(" / ")}`);
});

test("with no database bound, a token fails closed rather than open", async () => {
  const response = await onRequestGet({
    request: new Request("https://kryonsec.in/api/license/verify", {
      headers: { Authorization: `Bearer s_${"a".repeat(64)}` },
    }),
    env: {},
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).valid, false);
});

test("a membership key still wins, exactly as before", async () => {
  const db = testD1();
  // A key alongside a token that resolves to a revoked account: the key path
  // is what an existing install sends, and it must not be re-adjudicated.
  const { userId, token } = await machine(db);
  await revokeEntitlement(db, { userId, actor: "admin" });

  const response = await onRequestGet({
    request: new Request(`https://kryonsec.in/api/license/verify?key=${GOOD}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),
    env: { KRYONSEC_KEYS: KEYS, KRYONSEC_DB: db },
  });
  assert.equal((await response.json()).valid, true);
});
