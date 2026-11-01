// node --test "tests/*.test.mjs"
//
// `kryonsec login`, end to end: the CLI asks for a code, a person approves it
// in a browser, and the CLI collects one token — once.
//
// The properties worth guarding are the ones that decide whether this is an
// authentication system or a way to mint credentials for anyone who asks:
// a code grants nothing until an entitled account approves it; approving is
// an entitled act at the moment it happens, not at page-render time; and the
// token is minted at collection, once, so an approved-but-abandoned login
// leaves no live credential behind.

import test from "node:test";
import assert from "node:assert/strict";

import { createSession, csrfFor, SESSION_COOKIE, sha256Hex } from "../functions/_auth.js";
import { cliSessionFromToken } from "../functions/_cli.js";
import { onRequestGet as devicePage } from "../functions/beta/device.js";
import { onRequestPost as approve } from "../functions/api/beta/device/approve.js";
import { onRequestPost as poll } from "../functions/api/beta/device/poll.js";
import { onRequestPost as start } from "../functions/api/beta/device/start.js";
import { grantEntitlement, revokeEntitlement, submitApplication } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const ENV = (db) => ({ KRYONSEC_DB: db });

const startRequest = (fields = {}) =>
  new Request(`${SITE}/api/beta/device/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: "abc123", os: "Linux", arch: "x86_64", version: "1.3.7", ...fields }),
  });

const pollRequest = (device_code) =>
  new Request(`${SITE}/api/beta/device/poll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_code }),
  });

/** A signed-in, entitled account — the person at the browser. */
async function browser(db, options = {}) {
  const userId = await makeUser(db, options);
  const token = await createSession(db, userId);
  await grantEntitlement(db, { userId, actor: "admin" });
  return { userId, token, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

const approval = (who, code, decision, { csrf = null, origin = SITE } = {}) =>
  req(`${SITE}/api/beta/device/approve`, {
    method: "POST",
    cookie: who.cookie,
    body: new URLSearchParams({ code, decision, csrf: csrf ?? who.csrf }),
    headers: { ...(origin === SITE ? { "Sec-Fetch-Site": "same-origin" } : { "Sec-Fetch-Site": "cross-site" }), Origin: origin },
  });

/** The whole handshake, for the tests that are about what comes out of it. */
async function signIn(db, who, decision = "approve") {
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();
  await approve({ request: approval(who, started.code, decision), env: ENV(db) });
  return { started, collected: await (await poll({ request: pollRequest(started.device_code), env: ENV(db) })).json() };
}

// --- step 1: asking ---------------------------------------------------------

test("a start hands back a code, a secret, and a link — and no identity", async () => {
  const db = testD1();
  const response = await start({ request: startRequest(), env: ENV(db) });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.match(body.code, /^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  assert.match(body.device_code, /^[0-9a-f]{64}$/);
  assert.equal(body.url, `${SITE}/beta/device?code=${body.code}`);
  // Nothing here knows who the person is yet, and it must not pretend to.
  assert.equal(body.token, undefined);
  assert.equal(body.email, undefined);
});

test("a start with no database refuses rather than issuing a dead code", async () => {
  const response = await start({ request: startRequest(), env: {} });
  assert.equal(response.status, 503);
});

test("a flood of starts is capped", async () => {
  const db = testD1();
  let refused = 0;
  for (let i = 0; i < 70; i += 1) {
    const response = await start({ request: startRequest(), env: ENV(db) });
    if (response.status === 429) refused += 1;
  }
  assert.ok(refused > 0, "the cap should refuse once the table is filling up");
  // And it did not refuse the first ones — the cap bounds abuse without
  // making login unreliable for a person running it once.
  assert.ok(refused < 70, "the cap should not refuse everything");
});

// --- step 2: the page -------------------------------------------------------

test("the approval page is behind sign-in and comes back to itself", async () => {
  const db = testD1();
  const { started } = await signIn(db, await browser(db));
  const path = `/beta/device?code=${started.code}`;

  const response = await devicePage({ request: new Request(`${SITE}${path}`), env: ENV(db) });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), `/signin?next=${encodeURIComponent(path)}`);
});

test("the page shows the machine, so the wrong one cannot be approved by accident", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const response = await devicePage({
    request: new Request(`${SITE}/beta/device?code=${started.code}`, { headers: { Cookie: who.cookie } }),
    env: ENV(db),
  });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /Linux/);
  assert.match(body, /x86_64/);
  assert.match(body, /1\.3\.7/);
  assert.match(body, /value="approve"/);
  assert.match(body, /value="deny"/);
});

test("an account with no access is told so, and is given no buttons", async () => {
  const db = testD1();
  const userId = await makeUser(db);
  const token = await createSession(db, userId);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const body = await (
    await devicePage({
      request: new Request(`${SITE}/beta/device?code=${started.code}`, { headers: { Cookie: `${SESSION_COOKIE}=${token}` } }),
      env: ENV(db),
    })
  ).text();

  assert.match(body, /CANNOT/);
  assert.doesNotMatch(body, /value="approve"/);
});

test("an unknown code and a decided code look the same", async () => {
  const db = testD1();
  const who = await browser(db);
  const { started } = await signIn(db, who);

  const bodies = [];
  for (const code of ["ZZZZ-ZZZZ", started.code]) {
    const response = await devicePage({
      request: new Request(`${SITE}/beta/device?code=${code}`, { headers: { Cookie: who.cookie } }),
      env: ENV(db),
    });
    assert.equal(response.status, 410);
    bodies.push(await response.text());
  }
  // Telling a guessed code apart from a spent one would make this page a way
  // to test whether a code once existed.
  assert.match(bodies[0], /NO LONGER LIVE/);
  assert.match(bodies[1], /NO LONGER LIVE/);
});

// --- step 3: saying yes -----------------------------------------------------

test("approving a code does not mint a token yet", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const response = await approve({ request: approval(who, started.code, "approve"), env: ENV(db) });
  assert.equal(response.status, 303);
  assert.match(response.headers.get("Location"), /e=approved/);

  const row = db._raw.prepare("SELECT approved_by FROM cli_login_codes WHERE code = ?").get(started.code);
  assert.equal(row.approved_by, who.userId);
  // The point of the split: an approved login nobody collects leaves no live
  // credential behind, only a row that expires.
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
});

test("approving without a session approves nothing", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const response = await approve({
    request: req(`${SITE}/api/beta/device/approve`, {
      method: "POST",
      body: new URLSearchParams({ code: started.code, decision: "approve", csrf: who.csrf }),
      headers: { "Sec-Fetch-Site": "same-origin", Origin: SITE },
    }),
    env: ENV(db),
  });

  assert.equal(response.status, 303);
  assert.match(response.headers.get("Location"), /^\/signin/);
  assert.equal(db._raw.prepare("SELECT approved_at FROM cli_login_codes WHERE code = ?").get(started.code).approved_at, null);
});

test("a cross-site approval is refused", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const response = await approve({
    request: approval(who, started.code, "approve", { origin: "https://evil.example" }),
    env: ENV(db),
  });
  assert.equal(response.status, 403);
  assert.equal(db._raw.prepare("SELECT approved_at FROM cli_login_codes WHERE code = ?").get(started.code).approved_at, null);
});

test("an account revoked after the page rendered cannot approve", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  // The page was rendered, then access went away. The decision is made on the
  // POST, and it is made on the current answer.
  await revokeEntitlement(db, { userId: who.userId, actor: "admin", reason: "sharing the wheel" });
  const response = await approve({ request: approval(who, started.code, "approve"), env: ENV(db) });

  assert.equal(response.status, 403);
  assert.equal(db._raw.prepare("SELECT approved_at FROM cli_login_codes WHERE code = ?").get(started.code).approved_at, null);
});

test("a second approval cannot move the moment or the person", async () => {
  const db = testD1();
  const first = await browser(db);
  const second = await browser(db, { id: "u_2", email: "b@example.com" });
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();
  await approve({ request: approval(first, started.code, "approve"), env: ENV(db) });

  const response = await approve({ request: approval(second, started.code, "approve"), env: ENV(db) });
  assert.match(response.headers.get("Location"), /e=stale/);

  const row = db._raw.prepare("SELECT approved_by FROM cli_login_codes WHERE code = ?").get(started.code);
  assert.equal(row.approved_by, first.userId);
});

test("denying is recorded and reported as denied, not as unknown", async () => {
  const db = testD1();
  const who = await browser(db);
  const { collected } = await signIn(db, who, "deny");

  // Distinct from "unknown" so the terminal can say what happened instead of
  // making the person wait out the clock.
  assert.equal(collected.status, "denied");
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
});

// --- step 4: collecting -----------------------------------------------------

test("an approved login collects exactly one token, and only once", async () => {
  const db = testD1();
  const who = await browser(db);
  const { started, collected } = await signIn(db, who);

  assert.equal(collected.status, "approved");
  assert.match(collected.token, /^s_[0-9a-f]{64}$/);
  assert.equal(collected.email, "a@example.com");
  assert.equal(collected.label, "Linux/x86_64");

  // Stored hashed, and labelled with the machine the CLI described.
  const row = db._raw.prepare("SELECT user_id, label FROM cli_sessions WHERE token_hash = ?").get(await sha256Hex(collected.token));
  assert.equal(row.user_id, who.userId);
  assert.equal(row.label, "Linux/x86_64");

  // A second poll finds nothing. Two collections would be two ninety-day
  // credentials for one login.
  const again = await (await poll({ request: pollRequest(started.device_code), env: ENV(db) })).json();
  assert.equal(again.status, "unknown");
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 1);
});

test("a login approved and then revoked in between collects nothing", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();
  await approve({ request: approval(who, started.code, "approve"), env: ENV(db) });

  // Approval and collection are minutes apart on a slow connection, so the
  // entitlement is re-read at collection rather than trusted from the click.
  await revokeEntitlement(db, { userId: who.userId, actor: "admin", reason: "no longer eligible" });
  const collected = await (await poll({ request: pollRequest(started.device_code), env: ENV(db) })).json();

  assert.equal(collected.status, "denied");
  assert.equal(collected.token, undefined);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
});

test("an unapproved or malformed device code gets nothing", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  for (const value of [started.device_code, "x", "", "0".repeat(63), `${"a".repeat(64)}b`]) {
    const response = await poll({ request: pollRequest(value), env: ENV(db) });
    const body = await response.json();
    assert.notEqual(body.status, "approved", `leaked for ${JSON.stringify(value)}`);
  }
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_login_codes").get().n, 1);
});

test("an expired code is expired, not pending forever", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();
  db._raw
    .prepare("UPDATE cli_login_codes SET created_at = ? WHERE code = ?")
    .run("2020-01-01T00:00:00.000Z", started.code);

  const collected = await (await poll({ request: pollRequest(started.device_code), env: ENV(db) })).json();
  assert.equal(collected.status, "expired");
});

test("the token that comes out works at the download gate", async () => {
  const db = testD1();
  const who = await browser(db);
  const { collected } = await signIn(db, who);

  // The whole point of login is this: the token is a credential the rest of
  // the system already understands, with no second notion of "signed in".
  const resolved = await cliSessionFromToken(db, collected.token);
  assert.equal(resolved.userId, who.userId);
  assert.equal(resolved.id.startsWith("s"), true);
});

test("an applicant still in review cannot approve a machine in", async () => {
  const db = testD1();
  // Signed in, applied, waiting — the state a beta applicant is in for days.
  const userId = await makeUser(db);
  const token = await createSession(db, userId);
  await submitApplication(db, userId, { full_name: "Ada", contact_email: "ada@example.com", intended_use: "testing" });
  const started = await (await start({ request: startRequest(), env: ENV(db) })).json();

  const who = { cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
  const response = await approve({ request: approval(who, started.code, "approve"), env: ENV(db) });

  assert.equal(response.status, 403);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
});
